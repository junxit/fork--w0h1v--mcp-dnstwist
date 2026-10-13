#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { execFile } from 'child_process';
import { randomUUID } from 'crypto';
import { promisify } from 'util';
import { validateFuzzArgs } from './validate.js';

// execFile runs docker directly with an argument array. No shell is involved,
// so tool input can never be interpreted as shell syntax (CWE-78, issue #13).
const execFileAsync = promisify(execFile);
const DOCKER_IMAGE = 'elceef/dnstwist';

// A scan that runs longer than this is stopped and its container removed.
// Slow resolvers (DNS-over-HTTPS) and --ssdeep/--banners can take many minutes.
const DEFAULT_TIMEOUT_SECONDS = 600;

function scanTimeoutSeconds(): number {
  const raw = process.env.DNSTWIST_TIMEOUT_SECONDS;
  if (raw === undefined || raw === '') return DEFAULT_TIMEOUT_SECONDS;
  const seconds = Number(raw);
  if (!Number.isInteger(seconds) || seconds < 1 || seconds > 86400) {
    console.error(`DNSTWIST_TIMEOUT_SECONDS must be an integer from 1 to 86400, got ${JSON.stringify(raw)}`);
    process.exit(1);
  }
  return seconds;
}

const TIMEOUT_SECONDS = scanTimeoutSeconds();

interface DnstwistResult {
  banner_http?: string;
  dns_a?: string[];
  dns_aaaa?: string[];
  dns_mx?: string[];
  dns_ns?: string[];
  domain: string;
  fuzzer: string;
  whois_created?: string;
  whois_registrar?: string;
}

class DnstwistServer {
  private server: Server;

  constructor() {
    this.server = new Server(
      { name: 'dnstwist-server', version: '0.1.0' },
      { capabilities: { tools: {} } }
    );
    
    this.setupToolHandlers();
    
    this.server.onerror = (error) => console.error('[MCP Error]', error);
    for (const signal of ['SIGINT', 'SIGTERM'] as const) {
      process.on(signal, async () => {
        // Don't leave scans running after the server is gone: stop each
        // in-flight docker run first, then remove its container.
        for (const controller of this.runningContainers.values()) controller.abort();
        await Promise.all([...this.runningContainers.keys()].map((name) => this.removeContainer(name)));
        await this.server.close();
        process.exit(0);
      });
    }

    // Trigger setup immediately
    this.ensureSetup().catch(error => {
      console.error('Failed to setup dnstwist:', error);
      process.exit(1);
    });
  }

  private async execCommand(
    file: string,
    args: string[],
    options: { timeout?: number; signal?: AbortSignal } = {}
  ): Promise<{ stdout: string; stderr: string }> {
    console.error('Executing:', file, JSON.stringify(args));
    try {
      const result = await execFileAsync(file, args, {
        maxBuffer: 10 * 1024 * 1024,
        ...options
      });
      console.error('Command output:', result.stdout);
      if (result.stderr) console.error('Command stderr:', result.stderr);
      return result;
    } catch (error) {
      console.error('Command failed:', error);
      throw error;
    }
  }

  // Scans in progress: container name -> controller that stops its docker run.
  private runningContainers = new Map<string, AbortController>();

  // Killing the docker CLI doesn't stop the container it started, so a scan
  // that times out or is cancelled is removed by name. Right after the CLI
  // starts, the daemon may not have created the container yet ("No such
  // container"), so keep trying for a few seconds until a removal succeeds.
  private async removeContainer(name: string, attempts = 10, delayMs = 500): Promise<void> {
    for (let i = 0; i < attempts; i++) {
      try {
        await execFileAsync('docker', ['rm', '-f', name]);
        return;
      } catch {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }
    console.error(`Could not confirm removal of container ${name}`);
  }

  private async ensureSetup(): Promise<void> {
    try {
      console.error('Checking Docker...');
      try {
        await this.execCommand('docker', ['--version']);
      } catch (error) {
        throw new Error('Docker is not installed or not running. Please install Docker and try again.');
      }

      console.error('Checking if dnstwist image exists...');
      try {
        await this.execCommand('docker', ['image', 'inspect', DOCKER_IMAGE]);
        console.error('Dnstwist image found');
      } catch (error) {
        console.error('Dnstwist image not found, pulling...');
        await this.execCommand('docker', ['pull', DOCKER_IMAGE]);
        console.error('Dnstwist image pulled successfully');
      }
    } catch (error) {
      console.error('Setup failed:', error);
      throw error;
    }
  }

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'fuzz_domain',
          description: 'Generate and analyze domain permutations to detect potential typosquatting, phishing, and brand impersonation',
          inputSchema: {
            type: 'object',
            properties: {
              domain: {
                type: 'string',
                description: 'Domain name to analyze (e.g., example.com)'
              },
              nameservers: {
                type: 'string',
                description: 'Comma-separated DNS servers: IPv4 addresses or DNS-over-HTTPS URLs such as https://cloudflare-dns.com/dns-query (default: 1.1.1.1)',
                default: '1.1.1.1'
              },
              threads: {
                type: 'number',
                description: 'Number of threads to use for parallel processing',
                minimum: 1,
                maximum: 100,
                default: 50
              },
              format: {
                type: 'string',
                enum: ['json', 'csv', 'list'],
                description: 'Output format',
                default: 'json'
              },
              registered_only: {
                type: 'boolean',
                description: 'Show only registered domain permutations',
                default: true
              },
              mxcheck: {
                type: 'boolean',
                description: 'Check for MX records',
                default: true
              },
              ssdeep: {
                type: 'boolean',
                description: 'Generate fuzzy hashes of web pages to detect phishing',
                default: false
              },
              banners: {
                type: 'boolean',
                description: 'Capture HTTP banner information',
                default: true
              }
            },
            required: ['domain']
          }
        }
      ]
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      try {
        await this.ensureSetup();

        if (request.params.name !== 'fuzz_domain') {
          throw new McpError(
            ErrorCode.MethodNotFound,
            `Unknown tool: ${request.params.name}`
          );
        }

        const {
          domain,
          nameservers,
          threads,
          format,
          registered_only,
          mxcheck,
          ssdeep,
          banners
        } = validateFuzzArgs(request.params.arguments);

        // Build command arguments
        const args = [
          domain,
          '--format', format
        ];

        if (registered_only) args.push('--registered');
        if (nameservers) args.push('--nameservers', nameservers);
        if (threads) args.push('-t', threads.toString());
        if (mxcheck) args.push('--mxcheck');
        if (ssdeep) args.push('--ssdeep');
        if (banners) args.push('-b');

        // Run dnstwist in Docker
        const container = `mcp-dnstwist-${randomUUID()}`;
        const stop = new AbortController();
        this.runningContainers.set(container, stop);
        let stdout: string;
        try {
          ({ stdout } = await this.execCommand(
            'docker', ['run', '--rm', '--name', container, DOCKER_IMAGE, ...args],
            { timeout: TIMEOUT_SECONDS * 1000, signal: AbortSignal.any([extra.signal, stop.signal]) }
          ));
        } catch (error) {
          const stopped = extra.signal.aborted || stop.signal.aborted;
          const timedOut = Boolean((error as { killed?: boolean }).killed) && !stopped;
          // If dnstwist exited on its own, --rm already removed the container.
          if (timedOut || stopped) await this.removeContainer(container);
          if (timedOut) {
            const unit = TIMEOUT_SECONDS === 1 ? 'second' : 'seconds';
            throw new Error(
              `dnstwist did not finish within ${TIMEOUT_SECONDS} ${unit} and was stopped. ` +
              'Use an IPv4 nameserver (DNS-over-HTTPS is slow), turn off ssdeep or banners, ' +
              'or raise DNSTWIST_TIMEOUT_SECONDS.'
            );
          }
          throw error;
        } finally {
          this.runningContainers.delete(container);
        }

        // csv and list output are returned as dnstwist printed them.
        if (format !== 'json') {
          return { content: [{ type: 'text', text: stdout }] };
        }

        let results: DnstwistResult[];
        try {
          results = JSON.parse(stdout);
        } catch (error) {
          throw new Error(`Failed to parse dnstwist output: ${error}`);
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(results, null, 2)
            }
          ]
        };
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return {
          content: [
            {
              type: 'text',
              text: `Error executing dnstwist: ${errorMessage}`
            }
          ],
          isError: true
        };
      }
    });
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Dnstwist MCP server running on stdio');
  }
}

const server = new DnstwistServer();
server.run().catch(console.error);
