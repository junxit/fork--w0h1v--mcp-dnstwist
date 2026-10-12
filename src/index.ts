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
import { isIP } from 'net';
import { promisify } from 'util';

// execFile runs docker directly with an argument array. No shell is involved,
// so tool input can never be interpreted as shell syntax (CWE-78, issue #13).
const execFileAsync = promisify(execFile);
const DOCKER_IMAGE = 'elceef/dnstwist';

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

interface FuzzDomainArgs {
  domain: string;
  nameservers?: string;
  threads?: number;
  format?: 'json' | 'csv' | 'list';
  registered_only?: boolean;
  mxcheck?: boolean;
  ssdeep?: boolean;
  banners?: boolean;
}

// A hostname: dot-separated labels of letters, digits and inner hyphens, ending
// in an alphabetic or punycode TLD. It can't start with "-", so it can't be
// mistaken for a dnstwist option either.
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/i;
const FORMATS = ['json', 'csv', 'list'] as const;
const MAX_NAMESERVERS = 10;

function invalid(message: string): never {
  throw new McpError(ErrorCode.InvalidParams, `Invalid arguments for fuzz_domain: ${message}`);
}

function optionalBoolean(a: Record<string, unknown>, key: string, fallback: boolean): boolean {
  if (a[key] === undefined) return fallback;
  if (typeof a[key] !== 'boolean') invalid(`${key} must be a boolean`);
  return a[key] as boolean;
}

export function validateFuzzArgs(args: unknown): Required<FuzzDomainArgs> {
  if (!args || typeof args !== 'object') invalid('arguments must be an object');
  const a = args as Record<string, unknown>;

  if (typeof a.domain !== 'string' || !HOSTNAME.test(a.domain)) {
    invalid('domain must be a domain name such as example.com');
  }

  const nameservers = a.nameservers === undefined ? '1.1.1.1' : a.nameservers;
  if (typeof nameservers !== 'string') invalid('nameservers must be a string');
  const servers = (nameservers as string).split(',');
  if (servers.length > MAX_NAMESERVERS ||
      !servers.every((ns) => isIP(ns) !== 0 || HOSTNAME.test(ns))) {
    invalid(`nameservers must be up to ${MAX_NAMESERVERS} comma-separated IP addresses or hostnames`);
  }

  const threads = a.threads === undefined ? 50 : a.threads;
  if (typeof threads !== 'number' || !Number.isInteger(threads) || threads < 1 || threads > 100) {
    invalid('threads must be an integer from 1 to 100');
  }

  const format = a.format === undefined ? 'json' : a.format;
  if (!FORMATS.includes(format as typeof FORMATS[number])) {
    invalid(`format must be one of ${FORMATS.join(', ')}`);
  }

  return {
    domain: a.domain as string,
    nameservers: nameservers as string,
    threads: threads as number,
    format: format as (typeof FORMATS)[number],
    registered_only: optionalBoolean(a, 'registered_only', true),
    mxcheck: optionalBoolean(a, 'mxcheck', true),
    ssdeep: optionalBoolean(a, 'ssdeep', false),
    banners: optionalBoolean(a, 'banners', true),
  };
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
    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });

    // Trigger setup immediately
    this.ensureSetup().catch(error => {
      console.error('Failed to setup dnstwist:', error);
      process.exit(1);
    });
  }

  private async execCommand(file: string, args: string[]): Promise<{ stdout: string; stderr: string }> {
    console.error('Executing:', file, JSON.stringify(args));
    try {
      const result = await execFileAsync(file, args, {
        maxBuffer: 10 * 1024 * 1024
      });
      console.error('Command output:', result.stdout);
      if (result.stderr) console.error('Command stderr:', result.stderr);
      return result;
    } catch (error) {
      console.error('Command failed:', error);
      throw error;
    }
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
                description: 'Comma-separated list of DNS servers to use (default: 1.1.1.1)',
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

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
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
        const { stdout } = await this.execCommand(
          'docker', ['run', '--rm', DOCKER_IMAGE, ...args]
        );

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
