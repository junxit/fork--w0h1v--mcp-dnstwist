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
import { FUZZERS, LSH_ALGORITHMS, validateFuzzArgs } from './validate.js';

// execFile runs docker (or dnstwist) directly with an argument array. No shell is involved,
// so tool input can never be interpreted as shell syntax (CWE-78, issue #13).
const execFileAsync = promisify(execFile);
const DOCKER_IMAGE = 'elceef/dnstwist';

// A scan that runs longer than this is stopped and its container removed.
// Slow resolvers (DNS-over-HTTPS), LSH and banners can take many minutes.
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

type Runner = 'docker' | 'local';
const RUNNER_SETTINGS = ['docker', 'local', 'auto'] as const;

// docker: run the elceef/dnstwist image. local: run a dnstwist on PATH.
// auto (default): local when a dnstwist executable works, otherwise docker.
function runnerSetting(): (typeof RUNNER_SETTINGS)[number] {
  const raw = process.env.DNSTWIST_RUNNER;
  if (raw === undefined || raw === '') return 'auto';
  if (!(RUNNER_SETTINGS as readonly string[]).includes(raw)) {
    console.error(`DNSTWIST_RUNNER must be one of ${RUNNER_SETTINGS.join(', ')}, got ${JSON.stringify(raw)}`);
    process.exit(1);
  }
  return raw as (typeof RUNNER_SETTINGS)[number];
}

const RUNNER_SETTING = runnerSetting();

interface DnstwistResult {
  banner_http?: string;
  dns_a?: string[];
  dns_aaaa?: string[];
  dns_mx?: string[];
  dns_ns?: string[];
  domain: string;
  fuzzer: string;
  geoip?: string;
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
        // in-flight child process first, then remove any docker container.
        const scans = [...this.runningScans.values()];
        for (const scan of scans) scan.stop.abort();
        await Promise.all(scans.flatMap((scan) => (scan.container ? [this.removeContainer(scan.container)] : [])));
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
    options: { timeout?: number; signal?: AbortSignal; killSignal?: NodeJS.Signals; killOnAbort?: boolean } = {}
  ): Promise<{ stdout: string; stderr: string }> {
    console.error('Executing:', file, JSON.stringify(args));
    try {
      const { killOnAbort, ...execOptions } = options;
      const pending = execFileAsync(file, args, {
        maxBuffer: 10 * 1024 * 1024,
        ...execOptions,
        // execFile's own `signal` support always sends SIGTERM; when the process
        // must be killed outright, handle the abort here instead.
        ...(killOnAbort ? { signal: undefined } : {})
      });
      const abort = () => pending.child.kill('SIGKILL');
      if (killOnAbort && options.signal) {
        if (options.signal.aborted) abort();
        else options.signal.addEventListener('abort', abort, { once: true });
      }
      let result;
      try {
        result = await pending;
      } finally {
        options.signal?.removeEventListener('abort', abort);
      }
      console.error('Command output:', result.stdout);
      if (result.stderr) console.error('Command stderr:', result.stderr);
      return result;
    } catch (error) {
      console.error('Command failed:', error);
      throw error;
    }
  }

  // Scans in progress: id -> controller that stops the child process, plus the
  // container name when the docker runner started one.
  private runningScans = new Map<string, { stop: AbortController; container?: string }>();

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

  private runnerPromise?: Promise<Runner>;

  // Decided once. A failed check is not cached, so a later call can retry.
  private getRunner(): Promise<Runner> {
    this.runnerPromise ??= this.selectRunner().catch((error) => {
      this.runnerPromise = undefined;
      throw error;
    });
    return this.runnerPromise;
  }

  private async checkLocal(): Promise<void> {
    try {
      await this.execCommand('dnstwist', ['--version']);
    } catch (error) {
      throw new Error(
        'The dnstwist executable was not found or does not work (`dnstwist --version` failed). ' +
        'Install it (for example `pipx install "dnstwist[full]"`) or set DNSTWIST_RUNNER=docker.'
      );
    }
  }

  private async selectRunner(): Promise<Runner> {
    if (RUNNER_SETTING === 'docker') return 'docker';
    if (RUNNER_SETTING === 'local') {
      await this.checkLocal();
      console.error('Using the local dnstwist executable (DNSTWIST_RUNNER=local)');
      return 'local';
    }
    try {
      await this.checkLocal();
      console.error('Using the local dnstwist executable (DNSTWIST_RUNNER=auto)');
      return 'local';
    } catch {
      console.error('No working dnstwist executable on PATH; using Docker (DNSTWIST_RUNNER=auto)');
      return 'docker';
    }
  }

  private async checkDocker(): Promise<void> {
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
  }

  private async ensureSetup(): Promise<Runner> {
    try {
      const runner = await this.getRunner();
      // Docker is re-checked per call: the image or daemon can disappear.
      if (runner === 'docker') await this.checkDocker();
      return runner;
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
                description: 'Number of parallel lookups (1-100)',
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
                description: 'Check whether each mail server would accept email for any address, so it could intercept mail sent to typos of your domain',
                default: true
              },
              ssdeep: {
                type: 'boolean',
                description: 'Deprecated alias for lsh: "ssdeep" (ignored when lsh is set)',
                default: false
              },
              lsh: {
                type: 'string',
                enum: [...LSH_ALGORITHMS],
                description: 'Compare each permutation\'s web page with the original using a fuzzy hash (slow) to spot cloned phishing pages'
              },
              whois: {
                type: 'boolean',
                description: 'Look up WHOIS creation date and registrar for each domain (slower)',
                default: false
              },
              all_records: {
                type: 'boolean',
                description: 'Return all DNS records instead of only the first of each type',
                default: false
              },
              fuzzers: {
                type: 'array',
                items: { type: 'string', enum: [...FUZZERS] },
                minItems: 1,
                maxItems: FUZZERS.length,
                uniqueItems: true,
                description: 'Only use these fuzzing algorithms (default: all)'
              },
              banners: {
                type: 'boolean',
                description: 'Capture HTTP and SMTP server banners',
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
        const runner = await this.ensureSetup();

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
          banners,
          whois,
          all_records,
          fuzzers,
          lsh
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
        if (lsh) args.push('--lsh', lsh);
        if (banners) args.push('-b');
        if (whois) args.push('-w');
        if (all_records) args.push('-a');
        if (fuzzers) args.push('--fuzzers', fuzzers.join(','));

        const id = randomUUID();
        const container = runner === 'docker' ? `mcp-dnstwist-${id}` : undefined;
        const stop = new AbortController();
        this.runningScans.set(id, { stop, container });
        let stdout: string;
        try {
          const options = { timeout: TIMEOUT_SECONDS * 1000, signal: AbortSignal.any([extra.signal, stop.signal]) };
          ({ stdout } = container
            ? await this.execCommand('docker', ['run', '--rm', '--name', container, DOCKER_IMAGE, ...args], options)
            // dnstwist handles SIGTERM itself and may wind down slowly: kill it outright.
            : await this.execCommand('dnstwist', args, { ...options, killSignal: 'SIGKILL', killOnAbort: true }));
        } catch (error) {
          const stopped = extra.signal.aborted || stop.signal.aborted;
          const timedOut = Boolean((error as { killed?: boolean }).killed) && !stopped;
          // If dnstwist exited on its own, --rm already removed the container.
          if (container && (timedOut || stopped)) await this.removeContainer(container);
          if (timedOut) {
            const unit = TIMEOUT_SECONDS === 1 ? 'second' : 'seconds';
            throw new Error(
              `dnstwist did not finish within ${TIMEOUT_SECONDS} ${unit} and was stopped. ` +
              'Use an IPv4 nameserver (DNS-over-HTTPS is slow), turn off lsh, whois or banners, ' +
              'or raise DNSTWIST_TIMEOUT_SECONDS.'
            );
          }
          throw error;
        } finally {
          this.runningScans.delete(id);
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
