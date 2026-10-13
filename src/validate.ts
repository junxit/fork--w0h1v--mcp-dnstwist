import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';
import { isIP } from 'net';
import { domainToASCII } from 'url';

export interface FuzzDomainArgs {
  domain: string;
  nameservers: string;
  threads: number;
  format: 'json' | 'csv' | 'list';
  registered_only: boolean;
  mxcheck: boolean;
  ssdeep: boolean;
  banners: boolean;
}

// A hostname: dot-separated labels of letters, digits and inner hyphens, ending
// in an alphabetic or punycode TLD. It can't start with "-", so it can't be
// mistaken for a dnstwist option either.
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/i;
const FORMATS = ['json', 'csv', 'list'] as const;
const MAX_NAMESERVERS = 10;
// The DNS-over-HTTPS form dnstwist accepts (dnstwist.py --nameservers parsing).
const DOH = /^https:\/\/([a-z0-9.-]{4,253})\/dns-query$/;

function invalid(message: string): never {
  throw new McpError(ErrorCode.InvalidParams, `Invalid arguments for fuzz_domain: ${message}`);
}

/** Lowercase ASCII (punycode) form of a hostname, or null if it isn't one. */
function asciiHostname(value: string): string | null {
  const trimmed = value.trim();
  // domainToASCII silently drops inner tabs and newlines ("a.com\nb" becomes
  // "a.comb"), so reject whitespace and control characters first.
  if (/[\s\x00-\x1f\x7f]/.test(trimmed)) return null;
  // Handles Unicode (IDN) names; returns '' for invalid input.
  const ascii = domainToASCII(trimmed.replace(/\.$/, ''));
  return HOSTNAME.test(ascii) ? ascii : null;
}

function optionalBoolean(a: Record<string, unknown>, key: string, fallback: boolean): boolean {
  if (a[key] === undefined) return fallback;
  if (typeof a[key] !== 'boolean') invalid(`${key} must be a boolean`);
  return a[key] as boolean;
}

/**
 * Validate and normalise fuzz_domain arguments. Everything returned is safe to
 * pass to dnstwist as a separate argv entry: no value can start with "-".
 */
export function validateFuzzArgs(args: unknown): FuzzDomainArgs {
  if (!args || typeof args !== 'object') invalid('arguments must be an object');
  const a = args as Record<string, unknown>;

  const domain = typeof a.domain === 'string' ? asciiHostname(a.domain) : null;
  if (!domain) invalid('domain must be a domain name such as example.com');

  const rawNameservers = a.nameservers === undefined ? '1.1.1.1' : a.nameservers;
  if (typeof rawNameservers !== 'string') invalid('nameservers must be a string');
  // dnstwist only accepts IPv4 addresses and https://<host>/dns-query URLs, so
  // anything else would fail inside the container anyway.
  const servers = (rawNameservers as string).split(',').map((ns) => {
    const trimmed = ns.trim();
    if (isIP(trimmed) === 4) return trimmed;
    const doh = trimmed.match(DOH);
    return doh && HOSTNAME.test(doh[1]) ? trimmed : null;
  });
  if (servers.length > MAX_NAMESERVERS || servers.some((ns) => !ns)) {
    invalid(`nameservers must be up to ${MAX_NAMESERVERS} comma-separated IPv4 addresses ` +
      'or DNS-over-HTTPS URLs like https://cloudflare-dns.com/dns-query');
  }

  const threads = a.threads === undefined ? 50 : a.threads;
  if (typeof threads !== 'number' || !Number.isInteger(threads) || threads < 1 || threads > 100) {
    invalid('threads must be an integer from 1 to 100');
  }

  const format = a.format === undefined ? 'json' : a.format;
  if (!FORMATS.includes(format as (typeof FORMATS)[number])) {
    invalid(`format must be one of ${FORMATS.join(', ')}`);
  }

  return {
    domain: domain as string,
    nameservers: servers.join(','),
    threads: threads as number,
    format: format as (typeof FORMATS)[number],
    registered_only: optionalBoolean(a, 'registered_only', true),
    mxcheck: optionalBoolean(a, 'mxcheck', true),
    ssdeep: optionalBoolean(a, 'ssdeep', false),
    banners: optionalBoolean(a, 'banners', true),
  };
}
