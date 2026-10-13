// Unit tests for fuzz_domain argument validation. Run after `npm run build`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateFuzzArgs } from '../build/validate.js';

const ok = (args) => validateFuzzArgs({ domain: 'example.com', ...args });
const rejects = (args) => assert.throws(() => validateFuzzArgs({ domain: 'example.com', ...args }), /Invalid arguments/);

test('defaults', () => {
  assert.deepEqual(validateFuzzArgs({ domain: 'example.com' }), {
    domain: 'example.com', nameservers: '1.1.1.1', threads: 50, format: 'json',
    registered_only: true, mxcheck: true, ssdeep: false, banners: true,
    whois: false, all_records: false,
  });
});

test('domains are normalised to lowercase ASCII', () => {
  assert.equal(ok({ domain: 'Example.COM' }).domain, 'example.com');
  assert.equal(ok({ domain: 'example.com.' }).domain, 'example.com');
  assert.equal(ok({ domain: 'bücher.de' }).domain, 'xn--bcher-kva.de');
  assert.equal(ok({ domain: 'xn--bcher-kva.de' }).domain, 'xn--bcher-kva.de');
  assert.equal(ok({ domain: 'sub.example.co.uk' }).domain, 'sub.example.co.uk');
});

test('nameserver lists are trimmed and rejoined', () => {
  assert.equal(ok({ nameservers: '1.1.1.1, 8.8.8.8' }).nameservers, '1.1.1.1,8.8.8.8');
});

// dnstwist itself only accepts IPv4 addresses and https://<host>/dns-query.
test('DNS-over-HTTPS resolvers are accepted in the form dnstwist supports', () => {
  assert.equal(ok({ nameservers: 'https://cloudflare-dns.com/dns-query' }).nameservers,
    'https://cloudflare-dns.com/dns-query');
  assert.equal(ok({ nameservers: '1.1.1.1, https://dns.google/dns-query' }).nameservers,
    '1.1.1.1,https://dns.google/dns-query');
  // An IP-literal resolver avoids a bootstrap DNS lookup.
  assert.equal(ok({ nameservers: 'https://1.1.1.1/dns-query' }).nameservers, 'https://1.1.1.1/dns-query');
});

test('nameservers dnstwist would reject are rejected up front', () => {
  for (const nameservers of [
    'dns.google', '2606:4700:4700::1111', '::1', 'http://dns.google/dns-query',
    'https://dns.google/resolve', 'https://dns.google:443/dns-query', 'https://DNS.google/dns-query',
    'https://dns.google/dns-query?x=1', 'https://-x/dns-query', 'https://a b/dns-query',
    'https://$(id)/dns-query', 'https://1.1.1/dns-query', 'https://256.1.1.1/dns-query', '1.1.1', '256.1.1.1',
  ]) {
    rejects({ nameservers });
  }
});

test('anything that could reach a shell or become an option is rejected', () => {
  for (const domain of [
    'example.com; id', 'example.com|id', '$(id)', '`id`', 'example.com\nid', 'example.com\0',
    '--help', '-t', 'a b.com', 'example', '', '.', 'example..com', '-example.com', 'x'.repeat(254) + '.com',
  ]) {
    assert.throws(() => validateFuzzArgs({ domain }), /Invalid arguments/, JSON.stringify(domain));
  }
  for (const nameservers of [
    '1.1.1.1;id', '1.1.1.1|id', '$(id)', '`id`', '1.1.1.1 --whois', '-x', '1.1.1.1,,8.8.8.8',
    Array(11).fill('1.1.1.1').join(','),
  ]) {
    rejects({ nameservers });
  }
});

test('threads, format and flags are type-checked', () => {
  for (const threads of [0, 101, 1.5, -1, '50', NaN]) rejects({ threads });
  rejects({ format: 'xml' });
  rejects({ banners: 'yes' });
  assert.throws(() => validateFuzzArgs(null), /Invalid arguments/);
  assert.equal(ok({ format: 'csv', threads: 100 }).format, 'csv');
});

test('geoip is not an option', () => {
  assert.equal('geoip' in ok({ geoip: true }), false);
});

test('whois and all_records are booleans defaulting to false', () => {
  for (const key of ['whois', 'all_records']) {
    assert.equal(ok({ [key]: true })[key], true);
    assert.equal(ok({})[key], false);
    for (const bad of ['yes', 1, null, []]) rejects({ [key]: bad });
  }
});

test('fuzzers must be a unique list of known names', () => {
  assert.deepEqual(ok({ fuzzers: ['addition', 'vowel-swap', 'various'] }).fuzzers, ['addition', 'vowel-swap', 'various']);
  assert.equal(ok({}).fuzzers, undefined);
  for (const fuzzers of [
    [], 'addition', ['nope'], ['addition', 'addition'], ['*original'], ['addition,omission'], ['--help'],
    ['addition', 1], [null], { 0: 'addition' }, ['Addition'], [' addition'],
    // tld-swap needs a TLD list file, which this tool doesn't take.
    ['tld-swap'],
  ]) {
    rejects({ fuzzers });
  }
});

test('lsh is ssdeep or tlsh, and ssdeep: true is a deprecated alias', () => {
  assert.equal(ok({}).lsh, undefined);
  assert.equal(ok({ lsh: 'tlsh' }).lsh, 'tlsh');
  assert.equal(ok({ lsh: 'ssdeep' }).lsh, 'ssdeep');
  assert.equal(ok({ ssdeep: true }).lsh, 'ssdeep');
  assert.equal(ok({ ssdeep: false }).lsh, undefined);
  assert.equal(ok({ ssdeep: true, lsh: 'tlsh' }).lsh, 'tlsh');
  for (const lsh of ['md5', '--help', 'SSDEEP', true, 1, null]) rejects({ lsh });
});
