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
  assert.equal(ok({ nameservers: 'dns.google,2606:4700:4700::1111' }).nameservers, 'dns.google,2606:4700:4700::1111');
});

test('anything that could reach a shell or become an option is rejected', () => {
  for (const domain of [
    'example.com; id', 'example.com|id', '$(id)', '`id`', 'example.com\nid', 'example.com\0',
    '--help', '-t', 'a b.com', 'example', '', '.', 'example..com', '-example.com', 'x'.repeat(254) + '.com',
  ]) {
    assert.throws(() => validateFuzzArgs({ domain }), /Invalid arguments/, JSON.stringify(domain));
  }
  for (const nameservers of [
    '1.1.1.1;id', '1.1.1.1|id', '$(id)', '`id`', '1.1.1.1 --whois', '-x', 'fe80::1%$(id)', '1.1.1.1,,8.8.8.8',
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
