// End-to-end: run the real server over stdio with a fake `docker` on PATH and
// prove tool input can never reach a shell (CWE-78, issue #13).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync, existsSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const srcDir = fileURLToPath(new URL('../src/', import.meta.url));
const dir = mkdtempSync(join(tmpdir(), 'dnstwist-test-'));
const log = join(dir, 'docker-calls.jsonl');
const marker = (name) => join(dir, `pwned-${name}`);

// Fake docker: records its argv, succeeds for --version / image inspect, and
// prints an empty JSON result for `run`.
const fakeDocker = join(dir, 'docker');
writeFileSync(fakeDocker, `#!${process.execPath}
const fs = require('fs');
fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify({ argv: process.argv.slice(2) }) + '\\n');
if (process.argv[2] === 'run') process.stdout.write('[]');
`);
chmodSync(fakeDocker, 0o755);

let client;

before(async () => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL('../build/index.js', import.meta.url))],
    // Run inside the temp dir, so a regression can't drop files in the repo.
    cwd: dir,
    env: { ...process.env, PATH: `${dir}:${process.env.PATH}` },
    stderr: 'ignore',
  });
  client = new Client({ name: 'test', version: '0.0.0' });
  await client.connect(transport);
});

after(async () => {
  await client?.close();
  rmSync(dir, { recursive: true, force: true });
});

function runCalls() {
  if (!existsSync(log)) return [];
  return readFileSync(log, 'utf8').trim().split('\n').filter(Boolean)
    .map((line) => JSON.parse(line)).filter((call) => call.argv[0] === 'run');
}

const call = (args) => client.callTool({ name: 'fuzz_domain', arguments: args });

const payloads = [
  ['domain-semicolon', { domain: `example.com; touch ${marker('domain-semicolon')}` }],
  ['domain-subshell', { domain: `$(touch ${marker('domain-subshell')})` }],
  ['ns-semicolon', { domain: 'example.com', nameservers: `1.1.1.1;touch ${marker('ns-semicolon')}` }],
  ['ns-backticks', { domain: 'example.com', nameservers: `\`touch ${marker('ns-backticks')}\`` }],
  ['ns-pipe', { domain: 'example.com', nameservers: `1.1.1.1 | touch ${marker('ns-pipe')}` }],
];

for (const [name, args] of payloads) {
  test(`shell metacharacters never execute: ${name}`, async () => {
    const before = runCalls().length;
    const result = await call(args);
    assert.equal(existsSync(marker(name)), false, 'injected command ran on the host');
    assert.equal(result.isError, true, 'malicious input must be rejected');
    assert.equal(runCalls().length, before, 'docker must not run for rejected input');
  });
}

test('option injection through domain is rejected', async () => {
  for (const domain of ['--help', '-t', '--registered=x', 'example.com --whois']) {
    const result = await call({ domain });
    assert.equal(result.isError, true, domain);
  }
});

test('threads must be an integer from 1 to 100', async () => {
  for (const threads of [0, 101, 1.5, -1]) {
    const result = await call({ domain: 'example.com', threads });
    assert.equal(result.isError, true, String(threads));
  }
});

test('valid input reaches docker as a separate argv, unchanged', async () => {
  const result = await call({ domain: 'example.com', nameservers: '1.1.1.1,8.8.8.8', threads: 10 });
  assert.notEqual(result.isError, true, JSON.stringify(result.content));
  assert.deepEqual(runCalls().at(-1).argv, [
    'run', '--rm', 'elceef/dnstwist', 'example.com',
    '--format', 'json', '--registered', '--nameservers', '1.1.1.1,8.8.8.8',
    '-t', '10', '--mxcheck', '-b',
  ]);
});

test('hostname and IPv6 nameservers are accepted', async () => {
  const result = await call({ domain: 'example.co.uk', nameservers: 'dns.google,2606:4700:4700::1111' });
  assert.notEqual(result.isError, true, JSON.stringify(result.content));
  assert.deepEqual(runCalls().at(-1).argv.slice(3, 9),
    ['example.co.uk', '--format', 'json', '--registered', '--nameservers', 'dns.google,2606:4700:4700::1111']);
});

test('csv and list formats return dnstwist output as text instead of failing', async () => {
  const result = await call({ domain: 'example.com', format: 'csv' });
  assert.notEqual(result.isError, true, JSON.stringify(result.content));
  assert.equal(result.content[0].text, '[]');
  assert.equal(runCalls().at(-1).argv[5], 'csv');
});

// Validation already rejects everything a shell would treat specially, so a
// switch back to exec() would not change behaviour for valid input; `sh -c`
// even execs a single simple command directly. Guard the source instead.
test('source never runs commands through a shell', () => {
  const src = readdirSync(srcDir).filter((f) => f.endsWith('.ts'))
    .map((f) => readFileSync(join(srcDir, f), 'utf8')).join('\n');
  // \bexec\b matches exec and exec() but not execFile.
  assert.doesNotMatch(src, /\b(exec|execSync|spawnSync)\b/, 'use execFile with an argument array');
  assert.doesNotMatch(src, /shell\s*:\s*true/);
  assert.match(src, /execFile/);
});
