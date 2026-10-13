// Runner selection (DNSTWIST_RUNNER) with fake `dnstwist` and `docker` binaries.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync, existsSync, readFileSync, rmSync, mkdirSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const buildIndex = fileURLToPath(new URL('../build/index.js', import.meta.url));
const root = mkdtempSync(join(tmpdir(), 'dnstwist-runner-'));
after(() => rmSync(root, { recursive: true, force: true }));

const script = (log, body) => `#!${process.execPath}
const fs = require('fs');
const argv = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify({ argv, pid: process.pid }) + '\\n');
${body}
`;

// A scratch bin directory with a fake dnstwist and/or docker. PATH is only that
// directory, so a dnstwist installed on the developer's machine is never used.
function setup(name, { dnstwist, docker }) {
  const dir = join(root, name);
  mkdirSync(dir);
  const log = join(dir, 'calls.jsonl');
  if (dnstwist) {
    writeFileSync(join(dir, 'dnstwist'), script(log, `
if (argv.includes('--version')) { console.log('dnstwist 20250130'); }
else if (argv.includes('slow.example.com')) { setInterval(() => {}, 1000); process.on('SIGTERM', () => {}); }
else process.stdout.write('[{"domain":"example.com","fuzzer":"*original"}]');`));
    chmodSync(join(dir, 'dnstwist'), 0o755);
  }
  if (docker) {
    writeFileSync(join(dir, 'docker'), script(log, `if (argv[0] === 'run') process.stdout.write('[]');`));
    chmodSync(join(dir, 'docker'), 0o755);
  }
  const calls = () => (existsSync(log) ? readFileSync(log, 'utf8').trim().split('\n') : [])
    .filter(Boolean).map((l) => JSON.parse(l));
  return { dir, calls };
}

async function connect(dir, env) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [buildIndex],
    cwd: dir,
    env: { PATH: dir, ...env },
    stderr: 'ignore',
  });
  const client = new Client({ name: 'test', version: '0.0.0' });
  await client.connect(transport);
  return client;
}

const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };

test('local runner runs dnstwist directly with the same arguments, no docker', async () => {
  const { dir, calls } = setup('local', { dnstwist: true, docker: true });
  const client = await connect(dir, { DNSTWIST_RUNNER: 'local' });
  try {
    const result = await client.callTool({ name: 'fuzz_domain', arguments: { domain: 'example.com', whois: true, lsh: 'tlsh' } });
    assert.notEqual(result.isError, true, JSON.stringify(result.content));
    assert.equal(JSON.parse(result.content[0].text)[0].domain, 'example.com');
    const argvs = calls().map((c) => c.argv);
    assert.deepEqual(argvs.at(-1), [
      'example.com', '--format', 'json', '--registered', '--nameservers', '1.1.1.1',
      '-t', '50', '--mxcheck', '--lsh', 'tlsh', '-b', '-w',
    ]);
    assert.ok(argvs.some((a) => a[0] === '--version'));
  } finally {
    await client.close();
  }
});

test('auto uses a dnstwist on PATH, and ignores docker', async () => {
  const { dir, calls } = setup('auto-local', { dnstwist: true, docker: true });
  const client = await connect(dir, {});
  try {
    const result = await client.callTool({ name: 'fuzz_domain', arguments: { domain: 'example.com' } });
    assert.notEqual(result.isError, true, JSON.stringify(result.content));
    assert.equal(calls().some((c) => c.argv[0] === 'run'), false);
    assert.equal(calls().at(-1).argv[0], 'example.com');
  } finally {
    await client.close();
  }
});

test('auto falls back to docker when there is no dnstwist', async () => {
  const { dir, calls } = setup('auto-docker', { docker: true });
  const client = await connect(dir, { DNSTWIST_RUNNER: 'auto' });
  try {
    const result = await client.callTool({ name: 'fuzz_domain', arguments: { domain: 'example.com' } });
    assert.notEqual(result.isError, true, JSON.stringify(result.content));
    const run = calls().map((c) => c.argv).find((a) => a[0] === 'run');
    assert.ok(run, 'docker run expected');
    assert.equal(run[4], 'elceef/dnstwist');
  } finally {
    await client.close();
  }
});

test('docker runner is used even when dnstwist is on PATH', async () => {
  const { dir, calls } = setup('docker-forced', { dnstwist: true, docker: true });
  const client = await connect(dir, { DNSTWIST_RUNNER: 'docker' });
  try {
    await client.callTool({ name: 'fuzz_domain', arguments: { domain: 'example.com' } });
    assert.ok(calls().some((c) => c.argv[0] === 'run'));
    assert.ok(!calls().some((c) => c.argv[0] === 'example.com'));
  } finally {
    await client.close();
  }
});

test('a local scan that exceeds the time limit is killed, even if it ignores SIGTERM', async () => {
  const { dir, calls } = setup('local-timeout', { dnstwist: true });
  const client = await connect(dir, { DNSTWIST_RUNNER: 'local', DNSTWIST_TIMEOUT_SECONDS: '1' });
  try {
    const started = Date.now();
    const result = await client.callTool({ name: 'fuzz_domain', arguments: { domain: 'slow.example.com' } });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /did not finish within 1 second/);
    assert.ok(Date.now() - started < 10000);
    const pid = calls().find((c) => c.argv[0] === 'slow.example.com').pid;
    for (let i = 0; i < 50 && alive(pid); i++) await new Promise((r) => setTimeout(r, 100));
    assert.equal(alive(pid), false, 'dnstwist process must be dead');
  } finally {
    await client.close();
  }
});

test('cancelling a local scan kills the process', async () => {
  const { dir, calls } = setup('local-cancel', { dnstwist: true });
  const client = await connect(dir, { DNSTWIST_RUNNER: 'local' });
  try {
    const controller = new AbortController();
    const pending = client.callTool({ name: 'fuzz_domain', arguments: { domain: 'slow.example.com' } },
      undefined, { signal: controller.signal });
    for (let i = 0; i < 100 && !calls().some((c) => c.argv[0] === 'slow.example.com'); i++) {
      await new Promise((r) => setTimeout(r, 50));
    }
    const pid = calls().find((c) => c.argv[0] === 'slow.example.com').pid;
    controller.abort();
    await assert.rejects(pending);
    for (let i = 0; i < 50 && alive(pid); i++) await new Promise((r) => setTimeout(r, 100));
    assert.equal(alive(pid), false, 'dnstwist process must be dead');
  } finally {
    await client.close();
  }
});

test('shutting the server down kills in-flight local scans', async () => {
  const { dir, calls } = setup('local-shutdown', { dnstwist: true });
  const child = spawn(process.execPath, [buildIndex], { cwd: dir, env: { PATH: dir, DNSTWIST_RUNNER: 'local' }, stdio: ['pipe', 'pipe', 'ignore'] });
  const send = (msg) => child.stdin.write(JSON.stringify(msg) + '\n');
  send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '0' } } });
  send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'fuzz_domain', arguments: { domain: 'slow.example.com' } } });
  for (let i = 0; i < 100 && !calls().some((c) => c.argv[0] === 'slow.example.com'); i++) {
    await new Promise((r) => setTimeout(r, 50));
  }
  const pid = calls().find((c) => c.argv[0] === 'slow.example.com').pid;
  const exited = new Promise((r) => child.on('exit', r));
  child.kill('SIGTERM');
  await exited;
  for (let i = 0; i < 50 && alive(pid); i++) await new Promise((r) => setTimeout(r, 100));
  assert.equal(alive(pid), false, 'dnstwist process must be dead');
});

test('invalid or unusable runner settings exit with a clear message', async () => {
  const exitOf = (dir, env) => new Promise((resolve) => {
    const child = spawn(process.execPath, [buildIndex], { cwd: dir, env: { PATH: dir, ...env }, stdio: ['pipe', 'ignore', 'pipe'] });
    let err = '';
    child.stderr.on('data', (d) => { err += d; });
    child.on('exit', (code) => resolve({ code, err }));
    setTimeout(() => child.kill(), 8000);
  });
  const { dir } = setup('bad', {});
  const bad = await exitOf(dir, { DNSTWIST_RUNNER: 'podman' });
  assert.equal(bad.code, 1);
  assert.match(bad.err, /DNSTWIST_RUNNER must be one of docker, local, auto/);

  const missing = await exitOf(dir, { DNSTWIST_RUNNER: 'local' });
  assert.equal(missing.code, 1);
  assert.match(missing.err, /dnstwist executable was not found/);
});
