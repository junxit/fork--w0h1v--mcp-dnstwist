// Long scans: the server must stop and remove the dnstwist container when the
// time limit is hit or the client cancels, so no container outlives its call.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const dir = mkdtempSync(join(tmpdir(), 'dnstwist-timeout-'));
const log = join(dir, 'docker-calls.jsonl');

// Fake docker: records argv; `run` for slow.example.com hangs for 60 s,
// any other `run` prints an empty result; `rm -f` just succeeds.
const fakeDocker = join(dir, 'docker');
writeFileSync(fakeDocker, `#!${process.execPath}
const fs = require('fs');
const argv = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify({ argv }) + '\\n');
if (argv[0] === 'run' && argv.includes('slow.example.com')) setTimeout(() => {}, 60000);
else if (argv[0] === 'run') process.stdout.write('[]');
`);
chmodSync(fakeDocker, 0o755);

let client;

before(async () => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL('../build/index.js', import.meta.url))],
    cwd: dir,
    env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, DNSTWIST_TIMEOUT_SECONDS: '1' },
    stderr: 'ignore',
  });
  client = new Client({ name: 'test', version: '0.0.0' });
  await client.connect(transport);
});

after(async () => {
  await client?.close();
  rmSync(dir, { recursive: true, force: true });
});

const calls = () => (existsSync(log) ? readFileSync(log, 'utf8').trim().split('\n') : [])
  .filter(Boolean).map((line) => JSON.parse(line).argv);
const containerOf = (runArgv) => runArgv[runArgv.indexOf('--name') + 1];

async function removed(name) {
  // Cleanup runs right after the error is returned; give it a moment.
  for (let i = 0; i < 50; i++) {
    if (calls().some((a) => a[0] === 'rm' && a[1] === '-f' && a[2] === name)) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return false;
}

test('a scan that exceeds the time limit fails clearly and its container is removed', async () => {
  const started = Date.now();
  const result = await client.callTool({ name: 'fuzz_domain', arguments: { domain: 'slow.example.com' } });
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /did not finish within 1 second/);
  assert.ok(Date.now() - started < 10000, 'the call should end soon after the limit');
  const run = calls().filter((a) => a[0] === 'run').at(-1);
  assert.ok(await removed(containerOf(run)), 'expected docker rm -f <container>');
});

test('cancelling a call removes its container', async () => {
  const controller = new AbortController();
  const pending = client.callTool(
    { name: 'fuzz_domain', arguments: { domain: 'slow.example.com', threads: 2 } },
    undefined,
    { signal: controller.signal },
  );
  // Wait until the server has started docker, then cancel.
  for (let i = 0; i < 50 && !calls().some((a) => a[0] === 'run' && a.includes('2')); i++) {
    await new Promise((r) => setTimeout(r, 20));
  }
  controller.abort();
  await assert.rejects(pending);
  const run = calls().filter((a) => a[0] === 'run' && a.includes('2')).at(-1);
  assert.ok(run, 'docker run should have started before the cancel');
  assert.ok(await removed(containerOf(run)), 'expected docker rm -f <container>');
});

test('fast scans are unaffected and leave nothing to clean up', async () => {
  const result = await client.callTool({ name: 'fuzz_domain', arguments: { domain: 'example.com' } });
  assert.notEqual(result.isError, true, JSON.stringify(result.content));
  const run = calls().filter((a) => a[0] === 'run' && a.includes('example.com')).at(-1);
  assert.ok(!calls().some((a) => a[0] === 'rm' && a[2] === containerOf(run)));
});
