# Contributing to mcp-dnstwist

## Development setup

Requires Node.js 20.3 or later.

```sh
git clone https://github.com/w0h1v/mcp-dnstwist && cd mcp-dnstwist
npm ci
npm test
```

`npm test` builds the server and runs it against fake `docker` and `dnstwist` executables, so it needs neither Docker nor dnstwist. To try real scans, install Docker or dnstwist (`pipx install "dnstwist[full]"`) and point your MCP client at `node build/index.js`. `npm run dev` rebuilds on change.

## Guidelines

These protect against the command injection fixed in 1.0.5 ([GHSA-p4jr-h3rj-2rw4](https://github.com/w0h1v/mcp-dnstwist/security/advisories/GHSA-p4jr-h3rj-2rw4)):

- **No shell, ever.** Run commands with `execFile` and an argument array. `tests/injection.test.mjs` fails if the source uses `exec`, `execSync`, `spawnSync` or `shell: true`.
- **Validate every argument** in `src/validate.ts` before it reaches an argv, and make sure no value can start with `-`. Add rejection tests for new parameters.
- **Keep runs bounded.** Anything that starts dnstwist must respect the time limit and clean up on timeout, cancel and shutdown (`tests/timeout.test.mjs`).
- **Only scan domains you own or may assess.** Use `example.com` in tests, docs and issues.
- **Keep docs in step with code.** Update the README, `docs/` and `CHANGELOG.md` when tools, parameters or requirements change.

## Pull requests

Keep changes focused, fill in the pull request template, and describe how you tested. Merging to `main` publishes a new patch version to npm automatically.

## Security issues

Do not open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md).

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). By contributing, you agree that your contribution is licensed under the MIT license.
