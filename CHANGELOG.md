# Changelog

## 1.1.0

### Added
- Local runner: uses a `dnstwist` executable on `PATH` instead of Docker. `DNSTWIST_RUNNER` chooses `local`, `docker` or `auto` (the default: local when available).
- The Docker image bundles Node and dnstwist and runs as a non-root user, so it works on its own (Smithery, Glama) without access to a Docker daemon.
- `fuzz_domain` options: `whois` (registration date and registrar), `all_records`, `fuzzers` (pick permutation algorithms) and `lsh` (`ssdeep` or `tlsh` web-page similarity).
- Listed on the MCP Registry as `io.github.w0h1v/dnstwist`, updated by each release.
- CI (Node 20/22/24, package check, audit, Docker build), Dependabot, documentation site at <https://w0h1v.github.io/mcp-dnstwist/>, security policy, contributing guide, code of conduct, citation file, issue and pull request templates.

### Fixed
- The README listed WHOIS data as a feature, but the server never passed `--whois` to dnstwist.
- `ssdeep: true` used a hidden, deprecated dnstwist flag; it now maps to `--lsh ssdeep` and remains accepted.
- Tool descriptions for `mxcheck`, `banners` and `threads` now say what they actually do.

## 1.0.7

### Fixed
- Scans had no time limit, and stopping the docker CLI didn't stop the container, so abandoned scans kept running. Each scan now has a time limit (`DNSTWIST_TIMEOUT_SECONDS`, default 600), and its container is removed on timeout, cancellation and shutdown.

## 1.0.6

### Fixed
- DNS-over-HTTPS nameservers (`https://<host>/dns-query`) were rejected by 1.0.5. Nameserver validation now matches what dnstwist accepts: IPv4 addresses and DoH URLs.
- README and Dockerfile updated for the Node 20 requirement.

## 1.0.5

### Security
- **OS command injection in `fuzz_domain`** ([GHSA-p4jr-h3rj-2rw4](https://github.com/w0h1v/mcp-dnstwist/security/advisories/GHSA-p4jr-h3rj-2rw4), CWE-78). Tool arguments were run through a shell, so `domain` or `nameservers` could execute commands on the host. Commands now run without a shell, and all arguments are validated. Reported by BruceJin (@BruceJqs). Versions up to 1.0.4 are deprecated on npm.

### Changed
- MCP SDK 0.4.0 → 1.32.1. Publishing uses npm trusted publishing.

### Fixed
- `csv` and `list` output formats always failed; they now return dnstwist's text.

## 1.0.4 and earlier

Initial releases. Affected by GHSA-p4jr-h3rj-2rw4; do not use.
