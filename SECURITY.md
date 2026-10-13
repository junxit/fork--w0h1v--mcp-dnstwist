# Security policy

mcp-dnstwist is an independent project. It runs [dnstwist](https://github.com/elceef/dnstwist) and is not affiliated with it.

## Supported versions

Only the latest release receives security fixes.

| Version | Supported |
|---|---|
| Latest release | Yes |
| 1.0.4 and earlier | No: vulnerable to command injection, deprecated on npm |

## Reporting a vulnerability

Use GitHub private vulnerability reporting. Open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue or pull request for a suspected vulnerability.

Include the mcp-dnstwist version, how dnstwist runs (Docker, local install or the mcp-dnstwist image), steps to reproduce, and the impact you believe the issue has.

## Past advisories

| Advisory | Affected | Fixed | Summary |
|---|---|---|---|
| [GHSA-p4jr-h3rj-2rw4](https://github.com/w0h1v/mcp-dnstwist/security/advisories/GHSA-p4jr-h3rj-2rw4) | ≤ 1.0.4 | 1.0.5 | OS command injection through `domain` and `nameservers` in `fuzz_domain` (CWE-78) |

## Scope

In scope:

- **Command or argument injection**: any tool input that reaches a shell, or that becomes a dnstwist or Docker option it wasn't meant to be.
- **Validation bypass** of the checks in `src/validate.ts`.
- **Runaway processes**: scans or containers that outlive their time limit, a cancelled call, or the server.

Out of scope:

- **dnstwist's own behaviour and output.** Report those to the [dnstwist project](https://github.com/elceef/dnstwist).
- **What you scan.** Lookups go to the DNS servers, WHOIS servers and websites involved; scanning is up to the operator.
- **Local attackers with the same OS user** or with access to the Docker daemon.

## Trust model

Tool arguments are chosen by the AI model, and can be steered by content it reads (prompt injection), so the server treats them as hostile:

- **No shell.** dnstwist runs through `execFile` with an argument array, directly or as `docker run`. A test fails the build if the source uses a shell-based API.
- **Strict validation before any command runs.** Domains must be hostnames; nameservers must be IPv4 addresses or `https://<host>/dns-query`; numbers, enums and fuzzer names are checked. No value can start with `-`.
- **Bounded runs.** Each scan has a time limit (`DNSTWIST_TIMEOUT_SECONDS`). On timeout, cancellation or shutdown the scan's process or container is stopped and removed.

With the Docker runner the server needs access to the Docker daemon, which is equivalent to root on most systems. The local runner, or the mcp-dnstwist Docker image, avoids that.
