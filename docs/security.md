# Security model

mcp-dnstwist runs a program on your machine with arguments chosen by an AI model. That model can be steered by content it reads, such as a web page, email or document, so the server treats every argument as hostile.

## What protects you

**No shell.** dnstwist starts through `execFile` with an argument array, either directly or as `docker run`. Shell syntax such as `;`, `|`, `$( )` or backticks is never interpreted. A test fails the build if the source uses `exec`, `execSync`, `spawnSync` or `shell: true`.

**Strict validation before anything runs:**

| Argument | Accepted |
|---|---|
| `domain` | A domain name (Unicode names are converted to punycode). Can't start with `-`, so it can't become a dnstwist option |
| `nameservers` | Up to 10 IPv4 addresses or `https://<host>/dns-query` URLs, the forms dnstwist itself accepts |
| `threads` | Integer from 1 to 100 |
| `fuzzers` | Names from dnstwist's list of algorithms |
| `format`, `lsh` | Fixed sets of values |

**Bounded runs.** Each scan has a time limit (`DNSTWIST_TIMEOUT_SECONDS`, 10 minutes by default). When it's reached, when the client cancels the call, or when the server shuts down, the scan's process or container is stopped and removed.

## Choosing a runner

| Runner | What the server can do |
|---|---|
| Local `dnstwist` | Run dnstwist as your user |
| Docker (`elceef/dnstwist`) | Talk to the Docker daemon, which usually means root-equivalent access to the machine |
| The mcp-dnstwist Docker image | Run dnstwist inside its own container, as a non-root user, with no access to your Docker daemon |

The defences above apply to every runner. If you want the smallest blast radius anyway, use the local runner or the mcp-dnstwist image.

## What scanning reveals

A scan sends DNS queries for hundreds of lookalike domains to the nameservers you choose. With `mxcheck`, `banners`, `whois` or `lsh`, it also connects to mail servers, web servers and WHOIS services for registered lookalikes. Only scan domains you own or are authorized to assess.

## History

Versions up to 1.0.4 joined tool arguments into a shell command, allowing command injection ([GHSA-p4jr-h3rj-2rw4](https://github.com/w0h1v/mcp-dnstwist/security/advisories/GHSA-p4jr-h3rj-2rw4)). Fixed in 1.0.5; the old versions are deprecated on npm. Report new issues privately; see [SECURITY.md](https://github.com/w0h1v/mcp-dnstwist/blob/main/SECURITY.md).
