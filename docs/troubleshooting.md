# Troubleshooting

## "Neither dnstwist nor Docker is available"

The server needs one of them. Install dnstwist (`pipx install "dnstwist[full]"`) or start Docker. Desktop clients may not inherit your shell's `PATH`; add an `env` block with `PATH`, or set `DNSTWIST_RUNNER` explicitly.

## "missing DNSPython library" (or "requires DNSPython 2.x")

Your local dnstwist was installed without its optional packages, and the server always passes `--nameservers`. Reinstall with them: `pipx install --force "dnstwist[full]"`. Or set `DNSTWIST_RUNNER=docker` to use the Docker image instead.

## Docker permission errors

Your user must be able to run `docker ps`. On Linux, add yourself to the `docker` group (`sudo usermod -aG docker $USER`) and log in again, or use the local runner instead.

## Scans are slow on a Mac

The `elceef/dnstwist` image is amd64-only, so on Apple Silicon it runs under emulation. Install dnstwist locally (`pipx install "dnstwist[full]"`); the server uses it automatically.

## "dnstwist did not finish within N seconds"

The scan hit `DNSTWIST_TIMEOUT_SECONDS` (default 600) and was stopped. To speed it up:

- Include an IPv4 nameserver. DNS-over-HTTPS-only scans can take over 10 minutes.
- Turn off `whois`, `lsh` or `banners` if you don't need them.
- Limit `fuzzers` to the algorithms you care about.
- Or raise `DNSTWIST_TIMEOUT_SECONDS`.

## "Invalid arguments for fuzz_domain"

The message says which argument was rejected. Common causes:

- `domain` includes a scheme or path (`https://example.com/`). Pass just `example.com`.
- `nameservers` includes an IPv6 address or a plain hostname. dnstwist only accepts IPv4 addresses and `https://<host>/dns-query`.
- A `fuzzers` name isn't one of dnstwist's algorithms. See the [tool reference](tools.md#fuzz_domain).

## DNS errors or very few results

Your resolver may be rate-limiting the burst of queries. Lower `threads`, or pass several resolvers, for example `"1.1.1.1,8.8.8.8"`.
