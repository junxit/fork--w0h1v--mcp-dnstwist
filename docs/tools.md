# Tool reference

mcp-dnstwist has one tool, `fuzz_domain`. It generates lookalike versions of a domain (typos, homoglyphs, bit flips, added or swapped characters, other TLDs) and checks which ones exist.

Sample outputs are real responses from dnstwist 20250130, captured on 2026-10-12 against `example.com`. Long lists are cut to a few entries and marked `… N more`.

## `fuzz_domain`

Generate and analyze domain permutations to detect potential typosquatting, phishing, and brand impersonation

| Parameter | Type | Required | Default | Notes |
|---|---|---|---|---|
| `domain` | string | yes |  | Domain name to analyze (e.g., example.com) |
| `nameservers` | string | no | `"1.1.1.1"` | Comma-separated DNS servers: IPv4 addresses or DNS-over-HTTPS URLs such as https://cloudflare-dns.com/dns-query (default: 1.1.1.1) |
| `threads` | number | no | `50` | Number of parallel lookups (1-100) |
| `format` | string (json / csv / list) | no | `"json"` | Output format |
| `registered_only` | boolean | no | `true` | Show only registered domain permutations |
| `mxcheck` | boolean | no | `true` | Check whether each mail server would accept email for any address, so it could intercept mail sent to typos of your domain |
| `ssdeep` | boolean | no | `false` | Deprecated alias for lsh: "ssdeep" (ignored when lsh is set) |
| `lsh` | string (ssdeep / tlsh) | no |  | Compare each permutation's web page with the original using a fuzzy hash (slow) to spot cloned phishing pages |
| `whois` | boolean | no | `false` | Look up WHOIS creation date and registrar for each domain (slower) |
| `all_records` | boolean | no | `false` | Return all DNS records instead of only the first of each type |
| `fuzzers` | string[] | no |  | Only use these fuzzing algorithms (default: all) Values: `addition`, `bitsquatting`, `cyrillic`, `homoglyph`, `hyphenation`, `insertion`, `omission`, `plural`, `repetition`, `replacement`, `subdomain`, `transposition`, `vowel-swap`, `various`. |
| `banners` | boolean | no | `true` | Capture HTTP and SMTP server banners |

### What comes back

With `format: "json"` (the default), a list with one entry per domain. The first entry is the original domain (`fuzzer: "*original"`). Fields appear when dnstwist found data for them:

| Field | Meaning |
|---|---|
| `domain`, `fuzzer` | The lookalike, and the algorithm that produced it |
| `dns_a`, `dns_aaaa`, `dns_mx`, `dns_ns` | DNS records (only the first of each type unless `all_records`) |
| `mx_spy` | With `mxcheck`: the mail server accepts mail for any address, so it could intercept email |
| `banner_http`, `banner_smtp` | With `banners`: web and mail server banners |
| `whois_created`, `whois_registrar` | With `whois`: registration date and registrar |
| `ssdeep` or `tlsh` | With `lsh`: similarity score of the lookalike's web page to the original (named after the algorithm) |

`csv` and `list` return dnstwist's text output unchanged.

A default scan of `example.com` returns about 110 registered lookalikes, roughly 24,000 characters. Turning on `whois` adds about 40%, so narrow the `fuzzers` for large domains.

<details markdown="1">
<summary>Sample output (defaults): <code>{"domain": "example.com"}</code></summary>

```json
[
  {
    "banner_http": "cloudflare",
    "dns_a": [
      "104.20.23.154"
    ],
    "dns_aaaa": [
      "2606:4700:10::6814:179a"
    ],
    "dns_mx": [
      ""
    ],
    "dns_ns": [
      "elliott.ns.cloudflare.com"
    ],
    "domain": "example.com",
    "fuzzer": "*original"
  },
  {
    "banner_http": "nginx",
    "dns_a": [
      "103.168.172.37"
    ],
    "dns_mx": [
      "us1-smtp.messagingengine.com"
    ],
    "dns_ns": [
      "ns1.messagingengine.com"
    ],
    "domain": "exampler.com",
    "fuzzer": "addition"
  },
  {
    "banner_http": "cloudflare",
    "dns_a": [
      "104.21.23.31"
    ],
    "dns_aaaa": [
      "2606:4700:3030::6815:171f"
    ],
    "dns_ns": [
      "irena.ns.cloudflare.com"
    ],
    "domain": "example8.com",
    "fuzzer": "addition"
  },
  "… 108 more"
]
```

</details>

<details markdown="1">
<summary>Sample output (WHOIS for two algorithms): <code>{"domain": "example.com", "whois": true, "fuzzers": ["homoglyph", "bitsquatting"]}</code></summary>

```json
[
  {
    "dns_a": [
      "!ServFail"
    ],
    "dns_ns": [
      "!ServFail"
    ],
    "domain": "dxample.com",
    "fuzzer": "bitsquatting",
    "whois_created": "2021-03-06",
    "whois_registrar": "GMO Internet Group, Inc. d/b/a Onamae.com"
  },
  {
    "dns_a": [
      "!ServFail"
    ],
    "dns_aaaa": [
      "!ServFail"
    ],
    "domain": "exa-ple.com",
    "fuzzer": "bitsquatting",
    "whois_created": "2021-04-17",
    "whois_registrar": "GMO Internet Group, Inc. d/b/a Onamae.com"
  },
  {
    "dns_a": [
      "!ServFail"
    ],
    "dns_aaaa": [
      "!ServFail"
    ],
    "dns_ns": [
      "!ServFail"
    ],
    "domain": "exqmple.com",
    "fuzzer": "bitsquatting",
    "whois_created": "2019-03-04",
    "whois_registrar": "Amazon Registrar, Inc."
  },
  "… 26 more"
]
```

</details>

<details markdown="1">
<summary>Sample output (web-page similarity): <code>{"domain": "example.com", "lsh": "tlsh", "fuzzers": ["vowel-swap"]}</code></summary>

```json
[
  {
    "banner_http": "Apache",
    "dns_a": [
      "103.224.182.245"
    ],
    "dns_mx": [
      "park-mx.above.com"
    ],
    "dns_ns": [
      "ns1.abovedomains.com"
    ],
    "domain": "exemple.com",
    "fuzzer": "vowel-swap",
    "tlsh": 0
  },
  {
    "banner_http": "cloudflare",
    "dns_a": [
      "104.20.23.154"
    ],
    "dns_aaaa": [
      "2606:4700:10::6814:179a"
    ],
    "dns_mx": [
      ""
    ],
    "dns_ns": [
      "elliott.ns.cloudflare.com"
    ],
    "domain": "example.com",
    "fuzzer": "vowel-swap"
  },
  {
    "banner_http": "Kestrel",
    "dns_a": [
      "13.223.25.84"
    ],
    "dns_aaaa": [
      "2600:1f18:4ae:c605:dd5d:b838:5816:d7fb"
    ],
    "dns_ns": [
      "nsg1.namebrightdns.com"
    ],
    "domain": "examplo.com",
    "fuzzer": "vowel-swap",
    "tlsh": 11
  },
  "… 6 more"
]
```

</details>

<details markdown="1">
<summary>Sample output (plain list of all permutations): <code>{"domain": "example.com", "registered_only": false, "format": "list", "fuzzers": ["omission"]}</code></summary>

```text
eample.com
examle.com
exampe.com
exampl.com
exaple.com
exmple.com
xample.com
```

</details>
