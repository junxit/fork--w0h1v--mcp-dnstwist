# Example workflows

Prompts you can give an agent with mcp-dnstwist connected, and the tool calls they lead to. Only scan domains you own or are authorized to assess; the examples use `example.com`.

## Find registered lookalikes of your domain

> *"Which lookalike domains of example.com are registered, and do any of them accept email?"*

`fuzz_domain` with `{"domain": "example.com", "mxcheck": true}`. The default `registered_only: true` keeps the list to domains that exist.

## Check who registered them, and when

> *"For the registered lookalikes of example.com, show the registrar and creation date. Newest first."*

`fuzz_domain` with `{"domain": "example.com", "whois": true}`. WHOIS lookups make the scan slower; recently created lookalikes are the ones to look at first.

## Spot phishing pages that copy your site

> *"Do any lookalikes of example.com serve a page similar to the real one?"*

`fuzz_domain` with `{"domain": "example.com", "lsh": "tlsh", "banners": true}`. dnstwist fetches each registered lookalike's page and scores its similarity to the original.

## Focus on one kind of trick

> *"Only check homoglyph and bitsquatting variants of example.com."*

`fuzz_domain` with `{"domain": "example.com", "fuzzers": ["homoglyph", "bitsquatting"]}`. Fewer algorithms means a faster scan.

## Get a plain list for another tool

> *"Give me every permutation of example.com as a plain list, registered or not."*

`fuzz_domain` with `{"domain": "example.com", "registered_only": false, "format": "list"}`.
