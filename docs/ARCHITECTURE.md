# Architecture

## Purpose

`github.com/Trysac/u262-email-dns-audit` audits a domain's email DNS records over an injected resolver: SPF syntax and the 10-lookup limit per RFC 7208, DMARC policy per RFC 7489 and DKIM selector keys.

## Shape

```text
caller code --> package emaildnsaudit (repository root)
                    |
                    +-- Audit --> Resolver.LookupTXT
                    +-- no direct network access; no global mutable state
cmd/email-dns-audit --> Run(args, stdout, stderr) int
```

- Public API: `Resolver`, `Options`, `Finding`, `Report`, `Audit`, `Run`, `ErrInvalidDomain`, `ErrLookup`.
- Errors: invalid domains return `ErrInvalidDomain`; resolver failures other than not-found return `ErrLookup`. The library does not panic on input, print or exit.
- Side effects: `Audit` performs DNS TXT lookups only through the `Resolver` in `Options`; the CLI uses `net.DefaultResolver`. Tests inject a fake resolver and never use live DNS.
- Evaluation: findings are sorted by `Code`, then `Message`; the SPF lookup count is depth-first through includes and redirects and stops at the 11th lookup.

## Quality contract

`scripts/check` is the single definition of the gates; `fabrica.json` tells the factory and CI how to run it. See [TESTING.md](TESTING.md).

## Decisions

No architecture decision records are included in the supplied repository snapshot.
