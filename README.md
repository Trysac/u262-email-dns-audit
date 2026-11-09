# email-dns-audit

`email-dns-audit` audits a domain's email authentication DNS records through an injected resolver. It reports stable rule codes for SPF (RFC 7208), DMARC (RFC 7489) and DKIM selector records, and can be used as a library or CLI in CI.

## Features

- SPF: SPF001 no record; SPF002 permerror (more than one record starting with `v=spf1` followed by a space or end, an unknown mechanism, or an include target without exactly one SPF record); SPF003 `+all` or bare `all`; SPF004 `?all`, or no `all` mechanism and no `redirect=`; SPF005 more than 10 DNS-querying terms; SPF006 `ptr`.
- DMARC: DMARC001 no record at `_dmarc.<domain>` starting with `v=DMARC1`; DMARC002 `p=none`; DMARC003 invalid (v not first, p missing or not none/quarantine/reject, or several DMARC records).
- DKIM: DKIM001 for each selector without a record at `<selector>._domainkey.<domain>` or with an empty `p=` tag.
- Resolver injection: `Audit` accepts any `Resolver`; the CLI uses `net.DefaultResolver`; tests replace the resolver with an in-memory fake.
- Findings are sorted by `Code`, then `Message`.

## Installation

```bash
go install github.com/Trysac/u262-email-dns-audit/cmd/email-dns-audit@latest
```

## Library usage

```go
package main

import (
	"context"
	emaildnsaudit "github.com/Trysac/u262-email-dns-audit"
)

func main() {
	_, _ = emaildnsaudit.Audit(context.Background(), "example.com", emaildnsaudit.Options{})
}
```

## Public API

- `type Resolver interface { LookupTXT(ctx context.Context, name string) ([]string, error) }`; a `*net.DNSError` with `IsNotFound` true means no records.
- `type Options struct { Resolver Resolver; DKIMSelectors []string; Timeout time.Duration }`; nil resolver means `net.DefaultResolver`; zero timeout means 5s per lookup.
- `type Finding struct { Code, Severity, Message string }`; JSON tags `code`, `severity`, `message`.
- `type Report struct { Domain, SPF, DMARC string; SPFLookups int; Findings []Finding }`; JSON tags `domain`, `spf`, `dmarc`, `spf_lookups`, `findings`.
- `func Audit(ctx context.Context, domain string, opts Options) (Report, error)`; `func Run(args []string, stdout, stderr io.Writer) int`.
- Errors: `ErrInvalidDomain` for names that are not 1-253 characters with labels 1-63 of `[A-Za-z0-9-]` not starting or ending with `-`; `ErrLookup` for resolver errors other than not-found. A trailing dot is removed from the domain. TXT records over 4096 bytes count as invalid. Macros are counted but never expanded.

## CLI usage

```bash
email-dns-audit --dkim selector1,selector2 --json example.com
```

`Run` returns 2 for empty args. Exit code is 1 when any high-severity finding exists, 0 otherwise. `--json` prints the full `Report`.

## Rule codes

| Code | Severity | Meaning |
|------|----------|---------|
| SPF001 | high | No SPF record |
| SPF002 | high | SPF permerror (multiple records, unknown mechanism, include target without exactly one SPF record) |
| SPF003 | high | SPF policy allows all (`+all` or bare `all`) |
| SPF004 | medium | Softfail (`?all`) or no `all` and no `redirect=` |
| SPF005 | high | SPF exceeds 10 DNS lookups |
| SPF006 | low | `ptr` mechanism used |
| DMARC001 | high | No DMARC record |
| DMARC002 | medium | DMARC policy `p=none` |
| DMARC003 | high | Invalid DMARC record |
| DKIM001 | medium | DKIM selector missing or empty `p=` |

## Limitations

- DMARC organisational domain fallback is not implemented; the record must be at `_dmarc.<domain>`.
- DKIM key length and signature checks are not performed.
- MX, BIMI and MTA-STS records are not checked.
- Void lookup limits are not enforced; only the SPF DNS-querying terms are counted against 10.
- Live DNS is never used in tests; tests use an in-memory resolver.

## Why not online checkers

Online checkers are manual and cannot run in CI. This library can be scripted with stable rule codes and a fake resolver, so results are deterministic; it audits mail authentication records, not TLS certificates.

## Documentation

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and limits. See `docs/` for architecture, project scope, stack and testing.
