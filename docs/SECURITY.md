# Security notes

## Threat model

Defended:

- Input validation: domains are accepted only when, after removing one trailing dot, they are 1-253 characters with labels 1-63 of `[A-Za-z0-9-]` that do not start or end with `-`; otherwise `Audit` returns `ErrInvalidDomain` before lookups.
- Resolver failures: errors other than not-found are returned as `ErrLookup`; they are not silently ignored.
- Oversized TXT records: records over 4096 bytes count as invalid.
- SPF recursion: include and redirect evaluation is counted depth-first and stops at the 11th lookup, reporting SPF005; include loops do not recurse past 11 lookups.
- Lookup timeout: `Options.Timeout` defaults to 5s per lookup when zero.
- Supply chain: the implementation uses the Go standard library only.

Not defended:

- DMARC organisational domain fallback is not implemented; only `_dmarc.<domain>` is checked.
- DKIM key length and signature checks are not performed; DKIM001 only checks record presence and an empty `p=` tag.
- MX, BIMI and MTA-STS records are not checked.
- Void lookup limits are not enforced; only SPF DNS-querying terms are counted against 10.
- Macros in SPF are counted as lookups but never expanded.
- DNS authenticity and DNSSEC are not verified; the library reports what the supplied `Resolver` returns.
- Live DNS is never used in tests.

## Publishing

Releases are git tags served through the Go module proxy and checksum database. No registry token is stored in the repository.

To report a vulnerability, open an issue in the repository.
