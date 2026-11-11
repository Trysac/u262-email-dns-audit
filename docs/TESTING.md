# Testing

## Running

```sh
go test ./...
go test -cover .
```

## Tests present

The supplied code object contains no `*_test.go` files, so no test file names can be listed. The specified acceptance tests cover:

- `Audit` with a fake resolver holding SPF, DMARC and DKIM records returns no findings and `SPFLookups` 1.
- SPF: `v=spf1 +all` and `v=spf1 all` -> SPF003 high; `v=spf1 mx` -> SPF004 medium; `v=spf1 ptr -all` -> SPF006 low; `v=spf1 redirect=_spf.example.net` produces no SPF004.
- SPF lookup counting: 11 include terms produce SPF005 with message `SPF needs 11 DNS lookups, the limit is 10` and `SPFLookups` 11; an include loop `a -> b -> a` stops with SPF005 and never recurses past 11 lookups.
- SPF parsing: two `v=spf1` records -> SPF002; `v=spf10 -all` is not an SPF record, so no record -> SPF001; an include target without an SPF record -> SPF002.
- DMARC: `v=DMARC1; p=none` -> DMARC002 medium; no record -> DMARC001 high; `p=reject; v=DMARC1` and `v=DMARC1; p=maybe` -> DMARC003.
- DKIM: `v=DKIM1; p=` -> DKIM001 message `DKIM selector s1 is revoked (empty p=)`; missing selector -> DKIM001 `DKIM selector s1 has no record`.
- Errors and CLI: a resolver error other than not-found -> `ErrLookup`; `exa mple.com` or a 254-character name -> `ErrInvalidDomain`; `Run([]string{})` returns 2; `Run([]string{"--json", "example.com"})` with the test resolver prints a JSON report and returns 1 when any high finding exists.

## Policy

- Tests use a fake `Resolver`; no live DNS.
- Tests exercise the public API and assert findings, codes, severities, messages, `SPFLookups`, and errors (`errors.Is`).
- Findings are deterministic: sorted by `Code`, then `Message`.

## Tiers

- Local tier: unit tests over the fake resolver.
- CI tier: the same gate runner. No external tools are required by the specification.

## Layout

No test files or `testdata/` are present in the supplied code object.
