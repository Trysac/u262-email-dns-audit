# Project record

## Objective

Audit a domain's email DNS records over an injected resolver: SPF syntax and the 10-lookup limit per RFC 7208, DMARC policy per RFC 7489 and DKIM selector keys.

## Scope

- In scope: SPF, DMARC and DKIM selector checks in the public API documented in [README.md](../README.md), including rule codes SPF001-SPF006, DMARC001-DMARC003, DKIM001; domain validation; resolver injection; CLI `Run`.
- Out of scope: DMARC organisational domain fallback, DKIM key length and signature checks, MX/BIMI/MTA-STS records, void-lookup limits, and live DNS in tests.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 1432712 / 123562 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.1343 |

## Factory run u262 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | deepseek-v4-pro | yes | 1687 | 27478 | 0 | 3328 | 0.0556 |
| fix-1 | deepseek-flash | no | 16520 | 13129 | 0 | 297216 | 0.0112 |
| fix-2 | deepseek-flash | no | 17133 | 8107 | 0 | 120320 | 0.0078 |
| fix-3 | deepseek-flash | no | 9752 | 4467 | 0 | 34560 | 0.0042 |
| audit | deepseek-flash | no | 25602 | 27939 | 0 | 289792 | 0.0215 |
| fix-4 | deepseek-flash | no | 16537 | 11783 | 0 | 367104 | 0.0107 |
| threat-model | deepseek-flash | no | 24034 | 16051 | 0 | 204288 | 0.0138 |
| docs | deepseek-flash | no | 4455 | 14608 | 0 | 384 | 0.0094 |

Total: $0.1343. Prices: deepseek line, as measured by its adapter.
