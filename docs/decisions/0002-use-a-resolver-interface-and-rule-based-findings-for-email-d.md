# Use a resolver interface and rule-based findings for email DNS audit

Status: accepted (generated, pending human review)

## Context

Email authentication misconfigurations can lead to spoofing and delivery issues. We need an automatable audit that can run in CI without manual steps. The audit must evaluate SPF, DMARC, and DKIM according to RFC 7208 and RFC 7489, and produce stable rule codes for tooling.

## Decision

Implement a Go library with an injectable Resolver interface for DNS lookups. The core Audit function returns a Report containing a list of Findings with severity and message. Rules are implemented as pure functions over the DNS records, with recursion for SPF includes/redirects and cycle detection. A CLI is provided that uses net.DefaultResolver by default but can be tested with a fake resolver via an unexported package variable.

## Consequences

Positive: enables unit testing without network, supports CI integration, provides clear rule codes. Negative: the resolver injection makes the library slightly more complex; the CLI cannot be used for testing without compiler tricks (tests use internal package access).
