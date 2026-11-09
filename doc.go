// Package emaildnsaudit is a small, dependency-free Go library: Audit a domain's email DNS records over an injected resolver: SPF syntax and the 10-lookup limit per RFC 7208, DMARC policy per RFC 7489 and DKIM selector keys
//
// The public API is every exported identifier of this root package. Functions are pure: they do
// no I/O, keep no global mutable state and report invalid input through returned errors.
package emaildnsaudit
