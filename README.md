# email-dns-audit

[![Go Reference](https://pkg.go.dev/badge/github.com/Trysac/u262-email-dns-audit.svg)](https://pkg.go.dev/github.com/Trysac/u262-email-dns-audit)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/Trysac/u262-email-dns-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u262-email-dns-audit/actions/workflows/ci.yml)

Audit a domain's email DNS records over an injected resolver: SPF syntax and the 10-lookup limit per RFC 7208, DMARC policy per RFC 7489 and DKIM selector keys

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
go get github.com/Trysac/u262-email-dns-audit
```

Requires Go 1.23 or newer. No dependencies outside the standard library.

## Usage

```go
package main

import (
	"errors"
	"fmt"

	"github.com/Trysac/u262-email-dns-audit"
)

func main() {
	// Normalize trims surrounding whitespace and lower-cases the text.
	out, _ := emaildnsaudit.Normalize("  Hello World ")
	fmt.Println(out) // -> "hello world"

	// Blank input is rejected explicitly instead of returning an empty string.
	if _, err := emaildnsaudit.Normalize("   "); errors.Is(err, emaildnsaudit.ErrBlank) {
		fmt.Println("rejected:", err)
	}
}
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
