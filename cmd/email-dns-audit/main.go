package main

import (
	"os"

	"github.com/Trysac/u262-email-dns-audit"
)

func main() {
	os.Exit(emaildnsaudit.Run(os.Args[1:], os.Stdout, os.Stderr))
}
