package main

import (
	"os"

	"github.com/eltonlaice/php2shell-poc/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
