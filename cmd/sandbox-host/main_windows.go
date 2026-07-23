//go:build windows

package main

import (
	"fmt"
	"os"
)

// The companion remains a composition root. Service and runner entry modes
// are supplied by their implementation phases; an unknown invocation fails.
func main() {
	if len(os.Args) == 2 && os.Args[1] == "--self-test" {
		fmt.Fprintln(os.Stdout, "sandbox-host: ok")
		return
	}
	os.Exit(2)
}
