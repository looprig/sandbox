//go:build windows

package main

import (
	"context"
	"fmt"
	"os"

	win "github.com/looprig/sandbox/internal/windows"
	"golang.org/x/sys/windows/svc"
)

// The companion remains a composition root. Service and runner entry modes
// are supplied by their implementation phases; an unknown invocation fails.
func main() {
	if len(os.Args) == 2 && os.Args[1] == "--self-test" {
		fmt.Fprintln(os.Stdout, "sandbox-host: ok")
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--service" {
		if err := win.RunInstalledBrokerService(context.Background()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 1 {
		service, err := svc.IsWindowsService()
		if err == nil && service {
			if err := win.RunInstalledBrokerServiceDispatcher(); err != nil {
				os.Exit(1)
			}
			return
		}
	}
	os.Exit(2)
}
