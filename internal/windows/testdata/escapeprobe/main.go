package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fatal("missing operation")
	}
	switch os.Args[1] {
	case "read":
		if len(os.Args) != 3 {
			fatal("read requires path")
		}
		data, err := os.ReadFile(os.Args[2])
		if err != nil {
			fatal(err.Error())
		}
		_, _ = os.Stdout.Write(data)
	case "write":
		if len(os.Args) != 4 {
			fatal("write requires path and payload")
		}
		if err := os.WriteFile(os.Args[2], []byte(os.Args[3]), 0o600); err != nil {
			fatal(err.Error())
		}
	case "descendant-write":
		if len(os.Args) != 4 {
			fatal("descendant-write requires path and payload")
		}
		cmd := exec.Command(os.Args[0], "write", os.Args[2], os.Args[3])
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			fatal(err.Error())
		}
	case "sleep":
		if len(os.Args) != 3 {
			fatal("sleep requires milliseconds")
		}
		milliseconds, err := strconv.Atoi(os.Args[2])
		if err != nil || milliseconds < 0 {
			fatal("invalid sleep duration")
		}
		time.Sleep(time.Duration(milliseconds) * time.Millisecond)
	default:
		fatal("unknown operation")
	}
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
