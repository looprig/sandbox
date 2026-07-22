//go:build windows

// runtimeprobe is an intentionally small, installed-runner-shaped executable
// used by the restricted-runtime feasibility spike. It has no product role.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32        = windows.NewLazySystemDLL("kernel32.dll")
	procFlsAlloc    = kernel32.NewProc("FlsAlloc")
	procFlsFree     = kernel32.NewProc("FlsFree")
	procFlsSetValue = kernel32.NewProc("FlsSetValue")
	procLocaleName  = kernel32.NewProc("GetUserDefaultLocaleName")
	callbackSeen    atomic.Bool
)

func main() {
	mode := "smoke"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}

	var err error
	switch mode {
	case "smoke":
		err = smoke()
	case "subprocess":
		err = runSubprocess()
	case "dll-initializer":
		err = loadRuntimeDLLs()
	case "locale-console":
		err = localeAndConsole()
	case "tls-callback":
		err = runTLSCallbackFixture()
	default:
		err = fmt.Errorf("unknown mode %q", mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func smoke() error {
	if err := loadRuntimeDLLs(); err != nil {
		return err
	}
	return localeAndConsole()
}

func runSubprocess() error {
	cmd := exec.Command(os.Args[0], "smoke")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// LoadLibraryEx calls each module's process-attach initializer before it
// returns. These are the CRT and loader modules used by supported Go binaries.
func loadRuntimeDLLs() error {
	for _, name := range []string{"kernelbase.dll", "ucrtbase.dll"} {
		h, err := windows.LoadLibraryEx(name, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
		if err != nil {
			return fmt.Errorf("LoadLibraryEx(%s): %w", name, err)
		}
		if err := windows.FreeLibrary(h); err != nil {
			return fmt.Errorf("FreeLibrary(%s): %w", name, err)
		}
	}
	return nil
}

func localeAndConsole() error {
	const localeNameMaxLength = 85
	name := make([]uint16, localeNameMaxLength)
	r1, _, callErr := procLocaleName.Call(uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)))
	if r1 == 0 {
		return fmt.Errorf("GetUserDefaultLocaleName: %w", callErr)
	}
	// A service worker may have no console. Both zero (no console) and a valid
	// code page are legitimate startup states; the calls themselves must load.
	_, _ = windows.GetConsoleCP()
	_, _ = windows.GetConsoleOutputCP()
	return nil
}

// runTLSCallbackFixture uses Windows Fiber Local Storage, whose cleanup
// callback is dispatched by the same per-thread runtime machinery exercised by
// TLS users. The live report names it precisely; it is not represented as a PE
// image TLS-directory callback.
func runTLSCallbackFixture() error {
	callbackSeen.Store(false)
	callback := syscall.NewCallback(func(value uintptr) uintptr {
		if value == 1 {
			callbackSeen.Store(true)
		}
		return 0
	})
	index, _, callErr := procFlsAlloc.Call(callback)
	if index == ^uintptr(0) {
		return fmt.Errorf("FlsAlloc: %w", callErr)
	}
	if r1, _, err := procFlsSetValue.Call(index, 1); r1 == 0 {
		procFlsFree.Call(index)
		return fmt.Errorf("FlsSetValue: %w", err)
	}
	if r1, _, err := procFlsFree.Call(index); r1 == 0 {
		return fmt.Errorf("FlsFree: %w", err)
	}
	runtime.KeepAlive(callback)
	if !callbackSeen.Load() {
		return fmt.Errorf("FLS cleanup callback was not dispatched")
	}
	return nil
}
