package baseline

import (
	"fmt"
	"time"
)

type CleanupResult struct {
	Completed      bool
	WaitError      error
	TerminateError error
	CloseJobError  error
	KillError      error
}

func EnforceCleanupCompleted(result CleanupResult, fatal func(string)) bool {
	if result.Completed {
		return true
	}
	fatal(fmt.Sprintf("terminal incomplete cleanup: wait=%v terminate=%v close=%v kill=%v", result.WaitError, result.TerminateError, result.CloseJobError, result.KillError))
	return false
}

func CleanupWithWatchdog(done <-chan error, deadline <-chan time.Time, terminate, closeJob, kill func() error) CleanupResult {
	result := CleanupResult{TerminateError: terminate(), CloseJobError: closeJob(), KillError: kill()}
	select {
	case result.WaitError = <-done:
		result.Completed = true
	case <-deadline:
	}
	return result
}
