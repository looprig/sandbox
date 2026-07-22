package baseline

import "time"

type CleanupResult struct {
	Completed      bool
	WaitError      error
	TerminateError error
	CloseJobError  error
	KillError      error
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
