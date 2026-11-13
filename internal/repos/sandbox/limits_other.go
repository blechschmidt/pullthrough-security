//go:build !unix

package sandbox

// limitFileSize is a no-op where there are no resource limits; the host's
// watchdog of the work directory still applies.
func limitFileSize(uint64) error { return nil }
