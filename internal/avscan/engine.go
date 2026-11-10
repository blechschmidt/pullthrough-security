package avscan

import (
	"context"
	"errors"
	"io"
)

// ErrEngineUnavailable is returned (wrapped) by an Engine when it cannot be
// reached or the scan cannot be completed for a transport/protocol reason. The
// gate treats it as "engine unavailable" and applies the fail-open/fail-closed
// policy, as distinct from a successfully-completed clean/infected scan.
var ErrEngineUnavailable = errors.New("avscan: engine unavailable")

// Verdict is the engine's result for one scanned payload. A nil scan error with
// Infected=false is a clean verdict; Infected=true carries the Signature.
type Verdict struct {
	// Infected reports that the engine matched a malware signature.
	Infected bool
	// Signature is the matched signature name (e.g. "Eicar-Test-Signature") when
	// Infected; empty for a clean verdict.
	Signature string
	// Bytes is how many bytes of the payload were streamed to the engine.
	Bytes int64
}

// Engine scans a byte stream for malware. Implementations must be safe for
// concurrent use and must honour context cancellation.
type Engine interface {
	// Name identifies the engine (e.g. "clamav").
	Name() string
	// Scan streams r (already size-bounded by the caller) through the engine and
	// returns a verdict. It returns a non-nil error only on an engine/transport
	// failure (unreachable, protocol error, timeout, oversize rejection) — a clean
	// or infected result is a successful scan with a nil error. Such a failure
	// should wrap ErrEngineUnavailable.
	Scan(ctx context.Context, r io.Reader) (Verdict, error)
	// Ping verifies the engine is reachable and responsive. Used for status and
	// health reporting; it never blocks the pull path.
	Ping(ctx context.Context) error
}

// newEngine constructs the engine selected by cfg. An injected EngineImpl wins;
// otherwise the only built-in engine is the clamd client.
func newEngine(cfg Config) (Engine, error) {
	if cfg.EngineImpl != nil {
		return cfg.EngineImpl, nil
	}
	switch cfg.Engine {
	case EngineClamAV:
		return newClamdEngine(cfg.Address, cfg.Timeout)
	default:
		// Unreachable: validate() rejects unknown engines before construction.
		return nil, errUnknownEngine(cfg.Engine)
	}
}

func errUnknownEngine(name string) error {
	return &engineError{msg: "avscan: unknown engine " + name}
}

type engineError struct{ msg string }

func (e *engineError) Error() string { return e.msg }
