// Package logging provides a small wrapper around log/slog so the rest of the
// codebase has a single, consistent way to construct structured loggers.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Format enumerates the supported log output encodings.
type Format string

const (
	FormatJSON Format = "json"
	FormatText Format = "text"
)

// Options configures a logger created by New.
type Options struct {
	// Level is one of debug, info, warn, error (case-insensitive).
	Level string
	// Format selects the encoder. Defaults to JSON when empty.
	Format Format
	// Writer is the destination. Defaults to os.Stderr when nil.
	Writer io.Writer
	// AddSource attaches the source file:line to each record.
	AddSource bool
}

// parseLevel converts a textual level into an slog.Level, defaulting to info.
func parseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("logging: unknown level %q", level)
	}
}

// New constructs a *slog.Logger from the supplied options. It returns an error
// only when the configured level is invalid; all other fields fall back to
// sensible defaults so the caller can always obtain a usable logger.
func New(opts Options) (*slog.Logger, error) {
	level, err := parseLevel(opts.Level)
	if err != nil {
		return nil, err
	}

	w := opts.Writer
	if w == nil {
		w = os.Stderr
	}

	handlerOpts := &slog.HandlerOptions{
		Level:     level,
		AddSource: opts.AddSource,
	}

	var handler slog.Handler
	switch opts.Format {
	case FormatText:
		handler = slog.NewTextHandler(w, handlerOpts)
	case FormatJSON, "":
		handler = slog.NewJSONHandler(w, handlerOpts)
	default:
		return nil, fmt.Errorf("logging: unknown format %q", opts.Format)
	}

	return slog.New(handler), nil
}

// Must is a helper for call sites (such as early bootstrap) that cannot
// reasonably handle a logger construction error. It panics on failure.
func Must(opts Options) *slog.Logger {
	logger, err := New(opts)
	if err != nil {
		panic(err)
	}
	return logger
}
