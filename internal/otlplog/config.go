package otlplog

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"
)

// Config is the operator-facing OTLP-logs configuration, translated from the
// telemetry.otlpLogs YAML block. Export is active only when Enabled is true and
// Endpoint is non-empty; otherwise New returns a nil *Pipeline (a valid no-op),
// the default opt-out when no collector is deployed.
type Config struct {
	Enabled       bool
	Endpoint      string
	Insecure      bool
	TLSSkipVerify bool

	// ServiceName, ServiceVersion, Environment, and Tenant populate the standard
	// OTLP resource attributes (service.name, service.version,
	// deployment.environment, and the tenant identifier) attached to every batch.
	ServiceName    string
	ServiceVersion string
	Environment    string
	Tenant         string
	// ResourceAttributes are extra resource attributes (e.g. cluster, region).
	ResourceAttributes map[string]string
	// Headers are sent on every OTLP export request (e.g. an ingest token).
	Headers map[string]string

	// MinLevel is the minimum log level forwarded to the collector
	// (debug/info/warn/error, case-insensitive). Empty defaults to info.
	MinLevel string

	// Batch/retry tuning. Zero values fall back to the package defaults.
	Timeout        time.Duration
	BatchTimeout   time.Duration
	MaxQueueSize   int
	MaxBatchSize   int
	MaxRetries     int
	RetryBaseDelay time.Duration
	RetryMaxDelay  time.Duration

	// SpillPath, when set, enables a bounded file-backed overflow queue absorbing
	// bursts that exceed MaxQueueSize and surviving restarts. SpillMaxBytes caps
	// its on-disk size (non-positive = uncapped).
	SpillPath     string
	SpillMaxBytes int64

	// Logger is the forwarder's own diagnostic logger. It MUST NOT be the logger
	// whose handler this pipeline taps, or a forwarding warning would recurse.
	Logger *slog.Logger
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Active reports whether the configuration would produce a live exporter.
func (c Config) Active() bool { return c.Enabled && strings.TrimSpace(c.Endpoint) != "" }

// Pipeline bundles the running Forwarder with the handler-construction inputs so
// a caller can both drive the lifecycle (Metrics/Close) and wrap its logger.
type Pipeline struct {
	Forwarder    *Forwarder
	endpoint     string
	forwardLevel slog.Level
	addSource    bool
	now          func() time.Time
}

// New constructs an OTLP-logs Pipeline from config. It returns (nil, nil) when
// export is disabled or no endpoint is set, so the caller treats a nil Pipeline
// as the opt-out. It only errors on a malformed endpoint or spill path, so a
// typo fails fast at startup rather than silently dropping every log.
func New(cfg Config) (*Pipeline, error) {
	if !cfg.Active() {
		return nil, nil
	}
	level, err := parseLevel(cfg.MinLevel)
	if err != nil {
		return nil, err
	}
	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "pullthrough"
	}
	exporter, err := NewOTLPExporter(OTLPConfig{
		Endpoint:      cfg.Endpoint,
		Insecure:      cfg.Insecure,
		Headers:       cfg.Headers,
		Resource:      buildResource(cfg, serviceName),
		ScopeName:     defaultScopeName,
		Timeout:       cfg.Timeout,
		TLSSkipVerify: cfg.TLSSkipVerify,
	})
	if err != nil {
		return nil, err
	}

	var spill *spillQueue
	if p := strings.TrimSpace(cfg.SpillPath); p != "" {
		spill, err = openSpill(p, cfg.SpillMaxBytes)
		if err != nil {
			return nil, err
		}
	}

	fwd := newForwarder(forwarderOptions{
		Logger:       cfg.Logger,
		Exporter:     exporter,
		QueueSize:    cfg.MaxQueueSize,
		BatchSize:    cfg.MaxBatchSize,
		BatchTimeout: cfg.BatchTimeout,
		MaxRetries:   cfg.MaxRetries,
		BaseDelay:    cfg.RetryBaseDelay,
		MaxDelay:     cfg.RetryMaxDelay,
		Timeout:      cfg.Timeout,
		Spill:        spill,
		Now:          cfg.Now,
	})

	return &Pipeline{
		Forwarder:    fwd,
		endpoint:     exporter.Endpoint(),
		forwardLevel: level,
		addSource:    false,
		now:          cfg.Now,
	}, nil
}

// WithSource sets whether the handler attaches code.* source attributes, so the
// caller can align it with the logging block's addSource setting.
func (p *Pipeline) WithSource(addSource bool) *Pipeline {
	if p == nil {
		return nil
	}
	p.addSource = addSource
	return p
}

// Handler wraps inner so records flow to both the inner (stderr) handler and the
// OTLP forwarder. Safe on a nil Pipeline (returns inner unchanged).
func (p *Pipeline) Handler(inner slog.Handler) slog.Handler {
	if p == nil {
		return inner
	}
	return NewHandler(inner, p.Forwarder, HandlerOptions{
		ForwardLevel: p.forwardLevel,
		AddSource:    p.addSource,
		Now:          p.now,
	})
}

// Endpoint returns the normalized OTLP logs URL (for status surfaces).
func (p *Pipeline) Endpoint() string {
	if p == nil {
		return ""
	}
	return p.endpoint
}

// Metrics returns the forwarder's telemetry snapshot. Safe on a nil Pipeline.
func (p *Pipeline) Metrics() Metrics {
	if p == nil {
		return Metrics{}
	}
	return p.Forwarder.Metrics()
}

// Close flushes and shuts down the forwarder. Safe on a nil Pipeline and
// idempotent.
func (p *Pipeline) Close() error {
	if p == nil {
		return nil
	}
	return p.Forwarder.Close()
}

// buildResource assembles the OTLP resource attributes: the conventional
// service.* keys, the deployment environment and tenant, plus any operator extras
// (sorted for deterministic output).
func buildResource(cfg Config, serviceName string) []Attr {
	attrs := []Attr{String("service.name", serviceName)}
	if cfg.ServiceVersion != "" {
		attrs = append(attrs, String("service.version", cfg.ServiceVersion))
	}
	if cfg.Environment != "" {
		attrs = append(attrs, String("deployment.environment", cfg.Environment))
	}
	if cfg.Tenant != "" {
		attrs = append(attrs, String("tenant", cfg.Tenant))
	}
	keys := make([]string, 0, len(cfg.ResourceAttributes))
	for k := range cfg.ResourceAttributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		attrs = append(attrs, String(k, cfg.ResourceAttributes[k]))
	}
	return attrs
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
		return slog.LevelInfo, fmt.Errorf("otlplog: unknown level %q", level)
	}
}
