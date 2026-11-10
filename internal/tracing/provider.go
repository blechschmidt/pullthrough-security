package tracing

import (
	"fmt"
	"sort"
	"time"
)

// Config is the operator-facing tracing configuration, translated from the YAML
// tracing block. Tracing is active only when Enabled is true and Endpoint is
// non-empty; otherwise New returns a nil Provider (a valid no-op), which is the
// default opt-out when no collector is configured.
type Config struct {
	Enabled       bool
	Endpoint      string
	Insecure      bool
	ServiceName   string
	ServiceVer    string
	Environment   string
	SamplerRatio  float64
	ResourceAttrs map[string]string
	Headers       map[string]string
	Timeout       time.Duration
	BatchTimeout  time.Duration
	MaxQueueSize  int
	MaxBatchSize  int
	TLSSkipVerify bool
}

// Active reports whether the configuration would produce a live tracer.
func (c Config) Active() bool { return c.Enabled && c.Endpoint != "" }

// New constructs a Provider from config. It returns (nil, nil) when tracing is
// disabled or no endpoint is set, so the caller treats a nil Provider as the
// opt-out. It only errors on a malformed endpoint, so a typo fails fast at
// startup rather than silently dropping every span.
func New(cfg Config) (*Provider, error) {
	if !cfg.Active() {
		return nil, nil
	}
	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "pullthrough"
	}
	ratio := cfg.SamplerRatio
	if ratio == 0 {
		// A zero ratio from an explicitly-enabled tracer almost always means
		// "unset" rather than "sample nothing"; default to full sampling so an
		// operator who enables tracing actually sees traces.
		ratio = 1.0
	}

	exporter, err := NewOTLPExporter(OTLPConfig{
		Endpoint:      cfg.Endpoint,
		Insecure:      cfg.Insecure,
		Headers:       cfg.Headers,
		Resource:      buildResource(cfg, serviceName),
		ScopeName:     "github.com/blechschmidt/pullthrough-security",
		Timeout:       cfg.Timeout,
		TLSSkipVerify: cfg.TLSSkipVerify,
	})
	if err != nil {
		return nil, err
	}

	return NewProviderWithExporter(ProviderOptions{
		Exporter:      exporter,
		Sampler:       NewRatioSampler(ratio),
		ServiceName:   serviceName,
		MaxQueueSize:  cfg.MaxQueueSize,
		MaxBatchSize:  cfg.MaxBatchSize,
		FlushInterval: cfg.BatchTimeout,
	}), nil
}

// buildResource assembles the OTLP resource attributes: the conventional
// service.* keys plus any operator-supplied extras.
func buildResource(cfg Config, serviceName string) []Attr {
	attrs := []Attr{String("service.name", serviceName)}
	if cfg.ServiceVer != "" {
		attrs = append(attrs, String("service.version", cfg.ServiceVer))
	}
	if cfg.Environment != "" {
		attrs = append(attrs, String("deployment.environment", cfg.Environment))
	}
	// Operator extras, sorted for deterministic output.
	keys := make([]string, 0, len(cfg.ResourceAttrs))
	for k := range cfg.ResourceAttrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		attrs = append(attrs, String(k, cfg.ResourceAttrs[k]))
	}
	return attrs
}

// Status is the read-only tracing snapshot for the admin surface: the effective
// configuration plus the live exporter counters.
type Status struct {
	Enabled      bool    `json:"enabled"`
	Endpoint     string  `json:"endpoint,omitempty"`
	ServiceName  string  `json:"serviceName,omitempty"`
	SamplerRatio float64 `json:"samplerRatio"`
	Metrics      Metrics `json:"metrics"`
}

// Status returns the tracing status for the admin API. Safe on a nil Provider
// (reports disabled).
func (p *Provider) Status() Status {
	if p == nil {
		return Status{Enabled: false}
	}
	return Status{
		Enabled:     true,
		ServiceName: p.serviceName,
		Metrics:     p.Metrics(),
	}
}

// StatusWith returns the tracing status enriched with the endpoint and sampler
// ratio that are known to the constructing caller (the Provider does not retain
// the raw config). It is the form the admin/observability wiring uses.
func (p *Provider) StatusWith(endpoint string, ratio float64) Status {
	s := p.Status()
	s.Endpoint = endpoint
	s.SamplerRatio = ratio
	return s
}

// String renders a one-line description for startup logging.
func (c Config) String() string {
	if !c.Active() {
		return "tracing disabled"
	}
	return fmt.Sprintf("tracing -> %s (service=%s ratio=%.3g)", c.Endpoint, c.ServiceName, c.SamplerRatio)
}
