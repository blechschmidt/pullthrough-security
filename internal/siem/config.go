package siem

import (
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Config is the transport-agnostic configuration consumed by Build. The
// cmd/pullthrough layer translates the YAML config into this shape, mirroring
// the pattern used by the notification subsystem.
type Config struct {
	QueueSize       int
	BatchSize       int
	BatchTimeout    time.Duration
	MaxRetries      int
	RetryBaseDelay  time.Duration
	RetryMaxDelay   time.Duration
	Timeout         time.Duration
	MinSeverity     Severity
	ForwardAudit    bool
	ForwardFindings bool
	Spill           SpillConfig
	Sinks           []SinkConfig
	// OCSF configures the OCSF output encoder shared by all "ocsf" sinks.
	OCSF OCSFConfig
}

// SpillConfig configures the bounded disk-spill overflow queue.
type SpillConfig struct {
	Enabled  bool
	File     string
	MaxBytes int64
}

// SinkConfig declares one forwarding destination. Which fields apply depends on
// Kind: "splunk_hec" uses URL/Token/Index/Source/SourceType/Host/Headers;
// "syslog" uses Address/Network/Facility/Hostname/AppName/Vendor/Product/Version;
// "ocsf" uses URL/Token/AuthHeader/AuthScheme/Headers.
// TLS applies to the HEC and OCSF sinks and to a "tcp+tls" syslog sink.
type SinkConfig struct {
	Name string
	Kind string

	// Splunk HEC and OCSF HTTP.
	URL        string
	Token      string
	Index      string
	Source     string
	SourceType string
	Host       string
	Headers    map[string]string

	// OCSF HTTP auth overrides (optional).
	AuthHeader string
	AuthScheme string

	// Syslog / CEF.
	Address  string
	Network  string // tcp|udp|tcp+tls
	Facility int
	Hostname string
	AppName  string
	Vendor   string
	Product  string
	Version  string

	TLS TLSConfig
}

// ValidKind reports whether k names a supported sink kind.
func ValidKind(k string) bool {
	switch k {
	case "splunk_hec", "syslog", "ocsf":
		return true
	default:
		return false
	}
}

// Validate checks a Config for internal consistency. It is called both by the
// top-level config validator and by Build.
func (c Config) Validate() error {
	if c.QueueSize < 0 || c.BatchSize < 0 || c.MaxRetries < 0 {
		return fmt.Errorf("siem: queueSize, batchSize, and maxRetries must be non-negative")
	}
	if c.RetryBaseDelay < 0 || c.RetryMaxDelay < 0 || c.BatchTimeout < 0 || c.Timeout < 0 {
		return fmt.Errorf("siem: durations must be non-negative")
	}
	if !ValidSeverity(string(c.MinSeverity)) {
		return fmt.Errorf("siem: invalid minSeverity %q", c.MinSeverity)
	}
	if c.Spill.Enabled && strings.TrimSpace(c.Spill.File) == "" {
		return fmt.Errorf("siem: spill enabled but no spill file configured")
	}
	if len(c.Sinks) == 0 {
		return fmt.Errorf("siem: at least one sink is required when enabled")
	}
	for category, className := range c.OCSF.ClassMap {
		if !ValidOCSFClass(className) {
			return fmt.Errorf("siem: ocsf classMap category %q maps to unknown class %q (want detection_finding, vulnerability_finding, compliance_finding, authentication, or api_activity)", category, className)
		}
	}
	seen := make(map[string]bool, len(c.Sinks))
	for i, s := range c.Sinks {
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("siem: sink[%d] requires a name", i)
		}
		if seen[s.Name] {
			return fmt.Errorf("siem: duplicate sink name %q", s.Name)
		}
		seen[s.Name] = true
		if !ValidKind(s.Kind) {
			return fmt.Errorf("siem: sink %q has unknown kind %q (want splunk_hec, syslog, or ocsf)", s.Name, s.Kind)
		}
		switch s.Kind {
		case "ocsf":
			if strings.TrimSpace(s.URL) == "" {
				return fmt.Errorf("siem: ocsf sink %q requires a url", s.Name)
			}
			if !strings.HasPrefix(s.URL, "http://") && !strings.HasPrefix(s.URL, "https://") {
				return fmt.Errorf("siem: ocsf sink %q url must be http(s)", s.Name)
			}
		case "splunk_hec":
			if strings.TrimSpace(s.URL) == "" {
				return fmt.Errorf("siem: hec sink %q requires a url", s.Name)
			}
			if !strings.HasPrefix(s.URL, "http://") && !strings.HasPrefix(s.URL, "https://") {
				return fmt.Errorf("siem: hec sink %q url must be http(s)", s.Name)
			}
			if strings.TrimSpace(s.Token) == "" {
				return fmt.Errorf("siem: hec sink %q requires a token", s.Name)
			}
		case "syslog":
			if strings.TrimSpace(s.Address) == "" {
				return fmt.Errorf("siem: syslog sink %q requires an address", s.Name)
			}
			if s.Network != "" && !validSyslogNetwork(s.Network) {
				return fmt.Errorf("siem: syslog sink %q has invalid network %q", s.Name, s.Network)
			}
			if s.Facility < 0 || s.Facility > 23 {
				return fmt.Errorf("siem: syslog sink %q facility %d out of range 0..23", s.Name, s.Facility)
			}
		}
	}
	return nil
}

// Build validates the config, opens the spill (when enabled), constructs the
// sinks, and returns a started Forwarder.
func Build(cfg Config, logger *slog.Logger) (*Forwarder, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	// The OCSF encoder is shared by every "ocsf" sink; build it once so a bad
	// classMap override is reported before any sink or spill is opened.
	encoder, err := newOCSFEncoder(cfg.OCSF)
	if err != nil {
		return nil, err
	}
	sinks := make([]Sink, 0, len(cfg.Sinks))
	for _, sc := range cfg.Sinks {
		s, err := buildSink(sc, cfg.Timeout, encoder)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, s)
	}

	var spill *spillQueue
	if cfg.Spill.Enabled {
		sq, err := openSpill(cfg.Spill.File, cfg.Spill.MaxBytes)
		if err != nil {
			// Close any already-constructed sinks before failing.
			for _, s := range sinks {
				_ = s.Close()
			}
			return nil, err
		}
		spill = sq
	}

	return New(Options{
		Logger:          logger,
		Sinks:           sinks,
		MinSeverity:     cfg.MinSeverity,
		ForwardAudit:    cfg.ForwardAudit,
		ForwardFindings: cfg.ForwardFindings,
		QueueSize:       cfg.QueueSize,
		BatchSize:       cfg.BatchSize,
		BatchTimeout:    cfg.BatchTimeout,
		MaxRetries:      cfg.MaxRetries,
		RetryBaseDelay:  cfg.RetryBaseDelay,
		RetryMaxDelay:   cfg.RetryMaxDelay,
		Timeout:         cfg.Timeout,
		Spill:           spill,
	}), nil
}

// buildSink constructs a single Sink from its declarative config. The shared
// OCSF encoder is injected into any "ocsf" sink.
func buildSink(sc SinkConfig, timeout time.Duration, encoder *ocsfEncoder) (Sink, error) {
	switch sc.Kind {
	case "ocsf":
		return NewOCSFSink(OCSFOptions{
			Name:       sc.Name,
			URL:        sc.URL,
			Token:      sc.Token,
			AuthHeader: sc.AuthHeader,
			AuthScheme: sc.AuthScheme,
			Headers:    sc.Headers,
			Timeout:    timeout,
			TLS:        sc.TLS,
			Encoder:    encoder,
		})
	case "splunk_hec":
		return NewHECSink(HECOptions{
			Name:       sc.Name,
			URL:        sc.URL,
			Token:      sc.Token,
			Index:      sc.Index,
			Source:     sc.Source,
			SourceType: sc.SourceType,
			Host:       sc.Host,
			Headers:    sc.Headers,
			Timeout:    timeout,
			TLS:        sc.TLS,
		})
	case "syslog":
		return NewSyslogSink(SyslogOptions{
			Name:     sc.Name,
			Network:  sc.Network,
			Address:  sc.Address,
			Facility: sc.Facility,
			Hostname: sc.Hostname,
			AppName:  sc.AppName,
			Vendor:   sc.Vendor,
			Product:  sc.Product,
			Version:  sc.Version,
			Timeout:  timeout,
			TLS:      sc.TLS,
		})
	default:
		return nil, fmt.Errorf("siem: unknown sink kind %q", sc.Kind)
	}
}
