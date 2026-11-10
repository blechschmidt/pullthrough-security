package notify

import (
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Config is the declarative configuration for the notification subsystem. It is
// the plain (transport-agnostic) form; the config package holds the YAML-tagged
// mirror and the command wiring translates one into the other, matching the
// pattern used by the other subsystems.
type Config struct {
	// Workers is the number of asynchronous delivery workers (default 2).
	Workers int
	// QueueSize bounds the async delivery queue; a full queue drops the
	// notification rather than blocking the request path (default 256).
	QueueSize int
	// MaxRetries is the number of additional delivery attempts after the first on
	// a retryable failure (default 3).
	MaxRetries int
	// RetryBaseDelay is the base of the exponential backoff between retries
	// (default 500ms); RetryMaxDelay caps it (default 30s).
	RetryBaseDelay time.Duration
	RetryMaxDelay  time.Duration
	// Timeout bounds a single delivery attempt (default 10s).
	Timeout time.Duration
	// MinSeverity is the global severity floor; events below it are never
	// delivered regardless of routing (default info / no floor).
	MinSeverity Severity
	// RedactFields are extra field-key substrings to scrub in addition to the
	// built-in credential set.
	RedactFields []string
	// Sinks are the configured delivery destinations.
	Sinks []SinkConfig
	// Routes map event types and severities to sinks. When empty, a single
	// implicit route delivers every event type to every sink at MinSeverity.
	Routes []RouteConfig
}

// SinkConfig configures one delivery destination.
type SinkConfig struct {
	// Name uniquely identifies the sink within the Notifier (routing, metrics,
	// the test endpoint).
	Name string
	// Kind selects the implementation: "webhook" or "slack".
	Kind string
	// URL is the destination endpoint (the webhook URL or Slack incoming-webhook
	// URL). Treated as a secret for Slack.
	URL string
	// Headers are extra HTTP headers for the generic webhook sink (e.g. an
	// authorization or signature header). Ignored by the Slack sink.
	Headers map[string]string
	// Channel, Username, and IconEmoji are optional Slack display overrides.
	Channel   string
	Username  string
	IconEmoji string
	// InsecureSkipVerify disables TLS verification of the endpoint (test only).
	InsecureSkipVerify bool
}

// RouteConfig binds one or more sinks to the event types and minimum severity
// they should receive.
type RouteConfig struct {
	// Sinks are the sink names this route delivers to. Unknown names are a
	// configuration error.
	Sinks []string
	// EventTypes restricts the route to these event types; empty matches all
	// routable types.
	EventTypes []string
	// MinSeverity is the route's severity floor (in addition to the global one).
	MinSeverity Severity
}

// Validate checks a Config for internal consistency without constructing any
// sinks: unique non-empty sink names, recognized kinds and URLs, valid
// severities/event types, and routes that reference defined sinks.
func Validate(cfg Config) error {
	if cfg.Workers < 0 {
		return fmt.Errorf("notify: workers must not be negative, got %d", cfg.Workers)
	}
	if cfg.QueueSize < 0 {
		return fmt.Errorf("notify: queueSize must not be negative, got %d", cfg.QueueSize)
	}
	if cfg.MaxRetries < 0 {
		return fmt.Errorf("notify: maxRetries must not be negative, got %d", cfg.MaxRetries)
	}
	if !ValidSeverity(string(cfg.MinSeverity)) {
		return fmt.Errorf("notify: minSeverity %q is invalid (want none|low|medium|high|critical)", cfg.MinSeverity)
	}
	if len(cfg.Sinks) == 0 {
		return fmt.Errorf("notify: enabled but no sinks configured")
	}

	names := make(map[string]bool, len(cfg.Sinks))
	for i, s := range cfg.Sinks {
		name := strings.TrimSpace(s.Name)
		if name == "" {
			return fmt.Errorf("notify: sinks[%d] has an empty name", i)
		}
		if names[name] {
			return fmt.Errorf("notify: duplicate sink name %q", name)
		}
		names[name] = true
		switch strings.ToLower(strings.TrimSpace(s.Kind)) {
		case "webhook", "slack":
		default:
			return fmt.Errorf("notify: sink %q has unknown kind %q (want webhook|slack)", name, s.Kind)
		}
		if strings.TrimSpace(s.URL) == "" {
			return fmt.Errorf("notify: sink %q has an empty url", name)
		}
		if !strings.HasPrefix(s.URL, "http://") && !strings.HasPrefix(s.URL, "https://") {
			return fmt.Errorf("notify: sink %q url must be http(s), got %q", name, s.URL)
		}
	}

	for i, r := range cfg.Routes {
		if len(r.Sinks) == 0 {
			return fmt.Errorf("notify: routes[%d] references no sinks", i)
		}
		for _, sn := range r.Sinks {
			if !names[sn] {
				return fmt.Errorf("notify: routes[%d] references undefined sink %q", i, sn)
			}
		}
		if !ValidSeverity(string(r.MinSeverity)) {
			return fmt.Errorf("notify: routes[%d].minSeverity %q is invalid", i, r.MinSeverity)
		}
		for _, t := range r.EventTypes {
			if !ValidEventType(t) {
				return fmt.Errorf("notify: routes[%d] has unknown event type %q", i, t)
			}
		}
	}
	return nil
}

// Build validates cfg, constructs the configured sinks and routes, and returns a
// running Notifier. The caller owns the lifecycle and must Close it. When no
// routes are configured, an implicit catch-all route delivers every event type
// to every sink at the global severity floor.
func Build(cfg Config, logger *slog.Logger) (*Notifier, error) {
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}

	sinks := make(map[string]Sink, len(cfg.Sinks))
	for _, sc := range cfg.Sinks {
		s, err := buildSink(sc, cfg.Timeout)
		if err != nil {
			return nil, err
		}
		sinks[sc.Name] = s
	}

	var specs []RouteSpec
	if len(cfg.Routes) == 0 {
		// Implicit catch-all: every sink receives every event type.
		all := make([]Sink, 0, len(cfg.Sinks))
		for _, sc := range cfg.Sinks {
			all = append(all, sinks[sc.Name])
		}
		specs = append(specs, RouteSpec{Sinks: all, MinSeverity: cfg.MinSeverity})
	} else {
		for _, rc := range cfg.Routes {
			spec := RouteSpec{MinSeverity: rc.MinSeverity}
			for _, sn := range rc.Sinks {
				spec.Sinks = append(spec.Sinks, sinks[sn])
			}
			for _, t := range rc.EventTypes {
				spec.EventTypes = append(spec.EventTypes, EventType(strings.ToLower(strings.TrimSpace(t))))
			}
			specs = append(specs, spec)
		}
	}

	n := New(Options{
		Logger:      logger,
		Redactor:    NewRedactor(cfg.RedactFields),
		MinSeverity: cfg.MinSeverity,
		Routes:      specs,
		Workers:     cfg.Workers,
		QueueSize:   cfg.QueueSize,
		MaxRetries:  defaultMaxRetries(cfg.MaxRetries),
		BaseDelay:   cfg.RetryBaseDelay,
		MaxDelay:    cfg.RetryMaxDelay,
		Timeout:     cfg.Timeout,
	})
	return n, nil
}

// defaultMaxRetries applies the default of 3 when unset (0), preserving an
// explicit choice to disable retries via a negative-normalized-to-zero value is
// not possible through config, so 0 means "use default". Operators wanting no
// retries are served by the backoff cap and queue semantics in practice.
func defaultMaxRetries(v int) int {
	if v <= 0 {
		return 3
	}
	return v
}

// buildSink constructs a Sink from its config entry.
func buildSink(sc SinkConfig, timeout time.Duration) (Sink, error) {
	switch strings.ToLower(strings.TrimSpace(sc.Kind)) {
	case "webhook":
		return NewWebhookSink(WebhookOptions{
			Name:               sc.Name,
			URL:                sc.URL,
			Headers:            sc.Headers,
			Timeout:            timeout,
			InsecureSkipVerify: sc.InsecureSkipVerify,
		})
	case "slack":
		return NewSlackSink(SlackOptions{
			Name:               sc.Name,
			URL:                sc.URL,
			Channel:            sc.Channel,
			Username:           sc.Username,
			IconEmoji:          sc.IconEmoji,
			Timeout:            timeout,
			InsecureSkipVerify: sc.InsecureSkipVerify,
		})
	default:
		return nil, fmt.Errorf("notify: sink %q has unknown kind %q", sc.Name, sc.Kind)
	}
}
