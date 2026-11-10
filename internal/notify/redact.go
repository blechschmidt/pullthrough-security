package notify

import "strings"

// redactedPlaceholder replaces a sensitive value so the alert still records that
// a field was present without leaking its contents.
const redactedPlaceholder = "[REDACTED]"

// defaultSensitiveKeys are substrings (case-insensitive) of field keys whose
// values are scrubbed before an event leaves the process. Notifications are sent
// to third-party endpoints (Slack, arbitrary webhooks) that may log or index the
// payload, so leaking a credential here is as bad as logging it in cleartext.
var defaultSensitiveKeys = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"apikey",
	"api_key",
	"api-key",
	"authorization",
	"auth",
	"credential",
	"cookie",
	"session",
	"private",
	"signature",
	"bearer",
	"access_key",
	"accesskey",
}

// Redactor scrubs sensitive fields from an Event before delivery. It matches a
// field key against a set of case-insensitive substrings; a match replaces the
// value with a placeholder. The default set covers the common credential field
// names, and operators can extend it for domain-specific keys.
type Redactor struct {
	patterns []string // lowercased substrings
}

// NewRedactor builds a Redactor from the default sensitive-key set plus any
// extra operator-supplied substrings. Extra entries are lowercased and trimmed;
// blanks are ignored.
func NewRedactor(extra []string) *Redactor {
	patterns := make([]string, 0, len(defaultSensitiveKeys)+len(extra))
	patterns = append(patterns, defaultSensitiveKeys...)
	for _, e := range extra {
		e = strings.ToLower(strings.TrimSpace(e))
		if e != "" {
			patterns = append(patterns, e)
		}
	}
	return &Redactor{patterns: patterns}
}

// isSensitive reports whether a field key matches any configured pattern.
func (r *Redactor) isSensitive(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if k == "" {
		return false
	}
	for _, p := range r.patterns {
		if strings.Contains(k, p) {
			return true
		}
	}
	return false
}

// Apply returns a copy of ev with sensitive field values replaced by the
// redaction placeholder. The original event is not mutated, so the same Event
// value can be safely fanned out to multiple sinks. A nil Redactor returns ev
// unchanged (redaction disabled).
func (r *Redactor) Apply(ev Event) Event {
	if r == nil || len(ev.Fields) == 0 {
		return ev
	}
	// Copy the map so concurrent deliveries (and the caller) never observe a
	// mutated set of fields.
	out := make(map[string]string, len(ev.Fields))
	for k, v := range ev.Fields {
		if r.isSensitive(k) {
			out[k] = redactedPlaceholder
		} else {
			out[k] = v
		}
	}
	ev.Fields = out
	return ev
}
