package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Sink is a delivery destination for notifications. Implementations must be safe
// for concurrent use. Deliver returns nil on success and a non-nil error on
// failure; a *DeliveryError signals whether the failure is worth retrying.
type Sink interface {
	// Name is the operator-assigned identifier (unique within a Notifier),
	// used in routing, metrics labels, and the test endpoint.
	Name() string
	// Kind is the sink implementation type ("webhook" or "slack").
	Kind() string
	// Deliver sends one event, blocking until the destination responds, ctx is
	// canceled, or the request fails.
	Deliver(ctx context.Context, ev Event) error
}

// DeliveryError describes a failed delivery and whether a retry is warranted. A
// transient condition (network error, 429, or 5xx) is retryable; a 4xx other
// than 429 is a permanent misconfiguration that retrying cannot fix.
type DeliveryError struct {
	Sink      string
	Status    int // HTTP status, or 0 for a transport-level failure
	Retryable bool
	Err       error
}

func (e *DeliveryError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("notify: sink %q delivery failed: status %d", e.Sink, e.Status)
	}
	return fmt.Sprintf("notify: sink %q delivery failed: %v", e.Sink, e.Err)
}

func (e *DeliveryError) Unwrap() error { return e.Err }

// isRetryable reports whether err is a retryable delivery failure. A non
// *DeliveryError (e.g. a context cancellation or marshaling bug) is treated as
// non-retryable so it surfaces immediately rather than looping.
func isRetryable(err error) bool {
	var de *DeliveryError
	if errors.As(err, &de) {
		return de.Retryable
	}
	return false
}

// httpDoer is the HTTP client surface the sinks use, so tests can inject a
// custom transport (the httptest server uses the default client).
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// newHTTPClient builds the outbound client shared by the HTTP-based sinks. The
// timeout bounds a single delivery attempt; retries are handled by the Notifier.
func newHTTPClient(timeout time.Duration, insecureSkipVerify bool) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: timeout,
	}
	if insecureSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

// postJSON delivers a JSON body to url with the given headers and classifies the
// outcome into a (possibly retryable) DeliveryError. The response body is drained
// and bounded so a chatty endpoint cannot exhaust memory.
func postJSON(ctx context.Context, client httpDoer, sink, url string, headers map[string]string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		// A malformed URL is a permanent configuration error.
		return &DeliveryError{Sink: sink, Retryable: false, Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		// Transport failures (DNS, connection refused, timeout) are transient.
		return &DeliveryError{Sink: sink, Retryable: true, Err: err}
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the connection can be reused, and so a useful
	// snippet is available for diagnostics on failure.
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
	return &DeliveryError{
		Sink:      sink,
		Status:    resp.StatusCode,
		Retryable: retryable,
		Err:       fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet))),
	}
}

// --- generic webhook sink ---------------------------------------------------

// WebhookSink posts the event as a stable JSON document to an arbitrary HTTP
// endpoint. The schema is the webhookPayload below; downstream consumers
// (SIEMs, automation) parse it directly. Custom headers carry an auth token or
// signing secret when the endpoint requires one.
type WebhookSink struct {
	name    string
	url     string
	headers map[string]string
	client  httpDoer
}

// WebhookOptions configures a WebhookSink.
type WebhookOptions struct {
	Name               string
	URL                string
	Headers            map[string]string
	Timeout            time.Duration
	InsecureSkipVerify bool
	// Client overrides the HTTP client (tests inject one); nil builds a default.
	Client httpDoer
}

// NewWebhookSink constructs a generic HTTP webhook sink.
func NewWebhookSink(opts WebhookOptions) (*WebhookSink, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, fmt.Errorf("notify: webhook sink requires a name")
	}
	if strings.TrimSpace(opts.URL) == "" {
		return nil, fmt.Errorf("notify: webhook sink %q requires a url", opts.Name)
	}
	client := opts.Client
	if client == nil {
		client = newHTTPClient(opts.Timeout, opts.InsecureSkipVerify)
	}
	// Copy headers so later config mutation cannot affect a constructed sink.
	var headers map[string]string
	if len(opts.Headers) > 0 {
		headers = make(map[string]string, len(opts.Headers))
		for k, v := range opts.Headers {
			headers[k] = v
		}
	}
	return &WebhookSink{name: opts.Name, url: opts.URL, headers: headers, client: client}, nil
}

func (s *WebhookSink) Name() string { return s.name }
func (s *WebhookSink) Kind() string { return "webhook" }

// webhookPayload is the JSON document a WebhookSink posts. It is a flattened,
// self-describing view of an Event so consumers need no knowledge of this
// package's Go types.
type webhookPayload struct {
	Type      string            `json:"type"`
	Severity  string            `json:"severity"`
	Title     string            `json:"title"`
	Summary   string            `json:"summary,omitempty"`
	Timestamp string            `json:"timestamp"`
	Ecosystem string            `json:"ecosystem,omitempty"`
	Backend   string            `json:"backend,omitempty"`
	Artifact  string            `json:"artifact,omitempty"`
	Subject   string            `json:"subject,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
	Source    string            `json:"source"`
}

func (s *WebhookSink) Deliver(ctx context.Context, ev Event) error {
	payload := webhookPayload{
		Type:      string(ev.Type),
		Severity:  string(ev.Severity),
		Title:     ev.Title,
		Summary:   ev.Summary,
		Timestamp: ev.Time.UTC().Format(time.RFC3339),
		Ecosystem: ev.Ecosystem,
		Backend:   ev.Backend,
		Artifact:  ev.Artifact,
		Subject:   ev.Subject,
		Fields:    ev.Fields,
		Source:    "pullthrough-security",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return &DeliveryError{Sink: s.name, Retryable: false, Err: err}
	}
	return postJSON(ctx, s.client, s.name, s.url, s.headers, body)
}

// --- Slack incoming-webhook sink --------------------------------------------

// SlackSink posts to a Slack incoming webhook URL, rendering the event as a
// message with a severity-colored attachment and the structured fields as Slack
// attachment fields.
type SlackSink struct {
	name     string
	url      string
	channel  string // optional display override
	username string
	emoji    string
	client   httpDoer
}

// SlackOptions configures a SlackSink.
type SlackOptions struct {
	Name               string
	URL                string
	Channel            string // optional "#channel" override
	Username           string // optional bot display name
	IconEmoji          string // optional ":emoji:" override
	Timeout            time.Duration
	InsecureSkipVerify bool
	Client             httpDoer
}

// NewSlackSink constructs a Slack incoming-webhook sink.
func NewSlackSink(opts SlackOptions) (*SlackSink, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, fmt.Errorf("notify: slack sink requires a name")
	}
	if strings.TrimSpace(opts.URL) == "" {
		return nil, fmt.Errorf("notify: slack sink %q requires a url", opts.Name)
	}
	client := opts.Client
	if client == nil {
		client = newHTTPClient(opts.Timeout, opts.InsecureSkipVerify)
	}
	return &SlackSink{
		name:     opts.Name,
		url:      opts.URL,
		channel:  opts.Channel,
		username: opts.Username,
		emoji:    opts.IconEmoji,
		client:   client,
	}, nil
}

func (s *SlackSink) Name() string { return s.name }
func (s *SlackSink) Kind() string { return "slack" }

// slackMessage and slackAttachment model the subset of the Slack incoming-webhook
// payload the sink uses.
type slackMessage struct {
	Channel     string            `json:"channel,omitempty"`
	Username    string            `json:"username,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	Text        string            `json:"text"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

type slackAttachment struct {
	Color    string       `json:"color,omitempty"`
	Title    string       `json:"title,omitempty"`
	Text     string       `json:"text,omitempty"`
	Fields   []slackField `json:"fields,omitempty"`
	Footer   string       `json:"footer,omitempty"`
	TS       int64        `json:"ts,omitempty"`
	MrkdwnIn []string     `json:"mrkdwn_in,omitempty"`
}

type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// severityColor maps a severity to a Slack attachment color (hex or named).
func severityColor(sev Severity) string {
	switch NormalizeSeverity(string(sev)) {
	case SeverityCritical:
		return "#b80000" // dark red
	case SeverityHigh:
		return "danger" // red
	case SeverityMedium:
		return "warning" // amber
	case SeverityLow:
		return "#439fe0" // blue
	default:
		return "good" // green
	}
}

func (s *SlackSink) Deliver(ctx context.Context, ev Event) error {
	att := slackAttachment{
		Color:    severityColor(ev.Severity),
		Title:    ev.Title,
		Text:     ev.Summary,
		Footer:   "pullthrough-security",
		TS:       ev.Time.UTC().Unix(),
		MrkdwnIn: []string{"text"},
	}
	// Promote the most useful coordinate fields to short attachment fields, then
	// append the structured detail in a deterministic order.
	att.Fields = append(att.Fields, slackField{Title: "Type", Value: string(ev.Type), Short: true})
	att.Fields = append(att.Fields, slackField{Title: "Severity", Value: string(ev.Severity), Short: true})
	if ev.Ecosystem != "" {
		att.Fields = append(att.Fields, slackField{Title: "Ecosystem", Value: ev.Ecosystem, Short: true})
	}
	if ev.Artifact != "" {
		att.Fields = append(att.Fields, slackField{Title: "Artifact", Value: ev.Artifact, Short: true})
	}
	if ev.Subject != "" {
		att.Fields = append(att.Fields, slackField{Title: "Subject", Value: ev.Subject, Short: true})
	}
	for _, k := range ev.sortedFieldKeys() {
		att.Fields = append(att.Fields, slackField{Title: k, Value: ev.Fields[k], Short: true})
	}

	msg := slackMessage{
		Channel:     s.channel,
		Username:    s.username,
		IconEmoji:   s.emoji,
		Text:        fmt.Sprintf("*[%s]* %s", strings.ToUpper(string(ev.Severity)), ev.Title),
		Attachments: []slackAttachment{att},
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return &DeliveryError{Sink: s.name, Retryable: false, Err: err}
	}
	return postJSON(ctx, s.client, s.name, s.url, nil, body)
}
