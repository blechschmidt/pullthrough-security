package siem

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SyslogSink delivers events to a syslog collector over TCP, UDP, or TCP+TLS,
// rendering each event as an ArcSight Common Event Format (CEF) message with an
// RFC 5424-style syslog header. It holds a persistent connection, reconnecting
// lazily on first use and after any write error.
type SyslogSink struct {
	name     string
	network  string // "tcp" | "udp" | "tcp+tls"
	address  string
	facility int
	hostname string
	appName  string
	vendor   string
	product  string
	version  string
	timeout  time.Duration
	tlsCfg   *tls.Config

	// dial is overridable in tests to supply a pipe/loopback connection without a
	// real listener; nil uses the real network dialer.
	dial func(ctx context.Context) (net.Conn, error)

	mu   sync.Mutex
	conn net.Conn
}

// SyslogOptions configures a SyslogSink.
type SyslogOptions struct {
	Name string
	// Network is "tcp", "udp", or "tcp+tls". Defaults to "tcp".
	Network string
	// Address is the collector "host:port".
	Address string
	// Facility is the syslog facility number (0..23); defaults to 16 (local0).
	Facility int
	// Hostname is the syslog HOSTNAME field; defaults to the OS hostname.
	Hostname string
	// AppName is the syslog APP-NAME / CEF device product tag; defaults to
	// "pullthrough".
	AppName string
	// Vendor/Product/Version populate the CEF header prefix.
	Vendor  string
	Product string
	Version string
	Timeout time.Duration
	TLS     TLSConfig
	// Dial overrides the connection dialer (tests inject one).
	Dial func(ctx context.Context) (net.Conn, error)
}

// NewSyslogSink constructs a syslog/CEF sink.
func NewSyslogSink(opts SyslogOptions) (*SyslogSink, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, fmt.Errorf("siem: syslog sink requires a name")
	}
	network := opts.Network
	if network == "" {
		network = "tcp"
	}
	if !validSyslogNetwork(network) {
		return nil, fmt.Errorf("siem: syslog sink %q has invalid network %q (want tcp, udp, or tcp+tls)", opts.Name, network)
	}
	if opts.Dial == nil && strings.TrimSpace(opts.Address) == "" {
		return nil, fmt.Errorf("siem: syslog sink %q requires an address", opts.Name)
	}
	facility := opts.Facility
	if facility == 0 {
		facility = 16 // local0
	}
	if facility < 0 || facility > 23 {
		return nil, fmt.Errorf("siem: syslog sink %q facility %d out of range 0..23", opts.Name, facility)
	}
	hostname := opts.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
		if hostname == "" {
			hostname = "-"
		}
	}
	appName := opts.AppName
	if appName == "" {
		appName = "pullthrough"
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	s := &SyslogSink{
		name:     opts.Name,
		network:  network,
		address:  opts.Address,
		facility: facility,
		hostname: hostname,
		appName:  appName,
		vendor:   firstNonEmpty(opts.Vendor, "Blechschmidt"),
		product:  firstNonEmpty(opts.Product, "pullthrough-security"),
		version:  firstNonEmpty(opts.Version, "1"),
		timeout:  timeout,
		dial:     opts.Dial,
	}
	if network == "tcp+tls" && opts.Dial == nil {
		tlsCfg, err := opts.TLS.build()
		if err != nil {
			return nil, err
		}
		if tlsCfg.ServerName == "" {
			if host, _, herr := net.SplitHostPort(opts.Address); herr == nil {
				tlsCfg.ServerName = host
			}
		}
		s.tlsCfg = tlsCfg
	}
	return s, nil
}

func validSyslogNetwork(n string) bool {
	switch n {
	case "tcp", "udp", "tcp+tls":
		return true
	default:
		return false
	}
}

func (s *SyslogSink) Name() string { return s.name }
func (s *SyslogSink) Kind() string { return "syslog" }

// Close releases the persistent connection.
func (s *SyslogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

// DeliverBatch renders each event to a CEF syslog line and writes the batch over
// the persistent connection. A write error closes the connection (forcing a
// reconnect on the next attempt) and is reported as retryable so the forwarder
// re-queues the batch.
func (s *SyslogSink) DeliverBatch(ctx context.Context, batch []Event) error {
	if len(batch) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	conn, err := s.connLocked(ctx)
	if err != nil {
		return &DeliveryError{Sink: s.name, Retryable: true, Err: err}
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	} else {
		_ = conn.SetWriteDeadline(time.Now().Add(s.timeout))
	}
	for _, ev := range batch {
		msg := s.render(ev)
		if _, werr := conn.Write([]byte(msg)); werr != nil {
			_ = conn.Close()
			s.conn = nil
			return &DeliveryError{Sink: s.name, Retryable: true, Err: werr}
		}
	}
	return nil
}

// connLocked returns the live connection, dialing one if necessary. The caller
// must hold s.mu.
func (s *SyslogSink) connLocked(ctx context.Context) (net.Conn, error) {
	if s.conn != nil {
		return s.conn, nil
	}
	var (
		conn net.Conn
		err  error
	)
	switch {
	case s.dial != nil:
		conn, err = s.dial(ctx)
	case s.network == "udp":
		d := net.Dialer{Timeout: s.timeout}
		conn, err = d.DialContext(ctx, "udp", s.address)
	case s.network == "tcp+tls":
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: s.timeout}, Config: s.tlsCfg}
		conn, err = d.DialContext(ctx, "tcp", s.address)
	default: // tcp
		d := net.Dialer{Timeout: s.timeout}
		conn, err = d.DialContext(ctx, "tcp", s.address)
	}
	if err != nil {
		return nil, err
	}
	s.conn = conn
	return conn, nil
}

// render formats an event as a CEF message prefixed with an RFC 5424 syslog
// header and terminated with a newline (the framing TCP syslog collectors
// expect; harmless for UDP datagrams).
func (s *SyslogSink) render(ev Event) string {
	pri := s.facility*8 + syslogSeverity(ev.Severity)
	ts := ev.Time.UTC().Format(time.RFC3339)
	var b strings.Builder
	b.WriteByte('<')
	b.WriteString(strconv.Itoa(pri))
	b.WriteString(">1 ") // RFC 5424 version
	b.WriteString(ts)
	b.WriteByte(' ')
	b.WriteString(s.hostname)
	b.WriteByte(' ')
	b.WriteString(s.appName)
	b.WriteString(" - - - ") // PROCID MSGID STRUCTURED-DATA all nil
	b.WriteString(s.renderCEF(ev))
	b.WriteByte('\n')
	return b.String()
}

// renderCEF builds the CEF:0 message body.
func (s *SyslogSink) renderCEF(ev Event) string {
	var b strings.Builder
	b.WriteString("CEF:0|")
	b.WriteString(cefEscapeHeader(s.vendor))
	b.WriteByte('|')
	b.WriteString(cefEscapeHeader(s.product))
	b.WriteByte('|')
	b.WriteString(cefEscapeHeader(s.version))
	b.WriteByte('|')
	b.WriteString(cefEscapeHeader(signatureID(ev)))
	b.WriteByte('|')
	b.WriteString(cefEscapeHeader(nonEmpty(ev.Name, ev.Category)))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(ev.Severity.cefSeverity()))
	b.WriteByte('|')
	b.WriteString(cefExtensions(ev))
	return b.String()
}

// signatureID is the CEF device-event-class id: a stable per-event-type key.
func signatureID(ev Event) string {
	if ev.Category != "" {
		return string(ev.Source) + ":" + ev.Category
	}
	return string(ev.Source)
}

// cefExtensions renders the event's fields plus a few standard CEF keys as the
// extension segment ("k=v k2=v2 ...") in deterministic order.
func cefExtensions(ev Event) string {
	var parts []string
	add := func(k, v string) {
		if v == "" {
			return
		}
		parts = append(parts, k+"="+cefEscapeValue(v))
	}
	add("ptsSource", string(ev.Source))
	add("cat", ev.Category)
	add("outcome", ev.Outcome)
	add("suser", ev.Subject)
	add("rt", strconv.FormatInt(ev.Time.UTC().UnixMilli(), 10))
	add("msg", ev.Message)
	for _, k := range ev.sortedFieldKeys() {
		add("pts"+cefKey(k), ev.Fields[k])
	}
	return strings.Join(parts, " ")
}

// cefKey upper-cases the first letter of a field name so it reads as a camelCase
// CEF custom extension key (e.g. "ruleId" -> "ptsRuleId").
func cefKey(k string) string {
	if k == "" {
		return k
	}
	return strings.ToUpper(k[:1]) + k[1:]
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// cefEscapeHeader escapes the CEF header-field reserved characters: backslash
// and pipe.
func cefEscapeHeader(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `|`, `\|`)
	return r.Replace(s)
}

// cefEscapeValue escapes the CEF extension-value reserved characters: backslash,
// equals, and newlines.
func cefEscapeValue(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`, "\r", `\r`)
	return r.Replace(s)
}

// syslogSeverity maps the canonical severity onto an RFC 5424 syslog severity
// (0=emergency .. 7=debug).
func syslogSeverity(sev Severity) int {
	switch sev {
	case SeverityCritical:
		return 2 // critical
	case SeverityHigh:
		return 3 // error
	case SeverityMedium:
		return 4 // warning
	case SeverityLow:
		return 5 // notice
	default:
		return 6 // informational
	}
}
