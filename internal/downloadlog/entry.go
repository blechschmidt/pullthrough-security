package downloadlog

import (
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/blechschmidt/pullthrough-security/internal/clientip"
)

// Outcome is what became of a download request.
type Outcome string

const (
	// OutcomeServed: the artifact's bytes were sent to the client (200, or 206
	// for a byte range).
	OutcomeServed Outcome = "served"
	// OutcomeNotModified: the client revalidated a copy it already holds (304);
	// nothing was transferred.
	OutcomeNotModified Outcome = "not_modified"
	// OutcomeBlocked: an admission gate refused the request. Entry.Gate names
	// the gate, Entry.Code and Entry.Reason carry its explanation.
	OutcomeBlocked Outcome = "blocked"
	// OutcomeNotFound: the upstream does not have the artifact (404 / 410).
	OutcomeNotFound Outcome = "not_found"
	// OutcomeError: the request failed for any other reason — an upstream
	// error, a proxy error, a request the upstream rejected.
	OutcomeError Outcome = "error"
)

// Outcomes lists every outcome, in the order they are reported.
func Outcomes() []Outcome {
	return []Outcome{OutcomeServed, OutcomeNotModified, OutcomeBlocked, OutcomeNotFound, OutcomeError}
}

// valid reports whether o is a known outcome.
func (o Outcome) valid() bool {
	for _, k := range Outcomes() {
		if o == k {
			return true
		}
	}
	return false
}

// Classify derives the outcome of a request from its response status and from
// whether an admission gate refused it. A gate's refusal wins over the status:
// gates answer with different codes (403, 429, 451) and an upstream can answer
// 403 on its own, so the status alone cannot tell the two apart.
func Classify(status int, blocked bool) Outcome {
	switch {
	case blocked:
		return OutcomeBlocked
	case status == http.StatusNotModified:
		return OutcomeNotModified
	case status >= 200 && status < 300:
		return OutcomeServed
	case status == http.StatusNotFound || status == http.StatusGone:
		return OutcomeNotFound
	default:
		return OutcomeError
	}
}

// Kind says what sort of resource an entry is about.
type Kind string

const (
	// KindPackage is content a client installs, unpacks, builds or executes: a
	// package archive, an image manifest or layer, a module zip, a Git fetch.
	KindPackage Kind = "package"
	// KindMetadata is a document a client reads on the way to a package: an
	// index, a version list, a checksum. Recorded only on request
	// (Config.IncludeMetadata) — or when the request was refused.
	KindMetadata Kind = "metadata"
	// KindUnclassified is a resource the backend could not name. It may well be
	// a package served from a path the protocol adapter does not know, so it is
	// recorded.
	KindUnclassified Kind = "unclassified"
)

// Kinds lists every kind.
func Kinds() []Kind { return []Kind{KindPackage, KindMetadata, KindUnclassified} }

func (k Kind) valid() bool {
	for _, known := range Kinds() {
		if k == known {
			return true
		}
	}
	return false
}

// canonicalKind returns the package's constant for k, or KindUnclassified for a
// kind it does not know.
func canonicalKind(k Kind) Kind {
	switch k {
	case KindPackage:
		return KindPackage
	case KindMetadata:
		return KindMetadata
	default:
		return KindUnclassified
	}
}

// canonicalOutcome returns the package's constant for o. An outcome it does not
// know is derived from the response status instead.
func canonicalOutcome(o Outcome, status int) Outcome {
	switch o {
	case OutcomeServed:
		return OutcomeServed
	case OutcomeNotModified:
		return OutcomeNotModified
	case OutcomeBlocked:
		return OutcomeBlocked
	case OutcomeNotFound:
		return OutcomeNotFound
	case OutcomeError:
		return OutcomeError
	default:
		return Classify(status, false)
	}
}

// Entry is one recorded download: a request for a package, the address it came
// from, and what happened. Its JSON form is the admin API's wire format and the
// on-disk line format, so field names are part of the contract.
type Entry struct {
	// ID is the entry's sequence number. IDs increase in recording order, so
	// they order entries recorded within the same clock tick and serve as the
	// pagination cursor. A persistent log continues its sequence after a restart
	// for as long as its file holds an entry; one whose every entry has expired
	// starts again at 1. An ID identifies an entry among those the log holds,
	// not for all time.
	ID uint64 `json:"id"`
	// Time is when the request completed.
	Time time.Time `json:"time"`

	// ClientIP is the address the download is attributed to: the TCP peer, or —
	// when the peer is a configured trusted proxy — the client address that
	// proxy forwarded the request for.
	ClientIP string `json:"clientIp"`
	// ForwardedBy is the trusted proxy the connection actually came from. It is
	// set only when ClientIP was taken from that proxy's forwarding header.
	ForwardedBy string `json:"forwardedBy,omitempty"`

	// Ecosystem is the package ecosystem (cargo, go, npm, pip, docker, git, …).
	Ecosystem string `json:"ecosystem"`
	// Upstream is the name of the configured upstream that served the request.
	Upstream string `json:"upstream"`
	// Package and Version are the coordinate the request resolved to. Either
	// may be empty for a resource the protocol does not express as one.
	Package string `json:"package"`
	Version string `json:"version,omitempty"`
	// Artifact is the file name of what was requested (cfg-if-1.0.0.crate).
	Artifact string `json:"artifact,omitempty"`
	// Digest is the artifact's expected content digest, when the protocol
	// states one ("sha256:…").
	Digest string `json:"digest,omitempty"`
	// Kind tells a package from the metadata fetched around it.
	Kind Kind `json:"kind"`

	// Method and Path are the request as the proxy received it. The path
	// carries no query string: queries can hold credentials.
	Method string `json:"method"`
	Path   string `json:"path"`
	// Status is the HTTP status the proxy answered with.
	Status int `json:"status"`
	// Outcome classifies the result; see the Outcome constants.
	Outcome Outcome `json:"outcome"`
	// Gate, Code and Reason explain a blocked request: the admission gate that
	// refused it, its machine-readable reason code, and its explanation.
	Gate   string `json:"gate,omitempty"`
	Code   string `json:"code,omitempty"`
	Reason string `json:"reason,omitempty"`
	// Cache is how the artifact was obtained: HIT, MISS, COALESCED-HIT, or
	// BYPASS for a resource that is never cached.
	Cache string `json:"cache,omitempty"`
	// Bytes is how many bytes of the artifact were sent to the client; it is
	// zero unless the request was served (the body of a refusal is not package
	// content). Size is the artifact's full size when known; Bytes < Size means
	// a byte-range request or a transfer the client abandoned.
	Bytes int64 `json:"bytes"`
	Size  int64 `json:"size,omitempty"`
	// DurationMs is how long the proxy took to answer, including any upstream
	// fetch and every admission gate.
	DurationMs int64 `json:"durationMs"`

	// Subject, Tenant and AuthMethod identify the client: the user or the
	// workload behind the request, their team, and how they were identified —
	// "token", "oidc", "mtls", "ssh-key", or "personal-link" for a request that
	// came through a user's personal cache link (Task 177). They are empty for a
	// request nobody was identified for.
	Subject    string `json:"subject,omitempty"`
	Tenant     string `json:"tenant,omitempty"`
	AuthMethod string `json:"authMethod,omitempty"`
	// Link is the identifier of the personal cache link the request came
	// through. A user holds one link per machine or purpose; this says which.
	// It is the link's public identifier, never its token.
	Link string `json:"link,omitempty"`
	// Via says how the request reached the proxy when it was not sent to the
	// proxy's own address: "intercept" through the TLS-interception forward
	// proxy, "nat" through a NAT listener — the client addressed the upstream
	// host itself (Task 172). Empty for a request to the proxy's address.
	Via string `json:"via,omitempty"`
	// UserAgent is the client's User-Agent header: which tool, which version.
	UserAgent string `json:"userAgent,omitempty"`
	// TraceID correlates the entry with the request's distributed trace.
	TraceID string `json:"traceId,omitempty"`
}

// Coordinate renders the entry's package as "name@version" (or just the name).
func (e Entry) Coordinate() string {
	if e.Version == "" {
		return e.Package
	}
	return e.Package + "@" + e.Version
}

// Field length bounds. Everything in an entry except the address and the
// numbers is, directly or indirectly, chosen by the client or the upstream, so
// each field is capped: an entry has a bounded size however long a URL, a
// package name or a User-Agent header gets.
const (
	maxAddrLen      = 64
	maxNameLen      = 512
	maxVersionLen   = 256
	maxPathLen      = 1024
	maxShortLen     = 128
	maxReasonLen    = 512
	maxUserAgentLen = 256
)

// sanitize normalizes an entry before it is stored: fields are bounded and
// stripped of control characters, the address is canonicalized so that one host
// has one spelling, and unknown enum values fall back to a known one.
func (e *Entry) sanitize() {
	if canonical, ok := clientip.Canonical(e.ClientIP); ok {
		e.ClientIP = canonical
	} else {
		e.ClientIP = clean(e.ClientIP, maxAddrLen)
	}
	if e.ClientIP == "" {
		e.ClientIP = "unknown"
	}
	if canonical, ok := clientip.Canonical(e.ForwardedBy); ok {
		e.ForwardedBy = canonical
	} else {
		e.ForwardedBy = clean(e.ForwardedBy, maxAddrLen)
	}

	e.Ecosystem = clean(e.Ecosystem, maxShortLen)
	e.Upstream = clean(e.Upstream, maxShortLen)
	e.Package = clean(e.Package, maxNameLen)
	e.Version = clean(e.Version, maxVersionLen)
	e.Artifact = clean(e.Artifact, maxNameLen)
	e.Digest = clean(e.Digest, maxVersionLen)
	e.Method = clean(e.Method, 16)
	e.Path = clean(e.Path, maxPathLen)
	e.Gate = clean(e.Gate, maxShortLen)
	e.Code = clean(e.Code, maxShortLen)
	e.Reason = clean(e.Reason, maxReasonLen)
	e.Cache = clean(e.Cache, 32)
	e.Subject = clean(e.Subject, maxVersionLen)
	e.Tenant = clean(e.Tenant, maxVersionLen)
	e.AuthMethod = clean(e.AuthMethod, 32)
	e.Link = clean(e.Link, 64)
	e.UserAgent = clean(e.UserAgent, maxUserAgentLen)
	e.TraceID = clean(e.TraceID, 64)

	// The enums are stored as the package's own constants — never as the
	// caller's string, for the reason clean copies (see there).
	e.Kind = canonicalKind(e.Kind)
	e.Outcome = canonicalOutcome(e.Outcome, e.Status)
	e.Via = canonicalVia(e.Via)
	if e.Bytes < 0 {
		e.Bytes = 0
	}
	if e.Size < 0 {
		e.Size = 0
	}
	if e.DurationMs < 0 {
		e.DurationMs = 0
	}
	e.Time = e.Time.UTC()
}

// clean returns s without control characters or invalid UTF-8, trimmed, and cut
// to at most max bytes on a rune boundary. A cut value ends in "…" so a reader
// can tell it is not the whole string. The result never shares memory with s.
//
// Invisible format characters — bidirectional overrides, zero-width spaces and
// joiners — are written out ("\u{202E}") rather than kept or dropped. They
// change how a name is displayed without changing how it appears to be spelled,
// and this is a record people read to decide what was downloaded: a name must
// not be able to pass for another one, and one that tried must be recognizable.
func clean(s string, max int) string {
	if !needsCleaning(s, max) {
		// A copy, not a slice of s. What reaches the log is cut from a request:
		// the path is a substring of the request line, a package name a substring
		// of the path. Stored as it is, a twenty-byte name would keep the whole
		// request line it was cut from alive — a megabyte, if the client padded
		// its query string — for as long as the entry stays in the log.
		return strings.Clone(strings.TrimSpace(s))
	}

	var b strings.Builder
	b.Grow(min(len(s), max))
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			continue
		case r == '\t' || r == '\n' || r == '\r' || r == lineSeparator || r == paragraphSeparator:
			// Characters that break a line separate words; keep the separation.
			r = ' '
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			continue
		case unicode.Is(unicode.Cf, r):
			fmt.Fprintf(&b, "\\u{%04X}", r)
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if len(out) <= max {
		return out
	}
	const ellipsis = "…"
	cut := max - len(ellipsis)
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && !utf8.RuneStart(out[cut]) {
		cut--
	}
	return out[:cut] + ellipsis
}

// The Unicode line and paragraph separators: line breaks outside the ASCII
// control range.
const (
	lineSeparator      = '\u2028'
	paragraphSeparator = '\u2029'
)

// needsCleaning reports whether clean has anything to do to s besides trimming
// it. Nearly every string is plain ASCII of ordinary length, and those are
// decided by one pass over their bytes.
func needsCleaning(s string, max int) bool {
	if len(s) > max {
		return true
	}
	ascii := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			return true
		}
		if c >= utf8.RuneSelf {
			ascii = false
		}
	}
	if ascii {
		return false
	}
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if (r >= 0x80 && r < 0xa0) || r == lineSeparator || r == paragraphSeparator || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}

// The values of Entry.Via.
const (
	// ViaIntercept marks a request that came through the TLS-interception
	// forward proxy.
	ViaIntercept = "intercept"
	// ViaNAT marks a request that came through a NAT listener.
	ViaNAT = "nat"
)

// canonicalVia returns the package's constant for a Via value, or "" for
// anything else.
func canonicalVia(v string) string {
	switch v {
	case ViaIntercept:
		return ViaIntercept
	case ViaNAT:
		return ViaNAT
	default:
		return ""
	}
}
