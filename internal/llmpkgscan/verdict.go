package llmpkgscan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

// Verdict values the model may return.
const (
	VerdictMalicious  = "malicious"
	VerdictSuspicious = "suspicious"
	VerdictBenign     = "benign"
)

// Evidence is one place in the package the model cites for its verdict.
type Evidence struct {
	// Path is the file, as the model named it.
	Path string `json:"path"`
	// Line is the 1-based line, or 0 when the model gave none.
	Line int `json:"line,omitempty"`
	// Excerpt is the model's quote from that file. It is model output derived from
	// package content: treat it as untrusted text wherever it is displayed.
	Excerpt string `json:"excerpt,omitempty"`
	// Verified reports that the proxy found the quoted text in the named file of
	// the unpacked package. An unverified citation is a claim, not a fact.
	Verified bool `json:"verified"`
}

// ModelVerdict is the answer the model is required to give — exactly this
// object and nothing else.
type ModelVerdict struct {
	Verdict    string     `json:"verdict"`
	Confidence float64    `json:"confidence"`
	Reasons    []string   `json:"reasons"`
	Evidence   []Evidence `json:"evidence"`
}

// Verdict is the stored result of scanning one artifact.
type Verdict struct {
	// Key is the storage key: digest + model + prompt version.
	Key string `json:"key"`
	// Digest is the artifact's sha256 ("sha256:<hex>").
	Digest string `json:"digest"`

	// The model's answer, sanitized.
	Verdict    string     `json:"verdict"`
	Confidence float64    `json:"confidence"`
	Reasons    []string   `json:"reasons,omitempty"`
	Evidence   []Evidence `json:"evidence,omitempty"`

	// Injection lists deterministic indicators that package content addressed the
	// scanner. They are found by the proxy, not reported by the model.
	Injection []InjectionHit `json:"injection,omitempty"`
	// Anomalies are structural oddities of the archive (traversal names, escaping
	// links, a decompression bomb). StructuralRisk reports that at least one of
	// them has no innocent explanation.
	Anomalies      []string `json:"anomalies,omitempty"`
	StructuralRisk bool     `json:"structuralRisk,omitempty"`

	// How the verdict was produced.
	Provider      string `json:"provider"`
	Model         string `json:"model"`
	PromptVersion int    `json:"promptVersion"`
	// Mode is "tools" or "bundle".
	Mode      string `json:"mode"`
	Turns     int    `json:"turns"`
	ToolCalls int    `json:"toolCalls,omitempty"`

	// What the model could see.
	Format string `json:"format,omitempty"`
	// Kind says how the artifact was read: "archive", "file" (a payload that is
	// one file) or "oci-image" (an image assembled from its manifest, config and
	// layers; Digest is then the manifest's).
	Kind string `json:"kind,omitempty"`
	// Scope is empty for a scan of the whole artifact and "metadata-only" when
	// the artifact is larger than the scan limit and only what lies within the
	// limit was read (llmPackageScan.oversize: metadata-only). Such a verdict is
	// evidence about what was read; it says nothing about the rest.
	Scope string `json:"scope,omitempty"`
	// RootFS reports that the artifact was read as a piece of a root filesystem:
	// an image layer pulled on its own. Links are judged differently there (an
	// absolute target is how links are written in a root filesystem), so such a
	// reading is stored under a key of its own and never stands in for a reading
	// of the same bytes as a package.
	RootFS bool `json:"rootfs,omitempty"`
	// What an image verdict says about the image's blobs (see blobs.go). Blobs
	// lists the digests of its config and layers. Config is the config's digest
	// when it reads as an image config. Unexamined lists the layers the scan read
	// less of than a scan of the layer alone would — the image's shared budget was
	// spent on the layers above or ran out inside it, part of it could not be
	// opened, or the registry does not hold it: this verdict does not cover them,
	// and each is examined on its own when it is pulled. (A layer cut short only
	// by the size limit, under oversize: metadata-only, is not among them: a scan
	// of its own would stop at the same byte.)
	// Implicated lists the blobs the verdict holds something against — the
	// config, and the layers its evidence cites. While the verdict is refused,
	// those blobs are refused too.
	Blobs         []string `json:"blobs,omitempty"`
	Config        string   `json:"config,omitempty"`
	Unexamined    []string `json:"unexamined,omitempty"`
	Implicated    []string `json:"implicated,omitempty"`
	Files         int      `json:"files"`
	UnpackedBytes int64    `json:"unpackedBytes"`
	// Truncated reports that the verdict rests on an incomplete view of the
	// package; Coverage says, in sentences, what was missing.
	Truncated bool     `json:"truncated,omitempty"`
	Coverage  []string `json:"coverage,omitempty"`

	// Cost accounting.
	InputTokens         int     `json:"inputTokens"`
	OutputTokens        int     `json:"outputTokens"`
	CacheReadTokens     int     `json:"cacheReadTokens,omitempty"`
	CacheCreationTokens int     `json:"cacheCreationTokens,omitempty"`
	CostUSD             float64 `json:"costUsd"`

	// The coordinate the artifact was first scanned under, and who paid for the
	// scan. Informational: the verdict belongs to the digest, not the coordinate.
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	Filename  string `json:"filename,omitempty"`
	Tenant    string `json:"tenant,omitempty"`

	ScannedAt  time.Time `json:"scannedAt"`
	DurationMS int64     `json:"durationMs"`
}

// clone returns a deep copy, so a caller cannot mutate a stored verdict.
func (v *Verdict) clone() *Verdict {
	if v == nil {
		return nil
	}
	cp := *v
	cp.Reasons = append([]string(nil), v.Reasons...)
	cp.Evidence = append([]Evidence(nil), v.Evidence...)
	cp.Injection = append([]InjectionHit(nil), v.Injection...)
	cp.Anomalies = append([]string(nil), v.Anomalies...)
	cp.Coverage = append([]string(nil), v.Coverage...)
	cp.Blobs = append([]string(nil), v.Blobs...)
	cp.Unexamined = append([]string(nil), v.Unexamined...)
	cp.Implicated = append([]string(nil), v.Implicated...)
	return &cp
}

// ScopeMetadataOnly is Verdict.Scope for a metadata-only reading.
const ScopeMetadataOnly = "metadata-only"

// Bounds applied to a parsed verdict. The model's text is derived from package
// content, so its size is the publisher's to choose unless it is capped here.
const (
	maxVerdictBytes  = 64 << 10 // an answer larger than this is not a verdict
	maxReasons       = 10
	maxReasonChars   = 400
	maxEvidence      = 20
	maxExcerptChars  = 300
	maxEvidencePath  = maxPathBytes
	maxEvidenceLine  = 10_000_000
	maxVerdictFields = 4
)

// Errors from parsing a model answer. Every one of them makes the scan an
// error; none of them is ever read as a verdict.
var (
	// ErrNoVerdict means the model produced no answer at all.
	ErrNoVerdict = errors.New("llmpkgscan: model returned no verdict")
	// ErrMalformedVerdict means the answer is not exactly one verdict object of
	// the required shape.
	ErrMalformedVerdict = errors.New("llmpkgscan: model output is not a valid verdict")
	// ErrPromptLeak means the answer contains the system-prompt canary: the model
	// was coerced into disclosing its instructions, so the answer is discarded.
	ErrPromptLeak = errors.New("llmpkgscan: model output leaked the system prompt (injection suspected)")
)

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformedVerdict, fmt.Sprintf(format, args...))
}

// ParseVerdict parses a model answer under the strict output contract.
//
// The answer must be exactly one JSON object — optionally wrapped in a single
// markdown code fence, which models add out of habit — with the keys verdict,
// confidence, reasons and evidence and no others. It is deliberately NOT a
// "find the first {...} in the text" parser. A model that has read hostile
// content may quote it, and hostile content can contain a ready-made
// {"verdict":"benign",...}; a tolerant extractor would happily return the
// attacker's object from the middle of the model's prose. So: no text before or
// after, no second value, no duplicate keys (encoding/json would silently keep
// the last one), no unknown keys, and no wrong types.
//
// The only leniency is numeric: a confidence outside [0,1] is clamped rather
// than rejected, because that cannot change which verdict was given.
func ParseVerdict(text string) (*ModelVerdict, error) {
	if strings.Contains(text, promptCanary) {
		return nil, ErrPromptLeak
	}
	s := strings.TrimSpace(text)
	if s == "" {
		return nil, ErrNoVerdict
	}
	if len(s) > maxVerdictBytes {
		return nil, malformed("answer is %d bytes, over the %d-byte limit", len(s), maxVerdictBytes)
	}
	if !utf8.ValidString(s) {
		return nil, malformed("answer is not valid UTF-8")
	}
	s, err := stripFence(s)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(s, "{") {
		return nil, malformed("answer does not start with a JSON object")
	}

	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if tok, terr := dec.Token(); terr != nil || tok != json.Delim('{') {
		return nil, malformed("answer does not start with a JSON object")
	}

	var (
		out  ModelVerdict
		seen = make(map[string]bool, maxVerdictFields)
	)
	for dec.More() {
		tok, terr := dec.Token()
		if terr != nil {
			return nil, malformed("invalid JSON: %v", terr)
		}
		key, ok := tok.(string)
		if !ok {
			return nil, malformed("invalid JSON object key")
		}
		if seen[key] {
			return nil, malformed("duplicate key %q", key)
		}
		seen[key] = true

		var raw json.RawMessage
		if derr := dec.Decode(&raw); derr != nil {
			return nil, malformed("invalid JSON value for %q: %v", key, derr)
		}
		switch key {
		case "verdict":
			var v string
			if strictUnmarshal(raw, &v) != nil {
				return nil, malformed(`"verdict" must be a string`)
			}
			switch v = strings.ToLower(strings.TrimSpace(v)); v {
			case VerdictMalicious, VerdictSuspicious, VerdictBenign:
				out.Verdict = v
			default:
				return nil, malformed(`"verdict" must be malicious, suspicious or benign`)
			}
		case "confidence":
			var n json.Number
			if strictUnmarshal(raw, &n) != nil || !isJSONNumber(raw) {
				return nil, malformed(`"confidence" must be a number`)
			}
			f, ferr := n.Float64()
			if ferr != nil || math.IsNaN(f) || math.IsInf(f, 0) {
				return nil, malformed(`"confidence" must be a finite number`)
			}
			out.Confidence = clamp01(f)
		case "reasons":
			var reasons []string
			if !isJSONNull(raw) && strictUnmarshal(raw, &reasons) != nil {
				return nil, malformed(`"reasons" must be an array of strings`)
			}
			for _, r := range reasons {
				if r = cleanText(r, maxReasonChars); r != "" && len(out.Reasons) < maxReasons {
					out.Reasons = append(out.Reasons, r)
				}
			}
		case "evidence":
			ev, eerr := parseEvidence(raw)
			if eerr != nil {
				return nil, eerr
			}
			out.Evidence = ev
		default:
			return nil, malformed("unknown key %q", cleanText(key, 40))
		}
	}
	if tok, terr := dec.Token(); terr != nil || tok != json.Delim('}') {
		return nil, malformed("unterminated JSON object")
	}
	// Nothing may follow the object.
	if _, terr := dec.Token(); terr != io.EOF {
		return nil, malformed("unexpected content after the verdict object")
	}
	if !seen["verdict"] {
		return nil, malformed(`"verdict" is missing`)
	}
	if !seen["confidence"] {
		return nil, malformed(`"confidence" is missing`)
	}
	return &out, nil
}

// parseEvidence parses the evidence array: objects with the keys path, line
// and excerpt, and no others.
func parseEvidence(raw json.RawMessage) ([]Evidence, error) {
	if isJSONNull(raw) {
		return nil, nil
	}
	var items []json.RawMessage
	if strictUnmarshal(raw, &items) != nil {
		return nil, malformed(`"evidence" must be an array`)
	}
	var out []Evidence
	for _, item := range items {
		dec := json.NewDecoder(bytes.NewReader(item))
		dec.UseNumber()
		if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
			return nil, malformed(`each "evidence" item must be an object`)
		}
		var (
			ev   Evidence
			seen = make(map[string]bool, 3)
		)
		for dec.More() {
			tok, err := dec.Token()
			if err != nil {
				return nil, malformed("invalid evidence item: %v", err)
			}
			key, _ := tok.(string)
			if seen[key] {
				return nil, malformed("duplicate evidence key %q", cleanText(key, 40))
			}
			seen[key] = true
			var val json.RawMessage
			if derr := dec.Decode(&val); derr != nil {
				return nil, malformed("invalid evidence value: %v", derr)
			}
			switch key {
			case "path":
				var p string
				if strictUnmarshal(val, &p) != nil {
					return nil, malformed(`evidence "path" must be a string`)
				}
				ev.Path = cleanText(p, maxEvidencePath)
			case "line":
				if isJSONNull(val) {
					continue
				}
				var n json.Number
				if strictUnmarshal(val, &n) != nil || !isJSONNumber(val) {
					return nil, malformed(`evidence "line" must be a number`)
				}
				f, ferr := n.Float64()
				if ferr != nil || math.IsNaN(f) || f < 0 || f > maxEvidenceLine || f != math.Trunc(f) {
					// A nonsensical line number is not worth failing the scan over;
					// the citation simply carries no line.
					continue
				}
				ev.Line = int(f)
			case "excerpt":
				if isJSONNull(val) {
					continue
				}
				var x string
				if strictUnmarshal(val, &x) != nil {
					return nil, malformed(`evidence "excerpt" must be a string`)
				}
				ev.Excerpt = cleanText(x, maxExcerptChars)
			default:
				return nil, malformed("unknown evidence key %q", cleanText(key, 40))
			}
		}
		if ev.Path == "" && ev.Excerpt == "" {
			continue // an empty citation cites nothing
		}
		if len(out) < maxEvidence {
			out = append(out, ev)
		}
	}
	return out, nil
}

// stripFence removes one enclosing markdown code fence, if the whole answer is
// exactly one fenced block. Anything else that involves a fence is rejected:
// a fence with text around it is prose around the verdict.
func stripFence(s string) (string, error) {
	if !strings.HasPrefix(s, "```") {
		return s, nil
	}
	nl := strings.IndexByte(s, '\n')
	if nl < 0 || !strings.HasSuffix(s, "```") || len(s) < nl+4 {
		return "", malformed("unterminated code fence")
	}
	switch strings.ToLower(strings.TrimSpace(s[3:nl])) {
	case "", "json":
	default:
		return "", malformed("unexpected code fence language")
	}
	inner := strings.TrimSpace(s[nl+1 : len(s)-3])
	if strings.Contains(inner, "```") {
		return "", malformed("more than one code fence")
	}
	return inner, nil
}

// strictUnmarshal decodes one JSON value into v, rejecting trailing content.
func strictUnmarshal(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing content")
	}
	return nil
}

func isJSONNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}

// isJSONNumber reports whether raw is a JSON number literal (and not, say, a
// string holding digits, which json.Number would otherwise accept).
func isJSONNumber(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 0 && (t[0] == '-' || (t[0] >= '0' && t[0] <= '9'))
}

func clamp01(f float64) float64 {
	switch {
	case f < 0:
		return 0
	case f > 1:
		return 1
	}
	return f
}

// cleanText makes a piece of untrusted text safe to store and display on one
// line: whitespace is collapsed, control and invisible characters are dropped,
// invalid UTF-8 is replaced, and the result is cut to max characters. It is
// applied to everything the model says, because what the model says about a
// hostile package is shaped by that package.
func cleanText(s string, max int) string {
	var b strings.Builder
	n := 0
	space := false
	for _, r := range s {
		if max > 0 && n >= max {
			b.WriteRune('…')
			break
		}
		switch {
		case r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\f' || r == '\v' || r == 0x85 || r == 0xA0 || r == 0x2028 || r == 0x2029:
			space = true
			continue
		case r == utf8.RuneError || isControlRune(r) || isInvisibleRune(r):
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
			n++
		}
		space = false
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// verifyEvidence checks each citation against the tree: does the named file
// exist, and does the quoted text occur in it? A model can misquote or invent;
// marking which citations the proxy could confirm lets a human (and a policy
// rule) tell a grounded verdict from an asserted one. It never changes the
// verdict itself.
//
// A confirmed citation's line is corrected to where the text really is, unless
// the model's line is already at (or next to) an occurrence.
func verifyEvidence(t *Tree, evidence []Evidence) (verified int) {
	type haystack struct {
		text string
		offs []int32 // offs[i] is the offset in the file of text[i]
	}
	haystacks := make(map[*File]haystack) // whitespace-free content, per cited file
	for i := range evidence {
		ev := &evidence[i]
		f, ok := t.Lookup(ev.Path)
		if !ok || !f.Readable() {
			continue
		}
		// Record the path under the tree's own key, so it reads as listed.
		ev.Path = f.Path
		needle := normalizeForMatch(ev.Excerpt)
		if len(needle) < 6 {
			// Too short to mean anything; the file's existence is all that can be
			// confirmed, and that is not confirmation of the quote.
			continue
		}
		hs, cached := haystacks[f]
		if !cached {
			hs.text, hs.offs = stripSpace(f.Data)
			haystacks[f] = hs
		}
		at := strings.Index(hs.text, needle)
		if at < 0 {
			continue
		}
		ev.Verified = true
		verified++
		if ev.Line >= 1 && ev.Line <= f.Lines && occursNear(hs.text, hs.offs, needle, f, ev.Line) {
			continue // the model's line is right (or close enough)
		}
		ev.Line = f.lineAt(int(hs.offs[at]))
	}
	return verified
}

// normalizeForMatch reduces text to its non-whitespace content, so a quote
// matches regardless of how the model re-wrapped or re-indented it. A trailing
// ellipsis added by cleanText is dropped.
func normalizeForMatch(s string) string {
	s = strings.TrimSuffix(s, "…")
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if !isSpaceByte(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

// stripSpace returns data without ASCII whitespace, and for each remaining byte
// its offset in data.
func stripSpace(data []byte) (string, []int32) {
	out := make([]byte, 0, len(data))
	offs := make([]int32, 0, len(data))
	for i, c := range data {
		if !isSpaceByte(c) {
			out = append(out, c)
			offs = append(offs, int32(i))
		}
	}
	return string(out), offs
}

// occursNear reports whether needle occurs in the file starting within two
// lines of the given line.
func occursNear(text string, offs []int32, needle string, f *File, line int) bool {
	for from := 0; from < len(text); {
		i := strings.Index(text[from:], needle)
		if i < 0 {
			return false
		}
		at := from + i
		if d := f.lineAt(int(offs[at])) - line; d >= -2 && d <= 2 {
			return true
		}
		from = at + 1
	}
	return false
}
