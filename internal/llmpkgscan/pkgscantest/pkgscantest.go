// Package pkgscantest provides test doubles for the LLM package-content scan
// gate (internal/llmpkgscan): a deterministic, offline stand-in for a hosted
// model, and builders for the package archives it is shown.
//
// It lives outside _test.go files so the gate's own unit tests, the gateway's
// tests and the per-ecosystem integration suites can share one mock. It depends
// only on the provider abstraction (internal/scan/commit), never on the gate.
package pkgscantest

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

// MaliciousMarker is the plain alphanumeric sentinel the mock keys on: material
// that contains it is judged malicious, anything else benign. It is the same
// marker the commit-scan mocks use, and it is deliberately alphanumeric so no
// prompt-hardening step alters it — the mock decides on content that really
// reached the model.
const MaliciousMarker = "PTE2EMALICIOUSMARKER"

// BenignVerdict is the answer the mock gives for unremarkable material, in the
// exact shape the gate requires.
const BenignVerdict = `{"verdict": "benign", "confidence": 0.94, "reasons": ["No install-time execution, network access or obfuscation was found."], "evidence": []}`

// MaliciousVerdict renders the mock's malicious answer, citing where the marker
// was seen.
func MaliciousVerdict(path string, line int, excerpt string) string {
	out, _ := json.Marshal(map[string]any{
		"verdict":    "malicious",
		"confidence": 0.97,
		"reasons":    []string{"An install-time script downloads and executes a remote payload."},
		"evidence":   []map[string]any{{"path": path, "line": line, "excerpt": excerpt}},
	})
	return string(out)
}

// Provider is a deterministic commit.Provider (and commit.ToolProvider)
// standing in for Claude/Codex. The zero value is usable: it answers benign
// unless the material it was shown contains MaliciousMarker.
//
// Only the model's judgement is replaced. The gate's prompt construction, tool
// execution, output parsing and every bound run unmodified against it.
type Provider struct {
	// ProviderName is returned by Name ("mock-llm" when empty).
	ProviderName string
	// Judge, when set, replaces the default judgement. It receives everything the
	// model has been shown so far — the first prompt and every tool result — and
	// returns the model's final answer text verbatim (so a test can return
	// malformed output).
	Judge func(material string) string
	// Plan, when set, makes the mock use tools: it is called before each turn
	// with the 1-based turn number and the material so far, and returns the tool
	// calls to make on that turn. Returning none makes the mock answer.
	Plan func(turn int, material string) []commit.ToolCall
	// Delay is slept before every answer (honoring cancellation), to exercise
	// timeouts.
	Delay time.Duration
	// Err, when set, is returned from every call.
	Err error
	// Usage is reported for every completion (128/48 tokens when zero).
	Usage commit.Usage

	mu            sync.Mutex
	completions   int
	toolTurns     int
	requests      []commit.Request
	toolRequests  []commit.ToolRequest
	lastMaterial  string
	maliciousSeen int
}

var _ commit.ToolProvider = (*Provider)(nil)

// Name implements commit.Provider.
func (p *Provider) Name() string {
	if p.ProviderName == "" {
		return "mock-llm"
	}
	return p.ProviderName
}

// BundleOnly returns a view of the provider that implements only
// commit.Provider — a model without tool use — sharing this provider's
// behaviour and counters.
func (p *Provider) BundleOnly() commit.Provider { return bundleOnly{p} }

type bundleOnly struct{ p *Provider }

func (b bundleOnly) Name() string { return b.p.Name() }
func (b bundleOnly) Complete(ctx context.Context, req commit.Request) (string, commit.Usage, error) {
	return b.p.Complete(ctx, req)
}

func (p *Provider) usage() commit.Usage {
	if p.Usage == (commit.Usage{}) {
		return commit.Usage{InputTokens: 128, OutputTokens: 48}
	}
	return p.Usage
}

func (p *Provider) wait(ctx context.Context) error {
	if p.Delay <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(p.Delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Complete implements commit.Provider: one prompt in, one answer out.
func (p *Provider) Complete(ctx context.Context, req commit.Request) (string, commit.Usage, error) {
	p.mu.Lock()
	p.completions++
	p.requests = append(p.requests, req)
	p.lastMaterial = req.User
	p.mu.Unlock()
	if err := p.wait(ctx); err != nil {
		return "", commit.Usage{}, err
	}
	if p.Err != nil {
		return "", commit.Usage{}, p.Err
	}
	return p.answer(req.User), p.usage(), nil
}

// CompleteTools implements commit.ToolProvider.
func (p *Provider) CompleteTools(ctx context.Context, req commit.ToolRequest) (commit.ToolResponse, commit.Usage, error) {
	material := Material(req.Messages)
	p.mu.Lock()
	p.completions++
	p.toolTurns++
	turn := p.turnOf(req.Messages)
	p.toolRequests = append(p.toolRequests, req)
	p.lastMaterial = material
	p.mu.Unlock()
	if err := p.wait(ctx); err != nil {
		return commit.ToolResponse{}, commit.Usage{}, err
	}
	if p.Err != nil {
		return commit.ToolResponse{}, commit.Usage{}, p.Err
	}
	if p.Plan != nil && !req.NoTools {
		if calls := p.Plan(turn, material); len(calls) > 0 {
			return commit.ToolResponse{ToolCalls: calls, Stop: commit.ToolStopToolUse}, p.usage(), nil
		}
	}
	return commit.ToolResponse{Text: p.answer(material), Stop: commit.ToolStopEnd}, p.usage(), nil
}

// turnOf is the 1-based model turn a request is asking for: one more than the
// number of assistant turns already in the history.
func (p *Provider) turnOf(msgs []commit.ToolMessage) int {
	n := 1
	for _, m := range msgs {
		if m.Role == commit.ToolRoleAssistant {
			n++
		}
	}
	return n
}

func (p *Provider) answer(material string) string {
	if p.Judge != nil {
		return p.Judge(material)
	}
	if strings.Contains(material, MaliciousMarker) {
		p.mu.Lock()
		p.maliciousSeen++
		p.mu.Unlock()
		path, line, excerpt := Locate(material, MaliciousMarker)
		return MaliciousVerdict(path, line, excerpt)
	}
	return BenignVerdict
}

// Material flattens a tool conversation into the text the model was shown: the
// user turns and the tool results, in order.
func Material(msgs []commit.ToolMessage) string {
	var b strings.Builder
	for _, m := range msgs {
		if m.Role != commit.ToolRoleUser {
			continue
		}
		for _, r := range m.ToolResults {
			b.WriteString(r.Content)
			b.WriteByte('\n')
		}
		b.WriteString(m.Text)
		b.WriteByte('\n')
	}
	return b.String()
}

var (
	fileHeader = regexp.MustCompile(`(?m)^--- FILE: (.+?) \(\d+ bytes, \d+ lines\)`)
	readHeader = regexp.MustCompile(`(?m)^\((.+?) — \d+ bytes, \d+ lines\)$`)
	gutter     = regexp.MustCompile(`^\s*(\d+)\| (.*)$`)
	grepLine   = regexp.MustCompile(`^(.+?):(\d+): (.*)$`)
)

// Locate finds where needle appears in prompt material and reports the file,
// line and text it appears in, the way a model would cite it. It understands
// the gate's three renderings: a file shown in the first prompt, a read_file
// result, and a grep result line.
func Locate(material, needle string) (path string, line int, excerpt string) {
	idx := strings.Index(material, needle)
	if idx < 0 {
		return "", 0, ""
	}
	start := strings.LastIndexByte(material[:idx], '\n') + 1
	end := strings.IndexByte(material[idx:], '\n')
	if end < 0 {
		end = len(material) - idx
	}
	text := material[start : idx+end]

	if m := gutter.FindStringSubmatch(text); m != nil {
		line, _ = strconv.Atoi(m[1])
		excerpt = strings.TrimSpace(m[2])
		before := material[:start]
		last := func(re *regexp.Regexp) (string, int) {
			all := re.FindAllStringSubmatchIndex(before, -1)
			if len(all) == 0 {
				return "", -1
			}
			m := all[len(all)-1]
			return before[m[2]:m[3]], m[0]
		}
		fp, fi := last(fileHeader)
		rp, ri := last(readHeader)
		if ri > fi {
			return rp, line, excerpt
		}
		return fp, line, excerpt
	}
	if m := grepLine.FindStringSubmatch(text); m != nil {
		line, _ = strconv.Atoi(m[2])
		return m[1], line, strings.TrimSpace(m[3])
	}
	return "", 0, strings.TrimSpace(text)
}

// Calls returns the number of completions served (both kinds).
func (p *Provider) Calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.completions
}

// ToolTurns returns the number of tool-conversation completions served.
func (p *Provider) ToolTurns() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.toolTurns
}

// Requests returns the single-shot requests received.
func (p *Provider) Requests() []commit.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]commit.Request(nil), p.requests...)
}

// ToolRequests returns the tool-conversation requests received.
func (p *Provider) ToolRequests() []commit.ToolRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]commit.ToolRequest(nil), p.toolRequests...)
}

// LastMaterial returns what the model was shown on the most recent completion.
func (p *Provider) LastMaterial() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastMaterial
}

// Call builds a tool call with JSON arguments.
func Call(id, name string, args map[string]any) commit.ToolCall {
	raw, _ := json.Marshal(args)
	return commit.ToolCall{ID: id, Name: name, Input: raw}
}

// --- archive builders -------------------------------------------------------

func sortedNames(files map[string]string) []string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// TarGz builds a gzip-compressed tar holding files (path -> content), in path
// order so the result is deterministic.
func TarGz(files map[string]string) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, name := range sortedNames(files) {
		data := files[name]
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg})
		_, _ = io.WriteString(tw, data)
	}
	_ = tw.Close()
	_ = gw.Close()
	return buf.Bytes()
}

// Zip builds a zip archive holding files, in path order.
func Zip(files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range sortedNames(files) {
		w, _ := zw.Create(name)
		_, _ = io.WriteString(w, files[name])
	}
	_ = zw.Close()
	return buf.Bytes()
}

// NpmTarball builds an npm-style tarball: package/package.json carrying the
// given lifecycle scripts, plus extra files (paths relative to "package/").
func NpmTarball(name, version string, scripts map[string]string, extra map[string]string) []byte {
	manifest, _ := json.MarshalIndent(map[string]any{
		"name": name, "version": version, "main": "index.js", "scripts": scripts,
	}, "", "  ")
	files := map[string]string{"package/package.json": string(manifest) + "\n"}
	for p, c := range extra {
		files["package/"+p] = c
	}
	return TarGz(files)
}

// Digest returns an artifact's content digest in the cache's form,
// "sha256:<hex>".
func Digest(artifact []byte) string {
	sum := sha256.Sum256(artifact)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Opener returns an artifact stream factory over b, counting how often it is
// opened.
func Opener(b []byte, opens *int) func(context.Context) (io.ReadCloser, error) {
	var mu sync.Mutex
	return func(context.Context) (io.ReadCloser, error) {
		if opens != nil {
			mu.Lock()
			*opens++
			mu.Unlock()
		}
		return io.NopCloser(bytes.NewReader(b)), nil
	}
}
