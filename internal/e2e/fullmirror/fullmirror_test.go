//go:build integration
// +build integration

package fullmirror

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/e2e/pkgscan"
	fm "github.com/blechschmidt/pullthrough-security/internal/fullmirror"
)

// TestMain removes the proxy binary the suite built, if it built one.
func TestMain(m *testing.M) {
	code := m.Run()
	if proxyBinDir != "" {
		_ = os.RemoveAll(proxyBinDir)
	}
	os.Exit(code)
}

// followed returns the catalog's types a feed adapter follows — every one the
// configuration lets enable full mirroring — and the types nothing can follow.
func followed() (follow, refuse []fm.Entry) {
	for _, e := range fm.Catalog() {
		if fm.Followable(e.Type) == nil {
			follow = append(follow, e)
		} else {
			refuse = append(refuse, e)
		}
	}
	return follow, refuse
}

// selection applies envTypes. It reports whether the run is a selection.
func selection(t *testing.T) (map[string]bool, bool) {
	t.Helper()
	raw := strings.FieldsFunc(os.Getenv(envTypes), func(r rune) bool { return r == ',' || r == ' ' })
	if len(raw) == 0 {
		return nil, false
	}
	known := map[string]bool{}
	for _, e := range fm.Catalog() {
		known[e.Type] = true
	}
	out := map[string]bool{}
	for _, typ := range raw {
		if !known[typ] {
			t.Fatalf("%s names %q, which is not an upstream type of the full-mirroring catalog", envTypes, typ)
		}
		out[typ] = true
	}
	return out, true
}

// TestFullMirrorEveryAdapter is the suite: for every upstream type a feed
// adapter follows, the scenario of doc.go through the real binary; for every
// type nothing can follow, the refusal of `fullMirror.enabled` at
// configuration validation. It writes the matrix and fails when a type the
// catalog marks implemented (or partial) is not fully covered.
func TestFullMirrorEveryAdapter(t *testing.T) {
	bin := proxyBinary(t)
	selected, partial := selection(t)

	workDir := os.Getenv(envWorkDir)
	if workDir == "" {
		dir, err := os.MkdirTemp("", "fullmirror-e2e-")
		if err != nil {
			t.Fatalf("creating the work directory: %v", err)
		}
		workDir = dir
	}
	workDir, err := filepath.Abs(workDir)
	if err != nil {
		t.Fatalf("resolving the work directory: %v", err)
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("creating the work directory: %v", err)
	}
	keep := os.Getenv(envKeep) != ""

	follow, refuse := followed()
	byType := map[string]row{}
	for _, r := range rows() {
		byType[r.Type] = r
	}
	m := newMatrix()
	// A run narrowed with -run to some subtests runs only some rows: its
	// matrix is a partial one, whatever it lists (select with envTypes).
	narrowed := false
	if f := flag.Lookup("test.run"); f != nil && strings.Contains(f.Value.String(), "/") {
		narrowed = true
	}
	m.Partial = partial || narrowed
	var want, mustRefuse []string

	t.Run("types", func(t *testing.T) {
		for _, e := range follow {
			if partial && !selected[e.Type] {
				continue
			}
			want = append(want, e.Type)
			r, ok := byType[e.Type]
			if !ok {
				continue // reported by the coverage gate below
			}
			res := newRowResult(e.Type)
			res.Tier, res.Status, res.Feed = string(e.Tier), string(e.Status.State), r.Feed
			res.Notes = append(res.Notes, r.Notes...)
			m.add(res)
			t.Run(e.Type, func(t *testing.T) {
				t.Parallel()
				newRunner(t, bin, workDir, r, res).run(keep)
			})
		}
		for _, e := range refuse {
			if partial && !selected[e.Type] {
				continue
			}
			mustRefuse = append(mustRefuse, e.Type)
			ref := &refusal{Type: e.Type, Title: e.Title, Tier: string(e.Tier), Status: string(e.Status.State)}
			m.addRefusal(ref)
			t.Run("refused/"+e.Type, func(t *testing.T) {
				t.Parallel()
				checkRefused(t, bin, filepath.Join(workDir, "refused-"+e.Type), e, ref)
			})
		}
	})

	m.finalize(want, mustRefuse)
	writeMatrix(t, m, workDir)
	t.Logf("\n%s", m.Markdown())
	if len(m.Uncovered) > 0 {
		t.Errorf("full mirroring is not proven for %d upstream type(s) the catalog marks implemented or partial: %s.\n"+
			"Every followed type needs a row in this suite whose columns all pass (add internal/e2e/fullmirror/row_<type>.go).",
			len(m.Uncovered), strings.Join(m.Uncovered, ", "))
	}
	if len(m.Unrefused) > 0 {
		t.Errorf("full mirroring was not refused at configuration validation for: %s", strings.Join(m.Unrefused, ", "))
	}
	if !t.Failed() && !keep && os.Getenv(envWorkDir) == "" {
		// The rows' workspaces are gone already; the matrix stays, unless it
		// was written elsewhere.
		if os.Getenv(envReportDir) != "" {
			_ = os.RemoveAll(workDir)
		} else {
			t.Logf("the matrix is kept in %s (set %s to write it elsewhere)", workDir, envReportDir)
		}
	}
}

// checkRefused starts the proxy with full mirroring enabled for an upstream of
// a type nothing can follow: the configuration must be refused, naming
// fullMirror.enabled, while the same configuration without the fullMirror
// block starts — the refusal is the full mirror's, not a broken upstream's.
func checkRefused(t *testing.T, bin, dir string, e fm.Entry, ref *refusal) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if !t.Failed() {
			_ = os.RemoveAll(dir)
		}
	}()
	pc := procConfig{Type: e.Type, URL: "http://127.0.0.1:9/", StateDir: filepath.Join(dir, "state"), LLMBaseURL: "http://127.0.0.1:9", LLMAPIKey: "unused"}
	// The LLM package-scan suite's stub of the type supplies a valid upstream
	// (the generic type's declarative block, Nix's trusted key).
	if stub, err := pkgscan.StartStub(e.Type); err == nil {
		pc.URL, pc.Settings = stub.UpstreamURL(), stub.Settings()
		if g := stub.Generic(); g != nil {
			pc.Generic = g
		}
		defer stub.Close()
	}

	pc.Mirror = true
	listen, err := freeAddr()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := renderConfig(pc, listen)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config-refused.yaml")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-config", cfgPath)
	cmd.Dir = dir
	setParentDeathSignal(cmd)
	out, runErr := cmd.CombinedOutput()
	_ = os.WriteFile(filepath.Join(dir, "proxy-refused.log"), out, 0o644)
	reason := ""
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "fullMirror.enabled") {
			reason = line
			break
		}
	}
	ref.Error = configError(reason)
	switch {
	case ctx.Err() != nil:
		ref.Detail = "the proxy kept running with fullMirror.enabled"
	case runErr == nil:
		ref.Detail = "the proxy exited 0 with fullMirror.enabled"
	case reason == "":
		ref.Detail = "the proxy failed, but not on fullMirror.enabled: " + firstLine(out)
	case !strings.Contains(reason, "cannot be followed") && !strings.Contains(reason, "no feed adapter"):
		ref.Detail = "the refusal does not say why the type cannot be followed"
	default:
		ref.Refused = true
	}
	if !ref.Refused {
		t.Errorf("%s: %s\n%s", e.Type, ref.Detail, tailFile(filepath.Join(dir, "proxy-refused.log"), 10))
	}

	// The control: the upstream without the fullMirror block starts.
	pc.Mirror = false
	p, err := startProxy(bin, dir, "control", pc)
	if err != nil {
		ref.Detail = "the control configuration (no fullMirror block) does not start either: " + firstLine([]byte(err.Error()))
		t.Errorf("%s: %s", e.Type, err)
		return
	}
	p.stop()
	ref.Control = true
}

// configError extracts the configuration error from a log line: the "error"
// field of a JSON record, or the line itself.
func configError(line string) string {
	var rec map[string]any
	if json.Unmarshal([]byte(line), &rec) == nil {
		for _, k := range []string{"error", "err", "msg"} {
			if s, ok := rec[k].(string); ok && strings.Contains(s, "fullMirror") {
				return s
			}
		}
	}
	return strings.TrimSpace(line)
}

// writeMatrix writes the matrix (JSON and Markdown) to envReportDir, else to
// the work directory. A partial matrix gets a name of its own, so a run
// restricted to a few types never replaces the full matrix.
func writeMatrix(t *testing.T, m *matrix, workDir string) {
	t.Helper()
	dir := os.Getenv(envReportDir)
	if dir == "" {
		dir = workDir
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Errorf("creating the report directory %s: %v", dir, err)
		return
	}
	base := "full-mirror-matrix"
	if m.Partial {
		base += ".partial"
	}
	for name, data := range map[string][]byte{base + ".json": m.JSON(), base + ".md": []byte(m.Markdown())} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Errorf("writing %s: %v", path, err)
			continue
		}
		t.Logf("wrote %s", path)
	}
}

// TestEveryFollowedTypeHasARow is the cheap half of the coverage gate: it
// needs no proxy, so it fails within a second of an adapter being registered —
// or a catalog entry being marked implemented — without a row here, also in a
// run restricted to a selection.
func TestEveryFollowedTypeHasARow(t *testing.T) {
	follow, refuse := followed()
	byType := map[string]bool{}
	for _, r := range rows() {
		byType[r.Type] = true
	}
	for _, e := range follow {
		if !byType[e.Type] {
			t.Errorf("upstream type %q is followed by a feed adapter (catalog status %q) but has no row in the full-mirror suite.\n"+
				"Add internal/e2e/fullmirror/row_%s.go: the feed the adapter follows, served in front of the LLM package-scan "+
				"suite's stub registry, registered with register(row{…}). See row_npm.go for an example.", e.Type, e.Status.State, e.Type)
		}
		delete(byType, e.Type)
	}
	for _, e := range refuse {
		if byType[e.Type] {
			t.Errorf("upstream type %q has a row, but full mirroring cannot be enabled for it: %v", e.Type, fm.Followable(e.Type))
		}
		delete(byType, e.Type)
	}
	for typ := range byType {
		t.Errorf("row %q names no upstream type of the full-mirroring catalog", typ)
	}
	// Every type marked implemented or partial outside tier (d) is followed:
	// the catalog and the adapters agree.
	for _, e := range fm.Catalog() {
		marked := e.Status.State == fm.StateImplemented || e.Status.State == fm.StatePartial
		if marked && e.Tier != fm.TierNone {
			if err := fm.Followable(e.Type); err != nil {
				t.Errorf("the catalog marks %s %q, but it cannot be followed: %v", e.Type, e.Status.State, err)
			}
		}
	}
	adapters := fm.Adapters()
	sort.Strings(adapters)
	for _, a := range adapters {
		if fm.Followable(a) == nil {
			continue
		}
		t.Errorf("a feed adapter is registered for %q, but the configuration cannot enable it: %v", a, fm.Followable(a))
	}
}

// TestCoverageGateDetectsGaps guards the guard: the matrix must report a type
// as uncovered when it has no row, when a column failed, when a column was
// never reached — and must not report a fully passing type; a type that must
// be refused is reported unless its refusal and its control were shown.
func TestCoverageGateDetectsGaps(t *testing.T) {
	passing := func(typ string) *rowResult {
		r := newRowResult(typ)
		for _, c := range columns {
			r.pass(c)
		}
		return r
	}
	m := newMatrix()
	m.add(passing("npm"))
	failed := passing("pip")
	failed.fail(colBlocked, "the malicious wheel is cached")
	m.add(failed)
	unreached := newRowResult("cargo")
	unreached.pass(colMirrored)
	m.add(unreached)
	// A failure is sticky: a later pass of the same column must not hide it.
	failed.pass(colBlocked)
	m.addRefusal(&refusal{Type: "docker", Refused: true, Control: true})
	m.addRefusal(&refusal{Type: "git", Refused: true, Control: false, Detail: "control did not start"})
	m.addRefusal(&refusal{Type: "nix", Refused: false})

	m.finalize([]string{"npm", "pip", "cargo", "go"}, []string{"docker", "git", "nix", "swift"})
	if got, want := strings.Join(m.Uncovered, ","), "cargo,go,pip"; got != want {
		t.Fatalf("uncovered = %s, want %s", got, want)
	}
	if got, want := strings.Join(m.Unrefused, ","), "git,nix,swift"; got != want {
		t.Fatalf("unrefused = %s, want %s", got, want)
	}
	md := m.Markdown()
	for _, want := range []string{"CI FAIL", "the malicious wheel is cached", "| `npm` |", "control did not start"} {
		if !strings.Contains(md, want) {
			t.Errorf("the Markdown matrix lacks %q", want)
		}
	}
	var decoded struct {
		Rows      []json.RawMessage `json:"rows"`
		Refusals  []json.RawMessage `json:"refusals"`
		Uncovered []string          `json:"uncovered"`
	}
	if err := json.Unmarshal(m.JSON(), &decoded); err != nil || len(decoded.Rows) != 3 || len(decoded.Refusals) != 3 || len(decoded.Uncovered) != 3 {
		t.Errorf("the JSON matrix does not round-trip: %v (%d rows, %d refusals, %d uncovered)", err, len(decoded.Rows), len(decoded.Refusals), len(decoded.Uncovered))
	}
}
