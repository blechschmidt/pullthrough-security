package extension

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

func tenantInput(tenant, name string) HostInput {
	return HostInput{Signals: policyengine.Input{
		Tenant:   tenant,
		Artifact: policyengine.ArtifactInput{Ecosystem: "npm", Backend: "npm", Name: name, Version: "1"},
	}}
}

func TestManagerDisabled(t *testing.T) {
	_, err := NewManager(context.Background(), Config{Enabled: false})
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("want ErrDisabled, got %v", err)
	}
}

func TestManagerConfigValidation(t *testing.T) {
	mini := buildMiniModule(ABIVersion)
	cases := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"empty name", Config{Enabled: true, Modules: []ModuleConfig{{WASM: mini}}}, false},
		{"duplicate names", Config{Enabled: true, Modules: []ModuleConfig{{Name: "a", WASM: mini}, {Name: "a", WASM: mini}}}, false},
		{"no source", Config{Enabled: true, Modules: []ModuleConfig{{Name: "a"}}}, false},
		{"valid", Config{Enabled: true, Modules: []ModuleConfig{{Name: "a", WASM: mini}}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mgr, err := NewManager(context.Background(), tc.cfg)
			if mgr != nil {
				mgr.Close(context.Background())
			}
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

func TestManagerPerTenantSelection(t *testing.T) {
	mini := buildMiniModule(ABIVersion)
	mgr, err := NewManager(context.Background(), Config{
		Enabled: true,
		Modules: []ModuleConfig{
			{Name: "global", WASM: mini},
			{Name: "team-a-only", WASM: mini, Tenants: []string{"team-a"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close(context.Background())

	// team-a sees both modules.
	res := mgr.Evaluate(context.Background(), tenantInput("team-a", "x"))
	if len(res.Modules) != 2 {
		t.Fatalf("team-a: expected 2 modules, got %d", len(res.Modules))
	}
	// team-b sees only the global module.
	res = mgr.Evaluate(context.Background(), tenantInput("team-b", "x"))
	if len(res.Modules) != 1 || res.Modules[0].Module != "global" {
		t.Fatalf("team-b: expected only the global module, got %+v", res.Modules)
	}
}

func TestManagerCombineMostSevereWins(t *testing.T) {
	// A permissive mini module plus the conformance fixture; the fixture blocks an
	// ext-block coordinate, so the combined decision must be block regardless of
	// module order.
	mgr, err := NewManager(context.Background(), Config{
		Enabled: true,
		Modules: []ModuleConfig{
			{Name: "permissive", WASM: buildMiniModule(ABIVersion)},
			{Name: "strict", Path: conformancePath(), Limits: Limits{Timeout: 2 * time.Second}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close(context.Background())

	res := mgr.Evaluate(context.Background(), tenantInput("", "ext-block-pkg"))
	if !res.Block || res.Decision != DecisionBlock {
		t.Fatalf("expected combined block, got %s", res.Decision)
	}
	if res.Module != "strict" {
		t.Errorf("expected the strict module to drive the decision, got %q", res.Module)
	}
	if len(res.Modules) != 2 {
		t.Errorf("expected both modules to run, got %d", len(res.Modules))
	}
}

func TestManagerNotLoadedFailPolicy(t *testing.T) {
	// A module pointed at a missing file loads in a not-loaded state and is
	// resolved per its fail policy without ever failing construction.
	for _, failClosed := range []bool{false, true} {
		mgr, err := NewManager(context.Background(), Config{
			Enabled: true,
			Modules: []ModuleConfig{{Name: "missing", Path: filepath.Join(t.TempDir(), "nope.wasm"), FailClosed: failClosed}},
		})
		if err != nil {
			t.Fatalf("construction must not fail for a bad module: %v", err)
		}
		defer mgr.Close(context.Background())

		if mgr.Snapshot().Modules[0].Loaded {
			t.Fatal("expected module to be not-loaded")
		}
		res := mgr.Evaluate(context.Background(), tenantInput("", "x"))
		want := DecisionAllow
		if failClosed {
			want = DecisionBlock
		}
		if res.Decision != want {
			t.Errorf("failClosed=%v: decision = %s, want %s", failClosed, res.Decision, want)
		}
	}
}

func TestManagerHotReload(t *testing.T) {
	// Copy the conformance fixture to a temp path so we can swap it under the
	// manager and reload.
	src, err := os.ReadFile(conformancePath())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "gate.wasm")
	if err := os.WriteFile(path, src, 0o644); err != nil {
		t.Fatal(err)
	}
	mgr, err := NewManager(context.Background(), Config{
		Enabled: true,
		Modules: []ModuleConfig{{Name: "g", Path: path, Limits: Limits{Timeout: 2 * time.Second}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close(context.Background())

	if res := mgr.Evaluate(context.Background(), tenantInput("", "ext-block-pkg")); !res.Block {
		t.Fatal("pre-reload: expected block")
	}

	// Reload from the same (valid) bytes succeeds and the module keeps working.
	if err := mgr.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if res := mgr.Evaluate(context.Background(), tenantInput("", "ext-block-pkg")); !res.Block {
		t.Fatal("post-reload: expected block")
	}

	// Corrupt the file: a reload failure must keep the previously-working module
	// online (keepOnError) and record the error.
	if err := os.WriteFile(path, []byte("not wasm"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(context.Background()); err == nil {
		t.Fatal("expected reload of a corrupt module to error")
	}
	if !mgr.Snapshot().Modules[0].Loaded {
		t.Error("a failed reload must keep the previously-loaded module online")
	}
	if res := mgr.Evaluate(context.Background(), tenantInput("", "ext-block-pkg")); !res.Block {
		t.Error("module should still evaluate after a failed reload")
	}
}

func TestManagerMetrics(t *testing.T) {
	mgr := loadConformance(t, Limits{Timeout: 2 * time.Second}, false)
	ctx := context.Background()
	mgr.Evaluate(ctx, inputFor("ordinary", -1))      // allow
	mgr.Evaluate(ctx, inputFor("ext-block-x", -1))   // block
	mgr.Evaluate(ctx, inputFor("ext-warn-x", -1))    // warn
	mgr.Evaluate(ctx, inputFor("ext-badjson-x", -1)) // error

	snap := mgr.Snapshot().Modules[0]
	if snap.Invocations != 4 {
		t.Errorf("invocations = %d, want 4", snap.Invocations)
	}
	if snap.Allow != 1 || snap.Block != 1 || snap.Warn != 1 || snap.Errors != 1 {
		t.Errorf("counters: allow=%d block=%d warn=%d err=%d, want 1/1/1/1",
			snap.Allow, snap.Block, snap.Warn, snap.Errors)
	}

	// The Prometheus bridge projects each counter as a labeled sample.
	var sawInvocations, sawBlockVerdict bool
	for _, s := range mgr.MetricSamples() {
		if s.Name == "pullthrough_extension_invocations_total" && s.Labels["module"] == "conformance" && s.Value == 4 {
			sawInvocations = true
		}
		if s.Name == "pullthrough_extension_verdicts_total" && s.Labels["decision"] == "block" && s.Value == 1 {
			sawBlockVerdict = true
		}
	}
	if !sawInvocations || !sawBlockVerdict {
		t.Errorf("metric samples missing expected series (invocations=%v blockVerdict=%v)", sawInvocations, sawBlockVerdict)
	}
}

func TestManagerConcurrentInvoke(t *testing.T) {
	mgr := loadConformance(t, Limits{Timeout: 2 * time.Second}, false)
	const n = 16
	errc := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			name := "ordinary"
			if i%2 == 0 {
				name = "ext-block-x"
			}
			res := mgr.Evaluate(context.Background(), inputFor(name, -1))
			if i%2 == 0 && !res.Block {
				errc <- errors.New("expected block")
				return
			}
			errc <- nil
		}(i)
	}
	for i := 0; i < n; i++ {
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
	}
	if got := mgr.Snapshot().Modules[0].Invocations; got != n {
		t.Errorf("invocations = %d, want %d", got, n)
	}
}
