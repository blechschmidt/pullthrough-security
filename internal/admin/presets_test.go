package admin

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/presets"
)

func TestPresetsListAndDiffEndpoints(t *testing.T) {
	def := config.Default()
	mgr := presets.NewManager("", &def)
	srv := newTestServer(t, Options{Presets: mgr})

	var list struct {
		Presets []presets.Summary `json:"presets"`
	}
	if code := getJSON(t, srv, "/admin/api/presets", "", &list); code != http.StatusOK {
		t.Fatalf("list status = %d", code)
	}
	if len(list.Presets) < 3 {
		t.Fatalf("expected >=3 presets, got %d", len(list.Presets))
	}

	var diff struct {
		Diff presets.Diff `json:"diff"`
	}
	if code := getJSON(t, srv, "/admin/api/presets/diff?name=slsa-l3", "", &diff); code != http.StatusOK {
		t.Fatalf("diff status = %d", code)
	}
	if diff.Diff.Preset != "slsa-l3" || diff.Diff.Changed == 0 {
		t.Fatalf("unexpected diff payload: %+v", diff.Diff.Preset)
	}

	// Unknown preset is a 400.
	if code := getJSON(t, srv, "/admin/api/presets/diff?name=nope", "", nil); code != http.StatusBadRequest {
		t.Fatalf("unknown preset status = %d, want 400", code)
	}
}

func TestPresetsApplyEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("sigverify:\n  enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	live, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	mgr := presets.NewManager(path, live)
	srv := newTestServer(t, Options{Presets: mgr})

	// Without confirm:true, apply is rejected.
	if rec := postJSON(t, srv, "/admin/api/presets/apply", `{"name":"slsa-l3"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("apply without confirm = %d, want 400", rec.Code)
	}

	rec := postJSON(t, srv, "/admin/api/presets/apply", `{"name":"slsa-l3","confirm":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("apply status = %d: %s", rec.Code, rec.Body.String())
	}

	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.Sigverify.Enabled {
		t.Error("expected sigverify.enabled=true after apply")
	}
}

func TestPresetsDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	if code := getJSON(t, srv, "/admin/api/presets", "", nil); code != http.StatusNotFound {
		t.Fatalf("expected 404 when presets not wired, got %d", code)
	}
}
