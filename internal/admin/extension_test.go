package admin

import (
	"context"
	"net/http"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/extension"
)

// fakeExtensionInspector is a stand-in ExtensionInspector so the admin handler
// can be tested without compiling a real wasm module.
type fakeExtensionInspector struct {
	snap      extension.Snapshot
	reloadErr error
	reloaded  int
}

func (f *fakeExtensionInspector) Enabled() bool                { return f.snap.Enabled }
func (f *fakeExtensionInspector) Snapshot() extension.Snapshot { return f.snap }
func (f *fakeExtensionInspector) Reload(context.Context) error {
	f.reloaded++
	return f.reloadErr
}

func TestExtensionsEndpoint(t *testing.T) {
	insp := &fakeExtensionInspector{snap: extension.Snapshot{
		Enabled:    true,
		ABIVersion: extension.ABIVersion,
		Modules: []extension.ModuleSnapshot{
			{Name: "naming", Loaded: true, Invocations: 5, Block: 2},
		},
	}}
	srv := newTestServer(t, Options{Extension: insp})

	var resp extension.Snapshot
	if code := getJSON(t, srv, "/admin/api/extensions", "", &resp); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !resp.Enabled || len(resp.Modules) != 1 || resp.Modules[0].Name != "naming" {
		t.Fatalf("unexpected snapshot: %+v", resp)
	}
}

func TestExtensionsEndpointDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	var resp map[string]any
	if code := getJSON(t, srv, "/admin/api/extensions", "", &resp); code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when not configured", code)
	}
}

func TestExtensionsReload(t *testing.T) {
	insp := &fakeExtensionInspector{snap: extension.Snapshot{Enabled: true}}
	srv := newTestServer(t, Options{Extension: insp})

	rr := postJSON(t, srv, "/admin/api/extensions/reload", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if insp.reloaded != 1 {
		t.Fatalf("expected Reload to be called once, got %d", insp.reloaded)
	}
}
