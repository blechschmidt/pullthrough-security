package upstreampool

import (
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func newTestPool(t *testing.T, backend string) *Pool {
	t.Helper()
	doer := &fakeDoer{handler: func(r upstream.Request) (*upstream.Response, error) { return resp(200, "ok"), nil }}
	p, err := New(Config{
		Backend: backend, Client: doer,
		Endpoints: []EndpointConfig{
			{ID: "primary", URL: "https://primary.test"},
			{ID: "mirror", URL: "https://mirror.test"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestManagerAddAndLookup(t *testing.T) {
	m := NewManager()
	if m.Len() != 0 {
		t.Fatal("empty manager not empty")
	}
	if err := m.Add(newTestPool(t, "npm")); err != nil {
		t.Fatal(err)
	}
	if err := m.Add(newTestPool(t, "pip")); err != nil {
		t.Fatal(err)
	}
	// Duplicate backend rejected.
	if err := m.Add(newTestPool(t, "npm")); err == nil {
		t.Error("expected duplicate-backend error")
	}
	if m.Len() != 2 {
		t.Fatalf("Len = %d, want 2", m.Len())
	}
	if _, ok := m.Pool("npm"); !ok {
		t.Error("npm pool not found")
	}
	if _, ok := m.Pool("nope"); ok {
		t.Error("unexpected pool for unknown backend")
	}

	// Snapshots are ordered by backend name.
	snaps := m.Snapshots()
	if len(snaps) != 2 || snaps[0].Backend != "npm" || snaps[1].Backend != "pip" {
		t.Fatalf("snapshots not ordered by backend: %+v", snaps)
	}
}

func TestManagerOverridesRouteToBackend(t *testing.T) {
	m := NewManager()
	if err := m.Add(newTestPool(t, "npm")); err != nil {
		t.Fatal(err)
	}

	if err := m.SetDrained("npm", "mirror", true); err != nil {
		t.Fatal(err)
	}
	if err := m.OpenCircuit("npm", "primary"); err != nil {
		t.Fatal(err)
	}
	snap, _ := m.Snapshot("npm")
	for _, e := range snap.Endpoints {
		switch e.ID {
		case "mirror":
			if !e.Drained {
				t.Error("mirror not drained")
			}
		case "primary":
			if e.State != StateOpen.String() {
				t.Error("primary not opened")
			}
		}
	}
	if err := m.ResetCircuit("npm", "primary"); err != nil {
		t.Fatal(err)
	}

	// Unknown backend errors.
	if err := m.SetDrained("nope", "x", true); err == nil {
		t.Error("expected error for unknown backend")
	}
}

func TestNilManagerSafe(t *testing.T) {
	var m *Manager
	if m.Len() != 0 {
		t.Error("nil manager Len != 0")
	}
	if _, ok := m.Pool("x"); ok {
		t.Error("nil manager returned a pool")
	}
	if s := m.Snapshots(); s != nil {
		t.Error("nil manager returned snapshots")
	}
	m.StartProbing(nil) // must not panic
}
