package backends

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// ErrNotSupported indicates a backend cannot handle a particular request.
var ErrNotSupported = errors.New("backends: request not supported")

// Registry holds the set of configured backends keyed by Name. It is safe for
// concurrent use.
type Registry struct {
	mu       sync.RWMutex
	backends map[string]Backend
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{backends: make(map[string]Backend)}
}

// Register adds a backend. It returns an error if a backend with the same name
// is already registered or if the backend (or its name) is invalid.
func (r *Registry) Register(b Backend) error {
	if b == nil {
		return errors.New("backends: cannot register nil backend")
	}
	name := b.Name()
	if name == "" {
		return errors.New("backends: backend has empty name")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.backends[name]; exists {
		return fmt.Errorf("backends: %q already registered", name)
	}
	r.backends[name] = b
	return nil
}

// Get returns the backend registered under name and whether it was found.
func (r *Registry) Get(name string) (Backend, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.backends[name]
	return b, ok
}

// Names returns the sorted list of registered backend names.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.backends))
	for name := range r.backends {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Len returns the number of registered backends.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.backends)
}
