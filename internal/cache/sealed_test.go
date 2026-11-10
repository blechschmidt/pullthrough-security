package cache

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func TestSealedCacheServesHit(t *testing.T) {
	inner := NewMemoryCache()
	defer inner.Close()
	ctx := context.Background()
	if _, err := inner.Put(ctx, "k", bytes.NewReader([]byte("cached")), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}

	sealed := NewSealedCache(inner)

	// A loader that must never run in sealed mode.
	loader := func(context.Context) (io.Reader, map[string]string, error) {
		t.Fatal("loader must not be called in sealed mode")
		return nil, nil, nil
	}

	entry, err := sealed.GetOrLoad(ctx, "k", loader)
	if err != nil {
		t.Fatalf("GetOrLoad hit: %v", err)
	}
	data, _ := io.ReadAll(entry.Content)
	entry.Content.Close()
	if string(data) != "cached" {
		t.Errorf("got %q, want cached", data)
	}
}

func TestSealedCacheMissDoesNotLoad(t *testing.T) {
	inner := NewMemoryCache()
	defer inner.Close()
	sealed := NewSealedCache(inner)

	called := false
	loader := func(context.Context) (io.Reader, map[string]string, error) {
		called = true
		return bytes.NewReader([]byte("upstream")), nil, nil
	}

	_, err := sealed.GetOrLoad(context.Background(), "absent", loader)
	if called {
		t.Error("loader was invoked on a sealed miss")
	}
	if !errors.Is(err, ErrSealed) {
		t.Errorf("err = %v, want ErrSealed", err)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("ErrSealed should wrap ErrNotFound, got %v", err)
	}
}

func TestSealedCachePutStillWorks(t *testing.T) {
	// Imports/admin must still populate a sealed cache; only upstream loads are
	// blocked.
	inner := NewMemoryCache()
	defer inner.Close()
	sealed := NewSealedCache(inner)
	ctx := context.Background()

	if _, err := sealed.Put(ctx, "k", bytes.NewReader([]byte("v")), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := sealed.Stat(ctx, "k"); err != nil {
		t.Errorf("Stat after Put: %v", err)
	}
}
