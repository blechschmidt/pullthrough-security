package userlinks

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// S3Store keeps the registry in an S3-compatible object store: one object per
// record, "<prefix><kind>/<key>.json". It is the store for a multi-replica
// deployment that already shares its cache through such a bucket — the registry
// then needs no infrastructure of its own, only a prefix next to the cache's.
//
// It talks to the bucket directly rather than through the cache. Cache entries
// are evicted when the cache is full and moved between tiers; a link is neither.
type S3Store struct {
	objects *cache.S3Objects
	prefix  string
}

// NewS3Store opens the registry's store in the bucket cfg names, under prefix.
func NewS3Store(cfg cache.S3ClientConfig, prefix string) (*S3Store, error) {
	objects, err := cache.NewS3Objects(cfg)
	if err != nil {
		return nil, fmt.Errorf("userlinks: opening the s3 store: %w", err)
	}
	prefix = strings.TrimLeft(strings.TrimSpace(prefix), "/")
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return &S3Store{objects: objects, prefix: prefix}, nil
}

func (s *S3Store) key(name string) (string, error) {
	if !validObjectName(name) {
		return "", fmt.Errorf("userlinks: invalid object name %q", name)
	}
	return s.prefix + name + objectFileSuffix, nil
}

// List implements Store. One request lists a thousand objects with their ETags,
// so a refresh costs a handful of requests however many links there are, and
// downloads only what changed.
func (s *S3Store) List(ctx context.Context) ([]Object, error) {
	var out []Object
	err := s.objects.List(ctx, s.prefix, func(info cache.S3ObjectInfo) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		name, ok := strings.CutSuffix(strings.TrimPrefix(info.Key, s.prefix), objectFileSuffix)
		if !ok || !validObjectName(name) {
			return nil
		}
		out = append(out, Object{Name: name, Version: info.ETag})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("userlinks: listing the s3 store: %w", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Get implements Store.
func (s *S3Store) Get(ctx context.Context, name string) ([]byte, error) {
	key, err := s.key(name)
	if err != nil {
		return nil, err
	}
	data, err := s.objects.Get(ctx, key, maxObjectBytes)
	if err != nil {
		if errors.Is(err, cache.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("userlinks: reading %s: %w", name, err)
	}
	return data, nil
}

// Put implements Store.
func (s *S3Store) Put(ctx context.Context, name string, data []byte) error {
	key, err := s.key(name)
	if err != nil {
		return err
	}
	if err := s.objects.Put(ctx, key, data, "application/json"); err != nil {
		return fmt.Errorf("userlinks: writing %s: %w", name, err)
	}
	return nil
}

// Delete implements Store.
func (s *S3Store) Delete(ctx context.Context, name string) error {
	key, err := s.key(name)
	if err != nil {
		return err
	}
	if err := s.objects.Delete(ctx, key); err != nil {
		return fmt.Errorf("userlinks: deleting %s: %w", name, err)
	}
	return nil
}

// Close implements Store.
func (s *S3Store) Close() error { return s.objects.Close() }
