package cache

import (
	"bytes"
	"context"
	"errors"
	"io"
)

// errObjectTooLarge is returned by S3Objects.Get for an object larger than the
// caller's bound.
var errObjectTooLarge = errors.New("cache: s3 object exceeds the size bound")

// S3Objects is a small, unconditional object API over the dependency-free SigV4
// S3 client that backs S3Store: list, get, put and delete of whole small
// objects, addressed by key.
//
// It exists for state that must be shared by every replica of a multi-replica
// deployment but is not cache content — the personal-link registry (Task 177)
// keeps its records in the same bucket as the shared cache, under its own
// prefix. Such state must not go through the cache itself: cache entries are
// evicted, tiered and garbage-collected, and a credential that disappears
// because the cache was full is not acceptable. Like S3ConditionalClient it
// reuses the one audited S3 implementation rather than adding a second.
type S3Objects struct {
	c *s3HTTPClient
}

// S3ObjectInfo describes one listed object.
type S3ObjectInfo struct {
	// Key is the object's full key.
	Key string
	// ETag changes whenever the object's content changes; it is the cheap way to
	// tell that an object was rewritten without downloading it.
	ETag string
	// Size is the object's size in bytes.
	Size int64
}

// NewS3Objects builds an object client from the same configuration used for the
// cache S3 store.
func NewS3Objects(cfg S3ClientConfig) (*S3Objects, error) {
	c, err := newS3HTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	return &S3Objects{c: c}, nil
}

// List calls fn for every object whose key begins with prefix, paging
// transparently. An error returned by fn aborts the listing and is returned.
func (o *S3Objects) List(ctx context.Context, prefix string, fn func(S3ObjectInfo) error) error {
	return o.c.listObjects(ctx, prefix, func(key string, attrs objectAttrs) error {
		return fn(S3ObjectInfo{Key: key, ETag: attrs.ETag, Size: attrs.Size})
	})
}

// Get downloads an object of at most maxBytes bytes. It returns ErrNotFound when
// the key is absent, and an error when the object is larger than maxBytes — the
// objects this API is for are small records, and one that is not is not one of
// them.
func (o *S3Objects) Get(ctx context.Context, key string, maxBytes int64) ([]byte, error) {
	body, _, err := o.c.getObject(ctx, key)
	if err != nil {
		return nil, err
	}
	defer drainClose(body)
	data, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errObjectTooLarge
	}
	return data, nil
}

// Put writes (or replaces) the object at key.
func (o *S3Objects) Put(ctx context.Context, key string, data []byte, contentType string) error {
	return o.c.putObject(ctx, key, bytes.NewReader(data), int64(len(data)), hexSHA256(data), contentType)
}

// Delete removes the object at key. Removing an absent key is not an error.
func (o *S3Objects) Delete(ctx context.Context, key string) error {
	return o.c.deleteObject(ctx, key)
}

// Close releases idle connections.
func (o *S3Objects) Close() error { return o.c.close() }
