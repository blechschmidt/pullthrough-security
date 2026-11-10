package coord

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// s3Backend is a compare-and-swap lease store backed by S3-compatible object
// storage, reusing the cache subsystem's dependency-free SigV4 client. Each lease
// is a small JSON object whose ETag is the CAS token: acquisition is a
// create-if-absent (If-None-Match: *) and renewal/steal is a replace-if-match
// (If-Match: <etag>), so two replicas can never both believe they hold the lease.
//
// It is the natural coordination backend whenever the proxy is already running
// the s3 shared cache (Task 20) for HA: no extra infrastructure, the same bucket
// and credentials.
type s3Backend struct {
	cl     *cache.S3ConditionalClient
	prefix string // normalized: empty or ends with "/"
}

// newS3Backend constructs an S3 lease backend from S3 connection settings. prefix
// isolates lease objects within the bucket (defaults to "coord/leases/").
func newS3Backend(s3 S3Config, prefix string) (*s3Backend, error) {
	cl, err := cache.NewS3ConditionalClient(cache.S3ClientConfig{
		Endpoint:           s3.Endpoint,
		Region:             s3.Region,
		Bucket:             s3.Bucket,
		AccessKeyID:        s3.AccessKeyID,
		SecretAccessKey:    s3.SecretAccessKey,
		SessionToken:       s3.SessionToken,
		UsePathStyle:       s3.UsePathStyle,
		InsecureSkipVerify: s3.InsecureSkipVerify,
		MaxRetries:         s3.MaxRetries,
	})
	if err != nil {
		return nil, err
	}
	prefix = strings.TrimPrefix(strings.TrimSpace(prefix), "/")
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	if prefix == "" {
		prefix = "coord/leases/"
	}
	return &s3Backend{cl: cl, prefix: prefix}, nil
}

func (b *s3Backend) key(name string) string {
	return b.prefix + sanitizeName(name) + ".lease.json"
}

func (b *s3Backend) load(ctx context.Context, name string) (record, string, bool, error) {
	data, etag, err := b.cl.Get(ctx, b.key(name))
	if err != nil {
		if errors.Is(err, cache.ErrNotFound) {
			return record{}, "", false, nil
		}
		return record{}, "", false, err
	}
	var rec record
	if err := json.Unmarshal(data, &rec); err != nil {
		return record{}, "", false, fmt.Errorf("coord: decoding s3 lease %q: %w", name, err)
	}
	return rec, etag, true, nil
}

func (b *s3Backend) create(ctx context.Context, name string, rec record) (string, error) {
	data, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	etag, err := b.cl.CreateIfAbsent(ctx, b.key(name), data)
	if err != nil {
		if errors.Is(err, cache.ErrPreconditionFailed) {
			return "", ErrConflict
		}
		return "", err
	}
	return etag, nil
}

func (b *s3Backend) update(ctx context.Context, name, expectedVersion string, rec record) (string, error) {
	data, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	etag, err := b.cl.ReplaceIfMatch(ctx, b.key(name), data, expectedVersion)
	if err != nil {
		if errors.Is(err, cache.ErrPreconditionFailed) {
			return "", ErrConflict
		}
		return "", err
	}
	return etag, nil
}

func (b *s3Backend) remove(ctx context.Context, name, expectedVersion string) error {
	if err := b.cl.DeleteIfMatch(ctx, b.key(name), expectedVersion); err != nil {
		if errors.Is(err, cache.ErrPreconditionFailed) {
			return ErrConflict
		}
		return err
	}
	return nil
}

func (b *s3Backend) close() error { return b.cl.Close() }
