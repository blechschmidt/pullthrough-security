package userlinks

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// fakeS3 is the part of an S3-compatible object store the registry uses: PUT,
// GET and DELETE of an object, and ListObjectsV2 with a prefix and paging.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	// pageSize forces paging of listings.
	pageSize int
	// fail makes every request answer 500.
	fail bool
}

func newFakeS3() *fakeS3 { return &fakeS3{objects: map[string][]byte{}, pageSize: 3} }

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		http.Error(w, "<Error><Code>InternalError</Code></Error>", http.StatusInternalServerError)
		return
	}
	// Path-style addressing: /<bucket>/<key>.
	rest := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key, _ := strings.Cut(rest, "/")
	if bucket != "links-bucket" {
		http.Error(w, "<Error><Code>NoSuchBucket</Code></Error>", http.StatusNotFound)
		return
	}
	if key == "" && r.Method == http.MethodGet {
		f.list(w, r)
		return
	}
	switch r.Method {
	case http.MethodPut:
		data, _ := io.ReadAll(r.Body)
		f.objects[key] = data
		w.Header().Set("ETag", `"`+etagOf(data)+`"`)
		w.WriteHeader(http.StatusOK)
	case http.MethodGet, http.MethodHead:
		data, ok := f.objects[key]
		if !ok {
			http.Error(w, "<Error><Code>NoSuchKey</Code></Error>", http.StatusNotFound)
			return
		}
		w.Header().Set("ETag", `"`+etagOf(data)+`"`)
		_, _ = w.Write(data)
	case http.MethodDelete:
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func etagOf(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

func (f *fakeS3) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	prefix := q.Get("prefix")
	var keys []string
	for key := range f.objects {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	start := 0
	if token := q.Get("continuation-token"); token != "" {
		start = sort.SearchStrings(keys, token)
	}
	end := min(start+f.pageSize, len(keys))
	type content struct {
		Key  string `xml:"Key"`
		Size int    `xml:"Size"`
		ETag string `xml:"ETag"`
	}
	result := struct {
		XMLName               xml.Name  `xml:"ListBucketResult"`
		IsTruncated           bool      `xml:"IsTruncated"`
		NextContinuationToken string    `xml:"NextContinuationToken,omitempty"`
		Contents              []content `xml:"Contents"`
	}{}
	for _, key := range keys[start:end] {
		result.Contents = append(result.Contents, content{Key: key, Size: len(f.objects[key]), ETag: `"` + etagOf(f.objects[key]) + `"`})
	}
	if end < len(keys) {
		result.IsTruncated = true
		result.NextContinuationToken = keys[end]
	}
	w.Header().Set("Content-Type", "application/xml")
	_ = xml.NewEncoder(w).Encode(result)
}

func newS3TestStore(t *testing.T, prefix string) (*S3Store, *fakeS3) {
	t.Helper()
	fake := newFakeS3()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	store, err := NewS3Store(cache.S3ClientConfig{
		Endpoint: srv.URL, Region: "us-east-1", Bucket: "links-bucket",
		AccessKeyID: "test", SecretAccessKey: "test", UsePathStyle: true,
	}, prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, fake
}

// Every store behaves the same: this is the contract the registry relies on.
func TestStoreContract(t *testing.T) {
	stores := map[string]func(t *testing.T) Store{
		"memory": func(t *testing.T) Store { return NewMemoryStore() },
		"directory": func(t *testing.T) Store {
			s, err := NewDirStore(filepath.Join(t.TempDir(), "links"))
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
		"s3": func(t *testing.T) Store { s, _ := newS3TestStore(t, "proxy/userlinks"); return s },
	}
	for name, open := range stores {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := open(t)

			if objs, err := s.List(ctx); err != nil || len(objs) != 0 {
				t.Fatalf("a new store lists %v, %v; want nothing", objs, err)
			}
			if _, err := s.Get(ctx, "link/aa"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get of a missing object = %v, want ErrNotFound", err)
			}
			if err := s.Delete(ctx, "link/aa"); err != nil {
				t.Fatalf("Delete of a missing object = %v, want nil", err)
			}

			// More objects than one listing page of the fake S3 holds.
			want := map[string]string{}
			for _, name := range []string{"link/aa", "link/bb", "link/cc", "revoked/aa", "block/0123abcd", "usage/node-1.example"} {
				want[name] = `{"name":"` + name + `"}`
				if err := s.Put(ctx, name, []byte(want[name])); err != nil {
					t.Fatalf("Put %s: %v", name, err)
				}
			}
			objs, err := s.List(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(objs) != len(want) {
				t.Fatalf("List returned %d objects, want %d: %v", len(objs), len(want), objs)
			}
			versions := map[string]string{}
			for i, obj := range objs {
				if i > 0 && objs[i-1].Name >= obj.Name {
					t.Fatalf("the listing is not sorted: %v", objs)
				}
				if obj.Version == "" {
					t.Fatalf("object %s has no version", obj.Name)
				}
				versions[obj.Name] = obj.Version
				got, err := s.Get(ctx, obj.Name)
				if err != nil || string(got) != want[obj.Name] {
					t.Fatalf("Get %s = %q, %v; want %q", obj.Name, got, err, want[obj.Name])
				}
			}

			// Rewriting an object changes its version; the others keep theirs.
			time.Sleep(5 * time.Millisecond) // a file's version includes its mtime
			if err := s.Put(ctx, "block/0123abcd", []byte(`{"changed":true,"padding":"xxxxxxxx"}`)); err != nil {
				t.Fatal(err)
			}
			objs, _ = s.List(ctx)
			for _, obj := range objs {
				changed := obj.Version != versions[obj.Name]
				if (obj.Name == "block/0123abcd") != changed {
					t.Fatalf("after rewriting block/0123abcd, the version of %s changed=%v", obj.Name, changed)
				}
			}

			if err := s.Delete(ctx, "link/bb"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Get(ctx, "link/bb"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("a deleted object is still there: %v", err)
			}
			objs, _ = s.List(ctx)
			if len(objs) != len(want)-1 {
				t.Fatalf("after a delete the store lists %d objects, want %d", len(objs), len(want)-1)
			}

			// An object name is never a path: nothing that could address another
			// file, or another kind of thing, is accepted.
			for _, bad := range []string{
				"", "link", "link/", "/aa", "link/../x", "../link/aa", "link/a/b", "Link/aa", "link/AA",
				"link/a b", "link/.hidden", "link/-flag", "link/a\x00b", "link/" + strings.Repeat("a", 300),
				"link\\aa", "li.nk/aa",
			} {
				if err := s.Put(ctx, bad, []byte("x")); err == nil {
					t.Errorf("Put accepted the object name %q", bad)
				}
			}
		})
	}
}

// What the directory store promises beyond the contract: private files, atomic
// replacement, and a listing that only shows finished objects.
func TestDirStoreFiles(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "state", "links")
	s, err := NewDirStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "link/abc", []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "link", "abc.json")
	info, err := os.Stat(file)
	if err != nil {
		t.Fatalf("the object is not where the layout says: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("the object file has mode %o, want 0600: it names users", perm)
	}
	for _, d := range []string{dir, filepath.Join(dir, "link")} {
		if di, err := os.Stat(d); err != nil || di.Mode().Perm() != 0o700 {
			t.Errorf("directory %s has mode %v (%v), want 0700", d, di.Mode().Perm(), err)
		}
	}

	// Leftovers of writes — in progress, or abandoned — and stray files are not
	// objects.
	for _, name := range []string{".tmp-123", "notes.txt", ".abc.json.swp"} {
		if err := os.WriteFile(filepath.Join(dir, "link", name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	objs, err := s.List(ctx)
	if err != nil || len(objs) != 1 || objs[0].Name != "link/abc" {
		t.Fatalf("List = %v, %v; want only link/abc", objs, err)
	}

	// A temporary file old enough to be an abandoned write is cleaned up when
	// the store is opened; a recent one may be a write in progress elsewhere.
	old := filepath.Join(dir, "link", ".tmp-old")
	if err := os.WriteFile(old, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-2 * staleTemporaryAge)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDirStore(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the abandoned temporary file is still there (%v)", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "link", ".tmp-123")); err != nil {
		t.Errorf("a recent temporary file was removed: %v", err)
	}
}

func TestDirStoreNeedsAWritableDirectory(t *testing.T) {
	if _, err := NewDirStore("  "); err == nil {
		t.Error("an empty directory name was accepted")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: every directory is writable")
	}
	parent := t.TempDir()
	readonly := filepath.Join(parent, "ro")
	if err := os.Mkdir(readonly, 0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDirStore(readonly); err == nil {
		t.Error("a directory that cannot be written to was accepted")
	}
}

func TestS3StoreKeysAndErrors(t *testing.T) {
	ctx := context.Background()
	s, fake := newS3TestStore(t, "/proxy/cache/userlinks")
	if err := s.Put(ctx, "link/abc", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	_, ok := fake.objects["proxy/cache/userlinks/link/abc.json"]
	// Objects of other software under the same prefix, and other prefixes, are
	// not the registry's.
	fake.objects["proxy/cache/userlinks/link/readme.txt"] = []byte("x")
	fake.objects["proxy/cache/meta/aa/bb/thing.json"] = []byte("x")
	fake.objects["proxy/cache/userlinks/Link/UPPER.json"] = []byte("x")
	fake.mu.Unlock()
	if !ok {
		t.Fatalf("the object is not under the configured prefix: %v", keysOf(fake))
	}
	objs, err := s.List(ctx)
	if err != nil || len(objs) != 1 || objs[0].Name != "link/abc" {
		t.Fatalf("List = %v, %v; want only link/abc", objs, err)
	}

	fake.mu.Lock()
	fake.fail = true
	fake.mu.Unlock()
	if _, err := s.List(ctx); err == nil {
		t.Error("List succeeded against a failing bucket")
	}
	if _, err := s.Get(ctx, "link/abc"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Get against a failing bucket = %v; a failure must not read as \"not found\"", err)
	}
	if err := s.Put(ctx, "link/def", []byte(`{}`)); err == nil {
		t.Error("Put succeeded against a failing bucket")
	}
}

func keysOf(f *fakeS3) []string {
	var out []string
	for k := range f.objects {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
