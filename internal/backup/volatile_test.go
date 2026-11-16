package backup

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// hookStore runs a hook on the second read of a blob: between the backup's
// manifest pass and its streaming pass, when a running proxy goes on writing.
type hookStore struct {
	*cache.FilesystemStore
	gets int
	hook func()
}

func (s *hookStore) Get(ctx context.Context, key string) (io.ReadCloser, cache.Record, error) {
	s.gets++
	if s.gets == 2 && s.hook != nil {
		s.hook()
	}
	return s.FilesystemStore.Get(ctx, key)
}

// rewrite replaces a file the way the full mirror does: written aside,
// renamed over it.
func rewrite(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// A volatile source rewritten while the backup runs is archived as it was
// read, and restores to that version; the same rewrite of an ordinary source
// fails the backup, as it always has.
func TestVolatileSourceIsCapturedOnce(t *testing.T) {
	store := &hookStore{FilesystemStore: newStore(t)}
	put(t, store, "npm:a/-/a-1.0.0.tgz", "a-content")
	dir := t.TempDir()
	writeFile(t, dir, "upstreams/npm/state.json", `{"cursor":"seq:1"}`)
	writeFile(t, dir, "upstreams/npm/batch.json", `{"seq":1}`)
	writeFile(t, dir, "control.json", `{}`)
	statePath := filepath.Join(dir, "upstreams/npm/state.json")
	store.hook = func() {
		rewrite(t, statePath, `{"cursor":"seq:2, and longer"}`)
		_ = os.Remove(filepath.Join(dir, "upstreams/npm/batch.json"))
	}
	spoolParent := t.TempDir()
	buf, res := backupToBuffer(t, Options{Cache: store, SpoolDir: spoolParent, Sources: []MetadataSource{
		{Name: "full-mirror", Path: dir, Optional: true, Volatile: true},
	}})
	if res.MetadataFiles != 3 {
		t.Fatalf("MetadataFiles = %d, want 3", res.MetadataFiles)
	}
	if left, _ := os.ReadDir(spoolParent); len(left) != 0 {
		t.Errorf("the spool was left behind: %v", left)
	}
	restored := t.TempDir()
	if _, err := NewRestorer().Restore(context.Background(), bytes.NewReader(buf.Bytes()), RestoreOptions{
		Cache: newStore(t), Targets: map[string]string{"full-mirror": restored}, ExpectedManifestDigest: res.ManifestDigest,
	}); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(restored, "upstreams/npm/state.json")); string(got) != `{"cursor":"seq:1"}` {
		t.Errorf("restored state.json = %q, want the version the backup read", got)
	}
	if got, _ := os.ReadFile(filepath.Join(restored, "upstreams/npm/batch.json")); string(got) != `{"seq":1}` {
		t.Errorf("restored batch.json = %q", got)
	}

	// The same rewrite of an ordinary source fails the backup.
	writeFile(t, dir, "upstreams/npm/state.json", `{"cursor":"seq:1"}`)
	store.gets = 0
	store.hook = func() { rewrite(t, statePath, `{"cursor":"seq:3, and longer still"}`) }
	_, err := NewBackuper().Backup(context.Background(), io.Discard, Options{Cache: store, Sources: []MetadataSource{
		{Name: "full-mirror", Path: dir, Optional: true},
	}})
	if err == nil {
		t.Fatal("an ordinary source rewritten mid-backup did not fail the backup")
	}
}

// A file that disappears between the walk and the copy is left out.
func TestVolatileFileThatVanishesIsLeftOut(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "keep.json", "k")
	s := &spool{parent: t.TempDir()}
	defer s.remove()
	if _, _, _, err := s.capture(filepath.Join(dir, "gone.json")); !os.IsNotExist(err) {
		t.Fatalf("capture of a missing file: %v", err)
	}
	p, digest, fi, err := s.capture(filepath.Join(dir, "keep.json"))
	if err != nil || fi.Size() != 1 || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("capture: %q %q %v %v", p, digest, fi, err)
	}
	if got, _ := os.ReadFile(p); string(got) != "k" {
		t.Errorf("spool copy %q", got)
	}
}

// A store's temporary files (written aside, then renamed into place) are left
// out of the snapshot.
func TestIgnoredFilesAreLeftOut(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "upstreams/npm/state.json", "{}")
	writeFile(t, dir, "upstreams/npm/.tmp-state.json-123", "{half")
	_, files, err := scanSource(MetadataSource{Name: "full-mirror", Path: dir, Volatile: true, Ignore: []string{".tmp-*"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].relPath != "upstreams/npm/state.json" {
		t.Errorf("files %+v", files)
	}
}
