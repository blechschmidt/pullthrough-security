//go:build fuzz
// +build fuzz

package fullmirror

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"
)

// FuzzSnapshotRead feeds arbitrary bytes to the readers of a stored copy (a
// damaged or planted state file): reading the header, looking a package up,
// listing and reading every record must fail cleanly, never panic.
func FuzzSnapshotRead(f *testing.F) {
	dir := f.TempDir()
	fs := files{dir: dir}
	b := fs.newSnapBuilder("test")
	for _, r := range snapTestRecords() {
		b.Add(r)
	}
	h, err := b.Finish()
	if err != nil {
		f.Fatal(err)
	}
	valid, err := os.ReadFile(fs.path(snapName(h.Digest)))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(valid[:len(valid)/2])
	f.Add([]byte(snapMagic))
	var pre [len(snapMagic) + 8]byte
	copy(pre[:], snapMagic)
	binary.BigEndian.PutUint64(pre[len(snapMagic):], 1<<40)
	f.Add(pre[:])
	f.Fuzz(func(t *testing.T, data []byte) {
		d := t.TempDir()
		ff := files{dir: d}
		// Name the file by the digest its header claims, so the readers get
		// past the name check.
		digest := h.Digest
		if i := bytes.Index(data, []byte(`"digest":"`)); i >= 0 && len(data) >= i+10+64 {
			if cand := string(data[i+10 : i+10+64]); snapIsDigest(cand) {
				digest = cand
			}
		}
		if err := os.WriteFile(ff.path(snapName(digest)), data, 0o644); err != nil {
			t.Fatal(err)
		}
		hdr, err := ff.readSnapHeader(digest, "test")
		if err != nil {
			return
		}
		for _, name := range []string{"curl", "zlib", "zzz", ""} {
			_, _ = ff.snapLookup(hdr, name)
		}
		_, _, _ = ff.snapListNames(hdr, "", 5)
		_, _, _ = ff.snapListNames(hdr, "foo", 5)
		r, err := ff.openSnapshot(hdr, true)
		if err != nil {
			return
		}
		n := 0
		for r.Next() {
			n++
		}
		r.Close()
		if r.Err() == nil {
			// It read back: it must be a copy of exactly these records.
			sum := sha256.New()
			r2, _ := ff.openSnapshot(hdr, false)
			for r2.Next() {
				sum.Write(r2.Line())
				sum.Write([]byte{'\n'})
			}
			r2.Close()
			if hex.EncodeToString(sum.Sum(nil)) != digest || n != hdr.Records {
				t.Fatalf("a copy read back that does not match its digest")
			}
		}
	})
}

// FuzzSnapshotRecords stores arbitrary records and reads them back: whatever
// the builder keeps, a lookup finds, and two builds of the same records are
// the same copy.
func FuzzSnapshotRecords(f *testing.F) {
	f.Add("zlib", "1.3", "/pool/z/zlib.deb", "main", int64(5), int64(7), "ab", true, "curl", "8")
	f.Add(`q"u\o`, "", "", "", int64(0), int64(0), "", false, `q"u`, "1")
	f.Add("a!", "1", "/a", "", int64(1), int64(1), "", false, "a", "1")
	f.Fuzz(func(t *testing.T, n1, v1, p1, i1 string, s1, t1 int64, d1 string, y1 bool, n2, v2 string) {
		recs := []snapRecord{
			{Name: n1, Version: v1, Path: p1, Index: i1, Size: s1, Time: t1, Digest: d1, Yanked: y1},
			{Name: n2, Version: v2},
			{Name: n1, Version: v2, Path: p1},
		}
		fs := files{dir: t.TempDir()}
		build := func(order []int) *snapHeader {
			b := fs.newSnapBuilder("test")
			for _, i := range order {
				b.Add(recs[i])
			}
			h, err := b.Finish()
			if err != nil {
				t.Fatal(err)
			}
			return h
		}
		h1, h2 := build([]int{0, 1, 2}), build([]int{2, 1, 0, 1})
		if h1.Digest != h2.Digest {
			t.Fatalf("the same records made two copies")
		}
		for _, r := range recs {
			if !r.valid() {
				continue
			}
			got, err := fs.snapLookup(h1, r.Name)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, g := range got {
				if g == r {
					found = true
				}
			}
			if !found {
				t.Fatalf("lookup %q does not find %+v in %+v", r.Name, r, got)
			}
		}
	})
}
