//go:build fuzz
// +build fuzz

// Fuzz targets for the pkt-line sniffers that tell the download log (Task 176)
// which Git requests transfer content.
//
// Both read what a Git client sends, before anything has vouched for it: the
// body of an HTTP upload-pack request, and the client's side of an SSH session.
// The SSH sniffer runs on the goroutine that feeds the client's stream to
// git-upload-pack, where a panic would take the whole proxy down, so "never
// panics, never alters the stream" is the property that matters most. The
// second is that the answer depends on what the client sent, not on how the
// network happened to cut it into reads.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run='^$' -fuzz=FuzzFetchSniffer ./internal/git/
package git

import (
	"bytes"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"testing"
)

// pktSeeds are upload-pack client streams: well-formed, truncated and hostile.
var pktSeeds = []string{
	"",
	"0000",
	"0032want 95dcfa3633004da0049d3d0fa03f80589cbcaf31\n00000009done\n",
	"0014command=ls-refs\n0001000bpeel\n0000",
	"0012command=fetch\n0001000ethin-pack\n0032want 95dcfa3633004da0049d3d0fa03f80589cbcaf31\n0009done\n0000",
	"0014command=ls-refs\n00000012command=fetch\n0000",
	"0011command=fetch0000",
	"0016command=fetch-not\n",
	"0012COMMAND=fetch\n",
	"000fwant abcde\n",
	"000Fwant abcde\n",
	"000100020000",
	"0004",
	"0003",
	"ffff" + "want ",
	"fff",
	"zzzz0012command=fetch\n",
	"0012command=fet",
	"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff",
	"0023agent=git/2.43.0 want 95dcfa36\n0000",
}

// FuzzFetchSniffer feeds an arbitrary client stream through the SSH sniffer in
// one read and again in small reads. Neither may panic or alter the stream, and
// both must reach the same verdict.
func FuzzFetchSniffer(f *testing.F) {
	for _, s := range pktSeeds {
		f.Add([]byte(s), uint8(1))
		f.Add([]byte(s), uint8(3))
		f.Add([]byte(s), uint8(7))
	}
	f.Fuzz(func(t *testing.T, data []byte, chunk uint8) {
		whole := &fetchSniffer{r: bytes.NewReader(data)}
		got, err := io.ReadAll(whole)
		if err != nil {
			t.Fatalf("reading through the sniffer: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("the sniffer altered the stream: %d bytes in, %d out", len(data), len(got))
		}

		size := int(chunk)%16 + 1
		pieces := &fetchSniffer{r: &chunkReader{data: append([]byte(nil), data...), chunk: size}}
		got, err = io.ReadAll(pieces)
		if err != nil {
			t.Fatalf("reading through the sniffer in %d-byte reads: %v", size, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("the sniffer altered the stream when read %d bytes at a time", size)
		}
		if pieces.fetch != whole.fetch {
			t.Fatalf("the verdict depends on how the stream is cut: fetch=%v in one read, %v in %d-byte reads",
				whole.fetch, pieces.fetch, size)
		}

	})
}

// refListingOracle is an independent reading of "this request body transfers no
// objects": collect the lines up to the first delimiter or flush, the way a
// server does, and require exactly one command among them — a ref-only one —
// and no want line. (Or no request at all: nothing, or a lone flush.)
func refListingOracle(body []byte) bool {
	if len(body) == 0 || string(body) == "0000" {
		return true
	}
	var commands []string
	rest := body
	for {
		if len(rest) < 4 {
			return false
		}
		n := 0
		for _, c := range rest[:4] {
			switch {
			case c >= '0' && c <= '9':
				n = n*16 + int(c-'0')
			case c >= 'a' && c <= 'f':
				n = n*16 + int(c-'a') + 10
			case c >= 'A' && c <= 'F':
				n = n*16 + int(c-'A') + 10
			default:
				return false
			}
		}
		if n == 0 || n == 1 {
			break // flush or delimiter: the end of what names the command
		}
		if n < 4 || n > len(rest) {
			return false
		}
		line := strings.TrimSuffix(string(rest[4:n]), "\n")
		rest = rest[n:]
		if strings.HasPrefix(line, "want ") {
			return false
		}
		if strings.HasPrefix(line, "command=") {
			commands = append(commands, strings.TrimPrefix(line, "command="))
		}
	}
	if len(commands) != 1 {
		return false
	}
	switch commands[0] {
	case "ls-refs", "object-info", "bundle-uri":
		return true
	}
	return false
}

// FuzzAsksForNothingButRefs checks the decision that keeps a request out of the
// download log. It may only ever be made for a body that is a ref listing, and
// it must not depend on how much of the body was examined: what lies beyond the
// window cannot turn a request that was vouched for into a fetch.
func FuzzAsksForNothingButRefs(f *testing.F) {
	for _, s := range pktSeeds {
		f.Add([]byte(s), uint16(0))
		f.Add([]byte(s), uint16(9))
	}
	f.Add([]byte("0014command=ls-refs\n0015agent=git/2.43.0\n00010009peel\n0000"), uint16(30))
	f.Add([]byte("0015agent=git/2.43.0\n0012command=fetch\n0001"), uint16(0))
	f.Fuzz(func(t *testing.T, body []byte, cut uint16) {
		whole := asksForNothingButRefs(body, true)
		if whole && !refListingOracle(body) {
			t.Fatalf("%q is kept out of the log, and is not a ref listing", body)
		}
		// Examine only a prefix, as a body longer than the window is.
		k := int(cut) % (len(body) + 1)
		if asksForNothingButRefs(body[:k], false) && !whole {
			t.Fatalf("the first %d bytes of %q are taken for a ref listing; all of it is not", k, body)
		}
	})
}

// FuzzDescribeDownload sends an arbitrary body — plain or declared gzip — as an
// upload-pack request. Classifying it must not panic, and whatever the verdict,
// the handler that runs next must still read exactly the body the client sent.
func FuzzDescribeDownload(f *testing.F) {
	for _, s := range pktSeeds {
		f.Add([]byte(s), false)
		f.Add([]byte(s), true)
	}
	f.Add(bytes.Repeat([]byte("0032want 95dcfa3633004da0049d3d0fa03f80589cbcaf31\n"), 64), false)
	f.Fuzz(func(t *testing.T, body []byte, gzipped bool) {
		// Telling a fetch from a ref listing needs nothing of the backend but
		// the request, so the zero Backend serves.
		b := &Backend{}
		r := uploadPackRequest(body, gzipped)
		d, ok := b.DescribeDownload(r, "/octocat/Hello-World.git/git-upload-pack")
		if ok && d.Name == "" {
			t.Fatal("a download was reported without a repository name")
		}
		rest, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading the body after it was examined: %v", err)
		}
		if !bytes.Equal(rest, body) {
			t.Fatalf("the body was altered by examining it: %d bytes sent, %d left", len(body), len(rest))
		}
	})
}

// FuzzParseTree: a tree object comes from a repository nobody vouched for (the
// lock-file scanner of Task 178 walks commits through ObjectReader). The parser
// never panics, accepts only entries a checkout could produce, and reads its
// own canonical writing of what it accepted back to the same entries.
func FuzzParseTree(f *testing.F) {
	hash := bytes.Repeat([]byte{0xab}, 20)
	entry := func(mode, name string) []byte { return append([]byte(mode+" "+name+"\x00"), hash...) }
	f.Add(bytes.Join([][]byte{entry("100644", "a"), entry("40000", "d"), entry("160000", "m"), entry("120000", "s")}, nil), 20)
	f.Add(entry("100755", "package-lock.json"), 20)
	f.Add(entry("040000", "zero-padded"), 20)
	f.Add(append([]byte("100644 x\x00"), bytes.Repeat([]byte{1}, 32)...), 32)
	f.Add([]byte("40000 ..\x00"), 20)
	f.Add([]byte("100644 a/b\x00"), 20)
	f.Add([]byte{}, 20)
	f.Fuzz(func(t *testing.T, data []byte, hashLen int) {
		if hashLen != 20 && hashLen != 32 {
			hashLen = 20
		}
		entries, err := parseTree(data, hashLen)
		if err != nil {
			return
		}
		var canonical []byte
		for _, e := range entries {
			if validEntryName(e.Name) != nil || len(e.ID) != 2*hashLen || !isHexID(e.ID) {
				t.Fatalf("accepted entry %+v", e)
			}
			raw, err := hex.DecodeString(e.ID)
			if err != nil || len(raw) != hashLen {
				t.Fatalf("entry ID %q is not %d bytes of hex", e.ID, hashLen)
			}
			canonical = append(canonical, []byte(strconv.FormatUint(uint64(e.Mode), 8)+" "+e.Name+"\x00")...)
			canonical = append(canonical, raw...)
		}
		again, err := parseTree(canonical, hashLen)
		if err != nil || len(again) != len(entries) {
			t.Fatalf("the canonical form does not parse: %v", err)
		}
		for i := range again {
			if again[i] != entries[i] {
				t.Fatalf("entry %d: %+v, then %+v", i, entries[i], again[i])
			}
		}
	})
}
