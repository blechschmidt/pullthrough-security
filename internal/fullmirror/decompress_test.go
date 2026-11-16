package fullmirror

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

func TestOpenContentDecompressesBounded(t *testing.T) {
	content := strings.Repeat("Package: foo\nVersion: 1\n\n", 1000)
	var gz, zs, x bytes.Buffer
	gw := gzip.NewWriter(&gz)
	gw.Write([]byte(content))
	gw.Close()
	zw, _ := zstd.NewWriter(&zs)
	zw.Write([]byte(content))
	zw.Close()
	xw, _ := xz.NewWriter(&x)
	xw.Write([]byte(content))
	xw.Close()
	for name, body := range map[string][]byte{"plain": []byte(content), "gzip": gz.Bytes(), "zstd": zs.Bytes(), "xz": x.Bytes()} {
		r, release, err := openContent(bytes.NewReader(body), name, int64(len(content)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := io.ReadAll(r)
		release()
		if err != nil || string(got) != content {
			t.Errorf("%s: read %d bytes, %v", name, len(got), err)
		}
		// One byte less than the content is refused, not truncated.
		r, release, _ = openContent(bytes.NewReader(body), name, int64(len(content))-1)
		_, err = io.ReadAll(r)
		release()
		if !errors.Is(err, errTooLarge) || !IsPermanent(err) {
			t.Errorf("%s past its limit: %v", name, err)
		}
	}
	// A broken stream is a permanent error.
	if _, _, err := openContent(bytes.NewReader([]byte{0x1f, 0x8b, 0x08, 0, 0, 0}), "x", 100); err == nil {
		r, release, _ := openContent(bytes.NewReader([]byte{0x1f, 0x8b, 0x08, 0, 0, 0}), "x", 100)
		if _, err := io.ReadAll(r); err == nil {
			t.Errorf("a truncated gzip stream read cleanly")
		}
		release()
	}
}

func TestGetStream(t *testing.T) {
	srv := newFixtureServer(t)
	srv.on("GET", "/index").json("0123456789").withHeader("ETag", `"v2"`).withHeader("Last-Modified", "Mon, 16 Nov 2026 10:00:00 GMT")
	srv.on("GET", "/index").requireHeader("If-None-Match", `"v1"`).reply(http.StatusNotModified, nil) // later routes win
	srv.on("GET", "/gone").reply(http.StatusNotFound, nil)
	k, err := newKit(testEnv(t, "test", srv.URL(), nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	hdr := http.Header{}
	httpValidators{ETag: `"v1"`}.set(hdr)
	if _, _, err := k.getStream(ctx, srv.URL()+"/index", hdr, 100); !errors.Is(err, errNotModified) {
		t.Errorf("conditional GET: %v", err)
	}
	resp, body, err := k.getStream(ctx, srv.URL()+"/index", nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(body)
	body.Close()
	if string(data) != "0123456789" || validatorsOf(resp) != (httpValidators{ETag: `"v2"`, LastModified: "Mon, 16 Nov 2026 10:00:00 GMT"}) {
		t.Errorf("body %q validators %+v", data, validatorsOf(resp))
	}
	_, body, _ = k.getStream(ctx, srv.URL()+"/index", nil, 9)
	if _, err := io.ReadAll(body); !errors.Is(err, errTooLarge) {
		t.Errorf("a body past the limit: %v", err)
	}
	body.Close()
	if _, _, err := k.getStream(ctx, srv.URL()+"/gone", nil, 100); !IsPermanent(err) {
		t.Errorf("404: %v", err)
	}
}
