//go:build integration
// +build integration

// Integration tests for the CRAN backend against the live CRAN cloud mirror
// (https://cloud.r-project.org). Gated behind the `integration` build tag (and
// skipped when the network is unavailable) so the default `go test ./...` stays
// hermetic, mirroring internal/git's and the other backends' convention.
//
// Run with:
//
//	go test -tags integration ./internal/backends/cran/
package cran

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

const liveCRAN = "https://cloud.r-project.org"

func liveBackend(t *testing.T, m *Metrics) *Backend {
	t.Helper()
	hc := &http.Client{Timeout: 60 * time.Second}
	b, err := New(Options{
		Name:        "cran-live",
		UpstreamURL: liveCRAN,
		Client:      upstream.NewWithHTTPClient(hc, "pullthrough-integration/1"),
		Metrics:     m,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func skipIfOffline(t *testing.T, err error) {
	t.Helper()
	var ne net.Error
	if errors.As(err, &ne) || errors.Is(err, context.DeadlineExceeded) {
		t.Skipf("network unavailable: %v", err)
	}
}

func liveFetch(t *testing.T, b *Backend, path string) (*backends.FetchResult, []byte) {
	t.Helper()
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}})
	if err != nil {
		t.Fatalf("Resolve(%q): %v", path, err)
	}
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		skipIfOffline(t, err)
		t.Fatalf("Fetch(%q): %v", path, err)
	}
	body, rerr := io.ReadAll(fr.Content)
	_ = fr.Content.Close()
	if rerr != nil {
		var mm *ChecksumMismatchError
		if errors.As(rerr, &mm) {
			t.Fatalf("live content failed verification: %v", rerr)
		}
		skipIfOffline(t, rerr)
		t.Fatalf("read body for %q: %v", path, rerr)
	}
	fr.Resolved = res
	return fr, body
}

// TestLiveSourceFlow drives a real source package end-to-end: fetch the
// src/contrib PACKAGES index, pick the first package stanza, then download its
// tarball through the backend and confirm the backend verified it against the
// MD5sum the index declared.
func TestLiveSourceFlow(t *testing.T) {
	m := &Metrics{}
	b := liveBackend(t, m)

	_, packages := liveFetch(t, b, "/src/contrib/PACKAGES")
	pkg, version := firstStanza(packages)
	if pkg == "" || version == "" {
		t.Skip("could not parse a package from live PACKAGES")
	}

	path := "/src/contrib/" + pkg + "_" + version + ".tar.gz"
	fr, body := liveFetch(t, b, path)
	if len(body) == 0 {
		t.Fatalf("%s was empty", path)
	}
	if fr.Resolved.Metadata[MetaChecksumVerified] != "md5" {
		t.Errorf("%s was not MD5-verified: %q", path, fr.Resolved.Metadata[MetaChecksumVerified])
	}
	if st := m.Stats(); st.PackagesVerified < 1 || st.PackagesFetched < 1 {
		t.Errorf("verification metrics not recorded: %+v", st)
	}
}

// firstStanza returns the Package and Version of the first stanza in a PACKAGES
// document.
func firstStanza(data []byte) (pkg, version string) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			if pkg != "" && version != "" {
				return pkg, version
			}
			continue
		}
		if strings.HasPrefix(line, "Package:") {
			pkg = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
		} else if strings.HasPrefix(line, "Version:") {
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
		if pkg != "" && version != "" {
			return pkg, version
		}
	}
	return pkg, version
}
