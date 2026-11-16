//go:build integration
// +build integration

package fullmirror

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// RubyGems: the adapter follows the compact index's /versions file with Range
// requests from the end of a stored copy (If-None-Match; the copy plus the
// tail checked against the file's Repr-Digest), and fetches the whole file and
// diffs it when the tail does not continue the copy. Each gem's versions come
// from /info/<gem>, read through the proxy.
//
// The stub serves /versions as rubygems.org does: one line per publication,
// appended in the order of publication under an unchanged created_at line,
// with its SHA-256 as Repr-Digest. (The LLM package-scan suite's registry
// lists its gems sorted by name, which suits a client reading the whole file
// but is not an append-only file: a server that rewrites /versions must also
// renew created_at, and one that states no digest leaves a client nothing else
// to tell a rewrite by.)

func init() {
	register(row{
		Type:    "rubygems",
		Feed:    "the compact index's `/versions`, appended per publication, Repr-Digest; read by Range from the stored end",
		Start:   rubygemsFeedStart,
		Options: func(*feedEnv) map[string]string { return nil },
		Resumed: rubygemsResumed,
	})
}

// rubygemsCreatedAt is the created_at line of the stub's /versions.
const rubygemsCreatedAt = "created_at: 2024-01-02T03:04:05Z"

func rubygemsFeedStart(env *feedEnv) error {
	env.Stub.Handle("/versions", func(w http.ResponseWriter, r *http.Request) {
		pubs := env.Publications()
		body, err := rubygemsVersions(env, pubs)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		digest := sha256.Sum256(body)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Repr-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest[:])+":")
		w.Header().Set("ETag", rubygemsVersionsETag(body))
		http.ServeContent(w, r, "", time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC).Add(time.Duration(len(pubs))*time.Minute), bytes.NewReader(body))
	})
	return nil
}

// rubygemsVersions is /versions as it is with the gems pubs published: a
// line per publication, in the order of publication, below the header.
func rubygemsVersions(env *feedEnv, pubs []publication) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(rubygemsCreatedAt + "\n---\n")
	for _, p := range pubs {
		info, err := env.fetch("/info/" + p.Pkg.Name)
		if err != nil {
			return nil, err
		}
		sum := md5.Sum(info)
		fmt.Fprintf(&b, "%s %s %s\n", p.Pkg.Name, p.Pkg.Version, hex.EncodeToString(sum[:]))
	}
	return b.Bytes(), nil
}

// rubygemsVersionsETag is the ETag the stub serves /versions with: of the
// whole file, whatever part of it an answer carries.
func rubygemsVersionsETag(body []byte) string {
	digest := sha256.Sum256(body)
	return fmt.Sprintf(`"%x"`, digest[:12])
}

// rubygemsResumed: the restarted mirror read the tail of /versions from the
// end of the copy it kept. Its first request for /versions asked for the
// range from the copy's last byte — the copy being the file as it was before
// the late gem, three lines — conditionally on the ETag it was served with
// (If-None-Match); the stub, whose file has a line more, answered with that
// part (206). No request for /versions after the restart was answered with
// the whole file (200): an adapter that lost its copy, or took the tail for a
// rewrite of the file, fetches it whole.
func rubygemsResumed(env *feedEnv, requests []string) error {
	pubs := env.Publications()
	if len(pubs) != 4 || pubs[3].Variant != pkgLate {
		return fmt.Errorf("%d gems published, the last %q; want the late gem fourth", len(pubs), pubs[len(pubs)-1].Variant)
	}
	before, err := rubygemsVersions(env, pubs[:3])
	if err != nil {
		return err
	}
	wantRange, wantETag := fmt.Sprintf("bytes=%d-", len(before)-1), rubygemsVersionsETag(before)
	log, err := restartLog(env, requests)
	if err != nil {
		return err
	}
	first := true
	for _, r := range log {
		if path, _, _ := strings.Cut(r.URI, "?"); path != "/versions" {
			continue
		}
		if first {
			first = false
			switch {
			case r.Method != http.MethodGet || r.Header.Get("Range") != wantRange:
				return fmt.Errorf("the restarted proxy's first request for /versions was %s with Range %q, want a GET with Range %s, from the last byte of the %d-byte copy kept before the restart (%s)",
					r.Method, r.Header.Get("Range"), wantRange, len(before), r)
			case r.Header.Get("If-None-Match") != wantETag:
				return fmt.Errorf("the restarted proxy's first request for /versions carried If-None-Match %q, want %s, the ETag the copy was served with (%s)", r.Header.Get("If-None-Match"), wantETag, r)
			case r.Status != http.StatusPartialContent:
				return fmt.Errorf("the restarted proxy's first request for /versions was answered %d, want 206 (the tail after the copy): %s", r.Status, r)
			}
		}
		if r.Status == http.StatusOK {
			return fmt.Errorf("the restarted proxy fetched the whole of /versions: %s", r)
		}
	}
	if first {
		return fmt.Errorf("/versions was not read after the restart")
	}
	return nil
}
