//go:build fuzz
// +build fuzz

// Fuzz targets for the huggingface feed's parsers (Task 191): a listing page,
// its Link header, a repository's metadata, the RateLimit header of a 429
// and the listing tokens the cursor carries. None of them may panic; what
// they accept must stay bounded and well formed.
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzHuggingFaceListing$' -fuzztime=20s ./internal/fullmirror/
package fullmirror

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/huggingface"
)

func FuzzHuggingFaceListing(f *testing.F) {
	for i := 1; i <= 5; i++ {
		f.Add(fixture(f, "huggingface", "models-smolvlm-page"+string(rune('0'+i))+".json"))
	}
	f.Add(fixture(f, "huggingface", "datasets-fka-page1.json"))
	f.Add([]byte(`[{"_id":1,"id":"a/b","lastModified":"2026-13-01T00:00:00Z","sha":null},{"id":"a\u0000b","lastModified":"2026-01-01T00:00:00Z"}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		items, err := huggingfaceParseListing(data)
		if err != nil {
			return
		}
		for _, it := range items {
			li := it.listing()
			if !li.valid() || li.Time.IsZero() || li.Version != "" || !huggingfaceValidRepoID(li.Name) {
				t.Fatalf("item %+v", li)
			}
		}
	})
}

func FuzzHuggingFaceLink(f *testing.F) {
	for _, l := range strings.Split(strings.TrimSuffix(string(fixture(f, "huggingface", "models-smolvlm-links.txt")), "\n"), "\n") {
		f.Add(l)
	}
	for _, s := range []string{`<https://huggingface.co/api/models?cursor=x>; rel="prev", <https://huggingface.co/api/models?cursor=y>; rel=next`,
		`<>; rel=next`, `<https://huggingface.co/api/models?cursor=%zz>; rel="next"`, `<, >`, `>`, `<https://evil.example/api/models?cursor=a>; rel="next"`} {
		f.Add(s)
	}
	src := &huggingfaceSource{api: &url.URL{Scheme: "https", Host: "huggingface.co"}, kind: "models"}
	f.Fuzz(func(t *testing.T, link string) {
		for _, served := range []*url.URL{nil, {Scheme: "https", Host: "evil.example", Path: "/api/models"}} {
			c, err := src.nextCursor([]string{link}, served)
			if err != nil {
				continue
			}
			if c != "" && !huggingfaceValidCursor(c) || len(c) > huggingfaceMaxCursor || strings.ContainsAny(c, "\x00\r\n") {
				t.Fatalf("cursor %q", c)
			}
		}
	})
}

func FuzzHuggingFaceRevision(f *testing.F) {
	for _, name := range []string{"revision-smolvlm-256m-instruct.json", "revision-llama-3.2-1b.json", "revision-prompts-chat.json"} {
		f.Add(fixture(f, "huggingface", name))
	}
	f.Add([]byte(`{"sha":"x","siblings":[{"rfilename":"a/../b"},{"rfilename":5}],"gated":true}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		rev, err := huggingfaceParseRevision(data)
		if err != nil {
			return
		}
		if len(rev.files) > huggingfaceMaxFiles || (rev.sha != "" && !huggingfaceIsSHA(rev.sha)) {
			t.Fatalf("%+v", rev)
		}
		for _, file := range rev.files {
			if file == "" || !snapValidString(file, 1024) {
				t.Fatalf("file %q", file)
			}
			if rev.sha != "" {
				if p, ok := huggingface.ResolvePath(huggingface.RepoModel, "o/m", rev.sha, file); ok && !validArtifactPath(p) {
					t.Fatalf("path %q", p)
				}
			}
		}
	})
}

func FuzzHuggingFaceRateLimit(f *testing.F) {
	for _, s := range []string{`"api";r=0;t=42`, `"api";r=3;t=42`, `"pages";r=10;t=5, "api";r=0;t=99`, `r=0;t=-1`, `;;;=`, `"api";r=0;t=99999999999999999999`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		d, ok := huggingfaceRateLimitReset(v)
		if ok && (d <= 0 || d > maxRetryAfter) {
			t.Fatalf("%q: %s", v, d)
		}
	})
}

// FuzzHuggingFaceToken feeds arbitrary page tokens to the listing source, as
// a damaged cursor would: each is refused as an invalid cursor, or reads as
// the token it is written as, within the listing driver's bound.
func FuzzHuggingFaceToken(f *testing.F) {
	src := &huggingfaceSource{api: &url.URL{Scheme: "https", Host: "huggingface.co"}, authors: []string{"a", "b"}, kind: "models", limit: huggingfacePageSize}
	links := strings.Split(strings.TrimSuffix(string(fixture(f, "huggingface", "models-smolvlm-links.txt")), "\n"), "\n")
	cursor, err := src.nextCursor(links[:1], nil)
	if err != nil || cursor == "" {
		f.Fatalf("the recorded cursor: %q %v", cursor, err)
	}
	for _, s := range []string{src.passToken(1, time.Unix(1794744532, 0), cursor), src.passToken(0, time.Unix(0, 0), ""), src.everyToken(1, cursor),
		src.everyToken(0, ""), "0:01:", "0:1:a b", "2:", "e30", "!!"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, token string) {
		ctx := context.Background()
		author, ceiling, cur, err := src.parsePassToken(token)
		switch {
		case err != nil && !errors.Is(err, ErrCursorInvalid):
			t.Fatalf("parsePassToken(%q): %v", token, err)
		case err == nil && token != "" && src.passToken(author, ceiling, cur) != token:
			t.Fatalf("pass token %q reads as %d %s %q", token, author, ceiling, cur)
		case err == nil && len(token) > listingMaxToken:
			t.Fatalf("pass token of %d bytes", len(token))
		}
		passErr := err
		author, cur, err = src.parseEveryToken(token)
		switch {
		case err != nil && !errors.Is(err, ErrCursorInvalid):
			t.Fatalf("parseEveryToken(%q): %v", token, err)
		case err == nil && token != "" && src.everyToken(author, cur) != token:
			t.Fatalf("enumeration token %q reads as %d %q", token, author, cur)
		case err == nil && len(token) > listingMaxToken:
			t.Fatalf("enumeration token of %d bytes", len(token))
		}
		// Without an HTTP client nothing is read: a token that reads fails on
		// the request, one that does not as an invalid cursor.
		src.setPass(&huggingfacePass{})
		if _, rerr := src.recent(ctx, token); rerr == nil || (passErr != nil) != errors.Is(rerr, ErrCursorInvalid) {
			t.Fatalf("recent(%q) in a pass: %v (token: %v)", token, rerr, passErr)
		}
		src.setPass(nil)
		if _, rerr := src.recent(ctx, token); rerr == nil || (token != "") != errors.Is(rerr, ErrCursorInvalid) {
			t.Fatalf("recent(%q) outside a pass: %v", token, rerr)
		}
		if _, rerr := src.every(ctx, token); rerr == nil || (err != nil) != errors.Is(rerr, ErrCursorInvalid) {
			t.Fatalf("every(%q): %v (token: %v)", token, rerr, err)
		}
	})
}
