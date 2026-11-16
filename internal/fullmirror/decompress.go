package fullmirror

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/contentscan"
)

// This file reads the large documents the index-polling adapters follow
// (Task 191) as streams: an APT Packages file, a YUM primary.xml or a conda
// repodata.json runs to hundreds of megabytes once decompressed, and is parsed
// as it arrives rather than held in memory.

// errNotModified is what getStream reports for a 304.
var errNotModified = fmt.Errorf("not modified")

// getStream sends a GET for rawURL and returns the response of a 2xx answer,
// its body cut off with an error past limit bytes. A 304 is errNotModified;
// any other answer is an error httpStatusError classifies. The caller closes
// the body.
func (k kit) getStream(ctx context.Context, rawURL string, hdr http.Header, limit int64) (*http.Response, io.ReadCloser, error) {
	resp, err := k.do(ctx, http.MethodGet, rawURL, nil, hdr)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode == http.StatusNotModified {
		drain(resp.Body)
		return resp, nil, errNotModified
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer drain(resp.Body)
		return resp, nil, httpStatusError(rawURL, resp)
	}
	return resp, &limitedBody{r: resp.Body, c: resp.Body, left: limit, what: rawURL}, nil
}

// limitedBody fails a read past its limit, permanently: a document larger than
// the adapter reads is refused, not truncated.
type limitedBody struct {
	r    io.Reader
	c    io.Closer
	left int64
	what string
}

func (l *limitedBody) Read(p []byte) (int, error) {
	if l.left <= 0 {
		// Anything more is past the limit; a clean end is not.
		var one [1]byte
		if n, err := l.r.Read(one[:]); n > 0 {
			return 0, Permanent(fmt.Errorf("%s: %w", l.what, errTooLarge))
		} else if err != nil {
			return 0, err
		}
		return 0, nil
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}

func (l *limitedBody) Close() error {
	if l.c != nil {
		return l.c.Close()
	}
	return nil
}

// openContent returns a reader of a document's content: decompressed when it
// begins with the signature of gzip, bzip2, xz or zstd — the decoder's memory
// bounded, as it is for the content scan (contentscan.OpenCompressed: an xz
// dictionary or a zstd window larger than the strongest presets use is
// refused) — and as it is otherwise. Reading past limit bytes of content
// fails permanently. The returned function releases the decoder.
func openContent(r io.Reader, what string, limit int64) (io.Reader, func(), error) {
	br := bufio.NewReaderSize(r, 64<<10)
	dec, release, compressed, err := contentscan.OpenCompressed(br)
	if err != nil {
		release()
		return nil, func() {}, Permanent(fmt.Errorf("%s does not decompress: %w", what, err))
	}
	var src io.Reader = br
	if compressed {
		src = dec
	}
	return &limitedBody{r: src, left: limit, what: what + " (decompressed)"}, release, nil
}
