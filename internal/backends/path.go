package backends

import (
	"net/url"
	"strings"
)

// dotSegmentDecodeRounds is how many further rounds of percent-decoding
// HasDotSegment looks through. One round has already been applied by the HTTP
// server to the path it is given; a backend that splices that path into an
// upstream URL as a string hands the upstream a second chance to decode, and a
// lenient upstream or an intermediary a third.
const dotSegmentDecodeRounds = 2

// HasDotSegment reports whether a decoded request path holds a "." or ".."
// segment — plainly, behind a path parameter, behind a backslash, or behind
// another layer of percent-encoding.
//
// No package manager, registry client or Git client sends one: each resolves
// relative references before it puts a request on the wire. A path that still
// has one when it reaches a backend arrived in an encoded form ("%2e%2e" —
// the HTTP mux canonicalizes the plain spelling away, but matches on the
// escaped path and so lets that one through), and it means the request
// addresses something other than what its path reads as. The upstream that
// eventually receives it removes the segment, together with the one before a
// "..", and answers for the resulting path — with the proxy's credentials on
// the request, and with the proxy having classified, cached and gated the
// response as whatever the original path looked like.
//
// The variants are the ways a dot segment survives a naive check:
//
//   - "..;x": a servlet container (Tomcat under Artifactory, Jetty under Nexus)
//     strips the ";name=value" path parameter before it normalizes.
//   - "..\": IIS and some application servers treat a backslash as a separator.
//   - "%2e%2e" inside the already-decoded path (sent as "%252e%252e"): decoded
//     by whichever hop decodes once more.
func HasDotSegment(p string) bool {
	for round := 0; ; round++ {
		if hasPlainDotSegment(p) {
			return true
		}
		if round == dotSegmentDecodeRounds || !strings.Contains(p, "%") {
			return false
		}
		dec, err := url.PathUnescape(p)
		if err != nil || dec == p {
			// Not an escape sequence to anything downstream either.
			return false
		}
		p = dec
	}
}

// hasPlainDotSegment checks one decoding of a path.
func hasPlainDotSegment(p string) bool {
	for p != "" {
		seg := p
		if i := strings.IndexAny(p, `/\`); i >= 0 {
			seg, p = p[:i], p[i+1:]
		} else {
			p = ""
		}
		seg, _, _ = strings.Cut(seg, ";")
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}
