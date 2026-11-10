package pypiattest

import (
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

// digestBinds assesses whether a parsed in-toto statement binds the artifact's
// content digest. Binding is algorithm-aware: when the artifact digest's
// algorithm does not appear in any subject the binding is "not checkable"
// (checked=false) rather than a failure; when the algorithm IS present the hex
// must match (checked=true, ok=match). PyPI PEP 740 subjects bind sha256, which
// matches the proxy's content digest for a wheel/sdist. An empty artifact digest
// or a statement with no subjects is treated as not checkable.
func digestBinds(statement *sigverify.Statement, artDigest string) (checked, ok bool) {
	if statement == nil {
		return false, false
	}
	algo, hex, found := strings.Cut(strings.ToLower(strings.TrimSpace(artDigest)), ":")
	if !found || algo == "" || hex == "" {
		return false, false
	}
	for _, sub := range statement.Subject {
		for a, h := range sub.Digest {
			if strings.EqualFold(a, algo) {
				checked = true
				if strings.EqualFold(h, hex) {
					return true, true
				}
			}
		}
	}
	return checked, false
}
