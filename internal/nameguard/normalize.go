package nameguard

import "strings"

// normalizeName folds a package name to the comparison form used for equality and
// edit-distance, applying the equivalences each registry treats as identical:
//
//   - pip: PEP 503 normalization — lowercase, runs of [-_.] collapsed to a single
//     hyphen.
//   - npm: lowercase; scope and name preserved (the "@scope/name" shape matters
//     for namespace-mismatch detection).
//   - cargo: lowercase, "_" folded to "-" (crates.io treats them as confusable).
//   - nuget: lowercase (case-insensitive registry; dots are significant).
//   - go: lowercase module path; trailing slash trimmed.
//
// The result is only for comparison; the raw name is retained for homoglyph and
// display purposes.
func normalizeName(ecosystem, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	switch strings.ToLower(ecosystem) {
	case "pip", "pypi", "python":
		return collapseSeparators(strings.ToLower(name), true)
	case "cargo", "crates", "rust":
		return strings.ReplaceAll(strings.ToLower(name), "_", "-")
	case "npm", "node":
		return strings.ToLower(name)
	case "nuget", "dotnet":
		return strings.ToLower(name)
	case "go", "golang", "gomod":
		return strings.TrimRight(strings.ToLower(name), "/")
	default:
		return strings.ToLower(name)
	}
}

// collapseSeparators lowercases-agnostically collapses runs of the separator set
// to a single hyphen (PEP 503). When foldDot is false, '.' is left intact.
func collapseSeparators(s string, foldDot bool) string {
	var b strings.Builder
	b.Grow(len(s))
	prevSep := false
	for _, r := range s {
		sep := r == '-' || r == '_' || (foldDot && r == '.')
		if sep {
			if !prevSep {
				b.WriteByte('-')
			}
			prevSep = true
			continue
		}
		prevSep = false
		b.WriteRune(r)
	}
	return strings.Trim(b.String(), "-")
}

// scopeOf returns the namespace/scope component of a normalized name for the
// ecosystems that have one (npm "@scope" from "@scope/name", go "host/owner" from
// "host/owner/repo"), or "" when the name is unscoped.
func scopeOf(ecosystem, normalized string) string {
	switch strings.ToLower(ecosystem) {
	case "npm", "node":
		if strings.HasPrefix(normalized, "@") {
			if i := strings.IndexByte(normalized, '/'); i > 0 {
				return normalized[:i]
			}
		}
	case "go", "golang", "gomod":
		parts := strings.SplitN(normalized, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
	}
	return ""
}

// isScopePrefix reports whether a configured internal entry denotes a namespace
// scope rather than a single package (an npm "@scope" with no "/name"). Such
// entries shadow an entire private scope.
func isScopePrefix(ecosystem, entry string) bool {
	switch strings.ToLower(ecosystem) {
	case "npm", "node":
		return strings.HasPrefix(entry, "@") && !strings.Contains(entry, "/")
	}
	return false
}

// BuiltinPopular returns the seed list of popular package names per ecosystem.
// These are merged with operator-configured lists so the guard is useful out of
// the box; operators should extend them with the names that matter to their fleet
// (and add legitimate near-neighbors to the allowlist). The lists deliberately
// include known legitimate near-pairs (e.g. npm "preact" alongside "react") so
// the allowlist seed can suppress their cross-flagging.
func BuiltinPopular() map[string][]string {
	return map[string][]string{
		"pip": {
			"requests", "urllib3", "numpy", "pandas", "scipy", "flask", "django",
			"setuptools", "pip", "wheel", "boto3", "botocore", "pytest", "pyyaml",
			"cryptography", "certifi", "idna", "click", "jinja2", "werkzeug",
			"sqlalchemy", "tensorflow", "torch", "scikit-learn", "matplotlib",
			"beautifulsoup4", "selenium", "pillow", "colorama", "six", "python-dateutil",
		},
		"npm": {
			"react", "react-dom", "preact", "lodash", "express", "axios", "chalk",
			"commander", "debug", "webpack", "typescript", "vue", "vuex", "moment",
			"rxjs", "eslint", "jest", "babel", "next", "react-router", "redux",
			"underscore", "request", "bluebird", "async", "yargs", "dotenv",
			"mongoose", "socket.io", "ws", "uuid", "semver", "glob", "minimist",
		},
		"cargo": {
			"serde", "serde-json", "tokio", "rand", "clap", "regex", "log", "anyhow",
			"thiserror", "syn", "quote", "libc", "futures", "reqwest", "hyper",
			"chrono", "itertools", "bytes", "tracing", "lazy-static", "num", "rayon",
		},
		"nuget": {
			"newtonsoft.json", "serilog", "automapper", "moq", "xunit", "nunit",
			"dapper", "polly", "mediatr", "fluentvalidation", "entityframework",
			"microsoft.extensions.logging", "microsoft.aspnetcore", "restsharp",
		},
		"go": {
			"github.com/stretchr/testify", "github.com/sirupsen/logrus",
			"github.com/spf13/cobra", "github.com/spf13/viper", "github.com/gin-gonic/gin",
			"github.com/gorilla/mux", "github.com/pkg/errors", "google.golang.org/grpc",
			"github.com/prometheus/client_golang", "github.com/aws/aws-sdk-go",
		},
	}
}

// BuiltinAllow returns legitimate package names that are near-neighbors of a
// popular name and must not be flagged as typosquats. These are folded into the
// allowlist so true positives ("reqeusts") survive while real packages ("preact",
// "vuex") pass cleanly.
func BuiltinAllow() map[string][]string {
	return map[string][]string{
		"npm": {
			"preact", "vuex", "react-dom", "react-router", "redux", "react-redux",
			"request", "express", "compression",
		},
		"pip": {
			"requests-oauthlib", "requests-toolbelt", "urllib3", "django-cors-headers",
		},
		"cargo": {
			"serde-json", "serde-derive", "tokio-util", "tracing-subscriber",
		},
	}
}
