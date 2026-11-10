package contentscan

import (
	"math"
	"path"
	"regexp"
	"strings"
)

// Stable rule identifiers for content findings. They are "<gate>/<slug>" so the
// originating gate is legible in CI annotations and cannot collide.
const (
	RuleHighEntropyBlob = "contentscan/high-entropy-blob"
	RuleEmbeddedBinary  = "contentscan/embedded-binary"
	RuleObfuscatedCode  = "contentscan/obfuscated-code"
	RuleDynamicExec     = "contentscan/dynamic-exec"
	RuleEmbeddedSecret  = "contentscan/embedded-secret"
)

// --- embedded native binaries ------------------------------------------------

// binaryByMagic reports whether data begins with a recognized native-binary
// magic number, returning a short description of the format. These are formats
// that have no business inside a nominally-source package.
func binaryByMagic(data []byte) (string, bool) {
	switch {
	case len(data) >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F':
		return "ELF executable/object", true
	case len(data) >= 4 && data[0] == 0x00 && data[1] == 'a' && data[2] == 's' && data[3] == 'm':
		return "WebAssembly module", true
	case len(data) >= 8 && string(data[:8]) == "!<arch>\n":
		return "ar static library", true
	case len(data) >= 2 && data[0] == 'M' && data[1] == 'Z':
		return "PE/DOS executable (MZ)", true
	case len(data) >= 4 && isMachO(data):
		return "Mach-O / fat binary", true
	}
	return "", false
}

// isMachO recognizes the Mach-O (and universal/fat) magic numbers in either
// endianness. 0xCAFEBABE also fronts a Java class file; both are compiled
// artifacts, so the shared "compiled binary" classification is acceptable.
func isMachO(d []byte) bool {
	m := uint32(d[0])<<24 | uint32(d[1])<<16 | uint32(d[2])<<8 | uint32(d[3])
	switch m {
	case 0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE, 0xBEBAFECA:
		return true
	}
	return false
}

// binaryExtensions are file extensions that denote a compiled/native artifact.
var binaryExtensions = map[string]string{
	".so": "shared object", ".dll": "Windows DLL", ".dylib": "macOS dynamic library",
	".exe": "Windows executable", ".node": "native Node addon", ".wasm": "WebAssembly module",
	".class": "Java class", ".o": "object file", ".a": "static library",
	".pyd": "Python extension DLL", ".bin": "binary blob", ".msi": "Windows installer",
}

// classifyBinary returns a description when a file is a native binary (by magic
// or extension), else ("", false).
func classifyBinary(name string, data []byte) (string, bool) {
	if desc, ok := binaryByMagic(data); ok {
		return desc, true
	}
	if desc, ok := binaryExtensions[strings.ToLower(path.Ext(name))]; ok {
		return desc, true
	}
	return "", false
}

// --- high-entropy blobs ------------------------------------------------------

// expectedBinaryExtensions are file types whose content is legitimately
// high-entropy (compressed media, fonts, archives). A high-entropy blob with one
// of these extensions is unremarkable and is NOT flagged; the heuristic targets
// packed/encrypted payloads hiding under a source/text/data/unknown extension.
var expectedBinaryExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".bmp": true,
	".ico": true, ".tiff": true, ".woff": true, ".woff2": true, ".ttf": true, ".otf": true,
	".eot": true, ".gz": true, ".tgz": true, ".zip": true, ".bz2": true, ".xz": true,
	".zst": true, ".br": true, ".7z": true, ".rar": true, ".mp3": true, ".mp4": true,
	".webm": true, ".mov": true, ".avi": true, ".pdf": true, ".jar": true, ".wasm": true,
	".parquet": true, ".pack": true, ".idx": true, ".wav": true, ".flac": true, ".ogg": true,
}

// byteEntropy returns the Shannon entropy of data in bits per byte (0..8).
func byteEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var h float64
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}

// --- obfuscated / minified-plus-eval JavaScript ------------------------------

var jsExtensions = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".jsx": true, ".ts": true, ".tsx": true,
}

// jsEvalSink matches the dynamic-evaluation primitives that distinguish a
// malicious obfuscated bundle from a benign minified library (minification alone
// is extremely common and benign).
var jsEvalSink = regexp.MustCompile(`(?i)(\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*["'])`)

// jsPacker matches well-known JS packer/obfuscator signatures that are a strong
// obfuscation tell regardless of minification.
var jsPacker = regexp.MustCompile(`(?i)(eval\(function\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e|_0x[0-9a-f]{4,}|\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2})`)

// minifiedStats returns the longest line length and the fraction of whitespace
// bytes, used to detect minification.
func minifiedStats(s string) (longestLine int, wsRatio float64) {
	ws := 0
	cur := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\r' {
			ws++
		}
		if c == '\n' {
			if cur > longestLine {
				longestLine = cur
			}
			cur = 0
			continue
		}
		cur++
	}
	if cur > longestLine {
		longestLine = cur
	}
	if len(s) > 0 {
		wsRatio = float64(ws) / float64(len(s))
	}
	return longestLine, wsRatio
}

// obfuscatedJS evaluates whether a JavaScript file is obfuscated in a way that
// warrants a finding: a packer signature, or minification (a very long line and
// sparse whitespace) combined with a dynamic-eval sink. It returns the finding
// detail and severity when matched.
func obfuscatedJS(text string) (detail string, sev Severity, matched bool) {
	if jsPacker.MatchString(text) {
		return "packer/obfuscator signature (eval-packed or hex-escaped identifiers)", SeverityHigh, true
	}
	longest, ws := minifiedStats(text)
	minified := longest > 1000 && ws < 0.08
	if minified && jsEvalSink.MatchString(text) {
		return "minified source invoking a dynamic-eval sink (eval/Function)", SeverityHigh, true
	}
	return "", "", false
}

// --- dynamic code-execution sinks --------------------------------------------

// execRule matches a dynamic code-execution sink in file content. langs limits
// the rule to files of those extensions (empty = any text file). combo rules
// (base64-decode-then-run) carry a higher severity than a bare sink.
type execRule struct {
	id       string
	title    string
	severity Severity
	langs    map[string]bool
	re       *regexp.Regexp
}

func extSet(exts ...string) map[string]bool {
	m := make(map[string]bool, len(exts))
	for _, e := range exts {
		m[e] = true
	}
	return m
}

var jsLangs = extSet(".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")
var pyLangs = extSet(".py", ".pyw", ".pyi")
var shLangs = extSet(".sh", ".bash", ".zsh", ".ksh")
var rbLangs = extSet(".rb", ".rake", ".gemspec")
var phpLangs = extSet(".php", ".phtml", ".php5", ".inc")

// execRules is the deterministic sink catalog, evaluated in order. "combo" rules
// (decode-then-execute) are the strongest tell and are high severity.
var execRules = []execRule{
	// base64/decode-then-execute combinations (strongest signal) ----------------
	{id: "js-eval-decode", title: "JavaScript eval of a base64/hex-decoded payload", severity: SeverityHigh, langs: jsLangs,
		re: regexp.MustCompile(`(?i)\beval\s*\(\s*(?:atob|Buffer\.from|unescape|decodeURIComponent)`)},
	{id: "py-exec-decode", title: "Python exec/eval of a base64/hex-decoded payload", severity: SeverityHigh, langs: pyLangs,
		re: regexp.MustCompile(`(?i)\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|bytes\.fromhex|codecs\.decode|zlib\.decompress|marshal\.loads)`)},
	{id: "sh-curl-pipe-sh", title: "Shell: remote script piped directly into an interpreter", severity: SeverityHigh, langs: nil,
		re: regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b`)},
	{id: "sh-base64-pipe-sh", title: "Shell: base64-decoded payload piped into an interpreter", severity: SeverityHigh, langs: nil,
		re: regexp.MustCompile(`(?i)\bbase64\b[^\n|]*(?:-d|--decode)[^\n|]*\|\s*(?:ba|z|k)?sh\b`)},
	// bare dynamic-execution sinks (medium) --------------------------------------
	{id: "js-eval", title: "JavaScript dynamic-evaluation sink (eval/Function)", severity: SeverityMedium, langs: jsLangs,
		re: regexp.MustCompile(`(?i)(\beval\s*\(|\bnew\s+Function\s*\()`)},
	{id: "js-child-process", title: "JavaScript child-process / shell execution", severity: SeverityMedium, langs: jsLangs,
		re: regexp.MustCompile(`(?i)require\(\s*['"]child_process['"]\s*\)|\bchild_process\b|\bexecSync\s*\(`)},
	{id: "py-exec", title: "Python dynamic-execution sink (exec/eval/compile)", severity: SeverityMedium, langs: pyLangs,
		re: regexp.MustCompile(`(?i)\b(?:exec|eval|compile)\s*\(|\b__import__\s*\(`)},
	{id: "py-os-system", title: "Python OS command / subprocess execution", severity: SeverityMedium, langs: pyLangs,
		re: regexp.MustCompile(`(?i)\bos\.system\s*\(|\bsubprocess\.(?:Popen|call|run|check_output)\s*\(|\bos\.popen\s*\(`)},
	{id: "py-pickle", title: "Python pickle/marshal deserialization sink", severity: SeverityMedium, langs: pyLangs,
		re: regexp.MustCompile(`(?i)\b(?:pickle|cPickle|marshal)\.loads?\s*\(`)},
	{id: "rb-eval", title: "Ruby dynamic-evaluation / command execution", severity: SeverityMedium, langs: rbLangs,
		re: regexp.MustCompile("(?i)\\b(?:eval|instance_eval|class_eval|system|exec)\\s*[\\(\"']|`[^`\\n]+`")},
	{id: "php-eval", title: "PHP dynamic-evaluation / command execution", severity: SeverityMedium, langs: phpLangs,
		re: regexp.MustCompile(`(?i)\b(?:eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(`)},
}

// scanExecLine applies the sink catalog to one line of a file with the given
// extension, returning the matched rules (at most one per rule id).
func scanExecLine(ext, line string) []execRule {
	var out []execRule
	for i := range execRules {
		r := &execRules[i]
		if len(r.langs) > 0 && !r.langs[ext] {
			continue
		}
		if r.re.MatchString(line) {
			out = append(out, *r)
		}
	}
	return out
}
