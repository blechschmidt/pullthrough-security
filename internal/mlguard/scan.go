package mlguard

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
)

// Format is the weight-file container format the gate recognizes.
type Format string

const (
	// FormatSafetensors is the safe, tensor-only format (no executable opcodes);
	// the gate prefers it and never flags it.
	FormatSafetensors Format = "safetensors"
	// FormatPickle is a pickle-based weight file (.bin/.pkl/.pt/.pth/.ckpt),
	// possibly wrapped in a PyTorch ZIP container. These carry executable opcodes
	// and are the gate's scanning target.
	FormatPickle Format = "pickle"
	// FormatGGUF / FormatOtherWeights are other binary weight formats that are not
	// pickle-based (no arbitrary-callable execution on load); recorded but not
	// scanned.
	FormatGGUF         Format = "gguf"
	FormatOtherWeights Format = "weights"
	// FormatOther is a non-weight file (config.json, tokenizer, README); the gate
	// does not apply.
	FormatOther Format = ""
)

// classifyFormat labels a file by its name extension.
func classifyFormat(filename string) Format {
	lower := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(lower, ".safetensors"):
		return FormatSafetensors
	case strings.HasSuffix(lower, ".bin"),
		strings.HasSuffix(lower, ".pkl"),
		strings.HasSuffix(lower, ".pickle"),
		strings.HasSuffix(lower, ".pt"),
		strings.HasSuffix(lower, ".pth"),
		strings.HasSuffix(lower, ".ckpt"):
		return FormatPickle
	case strings.HasSuffix(lower, ".gguf"), strings.HasSuffix(lower, ".ggml"):
		return FormatGGUF
	case strings.HasSuffix(lower, ".h5"),
		strings.HasSuffix(lower, ".hdf5"),
		strings.HasSuffix(lower, ".onnx"),
		strings.HasSuffix(lower, ".npz"),
		strings.HasSuffix(lower, ".npy"),
		strings.HasSuffix(lower, ".msgpack"):
		return FormatOtherWeights
	default:
		return FormatOther
	}
}

// namedStream is one extracted pickle opcode stream and a label for diagnostics.
type namedStream struct {
	name string
	data []byte
}

// zipMagic / pickleProto are the leading bytes that distinguish a PyTorch ZIP
// container from a bare (protocol >= 2) pickle.
var zipMagic = []byte{'P', 'K', 0x03, 0x04}

const pickleProto = 0x80

// extractPickleStreams returns the pickle opcode stream(s) inside a weight blob.
// A PyTorch .pt/.bin/.ckpt is typically a ZIP whose data.pkl entry holds the
// object graph; a legacy file is a bare pickle. The caller passes the buffered
// bytes (already bounded to MaxScanBytes) and whether the source exceeded that
// bound. Extraction is bounded by maxEntries/perEntryCap and never panics.
func extractPickleStreams(data []byte, sourceTruncated bool, maxEntries, perEntryCap int) (streams []namedStream, truncated bool) {
	truncated = sourceTruncated
	if len(data) == 0 {
		return nil, truncated
	}

	if bytes.HasPrefix(data, zipMagic) {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			// A truncated/oversize ZIP cannot be parsed; fail safe and flag it.
			return nil, true
		}
		count := 0
		for _, f := range zr.File {
			if count >= maxEntries {
				truncated = true
				break
			}
			if f.FileInfo().IsDir() || !isPickleEntry(f.Name) {
				continue
			}
			count++
			b, tr := readZipEntry(f, perEntryCap)
			if tr {
				truncated = true
			}
			if len(b) > 0 {
				streams = append(streams, namedStream{name: f.Name, data: b})
			}
		}
		return streams, truncated
	}

	// Bare pickle (or a pickle-labeled file whose container we do not recognize):
	// scan the buffered bytes directly. scanPickle fails safe on non-pickle input.
	return []namedStream{{name: "<root>", data: data}}, truncated
}

// isPickleEntry reports whether a ZIP entry name denotes a pickle stream. PyTorch
// stores the object graph as ".../data.pkl"; other pickle entries end in .pkl.
func isPickleEntry(name string) bool {
	lower := strings.ToLower(name)
	base := lower
	if i := strings.LastIndex(lower, "/"); i >= 0 {
		base = lower[i+1:]
	}
	return base == "data.pkl" || strings.HasSuffix(base, ".pkl") || strings.HasSuffix(base, ".pickle")
}

// readZipEntry decompresses up to cap bytes of a ZIP entry, returning whether the
// entry was truncated at the cap. Errors are swallowed (fail-open on a corrupt
// entry).
func readZipEntry(f *zip.File, cap int) ([]byte, bool) {
	rc, err := f.Open()
	if err != nil {
		return nil, true
	}
	defer rc.Close()
	buf, err := io.ReadAll(io.LimitReader(rc, int64(cap)+1))
	truncated := err != nil || len(buf) > cap
	if len(buf) > cap {
		buf = buf[:cap]
	}
	return buf, truncated
}

// first component of a dotted module path, e.g. "os.path" -> "os".
func firstComponent(module string) string {
	if i := strings.IndexByte(module, '.'); i >= 0 {
		return module[:i]
	}
	return module
}

// execModules are Python modules whose mere import into a model-weight pickle is
// a code-execution primitive (process/shell/network/filesystem control). Any
// GLOBAL referencing one is critical.
var execModules = map[string]bool{
	"os": true, "posix": true, "nt": true, "subprocess": true, "sys": true,
	"socket": true, "shutil": true, "pty": true, "ctypes": true, "cffi": true,
	"commands": true, "popen2": true, "multiprocessing": true, "asyncio": true,
	"requests": true, "urllib": true, "urllib2": true, "httplib": true,
	"http": true, "ftplib": true, "smtplib": true, "telnetlib": true, "poplib": true,
	"pip": true, "setuptools": true, "distutils": true, "platform": true,
	"webbrowser": true, "aiohttp": true, "paramiko": true,
}

// builtinModules are the interpreter builtins namespaces.
var builtinModules = map[string]bool{
	"builtins": true, "__builtin__": true, "__builtins__": true,
}

// execBuiltinNames are the builtins that directly execute/compile/import code or
// fetch arbitrary attributes — critical when imported into a pickle.
var execBuiltinNames = map[string]bool{
	"eval": true, "exec": true, "execfile": true, "compile": true,
	"__import__": true, "getattr": true, "setattr": true, "open": true,
	"input": true, "breakpoint": true, "globals": true, "vars": true,
	"memoryview": true, "apply": true,
}

// suspiciousModules are modules that are abnormal in a weight file and are the
// building blocks of pickle exploits (dynamic import, payload decoding, debugger
// entry); a GLOBAL referencing one is high severity.
var suspiciousModules = map[string]bool{
	"importlib": true, "runpy": true, "code": true, "codeop": true,
	"pdb": true, "bdb": true, "base64": true, "codecs": true, "_codecs": true,
	"marshal": true, "dill": true, "pickle": true, "_pickle": true, "cpickle": true,
	"operator": true, "functools": true, "timeit": true, "tempfile": true,
	"glob": true, "fileinput": true, "pydoc": true, "pkgutil": true,
	"zipimport": true, "imp": true,
}

// classifyGlobal returns the finding severity and rule id for an imported global,
// or ok=false when the import is benign for a model weight (numpy/torch/
// collections rebuild helpers and the like).
func classifyGlobal(g globalRef) (Severity, string, bool) {
	mod := firstComponent(strings.ToLower(g.Module))
	name := g.Name
	switch {
	case execModules[mod]:
		return SeverityCritical, RuleCodeExecImport, true
	case builtinModules[mod]:
		if execBuiltinNames[name] {
			return SeverityCritical, RuleCodeExecImport, true
		}
		return SeverityHigh, RuleSuspiciousImport, true
	case suspiciousModules[mod]:
		return SeverityHigh, RuleSuspiciousImport, true
	default:
		return "", "", false
	}
}
