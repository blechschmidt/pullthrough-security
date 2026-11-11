package mlguard

import (
	"strings"
)

// Python pickle is a stack-based virtual machine: unpickling executes an opcode
// stream that can import arbitrary callables (GLOBAL / STACK_GLOBAL) and invoke
// them (REDUCE / INST / OBJ / NEWOBJ / BUILD). A malicious model "weight" file is
// a pickle whose opcode stream imports a code-execution primitive — os.system,
// subprocess.Popen, builtins.eval/exec, a socket, a network client — and calls it
// via __reduce__ (the REDUCE opcode), so merely LOADING the model runs the
// attacker's code. This is the dominant ML supply-chain attack vector.
//
// scanPickle is a deterministic, no-execution disassembler: it walks the opcode
// stream, extracting every GLOBAL/STACK_GLOBAL import and recording which
// invocation opcodes appear, without ever constructing an object or resolving an
// import. It is the ML analogue of the install-hook static scanner — fully
// reproducible, bounded, and panic-free on hostile input (it stops at the first
// malformed/unknown opcode and reports what it saw). It mirrors the approach of
// picklescan / fickling.

// globalRef is one imported callable referenced by a GLOBAL or STACK_GLOBAL
// opcode: its module and qualified name.
type globalRef struct {
	Module string
	Name   string
}

func (g globalRef) qualified() string {
	if g.Module == "" {
		return g.Name
	}
	return g.Module + "." + g.Name
}

// pickleScan is the result of disassembling one pickle opcode stream.
type pickleScan struct {
	Globals     []globalRef
	HasReduce   bool
	HasBuild    bool
	HasInst     bool // INST/OBJ: GLOBAL-and-call fused opcodes
	HasNewObj   bool
	OpcodeCount int
	// Truncated is set when scanning stopped early — at the opcode budget, an
	// unknown opcode, or a malformed argument — so the caller knows the view is
	// partial and can fail safe.
	Truncated bool
}

// Scanning bounds: a weight pickle's object graph is small (tensor metadata), so
// these caps are generous while keeping a hostile stream from exhausting CPU or
// memory. Exceeding them stops the scan and marks it truncated.
const (
	maxOpcodes      = 1 << 20 // 1,048,576 opcodes
	maxStackStrings = 1 << 16
	maxStringLen    = 4096 // per captured literal (only the head is needed for module/name)
)

// scanPickle disassembles a single pickle opcode stream. It never panics and is
// deterministic for a given input.
func scanPickle(data []byte) pickleScan {
	var sc pickleScan
	// stack holds recently-pushed string literals so STACK_GLOBAL (which takes its
	// module and name from the two top-of-stack strings) can be resolved. The
	// standard emitter pattern is "<unicode module> MEMOIZE <unicode name> MEMOIZE
	// STACK_GLOBAL", so tracking string pushes (with MEMOIZE as a no-op) resolves it.
	var stack []string
	push := func(s string) {
		if len(s) > maxStringLen {
			s = s[:maxStringLen]
		}
		if len(stack) >= maxStackStrings {
			// Drop the oldest to stay bounded; STACK_GLOBAL only needs the top two.
			stack = stack[1:]
		}
		stack = append(stack, s)
	}
	pop := func() string {
		if len(stack) == 0 {
			return ""
		}
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		return s
	}

	i := 0
	n := len(data)
	stop := func() pickleScan { sc.Truncated = true; return sc }

	for i < n {
		if sc.OpcodeCount >= maxOpcodes {
			return stop()
		}
		sc.OpcodeCount++
		op := data[i]
		i++

		switch op {
		case '.': // STOP — end of the (first) pickle
			return sc

		// --- GLOBAL variants ---------------------------------------------------
		case 'c': // GLOBAL: two newline-terminated strings (module, name)
			module, j, ok := readLine(data, i)
			if !ok {
				return stop()
			}
			name, k, ok := readLine(data, j)
			if !ok {
				return stop()
			}
			i = k
			sc.addGlobal(module, name)
			push(module + "." + name)
		case 'i': // INST: two lines then build-and-call
			module, j, ok := readLine(data, i)
			if !ok {
				return stop()
			}
			name, k, ok := readLine(data, j)
			if !ok {
				return stop()
			}
			i = k
			sc.HasInst = true
			sc.addGlobal(module, name)
		case 0x93: // STACK_GLOBAL: pop name, module from the stack
			name := pop()
			module := pop()
			sc.addGlobal(module, name)
			push(module + "." + name)

		// --- invocation opcodes ------------------------------------------------
		case 'R': // REDUCE
			sc.HasReduce = true
		case 'b': // BUILD
			sc.HasBuild = true
		case 'o': // OBJ
			sc.HasInst = true
		case 0x81: // NEWOBJ
			sc.HasNewObj = true
		case 0x92: // NEWOBJ_EX
			sc.HasNewObj = true

		// --- string/bytes pushes (tracked for STACK_GLOBAL) --------------------
		case 0x8c: // SHORT_BINUNICODE: 1-byte length
			s, j, ok := readSized(data, i, 1)
			if !ok {
				return stop()
			}
			i = j
			push(string(s))
		case 'X': // BINUNICODE: 4-byte length
			s, j, ok := readSized(data, i, 4)
			if !ok {
				return stop()
			}
			i = j
			push(string(s))
		case 0x8d: // BINUNICODE8: 8-byte length
			s, j, ok := readSized(data, i, 8)
			if !ok {
				return stop()
			}
			i = j
			push(string(s))
		case 'U': // SHORT_BINSTRING: 1-byte length
			s, j, ok := readSized(data, i, 1)
			if !ok {
				return stop()
			}
			i = j
			push(string(s))
		case 'T': // BINSTRING: 4-byte length
			s, j, ok := readSized(data, i, 4)
			if !ok {
				return stop()
			}
			i = j
			push(string(s))
		case 'C': // SHORT_BINBYTES: 1-byte length
			s, j, ok := readSized(data, i, 1)
			if !ok {
				return stop()
			}
			i = j
			push(string(s))
		case 'B': // BINBYTES: 4-byte length
			s, j, ok := readSized(data, i, 4)
			if !ok {
				return stop()
			}
			i = j
			push(string(s))
		case 0x8e: // BINBYTES8: 8-byte length
			s, j, ok := readSized(data, i, 8)
			if !ok {
				return stop()
			}
			i = j
			push(string(s))
		case 0x96: // BYTEARRAY8: 8-byte length
			_, j, ok := readSized(data, i, 8)
			if !ok {
				return stop()
			}
			i = j
		case 'S', 'V', 'P': // STRING / UNICODE / PERSID: newline-terminated
			s, j, ok := readLine(data, i)
			if !ok {
				return stop()
			}
			i = j
			push(s)
		case 'F', 'I', 'L', 'g': // FLOAT / INT / LONG / GET: newline-terminated
			_, j, ok := readLine(data, i)
			if !ok {
				return stop()
			}
			i = j
		case 'p': // PUT: newline-terminated
			_, j, ok := readLine(data, i)
			if !ok {
				return stop()
			}
			i = j

		// --- fixed-length argument opcodes -------------------------------------
		case 0x80: // PROTO: 1 arg byte
			i++
		case 0x82: // EXT1
			i++
		case 'K': // BININT1
			i++
		case 'h': // BINGET
			i++
		case 'q': // BINPUT
			i++
		case 0x83: // EXT2
			i += 2
		case 'M': // BININT2
			i += 2
		case 0x84: // EXT4
			i += 4
		case 'J': // BININT
			i += 4
		case 'j': // LONG_BINGET
			i += 4
		case 'r': // LONG_BINPUT
			i += 4
		case 'G': // BINFLOAT: 8 bytes
			i += 8
		case 0x95: // FRAME: 8 bytes
			i += 8
		case 0x8a: // LONG1: 1-byte length + data
			_, j, ok := readSized(data, i, 1)
			if !ok {
				return stop()
			}
			i = j
		case 0x8b: // LONG4: 4-byte length + data
			_, j, ok := readSized(data, i, 4)
			if !ok {
				return stop()
			}
			i = j

		// --- zero-argument opcodes (no bytes consumed, no tracking) ------------
		case '(', ')', ']', '}', 'l', 'd', 't', 'a', 'e', 's', 'u', '0', '1', '2',
			'N', 'Q', 0x85, 0x86, 0x87, 0x88, 0x89, 0x8f, 0x90, 0x91, 0x94, 0x97, 0x98:
			// MARK, EMPTY_TUPLE, EMPTY_LIST, EMPTY_DICT, LIST, DICT, TUPLE, APPEND,
			// APPENDS, SETITEM, SETITEMS, POP, POP_MARK, DUP, NONE, BINPERSID,
			// TUPLE1..3, NEWTRUE, NEWFALSE, EMPTY_SET, FROZENSET, ADDITEMS, MEMOIZE,
			// NEXT_BUFFER, READONLY_BUFFER.

		default:
			// Unknown or not-yet-handled opcode: stop rather than risk misaligned
			// parsing. Fail safe — report a truncated view.
			return stop()
		}
		if i > n {
			return stop()
		}
	}
	return sc
}

func (sc *pickleScan) addGlobal(module, name string) {
	module = strings.TrimSpace(module)
	name = strings.TrimSpace(name)
	if module == "" && name == "" {
		return
	}
	sc.Globals = append(sc.Globals, globalRef{Module: module, Name: name})
}

// readLine returns the bytes from offset up to (not including) the next '\n',
// advancing past it. ok=false when no terminator is found within the data.
func readLine(data []byte, offset int) (string, int, bool) {
	if offset > len(data) {
		return "", offset, false
	}
	for j := offset; j < len(data); j++ {
		if data[j] == '\n' {
			return string(data[offset:j]), j + 1, true
		}
	}
	return "", offset, false
}

// readSized reads a little-endian length of lenBytes bytes at offset, then that
// many payload bytes, returning the payload and the new offset. ok=false on any
// overrun or an implausibly large length.
func readSized(data []byte, offset, lenBytes int) ([]byte, int, bool) {
	if offset+lenBytes > len(data) {
		return nil, offset, false
	}
	var length uint64
	for k := 0; k < lenBytes; k++ {
		length |= uint64(data[offset+k]) << (8 * uint(k))
	}
	start := offset + lenBytes
	// Guard against a hostile length that would overrun the buffer.
	if length > uint64(len(data)-start) {
		return nil, offset, false
	}
	end := start + int(length)
	// Only the head of a literal is needed (module/name are short); cap the slice
	// we materialize while still advancing the cursor past the full payload.
	headEnd := end
	if end-start > maxStringLen {
		headEnd = start + maxStringLen
	}
	return data[start:headEnd], end, true
}

// PickleSummary is what a static walk of one pickle opcode stream shows: the
// callables it imports and whether it invokes anything. It is the read-only
// view other gates use to describe a pickle to a reviewer without unpickling
// it (the LLM package-content scan renders it for the model).
type PickleSummary struct {
	// Imports are the "module.name" callables referenced by GLOBAL, INST and
	// STACK_GLOBAL opcodes, in stream order, without duplicates.
	Imports []string
	// Flagged are the imports among them that this gate's own rules classify as
	// a process, network, code-execution or dynamic-import primitive (see
	// classifyGlobal), in stream order. A stream names its imports in whatever
	// order its author likes, so a reader that shows only the first so many of
	// Imports must show these first: one os.system behind two hundred harmless
	// names is otherwise the import that gets cut.
	Flagged []string
	// Reduce, Build, Inst and NewObj report the opcodes that call an imported
	// callable: REDUCE, BUILD, INST/OBJ and NEWOBJ.
	Reduce, Build, Inst, NewObj bool
	// Opcodes is the number of opcodes walked.
	Opcodes int
	// Truncated reports that the walk stopped early — at the opcode budget, an
	// unknown opcode or a malformed argument — so the summary is partial.
	Truncated bool
}

// SummarizePickle statically walks data as a pickle opcode stream and returns
// what it imports and invokes. Nothing is unpickled or executed. The caller
// decides whether data is a pickle at all; a walk of something else stops at
// the first byte that is not an opcode and returns an empty, truncated summary.
func SummarizePickle(data []byte) PickleSummary {
	sc := scanPickle(data)
	out := PickleSummary{
		Reduce: sc.HasReduce, Build: sc.HasBuild, Inst: sc.HasInst, NewObj: sc.HasNewObj,
		Opcodes: sc.OpcodeCount, Truncated: sc.Truncated,
	}
	seen := make(map[string]bool, len(sc.Globals))
	for _, g := range sc.Globals {
		if q := g.qualified(); q != "" && !seen[q] {
			seen[q] = true
			out.Imports = append(out.Imports, q)
			if _, _, flagged := classifyGlobal(g); flagged {
				out.Flagged = append(out.Flagged, q)
			}
		}
	}
	return out
}
