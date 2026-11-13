package lockfiles

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// puppetfile reads a Puppetfile, the module list r10k and librarian-puppet
// install from. Puppet has no lock file; a Puppetfile pins a Forge module
// when it names an exact version, and a Git module when it names a commit:
//
//	forge 'https://forge.puppet.com'
//	mod 'puppetlabs/stdlib', '9.4.1'            Forge, pinned
//	mod 'puppetlabs-apt', :latest                not pinned: a warning
//	mod 'apache', :git => 'https://…', :commit => '<sha>'
//	mod 'ntp', git: 'https://…', tag: 'v1.0'     a tag: unverified
//
// A Puppetfile is Ruby that r10k evaluates. This parser reads the
// declarations it is made of — forge, mod and moduledir calls whose
// arguments are literals — and reports any other statement as code it does
// not evaluate, rather than guessing what running it would declare. The file
// records no hash: the Forge publishes a release's checksums, the Puppetfile
// does not.
type puppetfile struct{}

func (puppetfile) Type() string            { return "puppet" }
func (puppetfile) Format() string          { return "Puppetfile" }
func (puppetfile) Detect(path string) bool { return baseName(path) == "Puppetfile" }

const puppetNoDigest = "a Puppetfile records no hash (the Forge publishes the release's checksums, the Puppetfile does not)"

// rbTokKind is the kind of a Ruby token.
type rbTokKind int

const (
	rbIdent    rbTokKind = iota
	rbString             // a literal string
	rbTemplate           // a double-quoted string with interpolation
	rbSymbol             // :name
	rbLabel              // name: (a hash key)
	rbArrow              // =>
	rbComma
	rbOpen
	rbClose
	rbNewline
	rbOther
)

type rbTok struct {
	kind rbTokKind
	text string
	line int
}

func (puppetfile) Parse(data []byte) (*Result, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("Puppetfile is not valid UTF-8")
	}
	res := &Result{}
	forge := ""
	err := rbStatements(string(data), func(st []rbTok, complete bool) {
		head := st[0]
		args, ok := rbCallArgs(st)
		switch {
		case head.kind != rbIdent || !ok || !complete:
			res.warnf("line %d: Ruby code this parser does not evaluate", head.line)
		case head.text == "forge":
			if len(args.positional) == 1 && args.positional[0].kind == rbString {
				forge = args.positional[0].text
			} else {
				res.warnf("line %d: a forge declaration this parser does not read", head.line)
			}
		case head.text == "moduledir":
		case head.text == "mod":
			if d, ok := puppetModule(res, args, forge, head.line); ok {
				res.Dependencies = append(res.Dependencies, d)
			}
		default:
			res.warnf("line %d: Ruby code this parser does not evaluate", head.line)
		}
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// rbArgs are a call's arguments: positional literals, then options (with
// the order they were given in).
type rbArgs struct {
	positional []rbTok
	options    map[string]rbTok
	order      []string
}

// rbCallArgs reads a statement "name arg, arg, key => value, key: value" or
// "name(…)" whose arguments are literals. ok is false for anything else.
func rbCallArgs(st []rbTok) (rbArgs, bool) {
	var args rbArgs
	toks := st[1:]
	if len(toks) > 0 && toks[0].kind == rbOpen {
		if toks[len(toks)-1].kind != rbClose {
			return args, false
		}
		toks = toks[1 : len(toks)-1]
	}
	for len(toks) > 0 {
		switch {
		case toks[0].kind == rbLabel && len(toks) > 1 && rbLiteral(toks[1]):
			if !args.setOption(toks[0].text, toks[1]) {
				return args, false
			}
			toks = toks[2:]
		case (toks[0].kind == rbSymbol || toks[0].kind == rbString) && len(toks) > 2 && toks[1].kind == rbArrow && rbLiteral(toks[2]):
			if !args.setOption(toks[0].text, toks[2]) {
				return args, false
			}
			toks = toks[3:]
		case rbLiteral(toks[0]) && len(args.options) == 0:
			args.positional = append(args.positional, toks[0])
			toks = toks[1:]
		default:
			return args, false
		}
		if len(toks) > 0 {
			if toks[0].kind != rbComma {
				return args, false
			}
			toks = toks[1:]
		}
	}
	return args, true
}

// setOption records an option; false when it is given twice (which Ruby
// warns about and r10k reads as the last).
func (a *rbArgs) setOption(key string, v rbTok) bool {
	if a.options == nil {
		a.options = map[string]rbTok{}
	}
	if _, dup := a.options[key]; dup {
		return false
	}
	a.options[key] = v
	a.order = append(a.order, key)
	return true
}

func rbLiteral(t rbTok) bool {
	return t.kind == rbString || t.kind == rbSymbol || t.kind == rbIdent && (t.text == "true" || t.text == "false" || t.text == "nil")
}

func puppetModule(res *Result, args rbArgs, forge string, line int) (Dependency, bool) {
	if len(args.positional) == 0 || args.positional[0].kind != rbString {
		res.warnf("line %d: a mod declaration without a name", line)
		return Dependency{}, false
	}
	name := args.positional[0].text
	opt := func(k string) string {
		if t, ok := args.options[k]; ok && t.kind == rbString {
			return t.text
		}
		return ""
	}
	if t, ok := args.options["local"]; ok && t.text == "true" {
		return Dependency{}, false // installed from the control repository itself
	}
	if opt("svn") != "" {
		res.warnf("line %d: %s comes from a Subversion repository, which this parser does not read", line, quoteName(name))
		return Dependency{}, false
	}
	if opt("type") == "tarball" {
		// r10k's tarball modules: a download URL, and the SHA-256 r10k checks
		// the download against as their "version".
		src := opt("source")
		dg, ok := hexDigest("sha256", opt("version"), "")
		if !isHTTPURL(src) || !ok {
			res.warnf("line %d: %s: a tarball module without an HTTP source and a SHA-256", line, quoteName(name))
			return Dependency{}, false
		}
		d := Dependency{Name: puppetName(name), Version: "sha256:" + dg.Value, Source: SourceURL, URL: cleanURL(src),
			Digests: []Digest{dg}, Line: line}
		if !validPackageName(d.Name) {
			res.warnf("line %d: a tarball module without a usable name", line)
			return Dependency{}, false
		}
		return d, true
	}
	if repo := opt("git"); repo != "" {
		// r10k folds :branch, :tag, :commit, :ref and :version into one
		// desired ref, the last one given winning.
		var refKeys []string
		for _, k := range args.order {
			switch k {
			case "branch", "tag", "commit", "ref", "version":
				refKeys = append(refKeys, k)
			}
		}
		if len(refKeys) == 0 {
			res.warnf("line %d: %s from a Git repository without a commit, tag or ref", line, quoteName(name))
			return Dependency{}, false
		}
		if len(refKeys) > 1 {
			res.warnf("line %d: %s names several refs (%s); r10k checks out the last, :%s", line, quoteName(name), strings.Join(refKeys, ", "), refKeys[len(refKeys)-1])
		}
		key := refKeys[len(refKeys)-1]
		ref := args.options[key]
		d := Dependency{Name: puppetName(name), Source: SourceGit, Registry: cleanGitRepoURL(repo), Line: line}
		switch {
		case key == "branch" || ref.kind != rbString:
			res.warnf("line %d: %s follows a branch, not a pinned version", line, quoteName(name))
			return Dependency{}, false
		case isCommitID(ref.text):
			d.Revision = strings.ToLower(ref.text)
			d.Version = d.Revision
		default:
			d.Version = ref.text // a tag, or a ref that may be a branch: unverified
		}
		if !validPackageName(d.Name) || !validVersion(d.Version) {
			res.warnf("line %d: a Git module without a usable name or reference", line)
			return Dependency{}, false
		}
		return d, true
	}
	version := ""
	if len(args.positional) > 1 {
		v := args.positional[1]
		if v.kind != rbString {
			res.warnf("line %d: %s is not pinned to a version (%s)", line, quoteName(name), v.text)
			return Dependency{}, false
		}
		version = v.text
	} else if v := opt("version"); v != "" {
		version = v
	}
	if version == "" {
		res.warnf("line %d: %s is not pinned to a version", line, quoteName(name))
		return Dependency{}, false
	}
	d := Dependency{Name: puppetName(name), Version: version, Line: line, UnverifiedReason: puppetNoDigest}
	if isHTTPURL(forge) {
		d.Registry = cleanURL(forge)
	}
	if !strings.Contains(d.Name, "-") || !validPackageName(d.Name) || !validVersion(d.Version) || strings.ContainsAny(d.Version, "<>=~ ") {
		res.warnf("line %d: not a Forge module name and exact version", line)
		return Dependency{}, false
	}
	return d, true
}

// puppetName spells a Forge module name as the Forge does: "owner-name"
// ("puppetlabs/stdlib" → "puppetlabs-stdlib").
func puppetName(s string) string { return strings.Replace(strings.TrimSpace(s), "/", "-", 1) }

// maxStatementTokens bounds the tokens kept of one statement: a mod
// declaration has a few dozen.
const maxStatementTokens = 4096

// rbStatements tokenises the Ruby a Puppetfile is made of and calls fn with
// each statement's tokens: a line break ends a statement unless it follows a
// comma, "=>" or a hash key, or comes inside parentheses; ";" ends one too.
// A statement longer than maxStatementTokens is passed cut short, with
// complete false. Only one statement's tokens are held at a time.
func rbStatements(s string, fn func(st []rbTok, complete bool)) error {
	var cur []rbTok
	complete := true
	depth := 0
	flush := func() {
		if len(cur) > 0 {
			fn(cur, complete)
		}
		cur, complete = cur[:0], true
	}
	emit := func(t rbTok) {
		switch t.kind {
		case rbOpen:
			depth++
		case rbClose:
			if depth > 0 {
				depth--
			}
		case rbNewline:
			if depth > 0 {
				return
			}
			if n := len(cur); n > 0 && (cur[n-1].kind == rbComma || cur[n-1].kind == rbArrow || cur[n-1].kind == rbLabel) {
				return
			}
			flush()
			return
		case rbOther:
			if t.text == ";" && depth == 0 {
				flush()
				return
			}
		}
		if len(cur) < maxStatementTokens {
			cur = append(cur, t)
		} else {
			complete = false
		}
	}
	line := 1
	for i := 0; i < len(s); {
		c := s[i]
		start := line
		var t rbTok
		switch {
		case c == '\n':
			t, i, line = rbTok{kind: rbNewline}, i+1, line+1
		case c == ' ' || c == '\t' || c == '\r':
			i++
			continue
		case c == '\\' && i+1 < len(s) && s[i+1] == '\n':
			i, line = i+2, line+1 // a continued line
			continue
		case c == '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			continue
		case c == '\'' || c == '"':
			value, literal, n, lines, err := rbQuoted(s[i:])
			if err != nil {
				return fmt.Errorf("Puppetfile line %d: %w", line, err)
			}
			i, line = i+n, line+lines
			t = rbTok{kind: rbString, text: value}
			if !literal {
				t = rbTok{kind: rbTemplate}
			}
			if i < len(s) && s[i] == ':' && (i+1 >= len(s) || s[i+1] != ':') && literal {
				t.kind = rbLabel // "key": value
				i++
			}
		case c == ':' && i+1 < len(s) && (isExIdentStart(s[i+1]) || s[i+1] == '"' || s[i+1] == '\''):
			i++
			if s[i] == '"' || s[i] == '\'' {
				value, literal, n, lines, err := rbQuoted(s[i:])
				if err != nil {
					return fmt.Errorf("Puppetfile line %d: %w", line, err)
				}
				if !literal {
					return fmt.Errorf("Puppetfile line %d: an interpolated symbol", line)
				}
				i, line = i+n, line+lines
				t = rbTok{kind: rbSymbol, text: value}
				break
			}
			j := i
			for j < len(s) && (isExIdentStart(s[j]) || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			t, i = rbTok{kind: rbSymbol, text: s[i:j]}, j
		case isExIdentStart(c):
			j := i
			for j < len(s) && (isExIdentStart(s[j]) || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			if j < len(s) && (s[j] == '?' || s[j] == '!') {
				j++
			}
			t, i = rbTok{kind: rbIdent, text: s[i:j]}, j
			if i < len(s) && s[i] == ':' && (i+1 >= len(s) || s[i+1] != ':') {
				t.kind = rbLabel
				i++
			}
		case c == '=' && i+1 < len(s) && s[i+1] == '>':
			t, i = rbTok{kind: rbArrow, text: "=>"}, i+2
		case c == ',':
			t, i = rbTok{kind: rbComma, text: ","}, i+1
		case c == '(':
			t, i = rbTok{kind: rbOpen, text: "("}, i+1
		case c == ')':
			t, i = rbTok{kind: rbClose, text: ")"}, i+1
		default:
			t, i = rbTok{kind: rbOther, text: s[i : i+1]}, i+1
		}
		t.line = start
		emit(t)
	}
	flush()
	return nil
}

// rbQuoted reads a quoted string at the start of s: its value, whether it is
// a literal (no "#{…}" in a double-quoted string), its length in bytes and
// the line breaks it spans.
func rbQuoted(s string) (value string, literal bool, n, lines int, err error) {
	quote := s[0]
	// Most strings have no escape: their value is a slice of the input.
	if end := strings.IndexByte(s[1:], quote); end >= 0 {
		v := s[1 : 1+end]
		if !strings.ContainsAny(v, "\\\n#") {
			return v, true, end + 2, 0, nil
		}
	}
	var b strings.Builder
	literal = true
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case c == quote:
			return b.String(), literal, i + 1, lines, nil
		case c == '\n':
			lines++
		case c == '\\' && i+1 < len(s):
			i++
			e := s[i]
			switch {
			case quote == '\'' && (e == '\\' || e == '\''):
				c = e
			case quote == '\'':
				b.WriteByte('\\')
				c = e
			case e == 'n':
				c = '\n'
			case e == 't':
				c = '\t'
			case e == '"' || e == '\\' || e == '#':
				c = e
			default:
				literal = false // an escape whose value this parser does not compute
				c = e
			}
			if e == '\n' {
				lines++
			}
		case quote == '"' && c == '#' && i+1 < len(s) && (s[i+1] == '{' || s[i+1] == '@' || s[i+1] == '$'):
			literal = false
		}
		b.WriteByte(c)
		if b.Len() > 64<<10 {
			return "", false, 0, 0, errors.New("string too long")
		}
	}
	return "", false, 0, 0, errors.New("unterminated string")
}
