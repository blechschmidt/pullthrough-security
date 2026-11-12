package lockfiles

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Container images pinned by digest: the base images of a Dockerfile (FROM,
// and images copied from with COPY --from) and the images of a Compose file.
// A reference without a digest is not pinned — a tag can be moved — and is a
// warning, not a dependency.

// imageRef is a parsed container image reference.
type imageRef struct {
	domain, path, tag, digest string
}

var (
	refDigestRE = regexp.MustCompile(`^(sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})$`)
	refTagRE    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	refPathRE   = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
	refDomainRE = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*|\[[0-9A-Fa-f:]+\])(?::[0-9]+)?$`)
)

// parseImageRef parses "[domain/]path[:tag][@digest]" as the distribution
// reference grammar does, with Docker Hub's defaults ("alpine" is
// docker.io/library/alpine).
func parseImageRef(s string) (imageRef, error) {
	if s == "" || len(s) > 512 {
		return imageRef{}, errors.New("not an image reference")
	}
	var r imageRef
	name := s
	if at := strings.IndexByte(s, '@'); at >= 0 {
		name, r.digest = s[:at], s[at+1:]
		if !refDigestRE.MatchString(r.digest) {
			return imageRef{}, errors.New("malformed digest")
		}
	}
	if colon := strings.LastIndexByte(name, ':'); colon > strings.LastIndexByte(name, '/') {
		name, r.tag = name[:colon], name[colon+1:]
		if !refTagRE.MatchString(r.tag) {
			return imageRef{}, errors.New("malformed tag")
		}
	}
	first, rest, hasSlash := strings.Cut(name, "/")
	switch {
	case hasSlash && (strings.ContainsAny(first, ".:") || first == "localhost" || first != strings.ToLower(first)):
		r.domain, r.path = first, rest
	case !hasSlash:
		r.domain, r.path = "docker.io", "library/"+name
	default:
		r.domain, r.path = "docker.io", name
	}
	if r.domain == "index.docker.io" {
		r.domain = "docker.io"
	}
	if !refDomainRE.MatchString(r.domain) || !refPathRE.MatchString(r.path) {
		return imageRef{}, errors.New("malformed repository name")
	}
	return r, nil
}

// registryURL is the URL of the registry an image is pulled from.
func (r imageRef) registryURL() string {
	if r.domain == "docker.io" {
		return "https://registry-1.docker.io"
	}
	return "https://" + r.domain
}

// imageDependency turns an image reference into a dependency, or a warning
// when it is not pinned by digest.
func imageDependency(res *Result, ref string, line int) (Dependency, bool) {
	r, err := parseImageRef(ref)
	if err != nil {
		res.warnf("line %d: not an image reference (%v)", line, err)
		return Dependency{}, false
	}
	if r.digest == "" {
		res.warnf("line %d: image %s is not pinned by digest", line, cleanURL(r.domain+"/"+r.path))
		return Dependency{}, false
	}
	alg, value, _ := strings.Cut(r.digest, ":")
	return Dependency{
		Type:     "docker",
		Name:     cleanURL(r.path),
		Version:  r.digest,
		Digests:  []Digest{{Algorithm: alg, Value: value}},
		Registry: r.registryURL(),
		Line:     line,
	}, true
}

// --- Dockerfile ------------------------------------------------------------------

// dockerfile reads the images a Dockerfile builds on.
type dockerfile struct{}

func (dockerfile) Type() string   { return "docker" }
func (dockerfile) Format() string { return "Dockerfile" }

// Detect accepts Dockerfile and Containerfile, with a suffix
// ("Dockerfile.prod") or as an extension ("app.dockerfile").
func (dockerfile) Detect(path string) bool {
	name := baseName(path)
	lower := strings.ToLower(name)
	for _, base := range []string{"dockerfile", "containerfile"} {
		if lower == base || strings.HasPrefix(lower, base+".") || strings.HasSuffix(lower, "."+base) {
			return true
		}
	}
	return false
}

// dockerInstruction is one instruction with its continuation lines joined.
type dockerInstruction struct {
	keyword, args string
	line          int
}

func (dockerfile) Parse(data []byte) (*Result, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("Dockerfile is not valid UTF-8")
	}
	instructions := dockerInstructions(string(data))
	res := &Result{}
	globalArgs := map[string]string{}
	stages := map[string]bool{}
	sawFrom := false
	for _, in := range instructions {
		switch in.keyword {
		case "ARG":
			if sawFrom {
				continue // a stage's ARG; FROM sees only those before the first FROM
			}
			for _, def := range strings.Fields(in.args) {
				name, value, _ := strings.Cut(def, "=")
				globalArgs[name] = strings.Trim(value, `"'`)
			}
		case "FROM":
			sawFrom = true
			fields := strings.Fields(in.args)
			var image string
			for i := 0; i < len(fields); i++ {
				if strings.HasPrefix(fields[i], "--") {
					continue
				}
				image = fields[i]
				if i+2 < len(fields) && strings.EqualFold(fields[i+1], "AS") {
					stages[strings.ToLower(fields[i+2])] = true
				}
				break
			}
			dockerImage(res, image, globalArgs, stages, in.line)
		case "COPY", "ADD":
			for _, f := range strings.Fields(in.args) {
				from, ok := strings.CutPrefix(f, "--from=")
				if !ok {
					continue
				}
				if _, isIndex := atoiSmall(from); isIndex || stages[strings.ToLower(from)] {
					continue // an earlier stage
				}
				if strings.Contains(from, "$") {
					continue // a stage ARG, unknown here
				}
				dockerImage(res, from, nil, stages, in.line)
			}
		}
	}
	return res, nil
}

// dockerImage records the image of a FROM / COPY --from.
func dockerImage(res *Result, image string, args map[string]string, stages map[string]bool, line int) {
	if image == "" {
		res.warnf("line %d: no image named", line)
		return
	}
	expanded, ok := expandVars(image, args)
	if !ok {
		res.warnf("line %d: the image is chosen by a build argument without a default", line)
		return
	}
	if strings.EqualFold(expanded, "scratch") || stages[strings.ToLower(expanded)] {
		return
	}
	if d, ok := imageDependency(res, expanded, line); ok {
		res.Dependencies = append(res.Dependencies, d)
	}
}

func atoiSmall(s string) (int, bool) {
	if s == "" || len(s) > 4 {
		return 0, false
	}
	n := 0
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// heredocRE finds the heredocs an instruction opens ("<<EOF", "<<-'EOT'").
var heredocRE = regexp.MustCompile(`<<(-?)(["']?)([A-Za-z_][A-Za-z0-9_]*)(["']?)`)

// dockerInstructions splits a Dockerfile into instructions: comments and
// blank lines dropped, continuation lines joined (the escape character can be
// changed by a parser directive), heredoc bodies skipped.
func dockerInstructions(src string) []dockerInstruction {
	lines := strings.Split(src, "\n")
	escape := byte('\\')
	var out []dockerInstruction
	directives := true
	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\r")
		trimmed := strings.TrimSpace(line)
		if directives {
			// Parser directives ("# escape=`", "# syntax=…") lead the file.
			if d, ok := strings.CutPrefix(trimmed, "#"); ok {
				if k, v, found := strings.Cut(strings.TrimSpace(d), "="); found {
					switch strings.ToLower(strings.TrimSpace(k)) {
					case "escape":
						if strings.TrimSpace(v) == "`" {
							escape = '`'
						}
						continue
					case "syntax", "check":
						continue
					}
				}
			}
			directives = false
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		start := i + 1
		var b strings.Builder
		for {
			t := strings.TrimRight(line, " \t\r")
			if len(t) > 0 && t[len(t)-1] == escape {
				b.WriteString(t[:len(t)-1])
				b.WriteByte(' ')
				i++
				// Comment lines inside a continuation are dropped.
				for i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), "#") {
					i++
				}
				if i >= len(lines) {
					break
				}
				line = strings.TrimRight(lines[i], "\r")
				continue
			}
			b.WriteString(line)
			break
		}
		text := strings.TrimSpace(b.String())
		keyword, args, _ := strings.Cut(text, " ")
		in := dockerInstruction{keyword: strings.ToUpper(keyword), args: strings.TrimSpace(args), line: start}
		out = append(out, in)
		// Skip heredoc bodies: their lines are data, not instructions.
		for _, m := range heredocRE.FindAllStringSubmatch(in.args, 8) {
			word, strip := m[3], m[1] == "-"
			for i+1 < len(lines) {
				i++
				body := strings.TrimRight(lines[i], "\r")
				if strip {
					body = strings.TrimLeft(body, "\t")
				}
				if body == word {
					break
				}
			}
		}
	}
	return out
}

// expandVars expands $VAR, ${VAR}, ${VAR:-default} and ${VAR:+alt} from vars
// (the build arguments with their defaults). ok is false when a variable is
// not defined and no default applies — the value is then decided at build
// time.
func expandVars(s string, vars map[string]string) (string, bool) {
	if !strings.Contains(s, "$") {
		return s, true
	}
	var b strings.Builder
	ok := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '$' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		if s[i+1] == '$' {
			b.WriteByte('$')
			i++
			continue
		}
		var name, op, word string
		if s[i+1] == '{' {
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return s, false
			}
			inner := s[i+2 : i+end]
			i += end
			name = inner
			for _, o := range []string{":-", ":+", "-", "+"} {
				if n, w, found := strings.Cut(inner, o); found {
					name, op, word = n, o, w
					break
				}
			}
		} else {
			j := i + 1
			for j < len(s) && (s[j] == '_' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z' || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			name = s[i+1 : j]
			i = j - 1
		}
		value, set := vars[name]
		switch op {
		case ":-", "-":
			if !set || (op == ":-" && value == "") {
				value, set = word, true
			}
		case ":+", "+":
			if set && (op == "+" || value != "") {
				value = word
			} else {
				value = ""
			}
			set = true
		}
		if !set {
			ok = false // decided at build time
		}
		b.WriteString(value)
	}
	return b.String(), ok
}

// --- Compose files ------------------------------------------------------------------

// composeFile reads the images of a Compose file's services.
type composeFile struct{}

func (composeFile) Type() string   { return "docker" }
func (composeFile) Format() string { return "compose" }

// Detect accepts compose.yaml, docker-compose.yml and their variants
// ("docker-compose.prod.yml", "compose.override.yaml").
func (composeFile) Detect(path string) bool {
	name := strings.ToLower(baseName(path))
	for _, ext := range []string{".yml", ".yaml"} {
		stem, ok := strings.CutSuffix(name, ext)
		if !ok {
			continue
		}
		for _, base := range []string{"compose", "docker-compose"} {
			if stem == base || strings.HasPrefix(stem, base+".") {
				return true
			}
		}
	}
	return false
}

func (composeFile) Parse(data []byte) (*Result, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, yamlError(err)
	}
	res := &Result{}
	c := newComposeResolver()
	top := c.mapping(&root)
	if top == nil {
		if yamlResolve(&root) == nil {
			return res, nil // an empty document
		}
		return nil, errors.New("compose file: not a YAML mapping")
	}
	servicesNode, err := c.get(top, "services")
	if err != nil {
		return nil, err
	}
	services := c.mapping(servicesNode)
	if servicesNode == nil {
		version, err := c.get(top, "version")
		if err != nil {
			return nil, err
		}
		if version == nil {
			services = top // the version 1 format: services at the top level
		}
	}
	if services == nil {
		return res, nil
	}
	for i := 0; i+1 < len(services.Content); i += 2 {
		svc := c.mapping(services.Content[i+1])
		if svc == nil {
			continue
		}
		img, err := c.get(svc, "image")
		if err != nil {
			return nil, err
		}
		img = c.resolve(img)
		if img == nil || img.Kind != yaml.ScalarNode || img.Value == "" {
			continue // built from a Dockerfile, which is scanned on its own
		}
		expanded, ok := expandVars(img.Value, nil)
		if !ok {
			res.warnf("line %d: the image depends on an environment variable", img.Line)
			continue
		}
		if d, ok := imageDependency(res, expanded, img.Line); ok {
			res.Dependencies = append(res.Dependencies, d)
		}
	}
	return res, nil
}

// finishImage maps an image dependency whose registry is the proxy — the
// container registry alias, "proxy.example.com/<upstream>/<repository>", or a
// personal link in front of it, "proxy.example.com/u/<token>/<upstream>/…" —
// back to the upstream, and removes the token.
func (p *Proxy) finishImage(d *Dependency) {
	prefix := strings.Trim(p.linkPrefix(), "/")
	host := strings.TrimPrefix(strings.TrimPrefix(d.Registry, "https://"), "http://")
	proxyHost := false
	for _, b := range p.publicBases() {
		if strings.EqualFold(b.Host, host) {
			proxyHost = true
		}
	}
	segs := strings.Split(d.Name, "/")
	personal := false
	if len(segs) >= 3 && segs[0] == prefix && (proxyHost || strings.HasPrefix(segs[1], linkTokenPrefix)) {
		segs, personal = segs[2:], true
	}
	if proxyHost || personal {
		// The configured upstreams describe this deployment, so they decide
		// only for its own host; elsewhere the first component names the
		// upstream, as the registry alias spells it.
		upstream := ""
		if proxyHost && p != nil {
			if up, ok := p.Upstreams[segs[0]]; ok && len(segs) > 1 && (up.Type == "docker" || up.Type == "helm" || up.Type == "") {
				upstream, segs = segs[0], segs[1:]
			} else if p.RegistryDefault != "" {
				upstream = p.RegistryDefault
			}
		}
		if upstream == "" && len(segs) > 1 {
			upstream, segs = segs[0], segs[1:]
		}
		d.Upstream = upstream
		d.Registry = "https://" + host
		if proxyHost && p != nil {
			if up, ok := p.Upstreams[upstream]; ok && up.URL != "" {
				d.Registry = redactText(sanitizeURL(up.URL), p.linkPrefix())
			}
		}
	}
	d.Name = redactText(strings.Join(segs, "/"), p.linkPrefix())
	d.Upstream = redactText(d.Upstream, p.linkPrefix())
	d.Registry = redactText(d.Registry, p.linkPrefix())
}
