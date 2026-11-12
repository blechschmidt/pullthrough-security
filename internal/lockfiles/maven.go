package lockfiles

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// --- gradle.lockfile ---------------------------------------------------------

// gradleLock reads Gradle's dependency lock state: gradle.lockfile (and
// buildscript-gradle.lockfile, settings-gradle.lockfile), one line per module
//
//	com.fasterxml.jackson.core:jackson-databind:2.17.2=compileClasspath,runtimeClasspath
//
// and the per-configuration files of Gradle before 6.0
// (gradle/dependency-locks/<configuration>.lockfile), without the "=…" part.
// Gradle records no hashes and no repository.
type gradleLock struct{}

func (gradleLock) Type() string   { return "maven" }
func (gradleLock) Format() string { return "gradle.lockfile" }
func (gradleLock) Detect(path string) bool {
	name := baseName(path)
	if name == "gradle.lockfile" || strings.HasSuffix(name, "-gradle.lockfile") {
		return true
	}
	return strings.HasSuffix(name, ".lockfile") && baseName(dirName(path)) == "dependency-locks"
}

func (gradleLock) Parse(data []byte) (*Result, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("gradle lock file is not valid UTF-8")
	}
	res := &Result{}
	for it := newLineIter(string(data)); ; {
		raw, lineNo, more := it.next()
		if !more {
			break
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		coords, confs, _ := strings.Cut(line, "=")
		if coords == "empty" {
			continue // configurations without dependencies
		}
		parts := strings.Split(coords, ":")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || !validVersion(parts[2]) || !validPackageName(coords) {
			res.warnf("line %d: not a group:artifact:version entry", lineNo)
			continue
		}
		d := Dependency{Name: parts[0] + ":" + parts[1], Version: parts[2], Line: lineNo}
		if confs != "" {
			d.Dev = true
			for _, c := range strings.Split(confs, ",") {
				if c = strings.TrimSpace(c); c != "" && !strings.HasPrefix(strings.ToLower(c), "test") {
					d.Dev = false
				}
			}
		}
		res.Dependencies = append(res.Dependencies, d)
	}
	return res, nil
}

// --- pom.xml -----------------------------------------------------------------

// pomXML reads the dependencies of a Maven POM whose versions are fixed in the
// file: a literal version, or a property defined in the same POM. A range, a
// SNAPSHOT, LATEST/RELEASE, a version managed elsewhere (a parent, a BOM) or
// a property from outside the file is reported as a warning, not guessed.
//
// Read: the parent POM, <dependencies> (also in profiles), build plugins and
// their dependencies, and BOMs imported in <dependencyManagement> — every
// artifact the build fetches by coordinates the file fixes. Other
// <dependencyManagement> and <pluginManagement> entries only constrain
// versions and are not dependencies themselves.
type pomXML struct{}

func (pomXML) Type() string            { return "maven" }
func (pomXML) Format() string          { return "pom.xml" }
func (pomXML) Detect(path string) bool { return baseName(path) == "pom.xml" }

// pomCoord is a <dependency>, <plugin> or <parent> being read.
type pomCoord struct {
	kind                                string // "dependency", "plugin", "parent"
	path                                string // element path of the record
	groupID, artifactID, version, scope string
	managed                             bool // in <dependencyManagement>
	lineNo                              int
}

// pomRecordPaths are the element paths whose children are read as a record.
var pomRecordPaths = map[string]string{
	"project/parent":                                                        "parent",
	"project/dependencies/dependency":                                       "dependency",
	"project/dependencyManagement/dependencies/dependency":                  "dependency",
	"project/build/plugins/plugin":                                          "plugin",
	"project/build/plugins/plugin/dependencies/dependency":                  "dependency",
	"project/profiles/profile/dependencies/dependency":                      "dependency",
	"project/profiles/profile/build/plugins/plugin":                         "plugin",
	"project/profiles/profile/dependencyManagement/dependencies/dependency": "dependency",
	"project/profiles/profile/build/plugins/plugin/dependencies/dependency": "dependency",
}

// maxPOMDepth bounds element nesting.
const maxPOMDepth = 256

func (pomXML) Parse(data []byte) (*Result, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	dec.CharsetReader = pomCharsetReader
	res := &Result{}
	props := map[string]string{}
	var project struct{ groupID, version, parentGroup, parentVersion string }
	var repos, pluginRepos []string
	var records []*pomCoord
	var stack []string
	var open []*pomCoord // records being read, innermost last
	var text strings.Builder
	sawProject := false

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, xmlError(err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			if len(stack) > maxPOMDepth {
				return nil, errors.New("pom.xml nested too deeply")
			}
			if len(stack) == 1 {
				if t.Name.Local != "project" {
					return nil, errors.New("not a POM: the root element is not <project>")
				}
				sawProject = true
			}
			text.Reset()
			p, ok := pomPath(stack)
			if !ok {
				continue
			}
			if kind, ok := pomRecordPaths[p]; ok {
				line, _ := dec.InputPos()
				rec := &pomCoord{kind: kind, path: p, lineNo: line, managed: strings.Contains(p, "dependencyManagement")}
				open = append(open, rec)
				records = append(records, rec)
			}
		case xml.CharData:
			if text.Len() < 4096 {
				text.Write(t)
			}
		case xml.EndElement:
			p, interesting := pomPath(stack)
			value := strings.TrimSpace(text.String())
			text.Reset()
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			if !interesting {
				continue
			}
			switch {
			case len(open) > 0 && open[len(open)-1].path == p:
				open = open[:len(open)-1]
			case len(open) > 0 && strings.TrimSuffix(p, "/"+t.Name.Local) == open[len(open)-1].path:
				rec := open[len(open)-1]
				switch t.Name.Local {
				case "groupId":
					rec.groupID = value
				case "artifactId":
					rec.artifactID = value
				case "version":
					rec.version = value
				case "scope":
					rec.scope = value
				}
			case strings.HasPrefix(p, "project/properties/") && strings.Count(p, "/") == 2:
				props[t.Name.Local] = value
			case p == "project/groupId":
				project.groupID = value
			case p == "project/version":
				project.version = value
			case p == "project/repositories/repository/url":
				repos = append(repos, value)
			case p == "project/pluginRepositories/pluginRepository/url":
				pluginRepos = append(pluginRepos, value)
			}
			if p == "project/parent/groupId" {
				project.parentGroup = value
			}
			if p == "project/parent/version" {
				project.parentVersion = value
			}
		}
	}
	if !sawProject {
		return nil, errors.New("not a POM: no <project> element")
	}

	// Built-in properties.
	if project.groupID == "" {
		project.groupID = project.parentGroup
	}
	if project.version == "" {
		project.version = project.parentVersion
	}
	builtin := map[string]string{
		"project.version": project.version, "pom.version": project.version, "version": project.version,
		"project.groupId": project.groupID, "pom.groupId": project.groupID, "groupId": project.groupID,
		"project.parent.version": project.parentVersion, "parent.version": project.parentVersion,
		"project.parent.groupId": project.parentGroup, "parent.groupId": project.parentGroup,
	}
	resolve := func(s string) (string, bool) { return pomResolve(s, props, builtin) }

	// One repository named: it is where the dependencies come from (plugins
	// come from the plugin repositories). With several, the file does not say.
	registry, pluginRegistry := "", ""
	if len(repos) == 1 {
		registry = cleanURL(repos[0])
	}
	if len(pluginRepos) == 1 {
		pluginRegistry = cleanURL(pluginRepos[0])
	}
	for _, rec := range records {
		if rec.managed && rec.scope != "import" {
			continue // a version constraint, not a dependency
		}
		group, okG := resolve(rec.groupID)
		artifact, okA := resolve(rec.artifactID)
		if rec.kind == "plugin" && rec.groupID == "" {
			group, okG = "org.apache.maven.plugins", true
		}
		name := group + ":" + artifact
		if !okG || !okA || group == "" || artifact == "" || !validPackageName(name) {
			res.warnf("line %d: a %s whose coordinates are not fixed in this file", rec.lineNo, rec.kind)
			continue
		}
		if rec.version == "" {
			res.warnf("line %d: %s has no version in this file (managed elsewhere)", rec.lineNo, name)
			continue
		}
		version, ok := resolve(rec.version)
		if !ok {
			res.warnf("line %d: %s: its version comes from a property not defined in this file", rec.lineNo, name)
			continue
		}
		if why := pomNotFixed(version); why != "" {
			res.warnf("line %d: %s is not pinned to a fixed version (%s)", rec.lineNo, name, why)
			continue
		}
		reg := registry
		if strings.Contains(rec.path, "/plugins/") {
			reg = pluginRegistry
		}
		res.Dependencies = append(res.Dependencies, Dependency{
			Name: name, Version: version, Registry: reg, Line: rec.lineNo, Dev: rec.scope == "test",
		})
	}
	return res, nil
}

// pomPath returns the element path of the innermost element ("project/
// dependencies/dependency"), when it can be one the reader looks for: no
// such path is deeper than nine elements or has a name longer than 64 bytes,
// and building longer paths for every element would make reading a crafted
// POM quadratic in the length of its names.
func pomPath(stack []string) (string, bool) {
	if len(stack) > 9 {
		return "", false
	}
	n := 0
	for _, name := range stack {
		if len(name) > 64 {
			return "", false
		}
		n += len(name) + 1
	}
	var b strings.Builder
	b.Grow(n)
	for i, name := range stack {
		if i > 0 {
			b.WriteByte('/')
		}
		b.WriteString(name)
	}
	return b.String(), true
}

// pomResolve replaces ${property} references, up to a fixed depth of
// indirection. ok is false when a reference cannot be resolved here.
func pomResolve(s string, props, builtin map[string]string) (string, bool) {
	for round := 0; round < 10 && strings.Contains(s, "${"); round++ {
		var b strings.Builder
		rest := s
		for {
			i := strings.Index(rest, "${")
			if i < 0 {
				b.WriteString(rest)
				break
			}
			j := strings.IndexByte(rest[i:], '}')
			if j < 0 {
				return s, false
			}
			name := rest[i+2 : i+j]
			v, ok := props[name]
			if !ok {
				v, ok = builtin[name]
			}
			if !ok || v == "" {
				return s, false
			}
			b.WriteString(rest[:i])
			b.WriteString(v)
			rest = rest[i+j+1:]
			if b.Len() > 4096 {
				return s, false
			}
		}
		s = b.String()
	}
	return s, !strings.Contains(s, "${")
}

// pomNotFixed says why a version is not a fixed one, or "".
func pomNotFixed(v string) string {
	switch {
	case v == "LATEST" || v == "RELEASE":
		return v
	case strings.ContainsAny(v, "[](),"):
		return "a range"
	case strings.HasSuffix(v, "-SNAPSHOT"):
		return "a SNAPSHOT"
	case !validVersion(v):
		return "not a version"
	}
	return ""
}

// pomCharsetReader accepts the single-byte encodings POMs are sometimes
// declared in, converting them to UTF-8.
func pomCharsetReader(charset string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(charset) {
	case "utf-8", "utf8", "us-ascii", "ascii":
		return input, nil
	case "iso-8859-1", "latin1", "latin-1", "iso8859-1", "windows-1252", "cp1252":
		raw, err := io.ReadAll(io.LimitReader(input, 64<<20))
		if err != nil {
			return nil, err
		}
		runes := make([]rune, len(raw))
		for i, b := range raw {
			runes[i] = rune(b)
		}
		return strings.NewReader(string(runes)), nil
	}
	return nil, fmt.Errorf("unsupported XML encoding %q", charset)
}

// xmlError describes an XML syntax error by its line, not its text.
func xmlError(err error) error {
	var se *xml.SyntaxError
	if errors.As(err, &se) {
		return fmt.Errorf("XML syntax error on line %d", se.Line)
	}
	return errors.New("XML document could not be read")
}
