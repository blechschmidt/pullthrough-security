package lockfiles

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

// gemfileLock reads Bundler's Gemfile.lock (gems.locked with gems.rb). Its
// sections:
//
//	GEM                       gems from a registry ("remote:")
//	GIT                       gems from a repository ("remote:", "revision:")
//	PATH                      gems from a local folder — not fetched
//	CHECKSUMS                 "name (version) sha256=…" (Bundler 2.6+)
//	BUNDLED WITH              the Bundler version that wrote the file
//
// A spec "nokogiri (1.16.7-x86_64-linux)" is one platform's build of a gem,
// a separate artifact with its own checksum; its version keeps the platform,
// as Bundler and the gem's file name spell it. Gemfile.lock does not record
// which gems are development-only.
type gemfileLock struct{}

func (gemfileLock) Type() string   { return "rubygems" }
func (gemfileLock) Format() string { return "Gemfile.lock" }
func (gemfileLock) Detect(path string) bool {
	name := baseName(path)
	return name == "Gemfile.lock" || name == "gems.locked"
}

// gemSpecRE matches "name (version)" with an optional checksum list after it.
var gemSpecRE = regexp.MustCompile(`^([^\s()]+) \(([^()\s]+)\)(?: (.*))?$`)

func (gemfileLock) Parse(data []byte) (*Result, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("Gemfile.lock is not valid UTF-8")
	}
	res := &Result{}
	section, remote, revision := "", "", ""
	inSpecs := false
	checksums := map[string][]Digest{}
	sawSection := false
	for it := newLineIter(string(data)); ; {
		raw, lineNo, more := it.next()
		if !more {
			break
		}
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			inSpecs = false
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		text := strings.TrimSpace(line)
		if indent == 0 {
			section, remote, revision, inSpecs = text, "", "", false
			sawSection = true
			continue
		}
		switch section {
		case "GEM", "GIT", "PATH", "PLUGIN SOURCE":
			switch {
			case indent == 2 && text == "specs:":
				inSpecs = true
			case indent == 2:
				key, value, _ := strings.Cut(text, ": ")
				switch key {
				case "remote":
					if remote == "" {
						remote = value
					}
				case "revision":
					revision = value
				}
			case indent == 4 && inSpecs:
				m := gemSpecRE.FindStringSubmatch(text)
				if m == nil {
					res.warnf("line %d: not a gem specification", lineNo)
					continue
				}
				if section == "PATH" || section == "PLUGIN SOURCE" {
					res.warnf("%s %s: from a %s source, not fetched from a registry", m[1], m[2], strings.ToLower(section))
					continue
				}
				d := Dependency{Name: m[1], Version: m[2], Line: lineNo}
				if section == "GIT" {
					d.Source, d.Registry = SourceGit, cleanGitRepoURL(remote)
					if isCommitID(revision) {
						d.Revision = strings.ToLower(revision)
					}
				} else {
					d.Registry = cleanURL(remote)
				}
				if !validPackageName(d.Name) || !validVersion(d.Version) {
					res.warnf("line %d: a gem without a usable name or version", lineNo)
					continue
				}
				res.add(d)
			}
		case "CHECKSUMS":
			m := gemSpecRE.FindStringSubmatch(text)
			if m == nil || m[3] == "" {
				continue
			}
			for _, sum := range strings.Split(m[3], ",") {
				if dg, ok := prefixedDigest(sum, ""); ok {
					checksums[m[1]+" "+m[2]] = append(checksums[m[1]+" "+m[2]], dg)
				}
			}
		case "BUNDLED WITH":
			res.FormatVersion = text
		}
	}
	if !sawSection {
		return nil, errors.New("not a Gemfile.lock: no sections")
	}
	for i := range res.Dependencies {
		d := &res.Dependencies[i]
		d.Digests = append(d.Digests, checksums[d.Name+" "+d.Version]...)
	}
	return res, nil
}
