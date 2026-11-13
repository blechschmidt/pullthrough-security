package livescan

import (
	"bytes"
	"embed"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// The corpus: known attacks, reconstructed.
//
// Each file testdata/corpus/<id>.txtar is one attack: a package (or a
// container image, an editor extension, a Git commit) that was really
// published with malicious content, rebuilt from the public analyses of it.
// The file's comment section is the sample's metadata (YAML); its files are
// the artifact's tree in two variants:
//
//	-- shared/<path> --     in both variants: the legitimate package
//	-- benign/<path> --     only in the benign variant (the last clean release)
//	-- malicious/<path> --  only in the malicious variant (the compromised one)
//
// A file under benign/ or malicious/ replaces a shared file of the same path.
// For a Git commit sample, shared/ is the repository before the change,
// benign/ an ordinary later change, and malicious/ the attacker's change.
//
// Why reconstructions and not the samples themselves: the samples are live
// malware, and this repository is public. The reconstructions keep what a
// reviewer would see — the files, the install hooks, the code paths from the
// trigger to the theft, the obfuscation layers, the strings — and differ from
// the originals in three ways, all stated in each sample's `reconstruction`
// note: every network endpoint of the malicious code is unresolvable (a
// `.invalid` host or a TEST-NET address, RFC 6761 / RFC 5737), so running one
// by accident cannot send anything anywhere (TestCorpusIsDefanged enforces
// it); payloads that were megabytes of bundled code are cut to the parts that
// matter; and the legitimate code around the payload is a much smaller stand-in
// for the real library. The txtar container keeps the trees from being
// installable or runnable as they sit in the repository.

//go:embed testdata/corpus/*.txtar
var corpusFS embed.FS

// Artifact kinds a sample can be served as.
const (
	KindNPM       = "npm"        // an npm package tarball (package/…)
	KindWheel     = "wheel"      // a Python wheel
	KindSdist     = "sdist"      // a Python source distribution (.tar.gz)
	KindOCIImage  = "oci-image"  // a container image (one layer)
	KindVSIX      = "vsix"       // a VS Code extension (.vsix) on Open VSX
	KindTarball   = "tarball"    // a release tarball served by a generic upstream
	KindGitCommit = "git-commit" // a commit judged by the LLM commit scan
)

var knownKinds = map[string]bool{
	KindNPM: true, KindWheel: true, KindSdist: true, KindOCIImage: true,
	KindVSIX: true, KindTarball: true, KindGitCommit: true,
}

// Sample is one reconstructed attack.
type Sample struct {
	// ID names the sample (the txtar file's base name).
	ID string `yaml:"id"`
	// Title is one line for reports.
	Title string `yaml:"title"`
	// Campaign groups the samples of one attack campaign (e.g. the TeamPCP
	// compromise of Trivy and what it led to).
	Campaign string `yaml:"campaign"`
	// Date is when the malicious version was published (YYYY-MM-DD).
	Date string `yaml:"date"`
	// Kind is how the artifact is served (one of the Kind constants).
	Kind string `yaml:"kind"`
	// Ecosystem is the proxy upstream type that serves it.
	Ecosystem string `yaml:"ecosystem"`
	// Name and Version are the malicious release in the ecosystem's spelling;
	// BenignVersion is the clean release used as the control.
	Name          string `yaml:"name"`
	Version       string `yaml:"version"`
	BenignVersion string `yaml:"benignVersion"`
	// Summary says what the real malicious version did.
	Summary string `yaml:"summary"`
	// Techniques are short tags (install-hook, credential-theft, …).
	Techniques []string `yaml:"techniques"`
	// Reconstruction says what the fixture keeps from the original and what it
	// changes.
	Reconstruction string `yaml:"reconstruction"`
	// References are the public analyses the reconstruction is based on.
	References []string `yaml:"references"`
	// LegitimateHosts are hosts of the real library that a malicious file may
	// name because it also holds the library's legitimate code (a manifest's
	// homepage, the API base URL of the client, the project's release page).
	// Every other host in a malicious file must be unresolvable.
	LegitimateHosts []string `yaml:"legitimateHosts,omitempty"`
	// ModelsMayRefuse lists models whose provider safeguards are known to
	// decline to judge this sample's malicious variant (a "refusal" stop reason:
	// the gate then has no verdict). With such a model a package that is blocked
	// without a verdict — only because failMode is closed — is the expected
	// outcome and passes with a note; with any other model the package must be
	// refused as malicious. The notes of the sample say what was observed.
	ModelsMayRefuse []string `yaml:"modelsMayRefuse,omitempty"`
	// Indicators are strings that occur in the malicious variant and not in the
	// benign one. The hermetic test's stand-in model keys on them; reports and
	// docs list them.
	Indicators []string `yaml:"indicators"`
	// Image describes a container image (kind oci-image).
	Image *ImageMeta `yaml:"image,omitempty"`
	// Commit describes the commits of a git-commit sample.
	Commit *CommitMeta `yaml:"commit,omitempty"`
	// Extension describes an Open VSX extension (kind vsix).
	Extension *ExtensionMeta `yaml:"extension,omitempty"`

	// Shared, Benign and Malicious are the file sections, by path.
	Shared        map[string][]byte `yaml:"-"`
	BenignOnly    map[string][]byte `yaml:"-"`
	MaliciousOnly map[string][]byte `yaml:"-"`
}

// ImageMeta is the configuration of a container image sample.
type ImageMeta struct {
	Entrypoint []string `yaml:"entrypoint"`
	Cmd        []string `yaml:"cmd"`
	Env        []string `yaml:"env"`
	WorkingDir string   `yaml:"workingDir"`
	User       string   `yaml:"user"`
	// History lines are the image's recorded build steps ("created_by").
	History []string `yaml:"history"`
}

// CommitMeta describes a git-commit sample's commits.
type CommitMeta struct {
	// Repository is the repository's name (owner/name).
	Repository string `yaml:"repository"`
	// BaseMessage, BenignMessage and MaliciousMessage are the commit messages.
	BaseMessage      string `yaml:"baseMessage"`
	BenignMessage    string `yaml:"benignMessage"`
	MaliciousMessage string `yaml:"maliciousMessage"`
	// Author is "Name <email>" of the benign commits; MaliciousAuthor of the
	// malicious one (attackers often impersonate a maintainer).
	Author          string `yaml:"author"`
	MaliciousAuthor string `yaml:"maliciousAuthor"`
}

// ExtensionMeta describes an Open VSX extension sample.
type ExtensionMeta struct {
	Publisher string `yaml:"publisher"`
	Name      string `yaml:"name"`
}

// Variant selects one of a sample's two artifacts.
type Variant string

const (
	Benign    Variant = "benign"
	Malicious Variant = "malicious"
)

// Files returns the tree of a variant: the shared files with the variant's
// own on top.
func (s *Sample) Files(v Variant) map[string][]byte {
	out := make(map[string][]byte, len(s.Shared)+len(s.MaliciousOnly))
	for p, b := range s.Shared {
		out[p] = b
	}
	own := s.BenignOnly
	if v == Malicious {
		own = s.MaliciousOnly
	}
	for p, b := range own {
		out[p] = b
	}
	return out
}

// VersionOf returns the version a variant is published as.
func (s *Sample) VersionOf(v Variant) string {
	if v == Malicious {
		return s.Version
	}
	return s.BenignVersion
}

// Corpus loads every sample, sorted by ID.
func Corpus() ([]*Sample, error) {
	entries, err := corpusFS.ReadDir("testdata/corpus")
	if err != nil {
		return nil, err
	}
	var out []*Sample
	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txtar") {
			continue
		}
		data, err := corpusFS.ReadFile("testdata/corpus/" + e.Name())
		if err != nil {
			return nil, err
		}
		s, err := ParseSample(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if want := strings.TrimSuffix(e.Name(), ".txtar"); s.ID != want {
			return nil, fmt.Errorf("%s: id %q does not match the file name", e.Name(), s.ID)
		}
		if seen[s.ID] {
			return nil, fmt.Errorf("%s: duplicate id %q", e.Name(), s.ID)
		}
		seen[s.ID] = true
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// fileHeader matches a txtar file header line: "-- name --".
var fileHeader = regexp.MustCompile(`^-- (\S(?:.*\S)?) --$`)

// ParseSample parses one txtar sample.
func ParseSample(data []byte) (*Sample, error) {
	comment, files, err := parseTxtar(data)
	if err != nil {
		return nil, err
	}
	s := &Sample{Shared: map[string][]byte{}, BenignOnly: map[string][]byte{}, MaliciousOnly: map[string][]byte{}}
	dec := yaml.NewDecoder(bytes.NewReader(comment))
	dec.KnownFields(true)
	if err := dec.Decode(s); err != nil {
		return nil, fmt.Errorf("metadata: %w", err)
	}
	for _, f := range files {
		section, rel, ok := strings.Cut(f.name, "/")
		if !ok || rel == "" {
			return nil, fmt.Errorf("file %q is not under shared/, benign/ or malicious/", f.name)
		}
		if clean := path.Clean(rel); clean != rel || strings.HasPrefix(rel, "/") || strings.HasPrefix(clean, "..") {
			return nil, fmt.Errorf("file %q: path is not clean and relative", f.name)
		}
		// A commit sample's tree is written into a working repository and
		// committed: a .git component would reach git's own directory (hooks
		// run during the commit, with whatever environment the suite has).
		for _, part := range strings.Split(rel, "/") {
			if strings.EqualFold(part, ".git") {
				return nil, fmt.Errorf("file %q: a path component is .git", f.name)
			}
		}
		var into map[string][]byte
		switch section {
		case "shared":
			into = s.Shared
		case "benign":
			into = s.BenignOnly
		case "malicious":
			into = s.MaliciousOnly
		default:
			return nil, fmt.Errorf("file %q is not under shared/, benign/ or malicious/", f.name)
		}
		if _, dup := into[rel]; dup {
			return nil, fmt.Errorf("file %q appears twice", f.name)
		}
		into[rel] = f.data
	}
	return s, s.validate()
}

type txtarFile struct {
	name string
	data []byte
}

// parseTxtar splits a txtar archive (golang.org/x/tools/txtar) into its
// comment and files. A file's content runs to the next header line.
func parseTxtar(data []byte) (comment []byte, files []txtarFile, err error) {
	lines := bytes.SplitAfter(data, []byte("\n"))
	cur := -1
	var buf bytes.Buffer
	flush := func() {
		if cur < 0 {
			comment = append([]byte(nil), buf.Bytes()...)
		} else {
			files[cur].data = append([]byte(nil), buf.Bytes()...)
		}
		buf.Reset()
	}
	for _, line := range lines {
		if m := fileHeader.FindSubmatch(bytes.TrimRight(line, "\r\n")); m != nil {
			flush()
			files = append(files, txtarFile{name: string(m[1])})
			cur = len(files) - 1
			continue
		}
		buf.Write(line)
	}
	flush()
	return comment, files, nil
}

var datePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// repositoryName is owner/name as a Git host spells it; no path component can
// be empty, "." or "..".
var repositoryName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$`)

// validate checks a sample's metadata and trees.
func (s *Sample) validate() error {
	var problems []string
	need := func(ok bool, format string, args ...any) {
		if !ok {
			problems = append(problems, fmt.Sprintf(format, args...))
		}
	}
	need(s.ID != "", "id is empty")
	need(s.Title != "", "title is empty")
	need(s.Campaign != "", "campaign is empty")
	need(datePattern.MatchString(s.Date), "date %q is not YYYY-MM-DD", s.Date)
	need(knownKinds[s.Kind], "kind %q is unknown", s.Kind)
	need(s.Ecosystem != "", "ecosystem is empty")
	need(s.Name != "", "name is empty")
	need(s.Version != "", "version is empty")
	need(s.BenignVersion != "" && s.BenignVersion != s.Version, "benignVersion must be set and differ from version")
	need(strings.TrimSpace(s.Summary) != "", "summary is empty")
	need(len(s.Techniques) > 0, "no techniques")
	need(strings.TrimSpace(s.Reconstruction) != "", "reconstruction note is empty")
	need(len(s.References) > 0, "no references")
	for _, r := range s.References {
		need(strings.HasPrefix(r, "https://"), "reference %q is not an https URL", r)
	}
	need(len(s.Indicators) > 0, "no indicators")
	for _, h := range s.LegitimateHosts {
		need(h != "" && !strings.ContainsAny(h, "/: \t") && !strings.HasPrefix(h, "."), "legitimateHosts entry %q is not a bare host name", h)
	}
	need(s.Kind != KindGitCommit || len(s.ModelsMayRefuse) == 0, "modelsMayRefuse is for package samples; a commit scan keeps the triage verdict when the deep stage is declined")
	for _, m := range s.ModelsMayRefuse {
		need(strings.TrimSpace(m) != "" && !strings.ContainsAny(m, " \t"), "modelsMayRefuse entry %q is not a model id", m)
	}
	need(len(s.MaliciousOnly) > 0, "no malicious/ files")
	switch s.Kind {
	case KindOCIImage:
		need(s.Image != nil && (len(s.Image.Entrypoint) > 0 || len(s.Image.Cmd) > 0), "an oci-image sample needs image.entrypoint or image.cmd")
	case KindGitCommit:
		need(s.Commit != nil && s.Commit.MaliciousMessage != "" && s.Commit.BenignMessage != "" && s.Commit.BaseMessage != "",
			"a git-commit sample needs commit.baseMessage, benignMessage and maliciousMessage")
		need(s.Commit != nil && repositoryName.MatchString(s.Commit.Repository),
			"commit.repository must be owner/name (letters, digits, . _ -), it names the repository the commit scan is shown")
		need(len(s.BenignOnly) > 0, "a git-commit sample needs benign/ files (the control commit)")
	case KindVSIX:
		need(s.Extension != nil && s.Extension.Publisher != "" && s.Extension.Name != "", "a vsix sample needs extension.publisher and extension.name")
	}
	benign, malicious := s.Files(Benign), s.Files(Malicious)
	for _, ind := range s.Indicators {
		need(treeContains(malicious, ind), "indicator %q does not occur in the malicious variant", ind)
		need(!treeContains(benign, ind), "indicator %q occurs in the benign variant", ind)
	}
	if len(problems) > 0 {
		return fmt.Errorf("sample %q: %s", s.ID, strings.Join(problems, "; "))
	}
	return nil
}

// treeContains reports whether any file of a tree (its path or content)
// contains s.
func treeContains(tree map[string][]byte, s string) bool {
	for p, b := range tree {
		if strings.Contains(p, s) || bytes.Contains(b, []byte(s)) {
			return true
		}
	}
	return false
}

// Paths returns a tree's paths, sorted.
func Paths(tree map[string][]byte) []string {
	out := make([]string, 0, len(tree))
	for p := range tree {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
