package lockfiles

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// chartLock reads Helm's Chart.lock (and requirements.lock, which Helm writes
// for an apiVersion v1 chart with a requirements.yaml): every chart
// dependency with its exact version and the repository it comes from — an
// HTTP chart repository, an OCI registry ("oci://…"), a local directory
// ("file://…") or the name of a repository the user added ("@stable",
// "alias:stable"), whose URL is in their Helm configuration and not here.
//
// Chart.lock records no digest of a chart archive. Its "digest" is the
// SHA-256 over the dependency list of Chart.yaml and the locked versions —
// Helm uses it to tell whether the lock is out of date — and pins no bytes.
//
// Helm reads the file through sigs.k8s.io/yaml: YAML 1.1 turned into JSON,
// decoded by encoding/json. So keys match ignoring case ("Repository" is
// the repository), and an unquoted scalar YAML 1.1 reads as a number,
// boolean or date becomes another string ("version: 1.10" is "1.1"). A key
// given twice in different cases, and such a scalar where a name, version or
// repository is expected, are refused: Helm never writes them.
type chartLock struct{}

func (chartLock) Type() string            { return "helm" }
func (chartLock) Format() string          { return "Chart.lock" }
func (chartLock) Detect(path string) bool { return baseName(path) == "Chart.lock" }

func (chartLock) Parse(data []byte) (*Result, error) {
	m, err := readYAMLLock(data, "Chart.lock")
	if err != nil {
		return nil, err
	}
	return readChartLock(m)
}

// requirementsLock reads a file named requirements.lock: Helm writes one for
// an apiVersion v1 chart, in Chart.lock's format — and Rye writes one in the
// requirements syntax of pip. A file that is a YAML mapping is read as
// Helm's; anything else as pip requirements, and reported as that format.
type requirementsLock struct{}

func (requirementsLock) Type() string            { return "helm" }
func (requirementsLock) Format() string          { return "requirements.lock" }
func (requirementsLock) Detect(path string) bool { return baseName(path) == "requirements.lock" }

func (requirementsLock) Parse(data []byte) (*Result, error) {
	root, yerr := readYAMLDoc(data, "requirements.lock")
	if yerr == nil && root != nil && root.Kind == yaml.MappingNode {
		return readChartLock(root)
	}
	res, err := requirementsTxt{}.Parse(data)
	if err != nil {
		if yerr != nil {
			return nil, yerr
		}
		return nil, err
	}
	res.parsedAs = requirementsTxt{}
	return res, nil
}

const chartNoDigest = "Chart.lock records no digest of the chart archive (its digest covers the dependency list)"

// readChartLock reads the root mapping of a Chart.lock.
func readChartLock(m *yaml.Node) (*Result, error) {
	res := &Result{}
	if m == nil {
		return res, nil
	}
	deps, err := yamlGetFold(m, "dependencies")
	if err != nil {
		return nil, err
	}
	digest, err := yamlGetFold(m, "digest")
	if err != nil {
		return nil, err
	}
	if deps == nil && digest == nil {
		return nil, errNotFormat("Chart.lock", "no dependencies and no digest")
	}
	for _, e := range yamlSeq(deps) {
		var field [3]string
		for i, key := range []string{"name", "version", "repository"} {
			n, err := yamlGetFold(e, key)
			if err != nil {
				return nil, err
			}
			if yaml11Ambiguous(n) {
				return nil, fmt.Errorf("Chart.lock line %d: an unquoted %s that YAML 1.1 reads as a number, boolean or date, which Helm turns into another string", n.Line, key)
			}
			field[i] = yamlScalar(n)
		}
		name, version, repo := field[0], field[1], strings.TrimSpace(field[2])
		line := e.Line
		if !validPackageName(name) || !validVersion(version) {
			res.warnf("line %d: a dependency without a usable name or version", line)
			continue
		}
		if strings.ContainsAny(version, "<>=~^*|, ") {
			res.warnf("%s: the version is a range, not a pin", name)
			continue
		}
		d := Dependency{Name: name, Version: version, Line: line, UnverifiedReason: chartNoDigest}
		lower := strings.ToLower(repo)
		switch {
		case strings.HasPrefix(lower, "file://"):
			res.warnf("%s %s: a chart in a local directory, not fetched", name, version)
			continue
		case strings.HasPrefix(lower, "https://"), strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "oci://"):
			d.Registry = cleanURL(repo)
		case strings.HasPrefix(repo, "@") || strings.HasPrefix(lower, "alias:"):
			res.warnf("%s %s: from the repository named %s in the user's Helm configuration, whose URL is not recorded", name, version, quoteName(repo))
		case repo == "":
			// No repository: a chart vendored into charts/, not fetched.
			res.warnf("%s %s: no repository; the chart is expected in charts/", name, version)
			continue
		default:
			res.warnf("%s %s: a repository this parser does not recognise", name, version)
			continue
		}
		res.add(d)
	}
	return res, nil
}

// yamlGetFold returns the value of the key of mapping m that equals key
// ignoring case — how encoding/json matches a struct field, and so how a
// file read through sigs.k8s.io/yaml is read. Two such keys are an error.
func yamlGetFold(m *yaml.Node, key string) (*yaml.Node, error) {
	m = yamlMapping(m)
	if m == nil {
		return nil, nil
	}
	var found *yaml.Node
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind != yaml.ScalarNode || !strings.EqualFold(k.Value, key) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("line %d: %q is given twice, in different cases", k.Line, key)
		}
		found = m.Content[i+1]
	}
	return found, nil
}

// yaml11Forms are plain scalars a YAML 1.1 reader (yaml.v2) resolves to a
// number, a boolean, null or a timestamp — and that, decoded into a string,
// are no longer what the file says.
var yaml11Forms = regexp.MustCompile(`^(?:` +
	`y|Y|yes|Yes|YES|n|N|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF` + // booleans
	`|~|null|Null|NULL` + // null
	`|[-+]?(?:0b[01_]+|0x[0-9a-fA-F_]+|0o?[0-7_]+|[0-9][0-9_]*)` + // integers (0 prefix: octal)
	`|[-+]?(?:[0-9][0-9_]*)?\.[0-9_]*(?:[eE][-+]?[0-9]+)?|[-+]?[0-9][0-9_]*[eE][-+]?[0-9]+` + // floats
	`|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)` +
	`|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?` + // base 60
	`|[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:[Tt ].*)?` + // timestamps
	`)$`)

// yaml11Ambiguous reports whether n is an unquoted scalar that a YAML 1.1
// reader does not read as the string it spells.
func yaml11Ambiguous(n *yaml.Node) bool {
	n = yamlResolve(n)
	if n == nil || n.Kind != yaml.ScalarNode || n.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return false
	}
	return n.Tag != "!!str" || yaml11Forms.MatchString(n.Value)
}
