package helm

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		path    string
		ok      bool
		kind    resourceKind
		name    string
		version string
	}{
		{"/index.yaml", true, kindIndex, "", ""},
		{"/nginx-1.2.3.tgz", true, kindChart, "nginx", "1.2.3"},
		{"/charts/nginx-1.2.3.tgz", true, kindChart, "nginx", "1.2.3"},
		{"/nginx-1.2.3.tgz.prov", true, kindProvenance, "nginx", "1.2.3"},
		{"/kube-state-metrics-5.0.1.tgz", true, kindChart, "kube-state-metrics", "5.0.1"},
		{"/mychart-2.0.0-rc.1.tgz", true, kindChart, "mychart", "2.0.0-rc.1"},
		// Rejections.
		{"", false, kindOther, "", ""},
		{"/", false, kindOther, "", ""},
		{"/foo.txt", false, kindOther, "", ""},
		{"/noversion.tgz", false, kindOther, "", ""},
		{"/-1.0.0.tgz", false, kindOther, "", ""},
		{"/../etc/passwd.tgz", false, kindOther, "", ""},
		{"/a/./b-1.0.0.tgz", false, kindOther, "", ""},
	}
	for _, c := range cases {
		r, ok := classify(c.path)
		if ok != c.ok {
			t.Errorf("classify(%q) ok = %v, want %v", c.path, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if r.kind != c.kind || r.name != c.name || r.version != c.version {
			t.Errorf("classify(%q) = {kind:%d name:%q version:%q}, want {kind:%d name:%q version:%q}",
				c.path, r.kind, r.name, r.version, c.kind, c.name, c.version)
		}
	}
}

func TestSplitChartFilename(t *testing.T) {
	cases := []struct {
		in      string
		name    string
		version string
		ok      bool
	}{
		{"nginx-1.2.3.tgz", "nginx", "1.2.3", true},
		{"my-app-0.1.0.tgz", "my-app", "0.1.0", true},
		{"chart-2.0.0-rc.1.tgz", "chart", "2.0.0-rc.1", true},
		{"noversion.tgz", "", "", false},
		{"-1.0.0.tgz", "", "", false},
		{"nginx-1.2.3.txt", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		name, version, ok := splitChartFilename(c.in)
		if ok != c.ok || name != c.name || version != c.version {
			t.Errorf("splitChartFilename(%q) = %q,%q,%v want %q,%q,%v",
				c.in, name, version, ok, c.name, c.version, c.ok)
		}
	}
}

func TestResourceHelpers(t *testing.T) {
	chart := resource{kind: kindChart, name: "n", version: "1"}
	if !chart.cacheable() || !chart.verifiableArtifact() || chart.coordinateName() != "n" {
		t.Error("chart resource helpers wrong")
	}
	idx := resource{kind: kindIndex}
	if idx.cacheable() || idx.verifiableArtifact() || idx.coordinateName() != "" {
		t.Error("index resource helpers wrong")
	}
	prov := resource{kind: kindProvenance, name: "n", version: "1"}
	if !prov.cacheable() || prov.verifiableArtifact() {
		t.Error("provenance resource helpers wrong")
	}
}
