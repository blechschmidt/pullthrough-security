package vulnscan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
)

// --- fixture builders (Task 150) --------------------------------------------

// buildPyWheel builds an in-memory Python wheel (a zip). files maps a
// wheel-relative path to its contents; callers lay out the *.dist-info/METADATA,
// top_level.txt, and package source as a real wheel would.
func buildPyWheel(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("wheel create %s: %v", name, err)
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Fatalf("wheel write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("wheel close: %v", err)
	}
	return buf.Bytes()
}

// buildPySdist builds an in-memory Python sdist (gzip+tar) whose entries are
// prefixed with "<dist>-<version>/", matching the sdist layout.
func buildPySdist(t *testing.T, dist, version string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	prefix := dist + "-" + version + "/"
	for name, body := range files {
		full := prefix + name
		if err := tw.WriteHeader(&tar.Header{
			Name: full, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body)),
		}); err != nil {
			t.Fatalf("sdist header %s: %v", name, err)
		}
		if _, err := io.WriteString(tw, body); err != nil {
			t.Fatalf("sdist write %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("sdist tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("sdist gzip close: %v", err)
	}
	return buf.Bytes()
}

// buildMavenJar builds an in-memory Java/Maven jar (a zip). files maps a
// jar-relative path to its contents.
func buildMavenJar(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("jar create %s: %v", name, err)
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Fatalf("jar write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("jar close: %v", err)
	}
	return buf.Bytes()
}

// --- Python golden fixtures -------------------------------------------------

// pyWheelMetadata is the wheel core-metadata: one used and one unused dependency.
const pyWheelMetadata = `Metadata-Version: 2.1
Name: consumer
Version: 1.0.0
Requires-Dist: used-dep>=1.0
Requires-Dist: unused-dep (>=3.0)
Requires-Dist: maybe-dep; extra == "dev"

The long description follows the blank line and must be ignored:
Requires-Dist: not-a-real-header
`

// pyWheelSource imports the used dependency (module "used_dep") and the artifact's
// own package, but never the unused dependency.
const pyWheelSource = `import os
import used_dep as u
from consumer import helper

def run():
    return u.go() + helper()
`

func pyWheelFixture(t *testing.T) []byte {
	return buildPyWheel(t, map[string]string{
		"consumer/__init__.py":                   "",
		"consumer/app.py":                        pyWheelSource,
		"consumer/helper.py":                     "def helper():\n    return 1\n",
		"consumer-1.0.0.dist-info/METADATA":      pyWheelMetadata,
		"consumer-1.0.0.dist-info/top_level.txt": "consumer\n",
		"consumer-1.0.0.dist-info/RECORD":        "",
	})
}

func TestPythonReachabilityWheelGoldenFixtures(t *testing.T) {
	idx := analyzeReachability(Artifact{Ecosystem: "pip"}, pyWheelFixture(t))
	if !idx.analyzed {
		t.Fatalf("expected analyzed wheel index, reason=%q", idx.reason)
	}
	if !idx.importsObserved {
		t.Fatalf("expected importsObserved from wheel source")
	}
	cases := []struct {
		name string
		key  string
		want Reachability
	}{
		{"reachable-used-dep", "used-dep", ReachabilityReachable},
		{"reachable-case-insensitive", "Used_Dep", ReachabilityReachable},
		{"unreachable-unused-dep", "unused-dep", ReachabilityUnreachable},
		{"unknown-undeclared", "never-declared", ReachabilityUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := idx.classify(tc.key, false)
			if got != tc.want {
				t.Fatalf("classify(%q) = %q (%s), want %q", tc.key, got, reason, tc.want)
			}
		})
	}
	// The artifact's own top-level module is reachable (provided by the artifact).
	if got, _ := idx.classify("consumer", false); got != ReachabilityReachable {
		t.Fatalf("own module = %q, want reachable", got)
	}
}

func TestPythonReachabilitySdistGoldenFixtures(t *testing.T) {
	data := buildPySdist(t, "consumer", "1.0.0", map[string]string{
		"consumer/__init__.py": "",
		"consumer/app.py":      pyWheelSource,
		"consumer/helper.py":   "def helper():\n    return 1\n",
		"PKG-INFO":             pyWheelMetadata,
		"setup.py":             "from setuptools import setup\nsetup(name='consumer', install_requires=['used-dep>=1.0', 'unused-dep>=3.0'])\n",
	})
	idx := analyzeReachability(Artifact{Ecosystem: "pip"}, data)
	if !idx.analyzed {
		t.Fatalf("expected analyzed sdist index, reason=%q", idx.reason)
	}
	if got, _ := idx.classify("used-dep", false); got != ReachabilityReachable {
		t.Fatalf("sdist used-dep = %q, want reachable", got)
	}
	if got, _ := idx.classify("unused-dep", false); got != ReachabilityUnreachable {
		t.Fatalf("sdist unused-dep = %q, want unreachable", got)
	}
}

func TestPythonReachabilityAffectedModuleHint(t *testing.T) {
	// A finding whose coordinate does not map to an obvious module name, but whose
	// advisory declares the affected import path, resolves via the hint.
	idx := analyzeReachability(Artifact{Ecosystem: "pip"}, pyWheelFixture(t))
	got, reason := idx.classifyFinding("some-dist", []string{"used_dep"}, false)
	if got != ReachabilityReachable {
		t.Fatalf("affected-hint classify = %q (%s), want reachable", got, reason)
	}
}

func TestPythonReachabilityDynamicImportYieldsUnknown(t *testing.T) {
	data := buildPyWheel(t, map[string]string{
		"consumer/__init__.py":              "",
		"consumer/app.py":                   "import importlib\nname = 'unused_dep'\nm = importlib.import_module(name)\n",
		"consumer-1.0.0.dist-info/METADATA": pyWheelMetadata,
	})
	idx := analyzeReachability(Artifact{Ecosystem: "pip"}, data)
	if !idx.dynamic {
		t.Fatalf("expected dynamic import flag from importlib.import_module(var)")
	}
	if got, _ := idx.classify("unused-dep", false); got != ReachabilityUnknown {
		t.Fatalf("declared dep with dynamic import = %q, want unknown", got)
	}
}

func TestPythonReachabilityParseFailureIsUnknown(t *testing.T) {
	// Garbage content cannot be parsed as a wheel or sdist: conservative default.
	idx := analyzeReachability(Artifact{Ecosystem: "pip"}, []byte("not an archive at all"))
	if idx.analyzed {
		t.Fatalf("unparseable Python artifact should not be analyzed")
	}
	if got, _ := idx.classify("anything", false); got != ReachabilityUnknown {
		t.Fatalf("parse failure dep = %q, want unknown", got)
	}
	// The primary component stays trivially reachable even without analysis.
	if got, _ := idx.classify("consumer", true); got != ReachabilityReachable {
		t.Fatalf("primary = %q, want reachable", got)
	}
}

func TestPythonReachabilityMetadataOnlyIsConservative(t *testing.T) {
	// Metadata present but no source files: a declared dependency cannot be proven
	// unused, so it stays Unknown (not Unreachable).
	data := buildPyWheel(t, map[string]string{
		"consumer-1.0.0.dist-info/METADATA": pyWheelMetadata,
	})
	idx := analyzeReachability(Artifact{Ecosystem: "pip"}, data)
	if !idx.analyzed {
		t.Fatalf("expected analyzed index from metadata alone, reason=%q", idx.reason)
	}
	if idx.importsObserved {
		t.Fatalf("did not expect importsObserved without source")
	}
	if got, _ := idx.classify("unused-dep", false); got != ReachabilityUnknown {
		t.Fatalf("declared dep without source = %q, want unknown", got)
	}
}

func TestPythonRequirementName(t *testing.T) {
	cases := map[string]string{
		"Flask (>=1.0)":                   "flask",
		"requests>=2; python_version<'3'": "requests",
		"foo[extra]==1.0":                 "foo",
		"Django_Rest.Framework":           "django-rest-framework",
		"  spaced-name  ":                 "spaced-name",
		"":                                "",
	}
	for in, want := range cases {
		if got := pythonRequirementName(in); got != want {
			t.Fatalf("pythonRequirementName(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- Java / Maven golden fixtures -------------------------------------------

const javaSource = `package com.example;

import org.apache.commons.lang3.StringUtils;
import java.util.List;

public final class App {
    public static void main(String[] args) {
        System.out.println(StringUtils.isBlank(""));
    }
}
`

const mavenPOM = `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>consumer</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>32.0.0-jre</version>
    </dependency>
  </dependencies>
</project>
`

func mavenJarFixture(t *testing.T) []byte {
	return buildMavenJar(t, map[string]string{
		"com/example/App.java":                        javaSource,
		"com/example/App.class":                       "\xca\xfe\xba\xbe", // JVM magic; content not parsed
		"META-INF/maven/com.example/consumer/pom.xml": mavenPOM,
	})
}

func TestJavaReachabilityGoldenFixtures(t *testing.T) {
	idx := analyzeReachability(Artifact{Ecosystem: "maven"}, mavenJarFixture(t))
	if !idx.analyzed {
		t.Fatalf("expected analyzed jar index, reason=%q", idx.reason)
	}
	if !idx.importsObserved {
		t.Fatalf("expected importsObserved from .java source")
	}
	cases := []struct {
		name string
		key  string
		want Reachability
	}{
		// groupId "org.apache.commons" is the namespace of the imported
		// org.apache.commons.lang3.StringUtils → reachable.
		{"reachable-commons-lang3", "org.apache.commons:commons-lang3", ReachabilityReachable},
		// guava is declared in the POM but no class under com.google.guava is
		// imported → unreachable.
		{"unreachable-guava", "com.google.guava:guava", ReachabilityUnreachable},
		// Not declared at all → unknown.
		{"unknown-undeclared", "io.netty:netty-all", ReachabilityUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := idx.classify(tc.key, false)
			if got != tc.want {
				t.Fatalf("classify(%q) = %q (%s), want %q", tc.key, got, reason, tc.want)
			}
		})
	}
}

func TestJavaReachabilityAffectedModuleHint(t *testing.T) {
	idx := analyzeReachability(Artifact{Ecosystem: "maven"}, mavenJarFixture(t))
	// Advisory declares the exact affected package; the coordinate's groupId would
	// not have matched (different group), but the import path does.
	got, reason := idx.classifyFinding("some.group:artifact", []string{"org.apache.commons.lang3"}, false)
	if got != ReachabilityReachable {
		t.Fatalf("affected-hint classify = %q (%s), want reachable", got, reason)
	}
}

func TestJavaReachabilityReflectionYieldsUnknown(t *testing.T) {
	src := `package com.example;
public class Dyn {
    public static void main(String[] a) throws Exception {
        Class<?> c = Class.forName(a[0]);
        c.getName();
    }
}
`
	data := buildMavenJar(t, map[string]string{
		"com/example/Dyn.java":                        src,
		"META-INF/maven/com.example/consumer/pom.xml": mavenPOM,
	})
	idx := analyzeReachability(Artifact{Ecosystem: "maven"}, data)
	if !idx.dynamic {
		t.Fatalf("expected dynamic flag from Class.forName(var)")
	}
	if got, _ := idx.classify("com.google.guava:guava", false); got != ReachabilityUnknown {
		t.Fatalf("declared dep with reflection = %q, want unknown", got)
	}
}

func TestJavaReachabilityParseFailureIsUnknown(t *testing.T) {
	idx := analyzeReachability(Artifact{Ecosystem: "maven"}, []byte("not a jar"))
	if idx.analyzed {
		t.Fatalf("unparseable jar should not be analyzed")
	}
	if got, _ := idx.classify("org.apache.commons:commons-lang3", false); got != ReachabilityUnknown {
		t.Fatalf("parse failure dep = %q, want unknown", got)
	}
	if got, _ := idx.classify("com.example:consumer", true); got != ReachabilityReachable {
		t.Fatalf("primary = %q, want reachable", got)
	}
}

func TestJavaReachabilityClassesOnlyIsConservative(t *testing.T) {
	// A jar with compiled classes and a POM but no source: imports cannot be
	// observed (bytecode is not parsed), so declared deps stay Unknown.
	data := buildMavenJar(t, map[string]string{
		"com/example/App.class":                       "\xca\xfe\xba\xbe",
		"META-INF/maven/com.example/consumer/pom.xml": mavenPOM,
	})
	idx := analyzeReachability(Artifact{Ecosystem: "maven"}, data)
	if !idx.analyzed {
		t.Fatalf("expected analyzed index from classes+pom, reason=%q", idx.reason)
	}
	if idx.importsObserved {
		t.Fatalf("did not expect importsObserved without .java source")
	}
	if got, _ := idx.classify("com.google.guava:guava", false); got != ReachabilityUnknown {
		t.Fatalf("declared dep without source = %q, want unknown", got)
	}
}

func TestJavaImportPackage(t *testing.T) {
	cases := map[string]string{
		"org.apache.commons.lang3.StringUtils": "org.apache.commons.lang3",
		"java.util.List":                       "java.util",
		"org.apache.commons.lang3":             "org.apache.commons.lang3", // wildcard (".*" pre-trimmed)
		"":                                     "",
	}
	for in, want := range cases {
		if got := javaImportPackage(in); got != want {
			t.Fatalf("javaImportPackage(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- service-level integration (Python + Java) ------------------------------

func TestServiceReachabilityPythonSuppress(t *testing.T) {
	data := pyWheelFixture(t)
	sc := &reachFixtureScanner{vulns: []Vulnerability{
		{ID: "CVE-PY-REACH", Severity: SeverityCritical, CVSS: 9.8, Package: "used-dep", Version: "1.0.0"},
		{ID: "CVE-PY-UNREACH", Severity: SeverityCritical, CVSS: 9.1, Package: "unused-dep", Version: "3.0.0"},
	}}
	svc, err := NewService(Config{
		FailSeverity: SeverityHigh,
		Action:       policy.ActionBlock,
		Reachability: ReachabilityConfig{Enabled: true, UnreachableAction: ReachActionSuppress},
	}, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	art := Artifact{Ecosystem: "pip", Name: "consumer", Version: "1.0.0", Digest: "sha256:py1"}
	report, _ := svc.Assess(context.Background(), art, reachOpener(data))

	byID := map[string]Vulnerability{}
	for _, v := range report.Vulnerabilities {
		byID[v.ID] = v
	}
	if got := byID["CVE-PY-REACH"].Reachability; got != ReachabilityReachable {
		t.Fatalf("reachable finding = %q, want reachable", got)
	}
	unreach := byID["CVE-PY-UNREACH"]
	if unreach.Reachability != ReachabilityUnreachable || !unreach.ReachSuppressed {
		t.Fatalf("unreachable finding = %q suppressed=%v, want unreachable+suppressed", unreach.Reachability, unreach.ReachSuppressed)
	}
	if report.Counts.Critical != 1 {
		t.Fatalf("critical count = %d, want 1 (suppressed excluded)", report.Counts.Critical)
	}
	if d := svc.Gate(report); !d.Action.Blocked() {
		t.Fatalf("expected block on reachable critical, got %s", d.Action)
	}
}

func TestServiceReachabilityJavaDowngrade(t *testing.T) {
	data := mavenJarFixture(t)
	sc := &reachFixtureScanner{vulns: []Vulnerability{
		{ID: "CVE-JAVA-UNREACH", Severity: SeverityCritical, CVSS: 9.1, Package: "com.google.guava:guava", Version: "32.0.0-jre"},
	}}
	svc, err := NewService(Config{
		FailSeverity: SeverityCritical,
		Action:       policy.ActionBlock,
		Reachability: ReachabilityConfig{Enabled: true, UnreachableAction: ReachActionDowngrade},
	}, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	art := Artifact{Ecosystem: "maven", Name: "com.example:consumer", Version: "1.0.0", Digest: "sha256:jv1"}
	report, _ := svc.Assess(context.Background(), art, reachOpener(data))

	v := report.Vulnerabilities[0]
	if v.Reachability != ReachabilityUnreachable {
		t.Fatalf("java finding reachability = %q, want unreachable", v.Reachability)
	}
	if v.Severity != SeverityHigh || v.ReachOriginalSeverity != SeverityCritical {
		t.Fatalf("downgrade: severity=%q original=%q, want high/critical", v.Severity, v.ReachOriginalSeverity)
	}
	if d := svc.Gate(report); d.Action.Blocked() {
		t.Fatalf("expected allow after downgrade below critical, got %s / %s", d.Action, d.Reason)
	}
}
