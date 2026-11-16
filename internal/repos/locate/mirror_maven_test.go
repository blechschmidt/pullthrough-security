package locate

import (
	"sort"
	"strings"
	"testing"
)

func TestMavenExtensionAndCentralHosts(t *testing.T) {
	for packaging, want := range map[string]string{"jar": "jar", "bundle": "jar", "maven-plugin": "jar", " WAR ": "war", "aar": "aar", "zip": "zip"} {
		if got, ok := MavenExtension(packaging); !ok || got != want {
			t.Errorf("MavenExtension(%q) = %q, %v; want %q", packaging, got, ok, want)
		}
	}
	for _, packaging := range []string{"pom", "", "hpi", "clojure", "${packaging}"} {
		if got, ok := MavenExtension(packaging); ok {
			t.Errorf("MavenExtension(%q) = %q, want none", packaging, got)
		}
	}
	hosts := MavenCentralHosts()
	sort.Strings(hosts)
	if strings.Join(hosts, ",") != "central.maven.org,repo.maven.apache.org,repo.maven.org,repo1.maven.org" {
		t.Errorf("MavenCentralHosts = %v", hosts)
	}
	// A copy: the caller cannot change the locator's table.
	hosts[0] = "changed"
	if MavenCentralHosts()[0] == "changed" {
		t.Errorf("MavenCentralHosts hands out the locator's own slice")
	}
}
