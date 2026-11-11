package clientguide

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseBlocksMarkersAndHeadings(t *testing.T) {
	doc := strings.Join([]string{
		"# npm",
		"",
		"Intro with a [link](../clients.md#authenticate) and an ![image](img.png).",
		"",
		"## Configure",
		"",
		"<!-- verified: lab:npm ci:npm -->",
		"```ini",
		"registry=https://proxy.example.com/v1/npm/",
		"```",
		"",
		"<!-- some other comment -->",
		"",
		"<!-- untested: needs a Windows host to run -->",
		"",
		"~~~powershell",
		"```not a fence inside a tilde block",
		"~~~",
		"",
		"## Good to know",
		"",
		"<!-- proxy-config -->",
		"  ```yaml",
		"  upstreams: {}",
		"  ```",
		"```",
		"no marker",
		"```",
	}, "\n")
	page, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := page.Title(); got != "npm" {
		t.Errorf("Title = %q", got)
	}
	if got, want := page.Sections(), []string{"Configure", "Good to know"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Sections = %v, want %v", got, want)
	}
	if got := len(page.Blocks); got != 4 {
		t.Fatalf("got %d blocks, want 4", got)
	}

	b := page.Blocks[0]
	if b.Lang != "ini" || b.Section != "Configure" || b.Line != 8 {
		t.Errorf("block 0 = %+v", b)
	}
	if b.Marker == nil || b.Marker.Kind != KindVerified ||
		!reflect.DeepEqual(b.Marker.Sources, []Source{{SourceLab, "npm"}, {SourceCI, "npm"}}) {
		t.Errorf("block 0 marker = %+v", b.Marker)
	}
	if !reflect.DeepEqual(b.Lines, []string{"registry=https://proxy.example.com/v1/npm/"}) {
		t.Errorf("block 0 lines = %q", b.Lines)
	}

	b = page.Blocks[1]
	if b.Marker == nil || b.Marker.Kind != KindUntested || b.Marker.Text != "needs a Windows host to run" {
		t.Errorf("block 1 marker = %+v (a blank line may separate a marker from its block)", b.Marker)
	}
	if len(b.Lines) != 1 || !strings.HasPrefix(b.Lines[0], "```not a fence") {
		t.Errorf("block 1 lines = %q: a backtick line does not close a tilde fence", b.Lines)
	}

	b = page.Blocks[2]
	if b.Marker == nil || b.Marker.Kind != KindProxyConfig || b.Section != "Good to know" || b.Lang != "yaml" {
		t.Errorf("block 2 = %+v (an indented fence is a fence)", b)
	}
	if page.Blocks[3].Marker != nil {
		t.Errorf("block 3 has a marker it was not given: %+v", page.Blocks[3].Marker)
	}

	var targets []string
	for _, l := range page.Links {
		targets = append(targets, l.Target)
	}
	if want := []string{"../clients.md#authenticate", "img.png"}; !reflect.DeepEqual(targets, want) {
		t.Errorf("links = %v, want %v", targets, want)
	}
}

func TestParseRejectsMalformedInput(t *testing.T) {
	for name, tc := range map[string]struct{ doc, want string }{
		"verified without a script": {"<!-- verified: -->\n```\nx\n```\n", "names no script"},
		"unknown source kind":       {"<!-- verified: tested:npm -->\n```\nx\n```\n", "is not a source"},
		"source without a name":     {"<!-- verified: lab: -->\n```\nx\n```\n", "is not a source"},
		"untested without a reason": {"<!-- untested: -->\n```\nx\n```\n", "needs a reason"},
		"untested with a stub":      {"<!-- untested: todo -->\n```\nx\n```\n", "needs a reason"},
		"illustration with text":    {"<!-- illustration: why -->\n```\nx\n```\n", "takes no argument"},
		"marker without a block":    {"<!-- verified: lab:npm -->\n\nSome prose.\n\n```\nx\n```\n", "not followed by a fenced block"},
		"marker at the end":         {"text\n\n<!-- illustration -->\n", "not followed by a fenced block"},
		"unterminated fence":        {"```sh\necho\n", "is not closed"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Parse error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestUnverified(t *testing.T) {
	lab := Source{SourceLab, "npm"}
	ci := Source{SourceCI, "npm"}
	scripts := map[Source]string{
		lab: strings.Join([]string{
			"cat > .npmrc <<EOF",
			"registry=https://proxy.example.com/v1/npm/",
			"cafile=/etc/ssl/corp-ca.pem",
			"EOF",
			`    echo "//proxy.example.com/v1/npm/:_authToken=${PROXY_TOKEN}" >> .npmrc`,
			`helm repo add podinfo https://proxy.example.com/v1/podinfo   --ca-file /etc/ssl/corp-ca.pem \`,
		}, "\n"),
		ci: strings.Join([]string{
			`echo "registry=$MOUNT/" > .npmrc`,
			`docker pull "$PROXY_HOST/$PKG_UPSTREAM/$PKG_NAME:$PKG_VERSION"`,
			`#   { "registry-mirrors": ["https://proxy.example.com"] }`,
			`pip install --index-url "$PROXY_URL/v1/pip/simple/" conan`,
			`export JSR_URL="$MOUNT"`,
		}, "\n"),
	}
	block := func(sources []Source, lines ...string) Block {
		return Block{Marker: &Marker{Kind: KindVerified, Sources: sources}, Lines: lines}
	}

	for name, tc := range map[string]struct {
		block       Block
		wantMissing []string
		wantUnused  []Source
	}{
		"lab lines verbatim": {
			block: block([]Source{lab}, "registry=https://proxy.example.com/v1/npm/", "cafile=/etc/ssl/corp-ca.pem"),
		},
		"the token placeholder is the lab's variable": {
			block: block([]Source{lab}, "//proxy.example.com/v1/npm/:_authToken=<token>"),
		},
		"whitespace and continuation context do not matter": {
			block: block([]Source{lab}, "  helm repo add podinfo https://proxy.example.com/v1/podinfo --ca-file /etc/ssl/corp-ca.pem"),
		},
		"comments and blank lines are the guide's own": {
			block: block([]Source{lab}, "# the registry", "", "registry=https://proxy.example.com/v1/npm/", "// a note"),
		},
		"a ci script spells the mount $MOUNT": {
			block: block([]Source{ci}, "registry=https://proxy.example.com/v1/npm/"),
		},
		"a ci script spells another package source $PROXY_URL/v1/<name>": {
			block: block([]Source{ci}, `pip install --index-url "https://proxy.example.com/v1/pip/simple/" conan`),
		},
		"a ci script spells the host $PROXY_HOST": {
			block: block([]Source{ci}, `docker pull "proxy.example.com/$PKG_UPSTREAM/$PKG_NAME:$PKG_VERSION"`),
		},
		"a ci script quotes a variable where the guide has an address": {
			block: block([]Source{ci}, "export JSR_URL=https://proxy.example.com/v1/jsr"),
		},
		"a ci script may quote an address literally": {
			block: block([]Source{ci}, `{ "registry-mirrors": ["https://proxy.example.com"] }`),
		},
		"either source may hold a line, both must hold one": {
			block: block([]Source{lab, ci}, "registry=https://proxy.example.com/v1/npm/", "cafile=/etc/ssl/corp-ca.pem"),
		},
		"a line no script has": {
			block:       block([]Source{lab, ci}, "registry=https://proxy.example.com/v1/npm/", "strict-ssl=false"),
			wantMissing: []string{"strict-ssl=false"},
		},
		"a source that verifies nothing": {
			block:      block([]Source{lab, ci}, "cafile=/etc/ssl/corp-ca.pem"),
			wantUnused: []Source{ci},
		},
		"another upstream name is another line in the lab": {
			block:       block([]Source{lab}, "registry=https://proxy.example.com/v1/other/"),
			wantMissing: []string{"registry=https://proxy.example.com/v1/other/"},
			wantUnused:  []Source{lab},
		},
		"a block of comments verifies nothing": {
			block:       block([]Source{lab}, "# only words"),
			wantMissing: []string{"(the block has no line to verify)"},
			wantUnused:  []Source{lab},
		},
		"a script that does not exist": {
			block:       block([]Source{{SourceLab, "absent"}}, "registry=https://proxy.example.com/v1/npm/"),
			wantMissing: []string{"registry=https://proxy.example.com/v1/npm/"},
			wantUnused:  []Source{{SourceLab, "absent"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			missing, unused := tc.block.Unverified(scripts)
			if !reflect.DeepEqual(missing, tc.wantMissing) {
				t.Errorf("missing = %q, want %q", missing, tc.wantMissing)
			}
			if !reflect.DeepEqual(unused, tc.wantUnused) {
				t.Errorf("unused = %v, want %v", unused, tc.wantUnused)
			}
		})
	}

	// Only verified blocks are held to a script.
	other := Block{Marker: &Marker{Kind: KindUntested, Text: "needs a Windows host"}, Lines: []string{"anything"}}
	if missing, unused := other.Unverified(scripts); missing != nil || unused != nil {
		t.Errorf("an untested block was verified: %v %v", missing, unused)
	}
}

func TestIsComment(t *testing.T) {
	for line, want := range map[string]bool{
		"# a comment":  true,
		"#":            true,
		"// a comment": true,
		"<!-- xml -->": true,
		"#!/bin/sh":    false,
		"#include <x>": false,
		"//proxy.example.com/v1/npm/:_authToken=<token>": false,
		"registry=x":    false,
		"; ini comment": false, // not skipped: write INI comments with "#"
	} {
		if got := isComment(line); got != want {
			t.Errorf("isComment(%q) = %v, want %v", line, got, want)
		}
	}
}

func TestSlugAndAnchors(t *testing.T) {
	for heading, want := range map[string]string{
		"Configure":                     "configure",
		"Trust a private CA":            "trust-a-private-ca",
		"npm, Yarn, pnpm (JavaScript)":  "npm-yarn-pnpm-javascript",
		"Docker / OCI images":           "docker--oci-images",
		"`ptctl config` — the snippets": "ptctl-config--the-snippets",
		"What is cached?":               "what-is-cached",
		"C/C++ (Conan)":                 "cc-conan",
	} {
		if got := Slug(heading); got != want {
			t.Errorf("Slug(%q) = %q, want %q", heading, got, want)
		}
	}

	page, err := Parse([]byte("# T\n\n## Configure\n\n### npm\n\n## Authenticate\n\n### npm\n\n### npm\n"))
	if err != nil {
		t.Fatal(err)
	}
	anchors := page.Anchors()
	for _, want := range []string{"t", "configure", "authenticate", "npm", "npm-1", "npm-2"} {
		if !anchors[want] {
			t.Errorf("anchor %q missing from %v", want, anchors)
		}
	}
}

func TestPageFor(t *testing.T) {
	for typ, want := range map[string]string{"npm": "npm", "deb": "apt", "apt": "apt", "rpm": "yum", "pub": "dart", "dart": "dart"} {
		if got := PageFor(typ); got != want {
			t.Errorf("PageFor(%q) = %q, want %q", typ, got, want)
		}
	}
}
