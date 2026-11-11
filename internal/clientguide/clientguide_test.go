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
		// A second marker would silently replace the first.
		"two markers for one block": {"<!-- verified: lab:npm -->\n<!-- illustration -->\n```\nx\n```\n", "line 1: the marker is not followed by a fenced block"},
		// An info string with more than a language is a block to a renderer; were
		// it not one here, the closing fence would open a block instead.
		"an info string with attributes": {"<!-- illustration -->\n```sh title=\"x\"\necho\n```\n", "is not just a language"},
		// Code that a renderer shows and that is not a block of the page: it
		// would need no marker.
		"a fence in a blockquote":           {"> text\n>\n> ```sh\n> rm -rf /\n> ```\n", "inside a blockquote"},
		"an indented code block":            {"Text.\n\n    npm config set strict-ssl false\n", "an indented code block"},
		"a tab-indented code block":         {"Text.\n\n\tnpm config set strict-ssl false\n", "an indented code block"},
		"an indented code block in a list":  {"- item\n\n      npm config set strict-ssl false\n", "an indented code block"},
		"a pre element":                     {"<pre>npm config set strict-ssl false</pre>\n", "<pre> element"},
		"a pre element with attributes":     {"Text <PRE class=\"x\">\ncode\n</pre>\n", "<pre> element"},
		"an indented block after a heading": {"## Configure\n\n    registry=x\n", "an indented code block"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Parse error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

// What looks like the cases above and is not: text a renderer does not show as
// a code block.
func TestParseAcceptsOrdinaryMarkdown(t *testing.T) {
	for name, doc := range map[string]string{
		"a list item's second paragraph":  "- item\n\n  more about the item\n",
		"a nested list":                   "- item\n\n    - nested\n    - nested too\n",
		"a numbered item's paragraph":     "1. item\n\n   more about the item\n",
		"a wrapped paragraph":             "Text that goes on\n    on an indented line, without a blank line before it.\n",
		"a code span of three backticks":  "Write ```` ``` ```` to open a block, or ```inline``` code.\n",
		"a blockquote":                    "> **Note.** `npm` reads `.npmrc`.\n> More.\n",
		"a table":                         "| a | b |\n|---|---|\n| `x` | y |\n",
		"a multi-line comment":            "<!-- a note\nover two lines -->\n",
		"a language with punctuation":     "<!-- illustration -->\n```c++\nint x;\n```\n",
		"a longer closing fence":          "<!-- illustration -->\n```sh\necho\n`````\n",
		"a fence indented in a list item": "- item:\n\n  <!-- illustration -->\n\n  ```sh\n  echo\n  ```\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); err != nil {
				t.Errorf("Parse: %v", err)
			}
		})
	}
}

func TestCheck(t *testing.T) {
	lab := Source{SourceLab, "npm"}
	ci := Source{SourceCI, "npm"}
	ci2 := Source{SourceLab, "conda"} // a second lab script, of another ecosystem
	checker := Checker{
		Scripts: map[Source]string{
			ci2: strings.Join([]string{
				"cat > ~/.condarc <<EOF",
				"channel_alias: https://proxy.example.com/v1",
				"ssl_verify: /etc/ssl/corp-ca.pem",
				"EOF",
				"conda create --yes --prefix env tzdata",
			}, "\n"),
			lab: strings.Join([]string{
				"#!/bin/sh",
				"# strict-ssl=false would also work, and nobody should do it",
				"cat > .npmrc <<EOF",
				"registry=https://proxy.example.com/v1/npm/",
				"cafile=/etc/ssl/corp-ca.pem",
				"EOF",
				`    echo "//proxy.example.com/v1/npm/:_authToken=${PROXY_TOKEN}" >> .npmrc`,
				`helm repo add podinfo https://proxy.example.com/v1/podinfo   --ca-file /etc/ssl/corp-ca.pem \`,
				`    --username pullthrough --password "${PROXY_TOKEN}"`,
				"mix local.hex --force >local-hex.log 2>&1",
				"npm install is-number >/dev/null",
				`grep -q "always-auth=true" .npmrc`,
				`composer config --global bearer.proxy.example.com "${PROXY_TOKEN}"`,
				"cat > settings.json <<EOF",
				"{",
				`  "registry": "https://proxy.example.com/v1/npm/"`,
				"}",
				"EOF",
				"cat > ~/.condarc <<'EOF'",
				"# the channels of this machine",
				"channel_alias: https://proxy.example.com/v1",
				"channels:",
				"  - conda-forge",
				"default_channels: []",
				"EOF",
				"cat > settings.xml <<EOF",
				"<settings>",
				"  <servers>",
				"    <server>",
				"      <id>pullthrough</id>",
				"    </server>",
				"  </servers>",
				"</settings>",
				"EOF",
			}, "\n"),
			ci: strings.Join([]string{
				`echo "registry=$MOUNT/" > .npmrc`,
				`docker pull "$PROXY_HOST/$PKG_UPSTREAM/$PKG_NAME:$PKG_VERSION"`,
				`#   { "registry-mirrors": ["https://proxy.example.com"] }`,
				`pip install --index-url "$PROXY_URL/v1/pip/simple/" conan`,
				`export JSR_URL="$MOUNT"`,
				`VERSION="$(awk '{print $3}' version.txt)"`,
			}, "\n"),
		},
		MountTypes: map[string]string{"npm": "npm", "npm-jsr": "npm", "pypi": "pip", "jsr": "jsr", "pip": "pip"},
		CITypes:    map[string]string{"npm": "npm"},
	}
	block := func(lang string, sources []Source, lines ...string) Block {
		return Block{Lang: lang, Marker: &Marker{Kind: KindVerified, Sources: sources}, Lines: lines}
	}

	for name, tc := range map[string]struct {
		block Block
		want  Result
	}{
		"lab lines verbatim": {
			block: block("ini", []Source{lab}, "registry=https://proxy.example.com/v1/npm/", "cafile=/etc/ssl/corp-ca.pem"),
		},
		"the token placeholder is the lab's variable": {
			block: block("ini", []Source{lab}, "//proxy.example.com/v1/npm/:_authToken=<token>"),
		},
		"indentation and alignment do not matter": {
			block: block("sh", []Source{lab}, `   helm repo add podinfo https://proxy.example.com/v1/podinfo --ca-file /etc/ssl/corp-ca.pem \`,
				`--username pullthrough     --password "<token>"`),
		},
		"blank lines do not matter": {
			block: block("ini", []Source{lab}, "", "registry=https://proxy.example.com/v1/npm/", "", "cafile=/etc/ssl/corp-ca.pem"),
		},
		"a comment the script writes into the file is a line of the file": {
			block: block("yaml", []Source{lab}, "# the channels of this machine", "channel_alias: https://proxy.example.com/v1"),
		},
		"part of a file, moved to the left margin": {
			block: block("xml", []Source{lab}, "<server>", "  <id>pullthrough</id>", "</server>"),
		},
		"part of a file, inside a list item": {
			block: block("xml", []Source{lab}, "     <servers>", "       <server>", "         <id>pullthrough</id>"),
		},
		"a command without the script's output redirection": {
			block: block("sh", []Source{lab}, "mix local.hex --force", "npm install is-number"),
		},
		"the line an echo writes into a file": {
			block: block("ini", []Source{lab, ci}, "//proxy.example.com/v1/npm/:_authToken=<token>", "registry=https://proxy.example.com/v1/npm/"),
		},
		"a ci script spells its own mount $MOUNT": {
			block: block("ini", []Source{ci}, "registry=https://proxy.example.com/v1/npm/"),
		},
		"$MOUNT stands for any upstream of the script's type": {
			block: block("ini", []Source{ci}, "registry=https://proxy.example.com/v1/npm-jsr/"),
		},
		"a ci script spells another package source $PROXY_URL/v1/<name>": {
			block: block("sh", []Source{ci}, `pip install --index-url "https://proxy.example.com/v1/pip/simple/" conan`),
		},
		"a ci script spells the host $PROXY_HOST": {
			block: block("sh", []Source{ci}, `docker pull "proxy.example.com/$PKG_UPSTREAM/$PKG_NAME:$PKG_VERSION"`),
		},
		"a ci script quotes a variable where the guide has an address": {
			block: block("sh", []Source{ci}, "export JSR_URL=https://proxy.example.com/v1/npm"),
		},
		"either source may hold a line, both must hold one": {
			block: block("ini", []Source{lab, ci}, "registry=https://proxy.example.com/v1/npm/", "cafile=/etc/ssl/corp-ca.pem"),
		},

		"a line no script has": {
			block: block("ini", []Source{lab, ci}, "registry=https://proxy.example.com/v1/npm/", "strict-ssl=false"),
			want:  Result{Missing: []string{"strict-ssl=false"}},
		},
		"a source that verifies nothing": {
			block: block("ini", []Source{lab, ci}, "cafile=/etc/ssl/corp-ca.pem"),
			want:  Result{Unused: []Source{ci}},
		},
		"another upstream name is another line in the lab": {
			block: block("ini", []Source{lab}, "registry=https://proxy.example.com/v1/other/"),
			want:  Result{Missing: []string{"registry=https://proxy.example.com/v1/other/"}, Unused: []Source{lab}},
		},
		"an empty block verifies nothing": {
			block: block("sh", []Source{lab}, "", "  "),
			want:  Result{Missing: []string{"(the block has no line to verify)"}, Unused: []Source{lab}},
		},
		// A verified block has no words of its own: a comment is a line like any
		// other, and "# cmd" reads as a command at a root prompt.
		"a comment the script does not write": {
			block: block("ini", []Source{lab}, "registry=https://proxy.example.com/v1/npm/", "# npm config set strict-ssl false"),
			want:  Result{Missing: []string{"# npm config set strict-ssl false"}},
		},
		"the end of a here document is not a line of the file": {
			block: block("ini", []Source{lab}, "cafile=/etc/ssl/corp-ca.pem", "EOF"),
			want:  Result{Missing: []string{"EOF"}},
		},
		// One script writes the file a block shows.
		"lines of two files in one block": {
			block: block("ini", []Source{lab, ci2}, "registry=https://proxy.example.com/v1/npm/", "ssl_verify: /etc/ssl/corp-ca.pem"),
			want:  Result{Scattered: true},
		},
		"commands of several scripts in one block": {
			block: block("sh", []Source{lab, ci2}, "npm install is-number", "conda create --yes --prefix env tzdata"),
		},
		"a file of one script next to a command of another": {
			block: block("sh", []Source{lab, ci2}, "conda create --yes --prefix env tzdata", "registry=https://proxy.example.com/v1/npm/", "cafile=/etc/ssl/corp-ca.pem"),
		},
		// The lines of a file keep the nesting the script gives them.
		"a file with its nesting destroyed": {
			block: block("yaml", []Source{lab}, "channels:", "- conda-forge", "    default_channels: []"),
			want:  Result{Misindented: []string{"- conda-forge", "    default_channels: []"}},
		},
		"a nested line moved out": {
			block: block("xml", []Source{lab}, "<server>", "<id>pullthrough</id>"),
			want:  Result{Misindented: []string{"<id>pullthrough</id>"}},
		},
		"a script that does not exist": {
			block: block("ini", []Source{{SourceLab, "absent"}}, "registry=https://proxy.example.com/v1/npm/"),
			want:  Result{Missing: []string{"registry=https://proxy.example.com/v1/npm/"}, Unused: []Source{{SourceLab, "absent"}}},
		},

		// A line of the guide is a whole line of the script, not a piece of one.
		"a line cut short at the front": {
			block: block("ini", []Source{lab}, "egistry=https://proxy.example.com/v1/npm/"),
			want:  Result{Missing: []string{"egistry=https://proxy.example.com/v1/npm/"}, Unused: []Source{lab}},
		},
		"a command without its last argument": {
			block: block("sh", []Source{lab}, "composer config --global bearer.proxy.example.com"),
			want:  Result{Missing: []string{"composer config --global bearer.proxy.example.com"}, Unused: []Source{lab}},
		},
		"a command without the flags the script runs it with": {
			block: block("sh", []Source{lab}, "helm repo add podinfo https://proxy.example.com/v1/podinfo"),
			want:  Result{Missing: []string{"helm repo add podinfo https://proxy.example.com/v1/podinfo"}, Unused: []Source{lab}},
		},
		"a key that is the end of another key": {
			block: block("ini", []Source{lab}, "file=/etc/ssl/corp-ca.pem"),
			want:  Result{Missing: []string{"file=/etc/ssl/corp-ca.pem"}, Unused: []Source{lab}},
		},
		// What a script only says, it has not run.
		"a line the script has in a comment": {
			block: block("ini", []Source{lab}, "strict-ssl=false would also work, and nobody should do it"),
			want:  Result{Missing: []string{"strict-ssl=false would also work, and nobody should do it"}, Unused: []Source{lab}},
		},
		"a configuration a ci script only shows in a comment": {
			block: block("json", []Source{ci}, `{ "registry-mirrors": ["https://proxy.example.com"] }`),
			want:  Result{Missing: []string{`{ "registry-mirrors": ["https://proxy.example.com"] }`}, Unused: []Source{ci}},
		},
		"a line the script only looks for": {
			block: block("ini", []Source{lab}, "always-auth=true"),
			want:  Result{Missing: []string{"always-auth=true"}, Unused: []Source{lab}},
		},
		// Braces are in every script: they are found, and show nothing.
		"a brace does not show which script a block is from": {
			block: block("json", []Source{lab}, "{", "}"),
			want:  Result{Unused: []Source{lab}},
		},
		"a brace is not found inside a variable": {
			block: block("json", []Source{ci}, "{", "}"),
			want:  Result{Missing: []string{"{", "}"}, Unused: []Source{ci}},
		},
		// The script's order.
		"the script's lines in another order": {
			block: block("ini", []Source{lab}, "cafile=/etc/ssl/corp-ca.pem", "registry=https://proxy.example.com/v1/npm/"),
			want:  Result{Misordered: []string{"registry=https://proxy.example.com/v1/npm/"}},
		},
		// A comment is a comment in its own language only.
		"a comment in a JSON block": {
			block: block("json", []Source{lab}, "{", "// the registry", `  "registry": "https://proxy.example.com/v1/npm/"`, "}"),
			want:  Result{Missing: []string{"// the registry"}},
		},
		// $MOUNT in an ecosystem test stands for that ecosystem's package source.
		"a ci script's $MOUNT is not another type's package source": {
			block: block("ini", []Source{ci}, "registry=https://proxy.example.com/v1/pypi/"),
			want:  Result{Missing: []string{"registry=https://proxy.example.com/v1/pypi/"}, Unused: []Source{ci}},
		},
		"nor a name the lab proxy does not have": {
			block: block("ini", []Source{ci}, "registry=https://proxy.example.com/v1/nowhere/"),
			want:  Result{Missing: []string{"registry=https://proxy.example.com/v1/nowhere/"}, Unused: []Source{ci}},
		},
		// Quotes are only dropped around the address a ci script holds in a variable.
		"other quotes stay": {
			block: block("sh", []Source{ci}, `VERSION=$(awk '{print $3}' version.txt)`),
			want:  Result{Missing: []string{`VERSION=$(awk '{print $3}' version.txt)`}, Unused: []Source{ci}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := checker.Check(tc.block)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Check = %+v, want %+v", got, tc.want)
			}
			if got.OK() != (len(tc.want.Missing)+len(tc.want.Misordered)+len(tc.want.Misindented)+len(tc.want.Unused) == 0 && !tc.want.Scattered) {
				t.Errorf("OK() = %v for %+v", got.OK(), got)
			}
		})
	}

	// Only verified blocks are held to a script.
	other := Block{Marker: &Marker{Kind: KindUntested, Text: "needs a Windows host"}, Lines: []string{"anything"}}
	if got := checker.Check(other); !got.OK() {
		t.Errorf("an untested block was verified: %+v", got)
	}
	if got := checker.Check(Block{Lines: []string{"anything"}}); !got.OK() {
		t.Errorf("a block without a marker was verified: %+v", got)
	}

	// Without the type maps, names are not compared.
	loose := Checker{Scripts: checker.Scripts}
	if got := loose.Check(block("ini", []Source{ci}, "registry=https://proxy.example.com/v1/pypi/")); !got.OK() {
		t.Errorf("without type maps: %+v", got)
	}
}

func TestExecuted(t *testing.T) {
	script := strings.Join([]string{
		"#!/bin/sh",
		"# lab: client=npm",
		"#",
		"set -eu",
		"",
		"   mix local.hex   --force >log 2>&1",
		`echo "registry=$MOUNT/" > .npmrc`,
		"echo 'a b' >> \"$HOME/file with spaces\"",
		`echo "LAB_CLIENT_VERSION=$(npm --version)"`,
		`export JSR_URL="$MOUNT"`,
		"#include <stdio.h>",
		"cmd 2>/dev/null",
		"cat > ~/.condarc <<EOF",
		"# a comment in the file",
		`channel_alias: "$MOUNT"`,
		"",
		"channels:",
		"  - conda-forge",
		"EOF",
		"python3 - <<'PY'",
		"import re   # not a comment of the script",
		"PY",
		"cat <<-END",
		"\t\tindented with tabs",
		"\tEND",
		"# a comment after the here documents",
		"after",
	}, "\n")
	cmd := func(forms ...string) scriptLine { return scriptLine{forms: forms} }
	doc := func(n, indent int, line string) scriptLine {
		return scriptLine{forms: []string{line}, heredoc: n, indent: indent}
	}
	want := []scriptLine{
		cmd("set -eu"),
		cmd("mix local.hex --force >log 2>&1", "mix local.hex --force"),
		cmd(`echo "registry=$MOUNT/" > .npmrc`, `echo "registry=$MOUNT/"`, "registry=$MOUNT/"),
		cmd(`echo 'a b' >> "$HOME/file with spaces"`, "a b"),
		cmd(`echo "LAB_CLIENT_VERSION=$(npm --version)"`),
		cmd(`export JSR_URL="$MOUNT"`),
		cmd("#include <stdio.h>"),
		cmd("cmd 2>/dev/null", "cmd"),
		cmd("cat > ~/.condarc <<EOF"),
		doc(1, 0, "# a comment in the file"),
		doc(1, 0, `channel_alias: "$MOUNT"`),
		doc(1, 0, "channels:"),
		doc(1, 2, "- conda-forge"),
		cmd("python3 - <<'PY'"),
		doc(2, 0, "import re # not a comment of the script"),
		cmd("cat <<-END"),
		doc(3, 0, "indented with tabs"),
		cmd("after"),
	}
	got := executed(script, SourceLab)
	if !reflect.DeepEqual(got, want) {
		for i := range want {
			if i >= len(got) || !reflect.DeepEqual(got[i], want[i]) {
				var have any = "(nothing)"
				if i < len(got) {
					have = got[i]
				}
				t.Fatalf("executed (lab): line %d = %+v, want %+v", i, have, want[i])
			}
		}
		t.Fatalf("executed (lab) has %d lines, want %d", len(got), len(want))
	}

	// An ecosystem test script's variables lose their quotes, in commands and
	// in the files it writes.
	ci := executed(script, SourceCI)
	for i, want := range map[int][]string{
		2:  {"echo registry=$MOUNT/ > .npmrc", "echo registry=$MOUNT/", "registry=$MOUNT/"},
		5:  {"export JSR_URL=$MOUNT"},
		10: {"channel_alias: $MOUNT"},
	} {
		if !reflect.DeepEqual(ci[i].forms, want) {
			t.Errorf("executed (ci) line %d = %q, want %q", i, ci[i].forms, want)
		}
	}
}

func TestSubstantial(t *testing.T) {
	for line, want := range map[string]bool{
		"}": false, "{": false, "EOF": false, "fi": false, `"": {`: false, "])": false,
		"netrc": true, "registry=x": true, "</settings>": true,
	} {
		if got := substantial(line); got != want {
			t.Errorf("substantial(%q) = %v, want %v", line, got, want)
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

// The values are what scripts/client-lab/lab.sh computes for the same text
// (its fingerprint function: grep, grep -v, openssl dgst -sha256): the two
// implementations have to agree, or every recorded result would look stale.
func TestFingerprintMatchesTheLab(t *testing.T) {
	sample := "#!/bin/sh\n# lab: client=npm\n# lab: image=node:22-slim\n#\n# A comment.\nset -eu\n\n   # an indented comment\n" +
		"cat > .npmrc <<EOF\nregistry=https://proxy.example.com/v1/npm/\n# a comment inside the file\nEOF\n\tnpm install is-number\n"
	for name, tc := range map[string]struct{ script, want string }{
		"a script":                    {sample, "0a34bb5082a8"},
		"no newline at the end":       {"echo no newline at the end", "21036fc0a709"},
		"nothing":                     {"", "e3b0c44298fc"},
		"carriage returns stay lines": {"set -eu\r\n\r\necho x\r\n", "a16effd6c5c8"},
	} {
		if got := Fingerprint(tc.script); got != tc.want {
			t.Errorf("%s: Fingerprint = %s, want %s", name, got, tc.want)
		}
	}

	// What a script executes decides; what it says about itself does not.
	same := []string{
		strings.Replace(sample, "# A comment.", "# Another comment, reworded.", 1),
		strings.Replace(sample, "# A comment.\n", "", 1),
		strings.Replace(sample, "set -eu\n\n", "set -eu\n\n\n# more\n", 1),
	}
	for _, s := range same {
		if Fingerprint(s) != Fingerprint(sample) {
			t.Errorf("a comment or a blank line changed the fingerprint:\n%s", s)
		}
	}
	different := []string{
		strings.Replace(sample, "npm install is-number", "npm install is-number --no-audit", 1),
		strings.Replace(sample, "image=node:22-slim", "image=node:24-slim", 1),
		strings.Replace(sample, "registry=https", "registry=http", 1),
		strings.Replace(sample, "\tnpm install", "npm install", 1), // indentation is part of a here document
		sample + "# lab: lookups=example.com\n",
	}
	for _, s := range different {
		if Fingerprint(s) == Fingerprint(sample) {
			t.Errorf("the fingerprint did not change for:\n%s", s)
		}
	}
}
