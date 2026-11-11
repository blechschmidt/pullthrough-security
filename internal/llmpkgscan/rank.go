package llmpkgscan

import (
	"bytes"
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Ranking decides what the model sees first. A package can hold thousands of
// files and the prompt cannot; the files that run automatically — at install,
// at build, at import — are where a malicious package has to put something, so
// they lead. Ranking only orders the material: nothing here is a verdict, and a
// low score hides nothing from the tools.

// Score bands.
const (
	scoreAutoExec  = 100 // runs automatically at install/build/startup
	scoreManifest  = 90  // declares what runs and what the package is
	scoreEntry     = 75  // first code executed on import/use
	scoreBuild     = 70  // build system files
	scoreScript    = 60  // shell/PowerShell/batch scripts
	scoreSource    = 30  // ordinary source code
	scoreConfig    = 20  // data/config
	scoreDoc       = 5   // prose
	scoreUnknown   = 10  // everything else
	penaltyAside   = 25  // tests, docs, examples, vendored trees
	penaltyBulk    = 10  // very large or minified files
	signalBoostCap = 50  // most the signal pass can add
	bulkBytes      = 256 << 10
)

// nameRule scores a file by its base name.
type nameRule struct {
	score int
	role  string
}

// exactNames maps a lower-cased base name to its rule.
var exactNames = map[string]nameRule{
	"package.json":     {scoreAutoExec, "npm manifest: declares the lifecycle scripts that run at install"},
	"setup.py":         {scoreAutoExec, "Python setup script: executed at install/build"},
	"setup.cfg":        {scoreManifest, "Python package metadata"},
	"pyproject.toml":   {scoreManifest, "Python build configuration: names the build backend that runs at install"},
	"manifest.in":      {scoreConfig, "Python sdist manifest"},
	"build.rs":         {scoreAutoExec, "Cargo build script: compiled and run at build"},
	"cargo.toml":       {scoreManifest, "Cargo manifest"},
	"extconf.rb":       {scoreAutoExec, "RubyGems native-extension build script: run at install"},
	"rakefile":         {scoreBuild, "Ruby build file"},
	"gemfile":          {scoreConfig, "Ruby dependency file"},
	"composer.json":    {scoreAutoExec, "Composer manifest: declares scripts and plugins that run at install"},
	"install.ps1":      {scoreAutoExec, "NuGet PowerShell script: run at install"},
	"init.ps1":         {scoreAutoExec, "NuGet PowerShell script: run when the package is loaded"},
	"uninstall.ps1":    {scoreAutoExec, "NuGet PowerShell script: run at uninstall"},
	"binding.gyp":      {scoreBuild, "node-gyp build file: drives a native build at install"},
	".npmrc":           {scoreManifest, "npm configuration shipped inside the package"},
	".yarnrc":          {scoreManifest, "yarn configuration shipped inside the package"},
	".yarnrc.yml":      {scoreManifest, "yarn configuration shipped inside the package"},
	"makefile":         {scoreBuild, "build file"},
	"gnumakefile":      {scoreBuild, "build file"},
	"cmakelists.txt":   {scoreBuild, "build file"},
	"configure":        {scoreBuild, "build configuration script"},
	"meson.build":      {scoreBuild, "build file"},
	"build.gradle":     {scoreBuild, "Gradle build file"},
	"build.gradle.kts": {scoreBuild, "Gradle build file"},
	"pom.xml":          {scoreManifest, "Maven project file"},
	"conanfile.py":     {scoreAutoExec, "Conan recipe: executed at install"},
	"go.mod":           {scoreConfig, "Go module file"},
	"dockerfile":       {scoreBuild, "container build file"},
	"entry_points.txt": {scoreManifest, "Python entry points: names the code console scripts run"},
	"metadata":         {scoreConfig, "Python distribution metadata"},
	"pkg-info":         {scoreConfig, "Python distribution metadata"},
	"sitecustomize.py": {scoreAutoExec, "Python sitecustomize: imported automatically at interpreter startup"},
	"usercustomize.py": {scoreAutoExec, "Python usercustomize: imported automatically at interpreter startup"},
	"__main__.py":      {scoreEntry, "Python module entry point"},
	"__init__.py":      {scoreEntry - 5, "Python package initializer: runs on import"},
	"index.js":         {scoreEntry, "likely JavaScript entry point"},
	"index.mjs":        {scoreEntry, "likely JavaScript entry point"},
	"index.cjs":        {scoreEntry, "likely JavaScript entry point"},
	"main.js":          {scoreEntry, "likely JavaScript entry point"},
	"lib.rs":           {scoreEntry - 10, "Rust crate root"},
	"main.rs":          {scoreEntry - 10, "Rust binary entry point"},
	"main.go":          {scoreEntry - 10, "Go program entry point"},
	"main.py":          {scoreEntry - 10, "likely Python entry point"},
}

// suffixRules score a file by a lower-cased name suffix. First match wins.
var suffixRules = []struct {
	suffix string
	rule   nameRule
}{
	{".pth", nameRule{scoreAutoExec, "Python .pth file: lines starting with 'import' are executed at every interpreter startup"}},
	{".gemspec", nameRule{scoreManifest + 5, "RubyGems specification: Ruby code evaluated at install"}},
	{".nuspec", nameRule{scoreManifest, "NuGet package manifest"}},
	{".targets", nameRule{scoreAutoExec - 5, "MSBuild targets file: executed at build"}},
	{".props", nameRule{scoreManifest, "MSBuild properties file: imported at build"}},
	{".podspec", nameRule{scoreManifest, "CocoaPods specification"}},
	{".min.js", nameRule{scoreSource - 20, "minified JavaScript"}},
	{".ps1", nameRule{scoreScript + 10, "PowerShell script"}},
	{".psm1", nameRule{scoreScript, "PowerShell module"}},
	{".sh", nameRule{scoreScript, "shell script"}},
	{".bash", nameRule{scoreScript, "shell script"}},
	{".zsh", nameRule{scoreScript, "shell script"}},
	{".bat", nameRule{scoreScript, "Windows batch script"}},
	{".cmd", nameRule{scoreScript, "Windows batch script"}},
	{".vbs", nameRule{scoreScript, "VBScript"}},
	{".node", nameRule{scoreUnknown, "native Node.js addon"}},
}

// sourceExt, configExt and docExt classify the rest by extension.
var (
	sourceExt = setOf(".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py", ".pyw", ".rb", ".php", ".rs", ".go",
		".java", ".kt", ".cs", ".c", ".h", ".cc", ".cpp", ".hpp", ".lua", ".pl", ".pm", ".swift", ".m", ".scala",
		".ex", ".exs", ".erl", ".hs", ".dart", ".jl", ".r", ".groovy", ".coffee", ".vue", ".svelte", ".wat")
	configExt = setOf(".json", ".yaml", ".yml", ".toml", ".xml", ".ini", ".cfg", ".conf", ".lock", ".properties", ".env")
	docExt    = setOf(".md", ".markdown", ".rst", ".txt", ".adoc", ".html", ".htm", ".css", ".svg", ".map")
)

func setOf(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

// lifecycleWords mark a script as part of an install/setup flow when one of
// them is a whole word of its file name ("post-install.js", "setup.sh" — but
// not "installer.js" or "setupTests.js").
var lifecycleWords = setOf("postinstall", "preinstall", "install", "uninstall", "setup", "bootstrap")

// nameTokens splits a file-name stem into its words.
func nameTokens(stem string) []string {
	return strings.FieldsFunc(stem, func(r rune) bool { return r == '-' || r == '_' || r == '.' || r == ' ' })
}

// asideDirs are trees that rarely carry a package's operative code.
var asideDirs = setOf("test", "tests", "__tests__", "spec", "specs", "example", "examples", "doc", "docs",
	"fixture", "fixtures", "testdata", "bench", "benchmarks", "vendor", "node_modules", "third_party", "locale", "locales")

// signalRule is one deterministic content hint: a hit when any of its needles
// occurs in the file, or when its custom matcher says so.
//
// The needles are plain substrings, not regular expressions. This pass reads
// every text file of every package on the pull path, and a regular expression
// with dozens of alternatives is two orders of magnitude slower than substring
// search — slow enough to matter for a package of a few megabytes.
type signalRule struct {
	name    string
	boost   int
	needles []string
	// words are needles that must not be preceded by an identifier character, so
	// "eval(" does not fire on "retrieval(".
	words []string
	match func(data []byte) bool
}

// signalRules look for the building blocks malicious packages are made of. A
// hit is not a finding — every one of these has ordinary uses — it only moves a
// file up the reading order and labels it in the listing.
var signalRules = []signalRule{
	{name: "exec", boost: 15, needles: []string{
		"child_process", "execSync", "spawnSync", "os.system(", "subprocess.", "popen(", "Runtime.getRuntime",
		"ProcessBuilder", "shell_exec(", "passthru(", "proc_open(", "Process.Start", "IO.popen", "Command::new",
		"std::process", "Start-Process", "os/exec", "WScript.Shell", "ShellExecute",
		"local-exec", "remote-exec", "repository_ctx.execute", "ctx.execute(", "System.cmd(", "os:cmd(", ":os.cmd(",
		"run(`", "system2(", "posix.system", "nt.system", "posix.popen", "subprocess.Popen", "builtins.exec", "builtins.eval",
	}},
	{name: "eval", boost: 15, needles: []string{
		"new Function(", "exec(compile(", "__import__(", "importlib.import_module", "marshal.loads", "pickle.loads",
		"Invoke-Expression", "instance_eval", "class_eval", "create_function(", "assert($_",
	}, words: []string{"eval(", "iex "}},
	{name: "decode", boost: 10, needles: []string{
		"b64decode", "base64_decode", "String.fromCharCode", "bytes.fromhex", "unhexlify", "FromBase64String",
		"Base64.decode64", "gzinflate(", "str_rot13(", "zlib.decompress", "base64 -d", "base64 --decode",
		"'base64'", `"base64"`,
	}, words: []string{"atob("}},
	{name: "network", boost: 5, needles: []string{
		"http://", "https://", "XMLHttpRequest", "urllib.request", "urlopen(", "requests.get", "requests.post",
		"socket.socket", "net.connect", "Invoke-WebRequest", "DownloadString", "DownloadFile", "Net::HTTP",
		"TcpStream", "/dev/tcp/", "require('http", `require("http`, "require('net')", `require("net")`,
		"require('dns')", `require("dns")`, "require('tls')", `require("tls")`, "require('dgram')", `require("dgram")`,
	}, words: []string{"fetch(", "curl ", "wget "}},
	{name: "secrets", boost: 10, needles: []string{
		"process.env", "os.environ", "ENV[", "$env:", ".npmrc", ".pypirc", ".ssh/", "id_rsa", "id_ed25519",
		".aws/credentials", "AWS_SECRET", "GITHUB_TOKEN", "NPM_TOKEN", ".docker/config.json", ".kube/config",
		".git-credentials", ".gnupg", "/etc/passwd", "/etc/shadow", "Keychain", "keychain", "wallet.dat", "Login Data",
	}},
	{name: "exfil-host", boost: 20, needles: []string{
		"discord.com/api/webhooks", "discordapp.com/api/webhooks", "api.telegram.org", "pastebin.com", "paste.ee",
		"ngrok.", "burpcollaborator", "oastify.com", "interact.sh", "webhook.site", "requestbin", "pipedream.net",
		"transfer.sh",
	}, match: hasIPPort},
	{name: "persistence", boost: 15, needles: []string{
		"crontab", ".bashrc", ".zshrc", ".bash_profile", "systemctl enable", "systemctl start", "LaunchAgents",
		"LaunchDaemons", "schtasks", "HKEY_", `CurrentVersion\Run`, `CurrentVersion\\Run`, "authorized_keys", "/etc/rc.local",
		".config/autostart",
	}},
	// A container or cluster workload that asks for the host: the things a
	// malicious image config, Helm chart or manifest reaches for.
	{name: "host-access", boost: 15, needles: []string{
		"helm.sh/hook", "privileged: true", "hostPID: true", "hostNetwork: true", "hostIPC: true", "/var/run/docker.sock",
		"hostPath:", "cluster-admin", "nsenter ", "--privileged", "CAP_SYS_ADMIN", "chroot /host", "LD_PRELOAD",
	}},
	{name: "obfuscation", boost: 15, match: looksObfuscated},
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// containsWord reports whether needle occurs in data not preceded by an
// identifier character.
func containsWord(data []byte, needle string) bool {
	nb := []byte(needle)
	for off := 0; off < len(data); {
		i := bytes.Index(data[off:], nb)
		if i < 0 {
			return false
		}
		at := off + i
		if at == 0 || !isIdentByte(data[at-1]) {
			return true
		}
		off = at + 1
	}
	return false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// hasIPPort reports a literal "a.b.c.d:port" — a hard-coded address to talk to.
func hasIPPort(data []byte) bool { return indexIPPort(data) >= 0 }

// indexIPPort returns the offset of the colon of the first literal
// "a.b.c.d:port" in data, or -1.
func indexIPPort(data []byte) int {
	for off := 0; off < len(data); {
		i := bytes.IndexByte(data[off:], ':')
		if i < 0 {
			return -1
		}
		colon := off + i
		off = colon + 1
		// Port: 2-5 digits after the colon.
		p := colon + 1
		for p < len(data) && p-colon <= 5 && isDigit(data[p]) {
			p++
		}
		if n := p - colon - 1; n < 2 || (p < len(data) && isDigit(data[p])) {
			continue
		}
		// Dotted quad before the colon: four groups of 1-3 digits.
		q, groups := colon, 0
		for groups < 4 {
			digits := 0
			for q > 0 && digits < 3 && isDigit(data[q-1]) {
				q--
				digits++
			}
			if digits == 0 {
				break
			}
			groups++
			if groups < 4 {
				if q == 0 || data[q-1] != '.' {
					break
				}
				q--
			}
		}
		if groups == 4 && (q == 0 || (!isDigit(data[q-1]) && data[q-1] != '.')) {
			return colon
		}
	}
	return -1
}

// looksObfuscated reports the textures of packed or encoded code: a very long
// unbroken run of base64 characters, a long string of \xNN or \u00NN escapes,
// or the _0x1234 identifiers a common JavaScript obfuscator emits.
func looksObfuscated(data []byte) bool {
	const (
		blobRun   = 240 // base64-alphabet characters in a row
		escapeRun = 24  // \xNN / \u00NN escapes in a row
	)
	run := 0
	for i := 0; i < len(data); i++ {
		c := data[i]
		if isIdentByte(c) || c == '+' || c == '/' || c == '=' {
			run++
			if run >= blobRun {
				return true
			}
			continue
		}
		run = 0
		if c != '\\' || i+1 >= len(data) {
			continue
		}
		// Count consecutive escapes starting here.
		n, j := 0, i
		for j+3 < len(data) && data[j] == '\\' {
			switch {
			case data[j+1] == 'x' && isHexByte(data[j+2]) && isHexByte(data[j+3]):
				j += 4
			case data[j+1] == 'u' && j+5 < len(data) && data[j+2] == '0' && data[j+3] == '0' && isHexByte(data[j+4]) && isHexByte(data[j+5]):
				j += 6
			default:
				j = len(data) // stop
				continue
			}
			n++
			if n >= escapeRun {
				return true
			}
		}
	}
	// _0x followed by 4+ hex digits, as its own identifier.
	for off := 0; off < len(data); {
		i := bytes.Index(data[off:], []byte("_0x"))
		if i < 0 {
			break
		}
		at := off + i
		off = at + 3
		if at > 0 && isIdentByte(data[at-1]) {
			continue
		}
		h := at + 3
		for h < len(data) && isHexByte(data[h]) {
			h++
		}
		if h-(at+3) >= 4 {
			return true
		}
	}
	return false
}

func isHexByte(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// Score bands for binaries. A binary's strings rank below ordinary source
// unless they say something: the signal pass lifts the ones that do.
const (
	scoreBinary     = 6  // any binary with a strings view
	scoreExecutable = 12 // machine code, or a member marked executable
)

// rankFiles scores every file in the tree.
func rankFiles(t *Tree) {
	referenced := npmScriptReferences(t)
	for _, f := range t.Files {
		// A file is ranked by where it sits in its own container: for a file of
		// an image layer that is its path in the layer's root filesystem, not the
		// directory the tree files the layer under.
		rel := f.Path
		if _, inLayer, ok := layerRelative(f.Path); ok {
			rel = inLayer
		}
		f.Score, f.Role = baseScore(rel)
		if r, ok := matchPathRule(rel); ok {
			if r.score > f.Score {
				f.Score = r.score
			}
			f.Role = r.role
		}
		if ref, ok := referenced[f.Path]; ok {
			if f.Score < ref.score {
				f.Score = ref.score
			}
			f.Role = ref.role
		}
		if f.Binary {
			if !f.Strings {
				// Nothing of it can be shown, so it must not crowd out what can; it
				// still appears in the listing, described.
				f.Score = 0
				continue
			}
			// The path says what it is for (a set-uid helper, an entrypoint); the
			// strings say what is in it.
			base := scoreBinary
			if f.Exec || executableKind(f.Kind) {
				base = scoreExecutable
			}
			if strings.HasPrefix(f.Kind, kindPickle) {
				// A pickle is a program: loading it runs what it imports.
				base = scoreEntry
				if f.Role == "" {
					f.Role = "Python pickle: unpickling it calls what it imports"
				}
			}
			if f.SetID {
				base += 10
				if f.Role == "" {
					f.Role = "set-uid/set-gid executable: runs with its owner's privileges"
				}
			}
			var boosted int
			f.Signals, boosted = applySignalsTo(f.Data, base, false)
			if boosted > f.Score || f.Role == "" {
				f.Score = boosted
			}
			if f.Score < 1 {
				f.Score = 1
			}
			continue
		}
		if f.Readable() && !docExt[strings.ToLower(path.Ext(f.Path))] {
			f.Signals, f.Score = applySignals(f.Data, f.Score)
		}
		if f.Size > bulkBytes {
			f.Score -= penaltyBulk
		}
		if f.Score < 1 {
			f.Score = 1
		}
	}
}

// pathRule scores a file by where it sits. It is how the files that a package
// manager, an init system or a shell runs by itself are recognized in formats
// whose install-time code is identified by location rather than by name: a
// Debian maintainer script, an RPM scriptlet, a conda link script, a cron job
// in an image layer.
//
// A rule matches when every field that is set agrees. Paths are lower-cased and
// relative to the root of the container the file is in.
type pathRule struct {
	dir     string // the parent directory, exactly
	dirPre  string // the path starts with this directory
	dirSuf  string // the parent directory ends with this path
	base    string // the file name, exactly
	basePre string // the file name starts with this
	baseSuf string // the file name ends with this
	rule    nameRule
}

func (r pathRule) matches(dir, base string) bool {
	if r.base != "" && base != r.base {
		return false
	}
	if r.basePre != "" && !strings.HasPrefix(base, r.basePre) {
		return false
	}
	if r.baseSuf != "" && !strings.HasSuffix(base, r.baseSuf) {
		return false
	}
	if r.dir != "" && dir != r.dir {
		return false
	}
	if r.dirPre != "" && dir != r.dirPre && !strings.HasPrefix(dir, r.dirPre+"/") {
		return false
	}
	if r.dirSuf != "" && dir != r.dirSuf && !strings.HasSuffix(dir, "/"+r.dirSuf) {
		return false
	}
	return true
}

// Shorthands for the roles that recur.
const (
	roleDebScript  = "Debian maintainer script: run as root by dpkg when the package is installed, upgraded or removed"
	roleRPMScript  = "RPM scriptlet (from the package header): run as root by rpm when the package is installed, upgraded or removed"
	roleRPMTrigger = "RPM trigger script (from the package header): run as root by rpm when the packages or files it names change"
	roleCron       = "cron job: run periodically, as root unless it names another user"
	roleShellInit  = "shell start-up file: sourced by login or interactive shells"
	roleSystemd    = "systemd unit: starts a service, timer or socket"
	roleEntrypoint = "container entrypoint script"
	rolePkgMgrConf = "package-manager configuration: can add repositories and hooks that run on every install"
)

// pathRules is the table, first match wins.
var pathRules = []pathRule{
	// --- Debian packages (control members are filed under DEBIAN/) ---
	{dir: "debian", base: "preinst", rule: nameRule{scoreAutoExec, roleDebScript}},
	{dir: "debian", base: "postinst", rule: nameRule{scoreAutoExec, roleDebScript}},
	{dir: "debian", base: "prerm", rule: nameRule{scoreAutoExec, roleDebScript}},
	{dir: "debian", base: "postrm", rule: nameRule{scoreAutoExec, roleDebScript}},
	{dir: "debian", base: "config", rule: nameRule{scoreAutoExec, "Debian debconf script: run as root by dpkg before the package is unpacked"}},
	{dir: "debian", base: "control", rule: nameRule{scoreManifest, "Debian control file: the package's name, version and dependencies"}},
	{dir: "debian", base: "triggers", rule: nameRule{scoreConfig + 10, "Debian triggers file: names what re-runs the maintainer scripts"}},
	{dir: "debian", rule: nameRule{scoreConfig, "Debian control member"}},

	// --- RPM packages (composed from the header by the proxy) ---
	{dir: "rpm/scriptlets", rule: nameRule{scoreAutoExec, roleRPMScript}},
	{dir: "rpm/triggers", rule: nameRule{scoreAutoExec - 5, roleRPMTrigger}},
	{dir: "rpm/filetriggers", rule: nameRule{scoreAutoExec - 5, roleRPMTrigger}},
	{dir: "rpm/transfiletriggers", rule: nameRule{scoreAutoExec - 5, roleRPMTrigger}},
	{dir: "rpm", base: "header.txt", rule: nameRule{scoreManifest, "RPM header summary: name, version, dependencies (composed by the proxy)"}},
	{dir: "rpm", base: "files.txt", rule: nameRule{scoreConfig + 10, "the files the RPM header lists (the payload itself was not fully read)"}},

	// --- conda packages ---
	{baseSuf: "-post-link.sh", rule: nameRule{scoreAutoExec, "conda post-link script: run at install"}},
	{baseSuf: "-pre-link.sh", rule: nameRule{scoreAutoExec, "conda pre-link script: run at install"}},
	{baseSuf: "-pre-unlink.sh", rule: nameRule{scoreAutoExec, "conda pre-unlink script: run at removal"}},
	{baseSuf: "-post-link.bat", rule: nameRule{scoreAutoExec, "conda post-link script: run at install"}},
	{baseSuf: "-pre-link.bat", rule: nameRule{scoreAutoExec, "conda pre-link script: run at install"}},
	{baseSuf: "-pre-unlink.bat", rule: nameRule{scoreAutoExec, "conda pre-unlink script: run at removal"}},
	{dirSuf: "etc/conda/activate.d", rule: nameRule{scoreAutoExec - 5, "conda activation script: sourced whenever the environment is activated"}},
	{dirSuf: "etc/conda/deactivate.d", rule: nameRule{scoreAutoExec - 10, "conda deactivation script"}},
	{dir: "info/recipe", base: "meta.yaml", rule: nameRule{scoreManifest, "conda recipe: how the package was built"}},
	{dir: "info", base: "index.json", rule: nameRule{scoreManifest, "conda package metadata"}},
	{dir: "info/recipe", rule: nameRule{scoreBuild, "conda recipe file"}},

	// --- a root filesystem: OS packages, Nix archives, image layers ---
	{dir: "etc", base: "ld.so.preload", rule: nameRule{scoreAutoExec, "ld.so.preload: libraries loaded into every dynamically linked process"}},
	{dir: "etc", base: "crontab", rule: nameRule{scoreAutoExec - 10, roleCron}},
	{dir: "etc/cron.d", rule: nameRule{scoreAutoExec - 10, roleCron}},
	{dir: "etc/cron.hourly", rule: nameRule{scoreAutoExec - 10, roleCron}},
	{dir: "etc/cron.daily", rule: nameRule{scoreAutoExec - 10, roleCron}},
	{dir: "etc/cron.weekly", rule: nameRule{scoreAutoExec - 10, roleCron}},
	{dir: "etc/cron.monthly", rule: nameRule{scoreAutoExec - 10, roleCron}},
	{dirPre: "var/spool/cron", rule: nameRule{scoreAutoExec - 10, roleCron}},
	{dir: "etc", base: "profile", rule: nameRule{scoreAutoExec - 10, roleShellInit}},
	{dir: "etc", base: "bash.bashrc", rule: nameRule{scoreAutoExec - 10, roleShellInit}},
	{dir: "etc", base: "environment", rule: nameRule{scoreScript, "system-wide environment"}},
	{dir: "etc/profile.d", rule: nameRule{scoreAutoExec - 10, roleShellInit}},
	{base: ".bashrc", rule: nameRule{scoreAutoExec - 10, roleShellInit}},
	{base: ".bash_profile", rule: nameRule{scoreAutoExec - 10, roleShellInit}},
	{base: ".profile", rule: nameRule{scoreAutoExec - 10, roleShellInit}},
	{base: ".zshrc", rule: nameRule{scoreAutoExec - 10, roleShellInit}},
	{base: "authorized_keys", rule: nameRule{scoreManifest + 5, "SSH authorized keys: who may log in"}},
	{dir: "etc", base: "rc.local", rule: nameRule{scoreAutoExec - 10, "rc.local: run at boot"}},
	{dir: "etc/init.d", rule: nameRule{scoreScript + 10, "init script: run at boot"}},
	{dir: "etc", base: "sudoers", rule: nameRule{scoreManifest, "sudo policy"}},
	{dir: "etc/sudoers.d", rule: nameRule{scoreManifest, "sudo policy"}},
	{dir: "etc", base: "passwd", rule: nameRule{scoreConfig + 15, "account database"}},
	{dir: "etc", base: "shadow", rule: nameRule{scoreConfig + 15, "password database"}},
	{dirPre: "etc/apt", rule: nameRule{scoreScript, rolePkgMgrConf}},
	{dir: "etc/yum.repos.d", rule: nameRule{scoreScript, rolePkgMgrConf}},
	{dirPre: "etc/dnf", rule: nameRule{scoreScript, rolePkgMgrConf}},
	{dir: "etc/pip.conf", rule: nameRule{scoreScript, rolePkgMgrConf}},
	{dirPre: "etc/udev/rules.d", rule: nameRule{scoreScript, "udev rule: can run a program when a device appears"}},
	{dirPre: "etc/pam.d", rule: nameRule{scoreConfig + 15, "PAM configuration: decides how logins are authenticated"}},
	{dirSuf: "systemd/system", baseSuf: ".service", rule: nameRule{scoreScript + 10, roleSystemd}},
	{dirSuf: "systemd/system", baseSuf: ".timer", rule: nameRule{scoreScript + 10, roleSystemd}},
	{dirSuf: "systemd/system", baseSuf: ".socket", rule: nameRule{scoreScript + 10, roleSystemd}},
	{dirSuf: "systemd/user", baseSuf: ".service", rule: nameRule{scoreScript + 10, roleSystemd}},
	{base: "docker-entrypoint.sh", rule: nameRule{scoreAutoExec - 10, roleEntrypoint}},
	{base: "entrypoint.sh", rule: nameRule{scoreAutoExec - 10, roleEntrypoint}},
	{dirSuf: "docker-entrypoint.d", rule: nameRule{scoreAutoExec - 10, roleEntrypoint}},
	{dirSuf: "nix-support", base: "setup-hook", rule: nameRule{scoreAutoExec - 10, "Nix setup hook: sourced by every build that depends on this store path"}},
	{dirSuf: "nix-support", rule: nameRule{scoreConfig + 10, "Nix support file"}},

	// --- Java ---
	{dir: "meta-inf", base: "manifest.mf", rule: nameRule{scoreManifest, "JAR manifest: Main-Class, Premain-Class / Agent-Class, Class-Path"}},
	{dir: "meta-inf/services", rule: nameRule{scoreEntry, "Java ServiceLoader registration: names a class the JVM loads by itself"}},
	{dirSuf: "meta-inf/maven", base: "plugin.xml", rule: nameRule{scoreManifest, "Maven plugin descriptor: the goals the plugin runs in a build"}},
	{dir: ".mvn", base: "extensions.xml", rule: nameRule{scoreAutoExec - 5, "Maven core extensions: loaded into every build of the project"}},
	{dirSuf: "gradle/wrapper", base: "gradle-wrapper.properties", rule: nameRule{scoreManifest, "Gradle wrapper configuration: the distribution URL the wrapper downloads and runs"}},
	{dirSuf: ".mvn/wrapper", base: "maven-wrapper.properties", rule: nameRule{scoreManifest, "Maven wrapper configuration: the distribution URL the wrapper downloads and runs"}},
	{base: "settings.gradle", rule: nameRule{scoreBuild, "Gradle settings script"}},
	{base: "settings.gradle.kts", rule: nameRule{scoreBuild, "Gradle settings script"}},
	{base: "init.gradle", rule: nameRule{scoreAutoExec - 5, "Gradle init script: run before every build"}},

	// --- Helm charts, Terraform, Ansible, Puppet ---
	{base: "chart.yaml", rule: nameRule{scoreManifest, "Helm chart metadata"}},
	{base: "values.yaml", rule: nameRule{scoreConfig + 15, "Helm chart default values"}},
	{dirSuf: "templates", baseSuf: ".yaml", rule: nameRule{scoreSource + 15, "Helm template: rendered into the Kubernetes objects the chart creates"}},
	{dirSuf: "templates", baseSuf: ".yml", rule: nameRule{scoreSource + 15, "Helm template: rendered into the Kubernetes objects the chart creates"}},
	{dirSuf: "templates", baseSuf: ".tpl", rule: nameRule{scoreSource + 10, "Helm template helpers"}},
	{baseSuf: ".tf", rule: nameRule{scoreSource + 20, "Terraform configuration: provisioners and external data sources run commands"}},
	{baseSuf: ".tf.json", rule: nameRule{scoreSource + 20, "Terraform configuration"}},
	{base: "galaxy.yml", rule: nameRule{scoreManifest, "Ansible collection metadata"}},
	{dir: "meta", base: "runtime.yml", rule: nameRule{scoreManifest, "Ansible collection runtime metadata"}},
	{dirPre: "plugins", baseSuf: ".py", rule: nameRule{scoreSource + 15, "Ansible plugin: Python run on the control node"}},
	{dirSuf: "tasks", baseSuf: ".yml", rule: nameRule{scoreSource + 10, "Ansible tasks"}},
	{dirSuf: "handlers", baseSuf: ".yml", rule: nameRule{scoreSource + 10, "Ansible handlers"}},
	{dirSuf: "lib/facter", baseSuf: ".rb", rule: nameRule{scoreEntry, "Puppet custom fact: Ruby run on every agent run"}},
	{dirPre: "manifests", baseSuf: ".pp", rule: nameRule{scoreSource + 15, "Puppet manifest"}},
	{dirPre: "lib/puppet", baseSuf: ".rb", rule: nameRule{scoreSource + 10, "Puppet Ruby extension: loaded by the agent or the server"}},

	// --- R, Perl, Haskell, Elixir/Erlang, Julia, Dart, Swift, Deno, Bazel ---
	{dir: "", base: "configure.win", rule: nameRule{scoreAutoExec, "R package configure script: run at install"}},
	{base: "cleanup", rule: nameRule{scoreBuild + 10, "R package cleanup script: run at install"}},
	{dirSuf: "src", basePre: "makevars", rule: nameRule{scoreBuild + 10, "R Makevars: make fragments run by R CMD INSTALL"}},
	{dirSuf: "r", base: "zzz.r", rule: nameRule{scoreEntry, "R load hooks (.onLoad / .onAttach): run when the package is loaded"}},
	{base: "install.libs.r", rule: nameRule{scoreAutoExec, "R install script: run at install"}},
	{base: "description", rule: nameRule{scoreManifest, "R package description"}},
	{base: "makefile.pl", rule: nameRule{scoreAutoExec, "Perl Makefile.PL: executed at install"}},
	{base: "build.pl", rule: nameRule{scoreAutoExec, "Perl Build.PL: executed at install"}},
	{base: "setup.hs", rule: nameRule{scoreAutoExec - 5, "Cabal Setup script: compiled and run at build when the package's build-type is Custom"}},
	{base: "setup.lhs", rule: nameRule{scoreAutoExec - 5, "Cabal Setup script: compiled and run at build when the package's build-type is Custom"}},
	{baseSuf: ".cabal", rule: nameRule{scoreManifest, "Cabal package description"}},
	{base: "mix.exs", rule: nameRule{scoreAutoExec, "Mix project file: Elixir code evaluated whenever the dependency is fetched or compiled"}},
	{base: "rebar.config.script", rule: nameRule{scoreAutoExec, "rebar3 config script: Erlang code evaluated at build"}},
	{base: "rebar.config", rule: nameRule{scoreManifest, "rebar3 configuration: may declare pre/post hooks"}},
	{base: "metadata.config", rule: nameRule{scoreManifest, "Hex package metadata"}},
	{dir: "deps", base: "build.jl", rule: nameRule{scoreAutoExec, "Julia build script: run by Pkg.build at install"}},
	{base: "project.toml", rule: nameRule{scoreManifest, "Julia project file"}},
	{base: "artifacts.toml", rule: nameRule{scoreManifest, "Julia artifacts file: binaries downloaded at install"}},
	{dir: "hook", base: "build.dart", rule: nameRule{scoreAutoExec, "Dart build hook: run when the package is built"}},
	{dir: "hook", base: "link.dart", rule: nameRule{scoreAutoExec, "Dart link hook: run when the package is built"}},
	{base: "pubspec.yaml", rule: nameRule{scoreManifest, "Dart package manifest"}},
	{base: "package.swift", rule: nameRule{scoreAutoExec, "Swift package manifest: compiled and executed by SwiftPM when the package is resolved"}},
	{basePre: "package@swift-", baseSuf: ".swift", rule: nameRule{scoreAutoExec, "Swift package manifest: compiled and executed by SwiftPM when the package is resolved"}},
	{base: "deno.json", rule: nameRule{scoreManifest, "Deno / JSR package configuration"}},
	{base: "deno.jsonc", rule: nameRule{scoreManifest, "Deno / JSR package configuration"}},
	{base: "jsr.json", rule: nameRule{scoreManifest, "JSR package configuration"}},
	{base: "module.bazel", rule: nameRule{scoreManifest, "Bazel module file: names dependencies, module extensions and repository rules"}},
	{base: "workspace", rule: nameRule{scoreManifest, "Bazel workspace file"}},
	{base: "workspace.bazel", rule: nameRule{scoreManifest, "Bazel workspace file"}},
	{baseSuf: ".bzl", rule: nameRule{scoreBuild + 10, "Starlark extension: repository rules in it can execute commands"}},
	{baseSuf: ".patch", rule: nameRule{scoreSource + 15, "patch: changes the source it is applied to"}},
	{baseSuf: ".diff", rule: nameRule{scoreSource + 15, "patch: changes the source it is applied to"}},

	// --- Homebrew bottles, editor extensions, wheels ---
	{dirSuf: ".brew", baseSuf: ".rb", rule: nameRule{scoreManifest + 5, "Homebrew formula: its install and post_install blocks are Ruby run by brew"}},
	{base: "install_receipt.json", rule: nameRule{scoreConfig + 10, "Homebrew install receipt"}},
	{base: "extension.vsixmanifest", rule: nameRule{scoreManifest, "VS Code extension manifest"}},
	{dirSuf: ".data/scripts", rule: nameRule{scoreEntry, "wheel script: installed onto PATH"}},
	{base: "conanfile.txt", rule: nameRule{scoreManifest, "Conan requirements file"}},
	{base: "handler.py", rule: nameRule{scoreEntry, "Hugging Face inference handler: run by the inference runtime"}},
}

// matchPathRule returns the first path rule that matches a container-relative
// path.
func matchPathRule(p string) (nameRule, bool) {
	lower := strings.ToLower(p)
	dir, base := path.Split(lower)
	dir = strings.TrimSuffix(dir, "/")
	for _, r := range pathRules {
		if r.matches(dir, base) {
			return r.rule, true
		}
	}
	return nameRule{}, false
}

// baseScore scores a file from its path alone.
func baseScore(p string) (int, string) {
	lower := strings.ToLower(p)
	base := path.Base(lower)
	ext := path.Ext(base)

	score, role := scoreUnknown, ""
	if r, ok := exactNames[base]; ok {
		score, role = r.score, r.role
	} else {
		matched := false
		for _, sr := range suffixRules {
			if strings.HasSuffix(base, sr.suffix) {
				score, role, matched = sr.rule.score, sr.rule.role, true
				break
			}
		}
		if !matched {
			switch {
			case sourceExt[ext]:
				score = scoreSource
			case configExt[ext]:
				score = scoreConfig
			case docExt[ext] || strings.HasPrefix(base, "readme") || strings.HasPrefix(base, "license") ||
				strings.HasPrefix(base, "changelog") || strings.HasPrefix(base, "copying"):
				score = scoreDoc
			}
		}
	}

	// A script whose name says it belongs to the install flow.
	if score < scoreAutoExec-10 && (sourceExt[ext] || score >= scoreScript) {
		for _, tok := range nameTokens(strings.TrimSuffix(base, ext)) {
			if lifecycleWords[tok] {
				score, role = scoreAutoExec-10, "named like an install/setup script"
				break
			}
		}
	}

	// Depth and location: a manifest or entry point buried in a test or vendored
	// tree, or several directories down, is rarely the package's own.
	dirs := strings.Split(lower, "/")
	dirs = dirs[:len(dirs)-1]
	for _, d := range dirs {
		if asideDirs[d] {
			// Whatever its name suggests, a file here is not the package's own
			// operative code: it ranks below ordinary source. (A file the manifest
			// actually runs is raised again by the caller; one that trips the
			// signal pass is raised by that.)
			if score > scoreSource {
				score = scoreSource
			}
			score -= penaltyAside
			break
		}
	}
	switch {
	case score >= scoreManifest && len(dirs) > 2:
		score -= 30
	case score >= scoreEntry-10 && len(dirs) > 3:
		score -= 15
	}
	return score, role
}

// matches reports whether the rule fires on data.
func (r signalRule) matches(data []byte) bool {
	for _, n := range r.needles {
		if bytes.Contains(data, []byte(n)) {
			return true
		}
	}
	for _, w := range r.words {
		if containsWord(data, w) {
			return true
		}
	}
	return r.match != nil && r.match(data)
}

// applySignals runs the signal pass over a file's content and returns the hits
// and the boosted score.
func applySignals(data []byte, score int) ([]string, int) {
	return applySignalsTo(data, score, true)
}

// applySignalsTo is applySignals with the obfuscation rule optional: it looks
// for long unbroken runs, which describes most strings of a binary.
func applySignalsTo(data []byte, score int, obfuscation bool) ([]string, int) {
	sample := data
	if len(sample) > signalScanCap {
		sample = sample[:signalScanCap]
	}
	var hits []string
	boost := 0
	for _, r := range signalRules {
		if !obfuscation && r.name == "obfuscation" {
			continue
		}
		if r.matches(sample) {
			hits = append(hits, r.name)
			boost += r.boost
		}
	}
	if boost > signalBoostCap {
		boost = signalBoostCap
	}
	return hits, score + boost
}

// npmLifecycleHooks are the package.json scripts npm runs by itself when a
// package is installed (or packed and installed from git).
var npmLifecycleHooks = []string{"preinstall", "install", "postinstall", "prepare", "prepublish", "preuninstall", "postuninstall"}

// scriptFileRef picks script-looking file names out of a shell command line.
var scriptFileRef = regexp.MustCompile(`[A-Za-z0-9_@./\\-]+\.(?:c?js|mjs|ts|sh|bash|py|rb|ps1|bat|cmd|pl|php)\b`)

// npmScriptReferences finds the files a package.json's lifecycle scripts and
// entry-point fields name, and maps each (by tree path) to why it matters. It
// reads only the outermost package.json files: a package's own manifest, not
// those of vendored dependencies.
func npmScriptReferences(t *Tree) map[string]nameRule {
	refs := make(map[string]nameRule)
	for _, f := range t.Files {
		if path.Base(f.Path) != "package.json" || !f.Readable() || strings.Count(f.Path, "/") > 1 {
			continue
		}
		var manifest struct {
			Scripts map[string]string `json:"scripts"`
			Main    string            `json:"main"`
			Module  string            `json:"module"`
			Browser json.RawMessage   `json:"browser"`
			Bin     json.RawMessage   `json:"bin"`
		}
		if json.Unmarshal(f.Data, &manifest) != nil {
			continue
		}
		dir := path.Dir(f.Path)
		resolve := func(ref string) (string, bool) {
			ref = strings.ReplaceAll(strings.TrimSpace(ref), `\`, "/")
			if ref == "" {
				return "", false
			}
			candidates := []string{path.Join(dir, ref)}
			if path.Ext(ref) == "" {
				candidates = append(candidates, path.Join(dir, ref+".js"), path.Join(dir, ref, "index.js"))
			}
			for _, c := range candidates {
				if tf, ok := t.Lookup(c); ok {
					return tf.Path, true
				}
			}
			return "", false
		}

		hooks := make([]string, 0, len(npmLifecycleHooks))
		for _, h := range npmLifecycleHooks {
			if _, ok := manifest.Scripts[h]; ok {
				hooks = append(hooks, h)
			}
		}
		sort.Strings(hooks)
		for _, h := range hooks {
			for _, m := range scriptFileRef.FindAllString(manifest.Scripts[h], 8) {
				if p, ok := resolve(m); ok {
					refs[p] = nameRule{scoreAutoExec, "run by the npm '" + h + "' lifecycle script"}
				}
			}
		}
		entry := func(ref, why string) {
			if p, ok := resolve(ref); ok {
				if _, already := refs[p]; !already {
					refs[p] = nameRule{scoreEntry, why}
				}
			}
		}
		entry(manifest.Main, "package entry point (package.json main)")
		entry(manifest.Module, "package entry point (package.json module)")
		var bin string
		if json.Unmarshal(manifest.Bin, &bin) == nil {
			entry(bin, "command-line entry point (package.json bin)")
		} else {
			var bins map[string]string
			if json.Unmarshal(manifest.Bin, &bins) == nil {
				names := make([]string, 0, len(bins))
				for n := range bins {
					names = append(names, n)
				}
				sort.Strings(names)
				for _, n := range names {
					entry(bins[n], "command-line entry point (package.json bin)")
				}
			}
		}
	}
	return refs
}

// byPriority returns the tree's files ordered for the prompt: highest score
// first, then smaller files, then path — a total, deterministic order.
func (t *Tree) byPriority() []*File {
	out := make([]*File, len(t.Files))
	copy(out, t.Files)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Size != b.Size {
			return a.Size < b.Size
		}
		return a.Path < b.Path
	})
	return out
}
