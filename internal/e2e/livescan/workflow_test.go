package livescan

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const workflowPath = "../../../.github/workflows/live-llm-scan.yml"

// The live workflow spends money and holds a credential, so how it is gated
// and where the credential goes are invariants, checked like code:
//
//   - it is switched off by a repository variable, at the job (so no secret is
//     read while it is off);
//   - it never runs for pull requests (they would hand the credential to
//     whoever can edit the workflow or the tests);
//   - it has read-only permissions;
//   - the secrets are named once each, in the `env:` of the step that runs the
//     suite and of the step that checks they exist — never at the job or
//     workflow level, never inside a script.
func TestLiveWorkflowIsGatedAndKeepsItsSecrets(t *testing.T) {
	raw, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		On          map[string]any    `yaml:"on"`
		Permissions map[string]string `yaml:"permissions"`
		Env         map[string]string `yaml:"env"`
		Jobs        map[string]struct {
			If    string            `yaml:"if"`
			Env   map[string]string `yaml:"env"`
			Steps []struct {
				Name string            `yaml:"name"`
				Uses string            `yaml:"uses"`
				Run  string            `yaml:"run"`
				Env  map[string]string `yaml:"env"`
				With map[string]any    `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}

	for _, forbidden := range []string{"pull_request", "pull_request_target", "workflow_run"} {
		if _, ok := wf.On[forbidden]; ok {
			t.Errorf("the live workflow must not run on %s", forbidden)
		}
	}
	for _, want := range []string{"workflow_dispatch", "schedule", "push"} {
		if _, ok := wf.On[want]; !ok {
			t.Errorf("the live workflow lost its %s trigger", want)
		}
	}
	if len(wf.Permissions) != 1 || wf.Permissions["contents"] != "read" {
		t.Errorf("permissions = %v, want contents: read and nothing else", wf.Permissions)
	}
	if len(wf.Jobs) != 1 {
		t.Fatalf("the live workflow has %d jobs, want exactly one (the gated one)", len(wf.Jobs))
	}

	secretRef := regexp.MustCompile(`secrets\.([A-Z0-9_]+)`)
	allowed := map[string]bool{"ANTHROPIC_API_KEY": true, "CLAUDE_CODE_OAUTH_TOKEN": true}
	for name, job := range wf.Jobs {
		// Exactly this condition: the variable on, and main only. (A substring
		// test would accept `... || true`.)
		const gate = "${{ vars.LIVE_LLM_SCAN_ENABLED == 'true' && github.ref == 'refs/heads/main' }}"
		if strings.TrimSpace(job.If) != gate {
			t.Errorf("job %s: if = %q, want exactly %q", name, job.If, gate)
		}
		for _, st := range job.Steps {
			if strings.HasPrefix(st.Uses, "actions/checkout@") && fmt.Sprint(st.With["persist-credentials"]) != "false" {
				t.Errorf("job %s: the checkout keeps the job token in .git/config (persist-credentials is not false)", name)
			}
		}
		for k, v := range job.Env {
			if secretRef.MatchString(v) {
				t.Errorf("job %s: the job-level env %s holds a secret; secrets belong to the steps that need them", name, k)
			}
		}
		spenders := 0
		for _, st := range job.Steps {
			if secretRef.MatchString(st.Run) {
				t.Errorf("job %s, step %q: a secret is referenced inside a script", name, st.Name)
			}
			for k, v := range st.Env {
				for _, m := range secretRef.FindAllStringSubmatch(v, -1) {
					if !allowed[m[1]] {
						t.Errorf("job %s, step %q: env %s uses the secret %s", name, st.Name, k, m[1])
					}
					if st.Uses != "" {
						t.Errorf("job %s, step %q: a secret is passed to an action", name, st.Name)
					}
				}
			}
			for k, v := range st.With {
				if s, ok := v.(string); ok && secretRef.MatchString(s) {
					t.Errorf("job %s, step %q: the input %s of %s holds a secret", name, st.Name, k, st.Uses)
				}
			}
			if strings.Contains(st.Run, "go test") && strings.Contains(st.Run, "-tags livellm") {
				spenders++
				for _, secret := range []string{"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"} {
					if !strings.Contains(st.Env[secret], "secrets."+secret) {
						t.Errorf("job %s, the suite's step does not receive %s", name, secret)
					}
				}
			}
		}
		if spenders != 1 {
			t.Errorf("job %s has %d steps that run the live suite, want 1", name, spenders)
		}
	}
	for k, v := range wf.Env {
		if secretRef.MatchString(v) {
			t.Errorf("the workflow-level env %s holds a secret", k)
		}
	}

	// The checks above read the parsed fields; this one reads the text, so a
	// form they cannot see — secrets['X'], toJSON(secrets), a secret in an if: —
	// is caught too. Every use of the secrets context, outside comments, must be
	// one of the two named secrets.
	var code []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			code = append(code, line)
		}
	}
	text := strings.Join(code, "\n")
	named := regexp.MustCompile(`secrets\.(ANTHROPIC_API_KEY|CLAUDE_CODE_OAUTH_TOKEN)\b`)
	if left := regexp.MustCompile(`\bsecrets\b`).ReplaceAllString(named.ReplaceAllString(text, ""), "\x00"); strings.Contains(left, "\x00") {
		t.Errorf("the workflow uses the secrets context in a form other than secrets.ANTHROPIC_API_KEY / secrets.CLAUDE_CODE_OAUTH_TOKEN (secrets[...], toJSON(secrets), inherit)")
	}
	if strings.Contains(text, "secrets: inherit") {
		t.Errorf("the workflow passes every secret on")
	}
}
