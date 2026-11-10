package extension

import (
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

func TestMarshalHostInputStampsABI(t *testing.T) {
	in := HostInput{Signals: policyengine.Input{Artifact: policyengine.ArtifactInput{Name: "left-pad", Version: "1.0.0"}}}
	b, err := MarshalHostInput("my-gate", in)
	if err != nil {
		t.Fatalf("MarshalHostInput: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `"abiVersion":1`) {
		t.Errorf("expected abiVersion stamped, got %s", s)
	}
	if !strings.Contains(s, `"module":"my-gate"`) {
		t.Errorf("expected module name, got %s", s)
	}
	if !strings.Contains(s, `"name":"left-pad"`) {
		t.Errorf("expected artifact signals, got %s", s)
	}
}

func TestParseVerdict(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
		want Decision
	}{
		{"allow", `{"decision":"allow"}`, true, DecisionAllow},
		{"warn with reason", `{"decision":"warn","reason":"heads up"}`, true, DecisionWarn},
		{"block with annotations", `{"decision":"block","annotations":{"rule":"x"}}`, true, DecisionBlock},
		{"unknown decision", `{"decision":"nuke"}`, false, ""},
		{"empty decision", `{}`, false, ""},
		{"unknown field", `{"decision":"allow","extra":1}`, false, ""},
		{"not json", `{`, false, ""},
		{"too many annotations", `{"decision":"allow","annotations":` + bigAnnotations(maxAnnotations+1) + `}`, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := ParseVerdict([]byte(tc.in))
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected error, got nil")
			}
			if tc.ok && v.Decision != tc.want {
				t.Errorf("decision = %q, want %q", v.Decision, tc.want)
			}
		})
	}
}

func TestParseVerdictReasonBound(t *testing.T) {
	long := `{"decision":"warn","reason":"` + strings.Repeat("a", maxReasonBytes+1) + `"}`
	if _, err := ParseVerdict([]byte(long)); err == nil {
		t.Fatal("expected oversized reason to be rejected")
	}
}

func TestPackUnpackResult(t *testing.T) {
	for _, tc := range []struct{ off, ln uint32 }{{0, 0}, {1, 2}, {65536, 4096}, {0xffffffff, 0xffffffff}} {
		off, ln := unpackResult(packResult(tc.off, tc.ln))
		if off != tc.off || ln != tc.ln {
			t.Errorf("pack/unpack(%d,%d) = (%d,%d)", tc.off, tc.ln, off, ln)
		}
	}
}

func bigAnnotations(n int) string {
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`"k`)
		b.WriteString(itoa(i))
		b.WriteString(`":"v"`)
	}
	b.WriteByte('}')
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
