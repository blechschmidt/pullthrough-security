package notify

import "testing"

func TestRedactorScrubsSensitiveKeys(t *testing.T) {
	r := NewRedactor(nil)
	ev := Event{Fields: map[string]string{
		"password":      "hunter2",
		"api_key":       "sk-123",
		"Authorization": "Bearer t",
		"x-auth-token":  "t",
		"package":       "left-pad",
		"version":       "1.0.0",
	}}
	out := r.Apply(ev)

	for _, k := range []string{"password", "api_key", "Authorization", "x-auth-token"} {
		if out.Fields[k] != redactedPlaceholder {
			t.Errorf("field %q = %q, want redacted", k, out.Fields[k])
		}
	}
	if out.Fields["package"] != "left-pad" || out.Fields["version"] != "1.0.0" {
		t.Errorf("non-sensitive fields were altered: %+v", out.Fields)
	}
}

func TestRedactorDoesNotMutateInput(t *testing.T) {
	r := NewRedactor(nil)
	in := Event{Fields: map[string]string{"token": "secret"}}
	_ = r.Apply(in)
	if in.Fields["token"] != "secret" {
		t.Errorf("input event was mutated: %q", in.Fields["token"])
	}
}

func TestRedactorExtraKeys(t *testing.T) {
	r := NewRedactor([]string{"badgenumber"})
	out := r.Apply(Event{Fields: map[string]string{"BadgeNumber": "007", "name": "bond"}})
	if out.Fields["BadgeNumber"] != redactedPlaceholder {
		t.Errorf("custom key not redacted: %q", out.Fields["BadgeNumber"])
	}
	if out.Fields["name"] != "bond" {
		t.Errorf("name altered: %q", out.Fields["name"])
	}
}

func TestNilRedactorPassThrough(t *testing.T) {
	var r *Redactor
	ev := Event{Fields: map[string]string{"token": "secret"}}
	out := r.Apply(ev)
	if out.Fields["token"] != "secret" {
		t.Errorf("nil redactor should pass through, got %q", out.Fields["token"])
	}
}
