package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRateLimitWaitDefaults: a request over a limit waits for its turn by
// default (Task 187: cargo's burst of parallel index fetches was refused at
// once and old cargo fails the build on the first 429).
func TestRateLimitWaitDefaults(t *testing.T) {
	d := Default()
	if d.RateLimit.MaxWait != time.Minute || d.RateLimit.MaxQueue != 1024 {
		t.Fatalf("defaults: maxWait %v maxQueue %d", d.RateLimit.MaxWait, d.RateLimit.MaxQueue)
	}

	load := func(t *testing.T, doc string) (*Config, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		return Load(path)
	}
	const head = "upstreams:\n  npm: {type: npm, url: \"https://registry.npmjs.org\"}\nrateLimit:\n  enabled: true\n  default: {maxConcurrent: 32}\n"

	// A config that names no wait keeps the defaults.
	if r := CheckBytes([]byte(head + "  maxWait: 3s\n  maxQueue: 8\n")); r.Errors != 0 {
		t.Fatalf("preflight errors: %+v", r.Issues)
	}
	c, err := load(t, head)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.RateLimit.MaxWait != time.Minute || c.RateLimit.MaxQueue != 1024 {
		t.Fatalf("unset: maxWait %v maxQueue %d", c.RateLimit.MaxWait, c.RateLimit.MaxQueue)
	}
	// An operator can turn waiting off, or tune it.
	c, err = load(t, head+"  maxWait: 0s\n  maxQueue: 64\n")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.RateLimit.MaxWait != 0 || c.RateLimit.MaxQueue != 64 {
		t.Fatalf("set: maxWait %v maxQueue %d", c.RateLimit.MaxWait, c.RateLimit.MaxQueue)
	}

	for field, doc := range map[string]string{
		"rateLimit.maxWait":  head + "  maxWait: -1s\n",
		"rateLimit.maxQueue": head + "  maxQueue: -1\n",
	} {
		if _, err := load(t, doc); err == nil || !strings.Contains(err.Error(), field) {
			t.Errorf("%s negative: err = %v", field, err)
		}
		if r := CheckBytes([]byte(doc)); r.Errors == 0 {
			t.Errorf("%s negative: preflight found nothing", field)
		}
	}
}

// TestRateLimitWaitBelowWriteTimeout: a wait as long as the response deadline
// is flagged by the preflight.
func TestRateLimitWaitBelowWriteTimeout(t *testing.T) {
	const head = "upstreams:\n  npm: {type: npm, url: \"https://registry.npmjs.org\"}\nrateLimit:\n  enabled: true\n  default: {maxConcurrent: 32}\n"
	warned := func(doc string) bool {
		for _, is := range CheckBytes([]byte(doc)).Issues {
			if is.Path == "rateLimit.maxWait" {
				return true
			}
		}
		return false
	}
	if warned(head) {
		t.Error("the defaults (1m wait, 5m write timeout) must not warn")
	}
	if !warned("server:\n  writeTimeout: 30s\n" + head) {
		t.Error("a 1m wait under a 30s write timeout must warn")
	}
	if warned("server:\n  writeTimeout: 30s\n" + head + "  maxWait: 10s\n") {
		t.Error("a 10s wait under a 30s write timeout must not warn")
	}
	if warned("server:\n  writeTimeout: 30s\nrateLimit:\n  enabled: false\n") {
		t.Error("a disabled limiter must not warn")
	}
}
