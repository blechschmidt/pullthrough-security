package config

import (
	"strings"
	"testing"
)

func TestValidateGitLFS_DisabledSkipsChecks(t *testing.T) {
	c := Default()
	c.Git.LFS.Enabled = false
	// Negative bounds are only rejected when LFS is enabled.
	c.Git.LFS.MaxObjectBytes = -1
	c.Git.LFS.ScanMaxBytes = -1
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled git.lfs must not enforce size bounds: %v", err)
	}
}

func TestValidateGitLFS_OK(t *testing.T) {
	c := Default()
	c.Git.LFS.Enabled = true
	c.Git.LFS.MaxObjectBytes = 1 << 30
	c.Git.LFS.ScanMaxBytes = 1 << 20
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid git.lfs config, got %v", err)
	}
	// Zero bounds are acceptable (the backend applies package defaults).
	c.Git.LFS.MaxObjectBytes = 0
	c.Git.LFS.ScanMaxBytes = 0
	if err := c.Validate(); err != nil {
		t.Fatalf("zero git.lfs bounds must be accepted (defaults apply), got %v", err)
	}
}

func TestValidateGitLFS_Errors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name:   "negative maxObjectBytes",
			mutate: func(c *Config) { c.Git.LFS.MaxObjectBytes = -5 },
			want:   "git.lfs.maxObjectBytes",
		},
		{
			name:   "negative scanMaxBytes",
			mutate: func(c *Config) { c.Git.LFS.ScanMaxBytes = -5 },
			want:   "git.lfs.scanMaxBytes",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			c.Git.LFS.Enabled = true
			tc.mutate(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tc.want)
			}
		})
	}
}
