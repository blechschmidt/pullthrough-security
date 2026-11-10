package config

import (
	"strings"
	"testing"
	"time"
)

func TestPromoteOnReadEnabled(t *testing.T) {
	cases := []struct {
		name string
		in   *bool
		want bool
	}{
		{"unset defaults to true", nil, true},
		{"explicit true", boolPtr(true), true},
		{"explicit false", boolPtr(false), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tcfg := TieringConfig{PromoteOnRead: tc.in}
			if got := tcfg.PromoteOnReadEnabled(); got != tc.want {
				t.Fatalf("PromoteOnReadEnabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidateTiering_DisabledSkips(t *testing.T) {
	c := Default()
	c.Cache.Tiering = TieringConfig{Enabled: false, Cold: TierBackendConfig{Backend: "nonsense"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled tiering must not be validated: %v", err)
	}
}

func TestValidateTiering_OKFilesystem(t *testing.T) {
	c := Default()
	c.Cache.Backend = "filesystem"
	c.Cache.Dir = "/var/lib/pt/hot"
	c.Cache.Tiering = TieringConfig{
		Enabled:         true,
		Cold:            TierBackendConfig{Backend: "filesystem", Dir: "/var/lib/pt/cold"},
		DemoteAfterIdle: time.Hour,
		SweepInterval:   10 * time.Minute,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid filesystem tiering rejected: %v", err)
	}
}

func TestValidateTiering_OKS3Cold(t *testing.T) {
	c := Default()
	c.Cache.Backend = "filesystem"
	c.Cache.Dir = "/var/lib/pt/hot"
	c.Cache.Tiering = TieringConfig{
		Enabled: true,
		Cold: TierBackendConfig{Backend: "s3", S3: S3CacheConfig{
			Bucket: "cold", AccessKeyID: "ak", SecretAccessKey: "sk",
		}},
		HotMaxBytes: 1 << 30,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid s3 cold tier rejected: %v", err)
	}
}

func TestValidateTiering_Errors(t *testing.T) {
	base := func() *Config {
		c := Default()
		c.Cache.Backend = "filesystem"
		c.Cache.Dir = "/var/lib/pt/hot"
		c.Cache.Tiering = TieringConfig{
			Enabled:         true,
			Cold:            TierBackendConfig{Backend: "filesystem", Dir: "/var/lib/pt/cold"},
			DemoteAfterIdle: time.Hour,
		}
		return &c
	}
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"memory backend", func(c *Config) { c.Cache.Backend = "memory" }, "in-memory backend"},
		{"missing cold backend", func(c *Config) { c.Cache.Tiering.Cold.Backend = "" }, "cold.backend is required"},
		{"unknown cold backend", func(c *Config) { c.Cache.Tiering.Cold.Backend = "ftp" }, "unknown cache.tiering.cold.backend"},
		{"missing cold dir", func(c *Config) { c.Cache.Tiering.Cold.Dir = "" }, "cold.dir is required"},
		{"cold dir aliases hot", func(c *Config) { c.Cache.Tiering.Cold.Dir = c.Cache.Dir }, "must differ from cache.dir"},
		{"cold s3 missing bucket", func(c *Config) {
			c.Cache.Tiering.Cold = TierBackendConfig{Backend: "s3", S3: S3CacheConfig{AccessKeyID: "a", SecretAccessKey: "b"}}
		}, "cold.s3.bucket is required"},
		{"negative idle", func(c *Config) { c.Cache.Tiering.DemoteAfterIdle = -time.Second }, "demoteAfterIdle must not be negative"},
		{"negative cap", func(c *Config) { c.Cache.Tiering.HotMaxBytes = -1 }, "hotMaxBytes must not be negative"},
		{"negative sweep", func(c *Config) { c.Cache.Tiering.SweepInterval = -time.Second }, "sweepInterval must not be negative"},
		{"no demotion trigger", func(c *Config) {
			c.Cache.Tiering.DemoteAfterIdle = 0
			c.Cache.Tiering.HotMaxBytes = 0
		}, "no demotion trigger"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}
