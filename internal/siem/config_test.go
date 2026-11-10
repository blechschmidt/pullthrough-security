package siem

import (
	"strings"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name:    "no sinks",
			cfg:     Config{},
			wantErr: "at least one sink",
		},
		{
			name:    "unknown kind",
			cfg:     Config{Sinks: []SinkConfig{{Name: "a", Kind: "kafka"}}},
			wantErr: "unknown kind",
		},
		{
			name:    "hec missing token",
			cfg:     Config{Sinks: []SinkConfig{{Name: "a", Kind: "splunk_hec", URL: "https://x"}}},
			wantErr: "requires a token",
		},
		{
			name:    "syslog missing address",
			cfg:     Config{Sinks: []SinkConfig{{Name: "a", Kind: "syslog"}}},
			wantErr: "requires an address",
		},
		{
			name: "duplicate names",
			cfg: Config{Sinks: []SinkConfig{
				{Name: "a", Kind: "syslog", Address: "h:514"},
				{Name: "a", Kind: "syslog", Address: "h:514"},
			}},
			wantErr: "duplicate sink name",
		},
		{
			name:    "bad severity",
			cfg:     Config{MinSeverity: "nope", Sinks: []SinkConfig{{Name: "a", Kind: "syslog", Address: "h:514"}}},
			wantErr: "invalid minSeverity",
		},
		{
			name:    "ocsf missing url",
			cfg:     Config{Sinks: []SinkConfig{{Name: "a", Kind: "ocsf"}}},
			wantErr: "requires a url",
		},
		{
			name:    "ocsf non-http url",
			cfg:     Config{Sinks: []SinkConfig{{Name: "a", Kind: "ocsf", URL: "ftp://x"}}},
			wantErr: "url must be http(s)",
		},
		{
			name: "ocsf bad class map",
			cfg: Config{
				OCSF:  OCSFConfig{ClassMap: map[string]string{"pull": "nope"}},
				Sinks: []SinkConfig{{Name: "a", Kind: "ocsf", URL: "https://lake/ingest"}},
			},
			wantErr: "unknown class",
		},
		{
			name: "valid",
			cfg: Config{Sinks: []SinkConfig{
				{Name: "splunk", Kind: "splunk_hec", URL: "https://x:8088", Token: "t"},
				{Name: "sys", Kind: "syslog", Address: "h:514", Network: "udp"},
				{Name: "lake", Kind: "ocsf", URL: "https://lake/ingest", Token: "t"},
			}},
			wantErr: "",
		},
		{
			name: "valid ocsf class map",
			cfg: Config{
				OCSF:  OCSFConfig{ClassMap: map[string]string{"pull": "api_activity", "custom": "Detection Finding"}},
				Sinks: []SinkConfig{{Name: "lake", Kind: "ocsf", URL: "https://lake/ingest"}},
			},
			wantErr: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestBuildConstructsForwarder(t *testing.T) {
	f, err := Build(Config{
		ForwardAudit:    true,
		ForwardFindings: true,
		OCSF:            OCSFConfig{SchemaVersion: "1.2.0"},
		Sinks: []SinkConfig{
			{Name: "splunk", Kind: "splunk_hec", URL: "https://x:8088", Token: "t"},
			{Name: "sys", Kind: "syslog", Address: "127.0.0.1:0", Network: "udp"},
			{Name: "lake", Kind: "ocsf", URL: "https://lake/ingest", Token: "t"},
		},
	}, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer f.Close()
	if f.Sinks() != 3 {
		t.Fatalf("sinks = %d, want 3", f.Sinks())
	}
}
