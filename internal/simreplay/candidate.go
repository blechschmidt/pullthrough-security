package simreplay

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ParseCandidate parses a CandidateConfig from raw bytes. The input may be YAML
// or JSON (JSON is a subset of YAML, so the YAML decoder accepts both). Unknown
// fields are rejected so a typo in a candidate config fails loudly rather than
// silently disabling a gate.
func ParseCandidate(raw []byte) (CandidateConfig, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var cfg CandidateConfig
	if err := dec.Decode(&cfg); err != nil {
		return CandidateConfig{}, fmt.Errorf("simreplay: parsing candidate config: %w", err)
	}
	return cfg, nil
}

// LoadCandidate reads and parses a candidate config file (YAML or JSON).
func LoadCandidate(path string) (CandidateConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return CandidateConfig{}, fmt.Errorf("simreplay: reading candidate config: %w", err)
	}
	return ParseCandidate(raw)
}
