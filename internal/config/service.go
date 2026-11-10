package config

// Service bundles the running configuration, its source path, and a drift
// detector so the admin surface can run the same validation against the live
// config or a candidate document, and report on-disk drift. It is the single
// object wired into the admin API for Task 85.
type Service struct {
	path     string
	live     *Config
	detector *Detector
}

// NewService captures the running configuration and the file it was loaded from
// (empty for a defaults-only process). The drift detector snapshots the boot
// fingerprint immediately.
func NewService(path string, live *Config) *Service {
	return &Service{
		path:     path,
		live:     live,
		detector: NewDetector(path, live),
	}
}

// Path returns the config file backing the running process ("" when none).
func (s *Service) Path() string { return s.path }

// ValidateLive runs the full validation pass against the running configuration.
func (s *Service) ValidateLive() *Report { return s.live.Check() }

// ValidateContent validates a candidate configuration supplied as raw YAML.
func (s *Service) ValidateContent(content string) *Report { return CheckBytes([]byte(content)) }

// ValidatePath validates a candidate configuration file on the server's disk.
func (s *Service) ValidatePath(path string) (*Report, error) { return CheckFile(path) }

// Drift recomputes the on-disk configuration and reports whether it has diverged
// from the running process.
func (s *Service) Drift() DriftStatus { return s.detector.Status() }

// Detector exposes the underlying drift detector (used by the metrics bridge).
func (s *Service) Detector() *Detector { return s.detector }
