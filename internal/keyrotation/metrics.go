package keyrotation

import "sync/atomic"

// Metrics holds the key-rotation subsystem's cumulative counters and current
// gauges. A nil *Metrics is a valid no-op, so the service can hold one
// unconditionally. The proxy's observability layer bridges a Snapshot into
// pullthrough_key_rotation_* scrape-time callbacks; the per-material
// pullthrough_key_expiry_seconds gauge is read live from the service instead,
// so it stays accurate between scans.
type Metrics struct {
	scans        atomic.Uint64
	sourceErrors atomic.Uint64
	warnings     atomic.Uint64 // cumulative transitions into the warning band
	criticals    atomic.Uint64 // cumulative transitions into the critical band
	expiries     atomic.Uint64 // cumulative transitions into the expired band
	rotations    atomic.Uint64
	rotationFail atomic.Uint64
	lastScanUnix atomic.Int64

	// Current per-band material counts from the most recent scan.
	curWarning  atomic.Int64
	curCritical atomic.Int64
	curExpired  atomic.Int64
}

// NewMetrics constructs a zeroed Metrics.
func NewMetrics() *Metrics { return &Metrics{} }

func (m *Metrics) recordScan(unix int64, warning, critical, expired int) {
	if m == nil {
		return
	}
	m.scans.Add(1)
	m.lastScanUnix.Store(unix)
	m.curWarning.Store(int64(warning))
	m.curCritical.Store(int64(critical))
	m.curExpired.Store(int64(expired))
}

func (m *Metrics) recordSourceError() {
	if m == nil {
		return
	}
	m.sourceErrors.Add(1)
}

// recordBandEntry counts a material transitioning into a more-severe band, the
// signal that drives a fresh notification.
func (m *Metrics) recordBandEntry(s Status) {
	if m == nil {
		return
	}
	switch s {
	case StatusWarning:
		m.warnings.Add(1)
	case StatusCritical:
		m.criticals.Add(1)
	case StatusExpired:
		m.expiries.Add(1)
	}
}

func (m *Metrics) recordRotation(ok bool) {
	if m == nil {
		return
	}
	if ok {
		m.rotations.Add(1)
	} else {
		m.rotationFail.Add(1)
	}
}

// Snapshot is an immutable view of the counters/gauges for the metrics layer.
type Snapshot struct {
	Scans             uint64 `json:"scans"`
	SourceErrors      uint64 `json:"sourceErrors"`
	Warnings          uint64 `json:"warnings"`
	Criticals         uint64 `json:"criticals"`
	Expiries          uint64 `json:"expiries"`
	Rotations         uint64 `json:"rotations"`
	RotationFailures  uint64 `json:"rotationFailures"`
	LastScanUnix      int64  `json:"lastScanUnix"`
	WarningMaterials  int64  `json:"warningMaterials"`
	CriticalMaterials int64  `json:"criticalMaterials"`
	ExpiredMaterials  int64  `json:"expiredMaterials"`
}

// Snapshot returns a consistent copy of the current counters.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	return Snapshot{
		Scans:             m.scans.Load(),
		SourceErrors:      m.sourceErrors.Load(),
		Warnings:          m.warnings.Load(),
		Criticals:         m.criticals.Load(),
		Expiries:          m.expiries.Load(),
		Rotations:         m.rotations.Load(),
		RotationFailures:  m.rotationFail.Load(),
		LastScanUnix:      m.lastScanUnix.Load(),
		WarningMaterials:  m.curWarning.Load(),
		CriticalMaterials: m.curCritical.Load(),
		ExpiredMaterials:  m.curExpired.Load(),
	}
}
