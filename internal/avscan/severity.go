package avscan

// Severity is the gate's risk vocabulary, ordered info < low < medium < high <
// critical. It maps onto the canonical findings/SARIF severity scale by name,
// matching the other admission gates (installhooks, mlguard, vulnscan). A
// byte-level malware detection is always reported at critical.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// detectionRisk is the ordinal 0..100 risk contribution of a confirmed malware
// detection, folded into the unified risk-scoring / policy engines. A positive
// AV hit is unambiguous, so it sits at the top of the scale.
const detectionRisk = 100
