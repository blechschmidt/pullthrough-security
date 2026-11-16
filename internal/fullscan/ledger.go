package fullscan

import (
	"math"
	"time"
)

// The cost budget. The full scan pays for the model calls it causes from two
// ceilings: one per UTC calendar day and one per UTC calendar month. Either
// spent pauses the queue until its window rolls over (or the operator raises
// the ceiling). A ceiling of zero is no ceiling; the configuration requires at
// least one.
//
// The check happens before a scan starts and the cost is known only once it
// ends, so the scans in flight when a ceiling is reached still complete: the
// overshoot is at most Options.Concurrency scans.

// Ledger is what the full scan has spent, persisted with its state.
type Ledger struct {
	// Day is the UTC day ("2006-01-02") DaySpentUSD belongs to; Month the UTC
	// month ("2006-01") of MonthSpentUSD.
	Day           string  `json:"day,omitempty"`
	DaySpentUSD   float64 `json:"daySpentUsd"`
	Month         string  `json:"month,omitempty"`
	MonthSpentUSD float64 `json:"monthSpentUsd"`
	// TotalSpentUSD is everything spent since the state was created.
	TotalSpentUSD float64 `json:"totalSpentUsd"`
	// AnnouncedDay and AnnouncedMonth are the windows whose exhaustion was
	// announced (audit event, alert): once per window.
	AnnouncedDay   string `json:"announcedDay,omitempty"`
	AnnouncedMonth string `json:"announcedMonth,omitempty"`
}

func dayOf(t time.Time) string   { return t.UTC().Format("2006-01-02") }
func monthOf(t time.Time) string { return t.UTC().Format("2006-01") }

// roll starts new windows once the day or month has changed.
func (l *Ledger) roll(now time.Time) {
	if d := dayOf(now); l.Day != d {
		l.Day, l.DaySpentUSD = d, 0
	}
	if m := monthOf(now); l.Month != m {
		l.Month, l.MonthSpentUSD = m, 0
	}
}

// add charges a cost.
func (l *Ledger) add(now time.Time, usd float64) {
	if !(usd > 0) || math.IsInf(usd, 0) {
		return
	}
	l.roll(now)
	l.DaySpentUSD += usd
	l.MonthSpentUSD += usd
	l.TotalSpentUSD += usd
}

// Windows of the budget.
const (
	WindowDay   = "day"
	WindowMonth = "month"
)

// exhausted reports whether a ceiling is spent, and which (the month first).
func (l *Ledger) exhausted(now time.Time, daily, monthly float64) (bool, string) {
	l.roll(now)
	if monthly > 0 && l.MonthSpentUSD >= monthly {
		return true, WindowMonth
	}
	if daily > 0 && l.DaySpentUSD >= daily {
		return true, WindowDay
	}
	return false, ""
}

// resetsAt is when a window's spend starts over.
func resetsAt(now time.Time, window string) time.Time {
	t := now.UTC()
	if window == WindowMonth {
		return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
	}
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
}
