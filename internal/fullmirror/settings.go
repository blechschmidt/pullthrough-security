package fullmirror

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Defaults of the per-upstream settings (upstreams.<name>.fullMirror).
const (
	// DefaultConcurrency is how many packages of one upstream are worked on at
	// a time.
	DefaultConcurrency = 2
	// MaxConcurrency bounds concurrency.
	MaxConcurrency = 32
	// DefaultRequestsPerSecond paces the requests made to one upstream: feed
	// polls, metadata, and artifact fetches.
	DefaultRequestsPerSecond = 2.0
	// DefaultPollInterval is the time between two polls of a feed that has
	// nothing more to give.
	DefaultPollInterval = 5 * time.Minute
	// MinPollInterval is the shortest poll interval accepted.
	MinPollInterval = 10 * time.Second
)

// Version policies.
const (
	// VersionsAll mirrors every version a change concerns.
	VersionsAll = "all"
	// VersionsLatest mirrors the newest N versions of each package.
	VersionsLatest = "latest"
)

// Settings is one upstream's full-mirror configuration as the engine takes
// it: the configuration's upstreams.<name>.fullMirror block, compiled.
type Settings struct {
	// Upstream is the upstream's name; Type its canonical type.
	Upstream string
	Type     string
	// Include and Exclude are RE2 patterns matched against the whole package
	// name. A package is mirrored when it matches an Include pattern (or none
	// is given) and no Exclude pattern.
	Include []*regexp.Regexp
	Exclude []*regexp.Regexp
	// Latest is the version policy: 0 mirrors every version ("all"), N the N
	// newest versions of each package ("latest" N).
	Latest int
	// MaxArtifactBytes refuses a file larger than this (0: no limit). A size
	// the registry states is checked before anything is fetched; otherwise the
	// fetch is cut off once it passes the limit, and nothing is cached.
	MaxArtifactBytes int64
	// ByteBudget is the most bytes the mirror adds to the cache from this
	// upstream, in total. When it is spent the mirror stops and waits for a
	// larger budget. Required.
	ByteBudget int64
	// Concurrency is how many packages are worked on at a time.
	Concurrency int
	// RequestsPerSecond paces every request made to the upstream on the
	// mirror's behalf.
	RequestsPerSecond float64
	// PollInterval is the time between polls of a feed that has nothing more
	// to give.
	PollInterval time.Duration
	// Window is the off-peak window the mirror works in.
	Window Window
	// DryRun polls the feed, applies every policy and checks the cache, but
	// fetches no artifact: what would be fetched is counted as skipped.
	DryRun bool
}

// withDefaults fills in the zero values.
func (s Settings) withDefaults() Settings {
	if s.Concurrency <= 0 {
		s.Concurrency = DefaultConcurrency
	}
	if s.Concurrency > MaxConcurrency {
		s.Concurrency = MaxConcurrency
	}
	if s.RequestsPerSecond <= 0 {
		s.RequestsPerSecond = DefaultRequestsPerSecond
	}
	if s.PollInterval <= 0 {
		s.PollInterval = DefaultPollInterval
	}
	return s
}

// VersionPolicy renders the version policy ("all", "latest 3").
func (s Settings) VersionPolicy() string {
	if s.Latest > 0 {
		return fmt.Sprintf("%s %d", VersionsLatest, s.Latest)
	}
	return VersionsAll
}

// Wants reports whether a package name passes the include and exclude
// patterns.
func (s Settings) Wants(name string) bool {
	if len(s.Include) > 0 {
		in := false
		for _, re := range s.Include {
			if re.MatchString(name) {
				in = true
				break
			}
		}
		if !in {
			return false
		}
	}
	for _, re := range s.Exclude {
		if re.MatchString(name) {
			return false
		}
	}
	return true
}

// maxPatternLength bounds one name pattern.
const maxPatternLength = 1024

// CompilePatterns compiles name patterns (RE2 syntax), each anchored so that
// it must match the whole package name: "lodash" does not match
// "lodash-evil", "@acme/.*" matches every package of the @acme scope.
func CompilePatterns(patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for i, p := range patterns {
		if strings.TrimSpace(p) == "" {
			return nil, fmt.Errorf("pattern %d is empty", i)
		}
		if len(p) > maxPatternLength {
			return nil, fmt.Errorf("pattern %d is longer than %d bytes", i, maxPatternLength)
		}
		re, err := regexp.Compile(`^(?:` + p + `)$`)
		if err != nil {
			return nil, fmt.Errorf("pattern %d %q is not a valid RE2 expression: %w", i, p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// ParseVersionPolicy reads the version policy: "all" (or empty) with latest
// 0, or "latest" with latest ≥ 1. It returns the engine's Latest value.
func ParseVersionPolicy(versions string, latest int) (int, error) {
	switch strings.ToLower(strings.TrimSpace(versions)) {
	case "", VersionsAll:
		if latest != 0 {
			return 0, fmt.Errorf("latest is set (%d) but versions is %q; set versions: latest", latest, VersionsAll)
		}
		return 0, nil
	case VersionsLatest:
		if latest < 1 {
			return 0, fmt.Errorf("versions: latest needs latest: N with N ≥ 1 (got %d)", latest)
		}
		return latest, nil
	}
	return 0, fmt.Errorf("unknown version policy %q (want %q or %q)", versions, VersionsAll, VersionsLatest)
}

// Window is a daily time window. The zero Window is always open.
type Window struct {
	set        bool
	start, end int // minutes after midnight
	loc        *time.Location
}

// ParseWindow reads a window from "HH:MM" bounds and an IANA time zone
// (default UTC). Both bounds empty is the always-open window; the window may
// wrap midnight (start 22:00, end 06:00). Equal bounds are refused: they would
// read as both "never" and "always".
func ParseWindow(start, end, timezone string) (Window, error) {
	start, end, timezone = strings.TrimSpace(start), strings.TrimSpace(end), strings.TrimSpace(timezone)
	if start == "" && end == "" {
		if timezone != "" {
			return Window{}, fmt.Errorf("a time zone is set but no window start and end")
		}
		return Window{}, nil
	}
	if start == "" || end == "" {
		return Window{}, fmt.Errorf("the window needs both a start and an end (HH:MM)")
	}
	s, err := parseClock(start)
	if err != nil {
		return Window{}, fmt.Errorf("window start: %w", err)
	}
	e, err := parseClock(end)
	if err != nil {
		return Window{}, fmt.Errorf("window end: %w", err)
	}
	if s == e {
		return Window{}, fmt.Errorf("the window starts and ends at %s; leave both empty to work around the clock", start)
	}
	loc := time.UTC
	if timezone != "" {
		if loc, err = time.LoadLocation(timezone); err != nil {
			return Window{}, fmt.Errorf("window time zone %q: %w", timezone, err)
		}
	}
	return Window{set: true, start: s, end: e, loc: loc}, nil
}

func parseClock(v string) (int, error) {
	h, m, ok := strings.Cut(v, ":")
	if !ok || len(h) != 2 || len(m) != 2 {
		return 0, fmt.Errorf("%q is not HH:MM", v)
	}
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if err1 != nil || err2 != nil || hh < 0 || hh > 23 || mm < 0 || mm > 59 {
		return 0, fmt.Errorf("%q is not a time of day (HH:MM, 00:00-23:59)", v)
	}
	return hh*60 + mm, nil
}

// Always reports whether the window is always open.
func (w Window) Always() bool { return !w.set }

// Contains reports whether t falls inside the window.
func (w Window) Contains(t time.Time) bool {
	if !w.set {
		return true
	}
	lt := t.In(w.loc)
	m := lt.Hour()*60 + lt.Minute()
	if w.start < w.end {
		return m >= w.start && m < w.end
	}
	return m >= w.start || m < w.end
}

// NextOpen returns when the window next opens after t (t itself when it is
// open).
func (w Window) NextOpen(t time.Time) time.Time {
	if w.Contains(t) {
		return t
	}
	lt := t.In(w.loc)
	open := time.Date(lt.Year(), lt.Month(), lt.Day(), w.start/60, w.start%60, 0, 0, w.loc)
	if !open.After(lt) {
		open = open.AddDate(0, 0, 1)
	}
	return open
}

// String renders the window ("22:00-06:00 Europe/Berlin", "always").
func (w Window) String() string {
	if !w.set {
		return "always"
	}
	return fmt.Sprintf("%02d:%02d-%02d:%02d %s", w.start/60, w.start%60, w.end/60, w.end%60, w.loc)
}
