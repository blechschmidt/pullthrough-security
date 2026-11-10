package egress

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// normalizeScheme lowercases and trims a URL scheme.
func normalizeScheme(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// ruleSet is a compiled host/domain/CIDR allowlist. It is matched by hostname
// (exact or domain-suffix) and, for IP-literal destinations, by CIDR membership.
// The original entry strings are retained so the allowlist can be rendered and
// individual entries removed at runtime.
type ruleSet struct {
	exact   map[string]bool   // exact hostnames, lowercased
	domains []string          // domain suffixes including the leading dot, e.g. ".npmjs.org"
	cidrs   []*net.IPNet      // permitted destination IP ranges (for IP-literal hosts)
	entry   map[string]string // canonical entry -> normalized form, for render/remove
}

func newRuleSet() *ruleSet {
	return &ruleSet{
		exact: map[string]bool{},
		entry: map[string]string{},
	}
}

// compileRuleSet builds a ruleSet from raw allowlist entries. Recognized forms:
//
//   - "registry.npmjs.org"      exact host
//   - ".npmjs.org" / "*.npmjs.org"  domain suffix (matches the apex and any subdomain)
//   - "10.0.0.0/8" / "192.0.2.1"    CIDR or IP literal
func compileRuleSet(entries []string) (*ruleSet, error) {
	rs := newRuleSet()
	for _, e := range entries {
		if err := rs.add(e); err != nil {
			return nil, err
		}
	}
	return rs, nil
}

// add inserts a single allowlist entry. Empty/whitespace entries are ignored.
func (rs *ruleSet) add(raw string) error {
	e := strings.TrimSpace(raw)
	if e == "" {
		return nil
	}
	key := strings.ToLower(e)
	if _, dup := rs.entry[key]; dup {
		return nil
	}

	switch {
	case strings.Contains(e, "/"):
		// CIDR.
		_, ipnet, err := net.ParseCIDR(e)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", e, err)
		}
		rs.cidrs = append(rs.cidrs, ipnet)
	case strings.HasPrefix(e, "*."):
		suffix := strings.ToLower(e[1:]) // keep the leading dot: "*.npmjs.org" -> ".npmjs.org"
		rs.domains = append(rs.domains, suffix)
	case strings.HasPrefix(e, "."):
		rs.domains = append(rs.domains, strings.ToLower(e))
	default:
		if ip := net.ParseIP(e); ip != nil {
			// Bare IP literal: treat as a /32 or /128.
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			_, ipnet, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", e, bits))
			rs.cidrs = append(rs.cidrs, ipnet)
		} else {
			rs.exact[key] = true
		}
	}
	rs.entry[key] = e
	return nil
}

// remove deletes a previously-added entry, returning whether it was present. The
// match is on the canonical (lowercased) entry string.
func (rs *ruleSet) remove(raw string) bool {
	key := strings.ToLower(strings.TrimSpace(raw))
	orig, ok := rs.entry[key]
	if !ok {
		return false
	}
	delete(rs.entry, key)

	switch {
	case strings.Contains(orig, "/") || (net.ParseIP(strings.TrimSpace(orig)) != nil):
		// Rebuild the CIDR slice without this entry. CIDRs are few; this is cheap
		// and avoids tracking parallel indices.
		rs.cidrs = rs.cidrs[:0]
		for _, e := range rs.entry {
			if strings.Contains(e, "/") {
				if _, n, err := net.ParseCIDR(e); err == nil {
					rs.cidrs = append(rs.cidrs, n)
				}
			} else if ip := net.ParseIP(strings.TrimSpace(e)); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				if _, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", e, bits)); err == nil {
					rs.cidrs = append(rs.cidrs, n)
				}
			}
		}
	case strings.HasPrefix(orig, "*.") || strings.HasPrefix(orig, "."):
		suffix := strings.ToLower(orig)
		if strings.HasPrefix(suffix, "*") {
			suffix = suffix[1:]
		}
		for i, d := range rs.domains {
			if d == suffix {
				rs.domains = append(rs.domains[:i], rs.domains[i+1:]...)
				break
			}
		}
	default:
		delete(rs.exact, key)
	}
	return true
}

// enforced reports whether the rule set carries any host/domain/CIDR rule (an
// empty set means "do not enforce a host allowlist").
func (rs *ruleSet) enforced() bool {
	return len(rs.exact) > 0 || len(rs.domains) > 0 || len(rs.cidrs) > 0
}

// entries returns the original entry strings in sorted order.
func (rs *ruleSet) entries() []string {
	out := make([]string, 0, len(rs.entry))
	for _, e := range rs.entry {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// matchHost reports whether host (a hostname or IP literal, no port) is permitted
// by this rule set. An empty (unenforced) rule set permits everything.
func (rs *ruleSet) matchHost(host string) bool {
	if !rs.enforced() {
		return true
	}
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".") // tolerate a fully-qualified trailing dot
	if h == "" {
		return false
	}
	if rs.exact[h] {
		return true
	}
	for _, suffix := range rs.domains {
		// suffix is ".npmjs.org": match the apex ("npmjs.org") and any subdomain.
		if h == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(h, suffix) {
			return true
		}
	}
	if ip := net.ParseIP(h); ip != nil {
		for _, n := range rs.cidrs {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// compileCIDRs parses a list of CIDR / IP-literal strings into IP networks.
func compileCIDRs(entries []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(entries))
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			if ip := net.ParseIP(e); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				e = fmt.Sprintf("%s/%d", e, bits)
			}
		}
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// inExceptions reports whether ip falls inside any configured private-block
// exception range.
func (g *Guard) inExceptions(ip net.IP) bool {
	for _, n := range g.exceptions {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
