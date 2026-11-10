package rubygems

import (
	"fmt"
	"strings"
)

// The RubyGems compact index (https://guides.rubygems.org/rubygems-org-api/,
// "compact index") exposes three plaintext documents that together let Bundler
// resolve and fetch gems without the legacy Marshal API:
//
//   - /names            newline-separated list of every gem name.
//   - /versions         every gem and the versions published for it, with an MD5
//                       of the gem's /info document for change detection.
//   - /info/<gem>       the per-gem document: one line per published version
//                       carrying its dependencies, the SHA-256 checksum of the
//                       .gem file, and the Ruby/RubyGems requirements.
//
// The backend serves all three live (they are mutable) but parses /info/<gem> to
// recover the per-version SHA-256 checksum, which is the supply-chain anchor used
// to verify a fetched .gem before it is cached or served.
//
// The /info/<gem> grammar (after a leading "---" line) is, per version:
//
//	VERSION[-PLATFORM] [DEP:CONSTRAINTS&DEP:CONSTRAINTS,...]|REQ:VALUE,REQ:VALUE,...
//
// The first whitespace-delimited token is the version (with an optional platform
// suffix, e.g. "1.13.0-x86_64-linux"). Everything after the final "|" is a
// comma-separated list of requirements; "checksum:<hex>" carries the SHA-256
// digest of the .gem.

// maxInfoBytes bounds how much of an /info/<gem> document the backend parses, so
// a hostile upstream cannot exhaust memory. Even very long-lived gems with
// thousands of releases stay well under this.
const maxInfoBytes = 16 << 20 // 16 MiB

// InfoVersion is one parsed line of an /info/<gem> document.
type InfoVersion struct {
	// Version is the version token, including any platform suffix
	// (e.g. "1.13.0" or "1.13.0-x86_64-linux").
	Version string
	// Checksum is the SHA-256 hex digest of the .gem file for this version, or
	// "" when the line declared none.
	Checksum string
	// Ruby and RubyGems carry the interpreter/tooling requirements when present.
	Ruby     string
	RubyGems string
}

// Info is the parsed form of an /info/<gem> compact-index document.
type Info struct {
	Versions []InfoVersion
}

// ParseInfo decodes an /info/<gem> compact-index document. It is lenient — a
// malformed line is skipped rather than failing the whole document — because the
// proxy serves the document live regardless; parsing exists only to recover the
// per-version checksum for verification and to surface counts. An over-large
// document is rejected so a hostile upstream cannot exhaust memory.
func ParseInfo(data []byte) (*Info, error) {
	if len(data) > maxInfoBytes {
		return nil, fmt.Errorf("rubygems: info document exceeds %d bytes", maxInfoBytes)
	}
	info := &Info{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		line = strings.TrimSpace(line)
		if line == "" || line == "---" {
			continue
		}
		v, ok := parseInfoLine(line)
		if !ok {
			continue
		}
		info.Versions = append(info.Versions, v)
	}
	return info, nil
}

// parseInfoLine parses a single /info/<gem> line into an InfoVersion. It returns
// ok=false for a line with no version token.
func parseInfoLine(line string) (InfoVersion, bool) {
	// The version token is everything up to the first space; the remainder holds
	// dependencies and (after the final "|") requirements.
	version := line
	rest := ""
	if sp := strings.IndexByte(line, ' '); sp >= 0 {
		version = line[:sp]
		rest = line[sp+1:]
	}
	version = strings.TrimSpace(version)
	if version == "" {
		return InfoVersion{}, false
	}

	v := InfoVersion{Version: version}

	// Requirements live after the final "|". Dependencies (before it) are not
	// needed for verification and are ignored.
	if bar := strings.LastIndex(rest, "|"); bar >= 0 {
		reqs := rest[bar+1:]
		for _, field := range strings.Split(reqs, ",") {
			field = strings.TrimSpace(field)
			key, val, ok := strings.Cut(field, ":")
			if !ok {
				continue
			}
			key = strings.TrimSpace(key)
			val = strings.TrimSpace(val)
			switch strings.ToLower(key) {
			case "checksum":
				if len(val) == gemChecksumHexLen && isHex(val) {
					v.Checksum = strings.ToLower(val)
				}
			case "ruby":
				v.Ruby = val
			case "rubygems":
				v.RubyGems = val
			}
		}
	}
	return v, true
}

// ChecksumFor returns the SHA-256 hex digest the document declares for the given
// version token (which may include a platform suffix), and whether one was
// found. The match is exact on the version token, which is exactly the substring
// of a .gem filename between the gem name and the ".gem" extension.
func (i *Info) ChecksumFor(version string) (string, bool) {
	for _, v := range i.Versions {
		if v.Version == version && v.Checksum != "" {
			return v.Checksum, true
		}
	}
	return "", false
}
