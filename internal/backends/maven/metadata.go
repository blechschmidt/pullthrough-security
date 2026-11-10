package maven

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// maven-metadata.xml is the mutable index document of the Maven layout. It comes
// in two flavours the proxy must understand to support release and snapshot
// resolution semantics:
//
//   - Release/group-artifact metadata (/<group>/<artifact>/maven-metadata.xml)
//     enumerates the published versions and names the latest and release
//     versions. A client consults it to resolve a version range or "LATEST".
//
//   - Snapshot metadata (/<group>/<artifact>/<version>-SNAPSHOT/maven-metadata.xml)
//     names the most recent timestamped build of a snapshot and, per
//     classifier/extension, the exact resolved filename. A client consults it to
//     turn "1.0-SNAPSHOT" into a concrete "1.0-20231010.123456-7.jar".
//
// The backend serves both live (they are mutable), but parses them to validate
// structure, count versions for metrics, and — for snapshots — expose the
// resolution helper used in tests and by callers that need to materialize a
// timestamped artifact name.

// Metadata is the parsed form of a maven-metadata.xml document. Fields absent
// from the document are left zero.
type Metadata struct {
	GroupID    string
	ArtifactID string
	// Latest and Release come from release-level metadata.
	Latest  string
	Release string
	// Versions lists every published version (release-level metadata).
	Versions []string
	// Snapshot, when non-nil, carries the snapshot resolution fields.
	Snapshot *SnapshotInfo
	// SnapshotVersions maps a "<classifier>:<extension>" key to the resolved
	// timestamped version for that artifact (snapshot-level metadata). The
	// classifier is empty for the main artifact.
	SnapshotVersions []SnapshotVersion
}

// SnapshotInfo carries the <versioning><snapshot> block of snapshot metadata:
// the build timestamp and incrementing build number that together form the
// resolved version, or a localCopy marker.
type SnapshotInfo struct {
	Timestamp   string
	BuildNumber int
	LocalCopy   bool
}

// SnapshotVersion is one <snapshotVersion> entry mapping a classifier/extension
// to its resolved (timestamped) version and update time.
type SnapshotVersion struct {
	Classifier string
	Extension  string
	Value      string
	Updated    string
}

// xmlMetadata mirrors the maven-metadata.xml schema for decoding.
type xmlMetadata struct {
	XMLName    xml.Name `xml:"metadata"`
	GroupID    string   `xml:"groupId"`
	ArtifactID string   `xml:"artifactId"`
	Versioning struct {
		Latest      string   `xml:"latest"`
		Release     string   `xml:"release"`
		Versions    []string `xml:"versions>version"`
		LastUpdated string   `xml:"lastUpdated"`
		Snapshot    *struct {
			Timestamp   string `xml:"timestamp"`
			BuildNumber *int   `xml:"buildNumber"`
			LocalCopy   bool   `xml:"localCopy"`
		} `xml:"snapshot"`
		SnapshotVersions []struct {
			Classifier string `xml:"classifier"`
			Extension  string `xml:"extension"`
			Value      string `xml:"value"`
			Updated    string `xml:"updated"`
		} `xml:"snapshotVersions>snapshotVersion"`
	} `xml:"versioning"`
}

// maxMetadataBytes bounds how much of a maven-metadata.xml document the backend
// parses, so a hostile upstream cannot exhaust memory. Real metadata is a few
// KiB to low hundreds of KiB even for very long-lived artifacts.
const maxMetadataBytes = 8 << 20 // 8 MiB

// ParseMetadata decodes a maven-metadata.xml document. It tolerates either
// release-level or snapshot-level metadata and returns a structured view. A
// document that is not well-formed XML, or whose root element is not <metadata>,
// is an error.
func ParseMetadata(data []byte) (*Metadata, error) {
	if len(data) > maxMetadataBytes {
		return nil, fmt.Errorf("maven: metadata document exceeds %d bytes", maxMetadataBytes)
	}
	var x xmlMetadata
	if err := xml.Unmarshal(data, &x); err != nil {
		return nil, fmt.Errorf("maven: parsing maven-metadata.xml: %w", err)
	}
	if x.XMLName.Local != "metadata" {
		return nil, fmt.Errorf("maven: maven-metadata.xml root element is %q, want \"metadata\"", x.XMLName.Local)
	}

	m := &Metadata{
		GroupID:    strings.TrimSpace(x.GroupID),
		ArtifactID: strings.TrimSpace(x.ArtifactID),
		Latest:     strings.TrimSpace(x.Versioning.Latest),
		Release:    strings.TrimSpace(x.Versioning.Release),
	}
	for _, v := range x.Versioning.Versions {
		if v = strings.TrimSpace(v); v != "" {
			m.Versions = append(m.Versions, v)
		}
	}
	if s := x.Versioning.Snapshot; s != nil {
		info := &SnapshotInfo{
			Timestamp: strings.TrimSpace(s.Timestamp),
			LocalCopy: s.LocalCopy,
		}
		if s.BuildNumber != nil {
			info.BuildNumber = *s.BuildNumber
		}
		m.Snapshot = info
	}
	for _, sv := range x.Versioning.SnapshotVersions {
		m.SnapshotVersions = append(m.SnapshotVersions, SnapshotVersion{
			Classifier: strings.TrimSpace(sv.Classifier),
			Extension:  strings.TrimSpace(sv.Extension),
			Value:      strings.TrimSpace(sv.Value),
			Updated:    strings.TrimSpace(sv.Updated),
		})
	}
	return m, nil
}

// ResolveSnapshot turns a base snapshot version (e.g. "1.0-SNAPSHOT") into the
// concrete resolved artifact filename for the requested classifier and
// extension, using the snapshot metadata. It first consults the explicit
// <snapshotVersions> entries (the authoritative, per-artifact mapping); if none
// match it falls back to composing "<base>-<timestamp>-<buildNumber>" from the
// <snapshot> block. It returns ok=false when the metadata carries neither.
//
// artifactID and baseVersion identify the artifact ("guava", "1.0-SNAPSHOT");
// classifier may be empty for the main artifact; ext is the extension without a
// leading dot (e.g. "jar").
func (m *Metadata) ResolveSnapshot(artifactID, baseVersion, classifier, ext string) (filename string, ok bool) {
	resolvedVersion, ok := m.resolveSnapshotVersion(baseVersion, classifier, ext)
	if !ok {
		return "", false
	}
	name := artifactID + "-" + resolvedVersion
	if classifier != "" {
		name += "-" + classifier
	}
	if ext != "" {
		name += "." + ext
	}
	return name, true
}

// resolveSnapshotVersion returns the resolved (timestamped) version string for a
// snapshot artifact.
func (m *Metadata) resolveSnapshotVersion(baseVersion, classifier, ext string) (string, bool) {
	for _, sv := range m.SnapshotVersions {
		if sv.Classifier == classifier && (ext == "" || sv.Extension == ext) && sv.Value != "" {
			return sv.Value, true
		}
	}
	if m.Snapshot != nil && m.Snapshot.Timestamp != "" {
		base := strings.TrimSuffix(baseVersion, "-SNAPSHOT")
		return fmt.Sprintf("%s-%s-%d", base, m.Snapshot.Timestamp, m.Snapshot.BuildNumber), true
	}
	return "", false
}
