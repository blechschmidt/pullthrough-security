package yum

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// repodata/repomd.xml is the manifest and trust anchor of an RPM repository. It
// enumerates every metadata file (primary, filelists, other, ...) by its
// repository-root-relative location and publishes a checksum for each. A client
// (and the proxy) fetches it first, then fetches the primary.xml it points to.
// The proxy parses repomd.xml to (a) verify a fetched repodata file against its
// declared checksum and (b) locate the primary.xml whose digests anchor .rpm
// verification. When a trusted GPG keyring is configured, repomd.xml's own
// signature is validated first, anchoring the whole chain.
//
// Schematic of the document the parser accepts:
//
//	<repomd xmlns="http://linux.duke.edu/metadata/repo">
//	  <revision>1700000000</revision>
//	  <data type="primary">
//	    <checksum type="sha256"><hex></checksum>
//	    <location href="repodata/abc-primary.xml.gz"/>
//	    <size>123</size>
//	  </data>
//	  ...
//	</repomd>

// maxRepomdBytes bounds how much of a repomd.xml document the parser reads.
const maxRepomdBytes = 8 << 20 // 8 MiB

// RepoMD is the parsed form of repomd.xml: each data entry's location and
// declared checksum, keyed and indexed for the two lookups the backend performs.
type RepoMD struct {
	Revision string
	Data     []RepoData
}

// RepoData is one <data> entry of repomd.xml.
type RepoData struct {
	// Type is the metadata type ("primary", "filelists", "other", ...).
	Type string
	// Location is the repository-root-relative href of the metadata file.
	Location string
	// Checksum is the digest declared for the (compressed) metadata file, when it
	// used a supported algorithm.
	Checksum expectedChecksum
	HasSum   bool
}

type rawRepoMD struct {
	XMLName  xml.Name      `xml:"repomd"`
	Revision string        `xml:"revision"`
	Data     []rawRepoData `xml:"data"`
}

type rawRepoData struct {
	Type     string `xml:"type,attr"`
	Checksum struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"checksum"`
	Location struct {
		Href string `xml:"href,attr"`
	} `xml:"location"`
}

// ParseRepoMD decodes and validates a repomd.xml document. A document that is not
// well-formed XML, or that carries no <data> entry with a usable location, is an
// error so the backend fails closed rather than treating garbage as an empty
// manifest.
func ParseRepoMD(data []byte) (*RepoMD, error) {
	if len(data) > maxRepomdBytes {
		return nil, fmt.Errorf("yum: repomd.xml exceeds %d bytes", maxRepomdBytes)
	}
	var raw rawRepoMD
	if err := xml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("yum: parsing repomd.xml: %w", err)
	}
	out := &RepoMD{Revision: strings.TrimSpace(raw.Revision)}
	for _, d := range raw.Data {
		href := strings.TrimLeft(strings.TrimSpace(d.Location.Href), "/")
		if href == "" || strings.Contains(href, "..") {
			continue
		}
		entry := RepoData{Type: strings.TrimSpace(d.Type), Location: href}
		if c, ok := parseChecksum(d.Checksum.Type, d.Checksum.Value); ok {
			entry.Checksum = c
			entry.HasSum = true
		}
		out.Data = append(out.Data, entry)
	}
	if len(out.Data) == 0 {
		return nil, fmt.Errorf("yum: repomd.xml carries no usable data entries")
	}
	return out, nil
}

// FindByLocation returns the data entry whose location matches a
// repository-root-relative repodata path.
func (r *RepoMD) FindByLocation(repodataPath string) (RepoData, bool) {
	key := strings.TrimLeft(repodataPath, "/")
	for _, d := range r.Data {
		if d.Location == key {
			return d, true
		}
	}
	return RepoData{}, false
}

// PrimaryLocation returns the location href of the primary.xml metadata file.
func (r *RepoMD) PrimaryLocation() (string, bool) {
	for _, d := range r.Data {
		if d.Type == "primary" {
			return d.Location, true
		}
	}
	return "", false
}
