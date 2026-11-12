//go:build integration
// +build integration

package pkgscan

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"html"
	"path"
	"sort"
	"strings"
)

// YUM / DNF: a repository is rooted at repodata/repomd.xml, which names each
// metadata file with its checksum and is signed by a detached, ASCII-armored
// signature (repodata/repomd.xml.asc, checked by a client with repo_gpgcheck).
// The client reads the primary package list repomd.xml points at
// (repodata/<sha256>-primary.xml.gz) and finds there each package's location —
// a path relative to the repository root, so it resolves against the proxy
// with no rewriting — and checksum, then downloads the .rpm. The backend
// follows the same chain: it verifies repomd.xml against the pinned key,
// primary.xml against repomd.xml, and the .rpm against primary.xml.
//
// An .rpm is a 96-byte lead, a signature header (digests and sizes of what
// follows), the main header (the package's identity, its file table, its
// scriptlets — this fixture has none) and the payload: a compressed cpio
// archive of the installed files, each named "./<install path>". The scanner
// lists the payload's files under their install paths without the leading
// "./", next to entries it composes from the header (RPM/header.txt).
//
// The proxy reports the name and version it reads from the file name,
// "<name>-<version>-<release>.<arch>.rpm" (the release is not part of it).

func init() {
	yum := eco{
		ID: "yum", Type: "yum", Title: "YUM / DNF (RPM)",
		Format:   ".rpm (lead, signature header, header, gzip cpio payload)",
		Settings: osRepoSettings,
		Registry: yumRegistry,
	}
	register(yum)
	register(alias(yum, "rpm"))
}

// yumRelease is the release every fixture package is built as.
const yumRelease = "1"

func yumRegistry(env stubEnv) (*registry, error) {
	reg := newRegistry()
	type pkg struct {
		spec     pkgSpec
		location string // relative to the repository root, as primary.xml names it
		rpm      rpmBuilt
	}
	var pkgs []pkg
	var primary strings.Builder
	fmt.Fprintf(&primary, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"+
		"<metadata xmlns=\"http://linux.duke.edu/metadata/common\" xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\" packages=\"%d\">\n", len(env.Specs))
	for _, s := range env.Specs {
		name := s.Name()
		meta := rpmMeta{
			Name: name, Version: fixtureVersion, Release: yumRelease,
			Summary:     "pullthrough llm-package-scan e2e fixture",
			Description: "A package the end-to-end suite of the LLM package-content scan pulls through the proxy.",
			Files: []member{
				{Name: "/usr/share/doc/" + name + "/README", Data: "pullthrough pkgscan e2e fixture package\n"},
				{Name: "/usr/share/" + name + "/" + markerFile, Data: s.Text("")},
			},
		}
		p := pkg{spec: s, rpm: rpmPackage(meta)}
		p.location = "Packages/" + name[:1] + "/" + meta.nevra() + ".rpm"
		reg.mux.File("/"+p.location, p.rpm.Data, "application/x-rpm")
		pkgs = append(pkgs, p)

		// The package's entry, in the subset of createrepo_c's layout that a client
		// resolves and downloads by.
		fmt.Fprintf(&primary, `<package type="rpm">
  <name>%s</name>
  <arch>noarch</arch>
  <version epoch="0" ver="%s" rel="%s"/>
  <checksum type="sha256" pkgid="YES">%s</checksum>
  <summary>%s</summary>
  <description>%s</description>
  <packager></packager>
  <url></url>
  <time file="%d" build="%d"/>
  <size package="%d" installed="%d" archive="%d"/>
  <location href="%s"/>
  <format>
    <rpm:license>MIT</rpm:license>
    <rpm:vendor></rpm:vendor>
    <rpm:group>Unspecified</rpm:group>
    <rpm:buildhost>%s</rpm:buildhost>
    <rpm:sourcerpm>%s</rpm:sourcerpm>
    <rpm:header-range start="%d" end="%d"/>
    <rpm:provides>
      <rpm:entry name="%s" flags="EQ" epoch="0" ver="%s" rel="%s"/>
    </rpm:provides>
  </format>
</package>
`, name, meta.Version, meta.Release, hexOf(p.rpm.Data), html.EscapeString(meta.Summary), html.EscapeString(meta.Description),
			stubModTime.Unix(), stubModTime.Unix(), len(p.rpm.Data), p.rpm.InstalledSize, p.rpm.ArchiveSize, p.location,
			rpmBuildHost, meta.sourceRPM(), p.rpm.HeaderStart, p.rpm.HeaderEnd, name, meta.Version, meta.Release)
	}
	primary.WriteString("</metadata>\n")

	primaryXML := []byte(primary.String())
	primaryGz := osRepoGzipStored(primaryXML)
	primaryLocation := "repodata/" + hexOf(primaryGz) + "-primary.xml.gz"
	reg.mux.File("/"+primaryLocation, primaryGz, "application/gzip")

	repomd := []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo" xmlns:rpm="http://linux.duke.edu/metadata/rpm">
  <revision>%d</revision>
  <data type="primary">
    <checksum type="sha256">%s</checksum>
    <open-checksum type="sha256">%s</open-checksum>
    <location href="%s"/>
    <timestamp>%d</timestamp>
    <size>%d</size>
    <open-size>%d</open-size>
  </data>
</repomd>
`, stubModTime.Unix(), hexOf(primaryGz), hexOf(primaryXML), primaryLocation, stubModTime.Unix(), len(primaryGz), len(primaryXML)))
	repomdSig, err := osRepoDetachSign(repomd)
	if err != nil {
		return nil, fmt.Errorf("signing repomd.xml: %w", err)
	}
	reg.mux.File("/repodata/repomd.xml", repomd, "text/xml")
	reg.mux.File("/repodata/repomd.xml.asc", repomdSig, "text/plain")

	for _, p := range pkgs {
		reg.add(p.spec.Variant, &pkgPull{
			Name: p.spec.Name(), Version: fixtureVersion,
			// What `dnf install <name>` asks the repository for (repo_gpgcheck=1).
			Preamble: []step{
				// The manifest: where the package list is, and its digest.
				{Path: "/repodata/repomd.xml", Contains: []string{
					`<location href="` + primaryLocation + `"/>`,
					`<checksum type="sha256">` + hexOf(primaryGz) + `</checksum>`,
				}},
				{Path: "/repodata/repomd.xml.asc", Contains: []string{"-----BEGIN PGP SIGNATURE-----"}},
				// The package list: where the package is, relative to the repository
				// root the client was pointed at (the proxy), and its digest.
				{Path: "/" + primaryLocation, Contains: []string{
					`<location href="` + p.location + `"/>`,
					`<checksum type="sha256" pkgid="YES">` + hexOf(p.rpm.Data) + `</checksum>`,
				}},
			},
			Payload: step{Path: "/" + p.location},
			Body:    p.rpm.Data,
			Marker:  "usr/share/" + p.spec.Name() + "/" + markerFile,
		})
	}
	return reg, nil
}

// ---------------------------------------------------------------------------
// An RPM writer
// ---------------------------------------------------------------------------

// rpmBuildHost is the build host the fixture packages name.
const rpmBuildHost = "pkgscan-e2e.invalid"

// rpmMeta describes a noarch binary package to build.
type rpmMeta struct {
	Name, Version, Release string
	Summary, Description   string
	// Files are the installed files, by absolute install path.
	Files []member
}

// nevra is the package's "<name>-<version>-<release>.<arch>" (no epoch).
func (m rpmMeta) nevra() string { return m.Name + "-" + m.Version + "-" + m.Release + ".noarch" }

// sourceRPM is the name of the source package the binary one claims to come from.
func (m rpmMeta) sourceRPM() string { return m.Name + "-" + m.Version + "-" + m.Release + ".src.rpm" }

// rpmBuilt is a written package, with the figures a repository's metadata
// records about it.
type rpmBuilt struct {
	Data []byte
	// HeaderStart and HeaderEnd are the byte range of the main header in Data.
	HeaderStart, HeaderEnd int
	// InstalledSize is the size of the installed files; ArchiveSize that of the
	// uncompressed payload.
	InstalledSize, ArchiveSize int
}

// Header data types (rpm's rpmTagType).
const (
	rpmTypeInt16       = 3
	rpmTypeInt32       = 4
	rpmTypeString      = 6
	rpmTypeBin         = 7
	rpmTypeStringArray = 8
	rpmTypeI18NString  = 9
)

// Header tags. A signature header has tags of its own, numbered apart from
// the main header's.
const (
	rpmTagHeaderSignatures = 62 // region tag of a signature header
	rpmTagHeaderImmutable  = 63 // region tag of a main header
	rpmTagHeaderI18NTable  = 100

	rpmSigTagSHA1        = 269
	rpmSigTagSHA256      = 273
	rpmSigTagSize        = 1000
	rpmSigTagMD5         = 1004
	rpmSigTagPayloadSize = 1007

	rpmTagName              = 1000
	rpmTagVersion           = 1001
	rpmTagRelease           = 1002
	rpmTagSummary           = 1004
	rpmTagDescription       = 1005
	rpmTagBuildTime         = 1006
	rpmTagBuildHost         = 1007
	rpmTagSize              = 1009
	rpmTagLicense           = 1014
	rpmTagGroup             = 1016
	rpmTagOS                = 1021
	rpmTagArch              = 1022
	rpmTagFileSizes         = 1028
	rpmTagFileModes         = 1030
	rpmTagFileRdevs         = 1033
	rpmTagFileMtimes        = 1034
	rpmTagFileDigests       = 1035
	rpmTagFileLinkTos       = 1036
	rpmTagFileFlags         = 1037
	rpmTagFileUserName      = 1039
	rpmTagFileGroupName     = 1040
	rpmTagSourceRPM         = 1044
	rpmTagFileVerifyFlags   = 1045
	rpmTagProvideName       = 1047
	rpmTagRequireFlags      = 1048
	rpmTagRequireName       = 1049
	rpmTagRequireVersion    = 1050
	rpmTagFileDevices       = 1095
	rpmTagFileInodes        = 1096
	rpmTagFileLangs         = 1097
	rpmTagProvideFlags      = 1112
	rpmTagProvideVersion    = 1113
	rpmTagDirIndexes        = 1116
	rpmTagBasenames         = 1117
	rpmTagDirNames          = 1118
	rpmTagPayloadFormat     = 1124
	rpmTagPayloadCompressor = 1125
	rpmTagPayloadFlags      = 1126
	rpmTagFileDigestAlgo    = 5011
	rpmTagEncoding          = 5062
	rpmTagPayloadDigest     = 5092
	rpmTagPayloadDigestAlgo = 5093
	rpmTagPayloadDigestAlt  = 5097
)

// Dependency flags (rpmsenseFlags) and the digest algorithm (PGPHASHALGO_SHA256).
const (
	rpmSenseLess   = 1 << 1
	rpmSenseEqual  = 1 << 3
	rpmSenseRPMLib = 1 << 24
	rpmHashSHA256  = 8
)

// rpmHeader collects the entries of a header and writes it in the on-disk
// format: an intro (magic, entry count, data size), an index of 16-byte
// entries (tag, type, offset into the data, count), then the data, each value
// aligned to its type's size.
type rpmHeader struct{ entries []rpmEntry }

type rpmEntry struct {
	tag, typ, count uint32
	data            []byte
}

func (h *rpmHeader) add(tag, typ uint32, count int, data []byte) {
	h.entries = append(h.entries, rpmEntry{tag: tag, typ: typ, count: uint32(count), data: data})
}

func (h *rpmHeader) str(tag uint32, s string) { h.add(tag, rpmTypeString, 1, append([]byte(s), 0)) }

// i18n adds a translatable string; its one value is for the one locale of the
// header's I18N table, "C".
func (h *rpmHeader) i18n(tag uint32, s string) {
	h.add(tag, rpmTypeI18NString, 1, append([]byte(s), 0))
}

func (h *rpmHeader) strs(tag uint32, ss ...string) {
	var b []byte
	for _, s := range ss {
		b = append(append(b, s...), 0)
	}
	h.add(tag, rpmTypeStringArray, len(ss), b)
}

func (h *rpmHeader) int32s(tag uint32, vs ...uint32) {
	b := make([]byte, 4*len(vs))
	for i, v := range vs {
		binary.BigEndian.PutUint32(b[4*i:], v)
	}
	h.add(tag, rpmTypeInt32, len(vs), b)
}

func (h *rpmHeader) int16s(tag uint32, vs ...uint16) {
	b := make([]byte, 2*len(vs))
	for i, v := range vs {
		binary.BigEndian.PutUint16(b[2*i:], v)
	}
	h.add(tag, rpmTypeInt16, len(vs), b)
}

func (h *rpmHeader) bin(tag uint32, b []byte) { h.add(tag, rpmTypeBin, len(b), b) }

// encode renders the header as one region, as rpm writes every header: the
// entry of the region tag comes first in the index and points at a 16-byte
// trailer at the end of the data — itself an index entry, of the region tag,
// whose (negative) offset spans the whole index.
func (h *rpmHeader) encode(region uint32) []byte {
	entries := append([]rpmEntry(nil), h.entries...)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].tag < entries[j].tag })
	il := len(entries) + 1

	var data bytes.Buffer
	offsets := make([]int, len(entries))
	for i, e := range entries {
		for align := rpmAlignment(e.typ); data.Len()%align != 0; {
			data.WriteByte(0)
		}
		offsets[i] = data.Len()
		data.Write(e.data)
	}
	trailerAt := data.Len()
	entry := func(tag, typ uint32, offset int32, count uint32) []byte {
		b := make([]byte, 16)
		binary.BigEndian.PutUint32(b[0:], tag)
		binary.BigEndian.PutUint32(b[4:], typ)
		binary.BigEndian.PutUint32(b[8:], uint32(offset))
		binary.BigEndian.PutUint32(b[12:], count)
		return b
	}
	data.Write(entry(region, rpmTypeBin, -int32(il*16), 16))

	var out bytes.Buffer
	out.Write([]byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0})
	_ = binary.Write(&out, binary.BigEndian, uint32(il))
	_ = binary.Write(&out, binary.BigEndian, uint32(data.Len()))
	out.Write(entry(region, rpmTypeBin, int32(trailerAt), 16))
	for i, e := range entries {
		out.Write(entry(e.tag, e.typ, int32(offsets[i]), e.count))
	}
	out.Write(data.Bytes())
	return out.Bytes()
}

// rpmAlignment is the boundary a value of the given type is aligned to in a
// header's data: its size for an integer, none for strings and binary data.
func rpmAlignment(typ uint32) int {
	switch typ {
	case rpmTypeInt16:
		return 2
	case rpmTypeInt32:
		return 4
	}
	return 1
}

// rpmPackage writes a noarch binary package in the RPM v4 format, gzip
// payload, laid out as rpmbuild lays one out:
//
//	lead              96 bytes: magic, format 3.0, binary, the NEVR, header-style signature
//	signature header  SHA-1 and SHA-256 of the main header; size and MD5 of header and
//	                  payload; the uncompressed payload's size — padded to 8 bytes
//	main header       identity, file table (directory/basename form, with sizes,
//	                  modes, SHA-256 digests, owners), dependencies, payload description
//	payload           gzip-compressed cpio (newc) of "./<install path>" members, in
//	                  the order of the header's file table
func rpmPackage(m rpmMeta) rpmBuilt {
	files := append([]member(nil), m.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	mtime := uint32(stubModTime.Unix())

	cpio := rpmCpio(files, mtime)
	payload := gzipOf(cpio)

	h := &rpmHeader{}
	h.strs(rpmTagHeaderI18NTable, "C")
	h.str(rpmTagName, m.Name)
	h.str(rpmTagVersion, m.Version)
	h.str(rpmTagRelease, m.Release)
	h.i18n(rpmTagSummary, m.Summary)
	h.i18n(rpmTagDescription, m.Description)
	h.int32s(rpmTagBuildTime, mtime)
	h.str(rpmTagBuildHost, rpmBuildHost)
	h.str(rpmTagLicense, "MIT")
	h.i18n(rpmTagGroup, "Unspecified")
	h.str(rpmTagOS, "linux")
	h.str(rpmTagArch, "noarch")
	h.str(rpmTagSourceRPM, m.sourceRPM())

	// The file table, in the compressed directory/basename form.
	var (
		sizes, mtimes, flags, verify, devices, inodes, dirIndexes []uint32
		modes, rdevs                                              []uint16
		digests, linkTos, users, groups, langs, basenames, dirs   []string
		installed                                                 int
	)
	dirIndex := map[string]int{}
	for i, f := range files {
		mode := f.Mode
		if mode == 0 {
			mode = 0o644
		}
		dir, base := path.Split(f.Name)
		if _, ok := dirIndex[dir]; !ok {
			dirIndex[dir] = len(dirs)
			dirs = append(dirs, dir)
		}
		sum := sha256.Sum256([]byte(f.Data))
		sizes = append(sizes, uint32(len(f.Data)))
		modes = append(modes, uint16(0o100000|mode))
		rdevs = append(rdevs, 0)
		mtimes = append(mtimes, mtime)
		digests = append(digests, hex.EncodeToString(sum[:]))
		linkTos = append(linkTos, "")
		flags = append(flags, 0)
		users = append(users, "root")
		groups = append(groups, "root")
		verify = append(verify, 0xffffffff)
		devices = append(devices, 1)
		inodes = append(inodes, uint32(i+1))
		langs = append(langs, "")
		dirIndexes = append(dirIndexes, uint32(dirIndex[dir]))
		basenames = append(basenames, base)
		installed += len(f.Data)
	}
	h.int32s(rpmTagSize, uint32(installed))
	h.int32s(rpmTagFileSizes, sizes...)
	h.int16s(rpmTagFileModes, modes...)
	h.int16s(rpmTagFileRdevs, rdevs...)
	h.int32s(rpmTagFileMtimes, mtimes...)
	h.strs(rpmTagFileDigests, digests...)
	h.strs(rpmTagFileLinkTos, linkTos...)
	h.int32s(rpmTagFileFlags, flags...)
	h.strs(rpmTagFileUserName, users...)
	h.strs(rpmTagFileGroupName, groups...)
	h.int32s(rpmTagFileVerifyFlags, verify...)
	h.int32s(rpmTagFileDevices, devices...)
	h.int32s(rpmTagFileInodes, inodes...)
	h.strs(rpmTagFileLangs, langs...)
	h.int32s(rpmTagDirIndexes, dirIndexes...)
	h.strs(rpmTagBasenames, basenames...)
	h.strs(rpmTagDirNames, dirs...)
	h.int32s(rpmTagFileDigestAlgo, rpmHashSHA256)

	// What the package provides, and the rpm features reading it requires: the
	// file table's form, SHA-256 file digests, payload names with a "./" prefix.
	h.strs(rpmTagProvideName, m.Name)
	h.int32s(rpmTagProvideFlags, rpmSenseEqual)
	h.strs(rpmTagProvideVersion, m.Version+"-"+m.Release)
	rpmlib := uint32(rpmSenseRPMLib | rpmSenseLess | rpmSenseEqual)
	h.strs(rpmTagRequireName, "rpmlib(CompressedFileNames)", "rpmlib(FileDigests)", "rpmlib(PayloadFilesHavePrefix)")
	h.int32s(rpmTagRequireFlags, rpmlib, rpmlib, rpmlib)
	h.strs(rpmTagRequireVersion, "3.0.4-1", "4.6.0-1", "4.0-1")

	h.str(rpmTagPayloadFormat, "cpio")
	h.str(rpmTagPayloadCompressor, "gzip")
	h.str(rpmTagPayloadFlags, "6") // the compression level: gzipOf's, Go's default
	h.str(rpmTagEncoding, "utf-8")
	h.strs(rpmTagPayloadDigest, hexOf(payload))
	h.int32s(rpmTagPayloadDigestAlgo, rpmHashSHA256)
	h.strs(rpmTagPayloadDigestAlt, hexOf(cpio))
	header := h.encode(rpmTagHeaderImmutable)

	headerSHA1 := sha1.Sum(header)
	whole := md5.New()
	whole.Write(header)
	whole.Write(payload)
	sig := &rpmHeader{}
	sig.str(rpmSigTagSHA1, hex.EncodeToString(headerSHA1[:]))
	sig.str(rpmSigTagSHA256, hexOf(header))
	sig.int32s(rpmSigTagSize, uint32(len(header)+len(payload)))
	sig.bin(rpmSigTagMD5, whole.Sum(nil))
	sig.int32s(rpmSigTagPayloadSize, uint32(len(cpio)))
	signature := sig.encode(rpmTagHeaderSignatures)

	var out bytes.Buffer
	out.Write(rpmLead(m.Name + "-" + m.Version + "-" + m.Release))
	out.Write(signature)
	for out.Len()%8 != 0 {
		out.WriteByte(0) // the signature header is padded to an 8-byte boundary
	}
	start := out.Len()
	out.Write(header)
	end := out.Len()
	out.Write(payload)
	return rpmBuilt{Data: out.Bytes(), HeaderStart: start, HeaderEnd: end, InstalledSize: installed, ArchiveSize: len(cpio)}
}

// rpmLead is the 96-byte lead: magic, format version 3.0, type 0 (binary),
// architecture 0 (rpm reads neither it nor the OS field), the NEVR in a
// NUL-padded 66-byte field, OS 1 (Linux), signature type 5 (a header-style
// signature follows) and 16 reserved bytes.
func rpmLead(nevr string) []byte {
	lead := make([]byte, 96)
	copy(lead, []byte{0xed, 0xab, 0xee, 0xdb, 3, 0})
	copy(lead[10:75], nevr)
	binary.BigEndian.PutUint16(lead[76:], 1)
	binary.BigEndian.PutUint16(lead[78:], 5)
	return lead
}

// rpmCpio writes the payload archive in the "newc" cpio format: per file a
// 110-byte header ("070701" and thirteen 8-digit hex fields: inode, mode, uid,
// gid, link count, mtime, size, device major/minor, rdev major/minor, name
// size, checksum), the NUL-terminated name, both padded to a multiple of four
// bytes, then the data, padded likewise; and a final "TRAILER!!!" member.
func rpmCpio(files []member, mtime uint32) []byte {
	var b bytes.Buffer
	pad := func() {
		for b.Len()%4 != 0 {
			b.WriteByte(0)
		}
	}
	write := func(ino, mode, nlink, modTime uint32, name, data string) {
		fmt.Fprintf(&b, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
			ino, mode, 0, 0, nlink, modTime, len(data), 0, 0, 0, 0, len(name)+1, 0)
		b.WriteString(name)
		b.WriteByte(0)
		pad()
		b.WriteString(data)
		pad()
	}
	for i, f := range files {
		mode := f.Mode
		if mode == 0 {
			mode = 0o644
		}
		write(uint32(i+1), uint32(0o100000|mode), 1, mtime, "."+f.Name, f.Data)
	}
	write(0, 0, 1, 0, "TRAILER!!!", "")
	return b.Bytes()
}
