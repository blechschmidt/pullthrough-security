package locate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// This file holds the locators that read a registry index through the proxy
// before they can name an artifact.

// fetchDocument reads an index document and fails on anything but 200.
func fetchDocument(ctx context.Context, env Env, up Upstream, p, accept string) (Document, error) {
	if env.Fetch == nil {
		return Document{}, unsupported("locating this dependency needs its registry index, which cannot be read here")
	}
	doc, err := env.Fetch.FetchDocument(ctx, up.Name, p, accept)
	if err != nil {
		return Document{}, fmt.Errorf("locate: reading %s through upstream %q: %w", p, up.Name, err)
	}
	if doc.Status != http.StatusOK {
		return doc, fmt.Errorf("locate: reading %s through upstream %q: status %d", p, up.Name, doc.Status)
	}
	return doc, nil
}

// --- pip ----------------------------------------------------------------------

// pipFile is one distribution file a simple page lists.
type pipFile struct {
	Filename string
	URL      string
	SHA256   string
}

// pipNormalize is PEP 503 name normalization.
var pipSeparators = regexp.MustCompile(`[-_.]+`)

func pipNormalize(name string) string {
	return pipSeparators.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}

// pip: a distribution file is "/files/<scheme>/<host>/<path>" (pkgmgr pip.go),
// known only from the project's simple page — whose file URLs the backend
// rewrites to that form. Which files: those the lock file hashes (by file name,
// or by digest when it lists hashes without names, as pip's --hash does); with
// no hashes, every file of the version, pinned as served.
func locatePip(ctx context.Context, env Env, dep lockfiles.Dependency, up Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	name := pipNormalize(dep.Name)
	page := "/simple/" + segment(name) + "/"
	doc, err := fetchDocument(ctx, env, up, page, "application/vnd.pypi.simple.v1+json, text/html;q=0.1")
	if err != nil {
		return nil, nil, err
	}
	files, err := parseSimplePage(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("locate: reading the simple page of %s: %w", name, err)
	}

	byName := map[string][]lockfiles.Digest{}
	var anyOf []lockfiles.Digest
	for _, d := range dep.Digests {
		switch {
		case d.Of == "":
			anyOf = append(anyOf, d)
		default:
			byName[d.Of] = append(byName[d.Of], d)
		}
	}

	var arts []Artifact
	var notes []string
	add := func(f pipFile, expect []lockfiles.Digest) {
		a := Artifact{Role: "file", File: f.Filename, Expect: expect}
		if p, ok := pipFilePath(up, page, f.URL); ok {
			a.Path = p
		} else {
			a.Error = "the simple page lists " + f.Filename + " at a location the upstream does not serve"
		}
		arts = append(arts, a)
	}

	switch {
	case len(byName) > 0:
		listed := map[string]pipFile{}
		for _, f := range files {
			listed[f.Filename] = f
		}
		names := make([]string, 0, len(byName))
		for n := range byName {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			f, ok := listed[n]
			if !ok {
				arts = append(arts, Artifact{Role: "file", File: n, Expect: byName[n],
					Error: "the lock file hashes " + n + ", which the project's simple page does not list"})
				continue
			}
			add(f, byName[n])
		}
	case len(anyOf) > 0:
		wanted := map[string]bool{}
		for _, d := range anyOf {
			if d.Algorithm == "sha256" {
				wanted[strings.ToLower(d.Value)] = true
			}
		}
		for _, f := range files {
			if f.SHA256 != "" && wanted[f.SHA256] {
				add(f, anyOf)
			}
		}
		if len(arts) == 0 {
			return nil, nil, fmt.Errorf("locate: no file of %s on its simple page has a hash the lock file lists", name)
		}
		notes = append(notes, fmt.Sprintf("the lock file lists hashes without file names; %d file(s) of the simple page carry one of them", len(arts)))
	default:
		for _, f := range files {
			if v, ok := pipFileVersion(name, f.Filename); ok && pipSameVersion(v, dep.Version) {
				add(f, nil)
			}
		}
		if len(arts) == 0 {
			return nil, nil, fmt.Errorf("locate: the simple page of %s lists no file of version %s", name, dep.Version)
		}
		notes = append(notes, "the lock file records no hashes: every file of the version is pinned as served (trust on first use)")
	}
	return arts, notes, nil
}

// pipFilePath maps a file URL of a simple page to the backend path: the
// rewritten "/v1/<upstream>/files/…" form, a URL beneath the upstream, or a
// URL relative to the page.
func pipFilePath(up Upstream, page, raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	u.Fragment = ""
	if u.Scheme == "" && u.Host == "" && !strings.HasPrefix(u.Path, "/v1/") {
		// Relative to the page.
		base := &url.URL{Path: page}
		ref := base.ResolveReference(&url.URL{Path: u.Path, RawPath: u.RawPath})
		return ref.EscapedPath(), true
	}
	return proxyPath(up, u.String())
}

// parseSimplePage reads a PEP 691 JSON or PEP 503 HTML simple page.
func parseSimplePage(doc Document) ([]pipFile, error) {
	ct := strings.ToLower(doc.ContentType)
	body := doc.Body
	if strings.Contains(ct, "json") || (len(body) > 0 && body[0] == '{') {
		var page struct {
			Files []struct {
				Filename string            `json:"filename"`
				URL      string            `json:"url"`
				Hashes   map[string]string `json:"hashes"`
			} `json:"files"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, err
		}
		out := make([]pipFile, 0, len(page.Files))
		for _, f := range page.Files {
			if f.Filename == "" || f.URL == "" {
				continue
			}
			out = append(out, pipFile{Filename: f.Filename, URL: f.URL, SHA256: strings.ToLower(f.Hashes["sha256"])})
		}
		return out, nil
	}
	return parseSimpleHTML(string(body)), nil
}

var (
	anchorRE = regexp.MustCompile(`(?is)<a\s[^>]*?href\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>(.*?)</a>`)
	tagRE    = regexp.MustCompile(`<[^>]*>`)
)

// parseSimpleHTML reads the anchors of a PEP 503 page. A file's sha256 is the
// URL fragment "#sha256=<hex>".
func parseSimpleHTML(page string) []pipFile {
	var out []pipFile
	for _, m := range anchorRE.FindAllStringSubmatch(page, -1) {
		href := m[2] + m[3] + m[4]
		href = htmlUnescape(href)
		text := strings.TrimSpace(htmlUnescape(tagRE.ReplaceAllString(m[5], "")))
		u, err := url.Parse(href)
		if err != nil {
			continue
		}
		name := text
		if name == "" {
			name = path.Base(u.Path)
		}
		f := pipFile{Filename: name, URL: href}
		if algo, v, ok := strings.Cut(u.Fragment, "="); ok && strings.EqualFold(algo, "sha256") {
			f.SHA256 = strings.ToLower(v)
		}
		out = append(out, f)
	}
	return out
}

func htmlUnescape(s string) string {
	r := strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&#39;", "'", "&#x27;", "'")
	return r.Replace(s)
}

// pipFileVersion extracts the version from a wheel or sdist file name of the
// project.
func pipFileVersion(project, file string) (string, bool) {
	switch {
	case strings.HasSuffix(file, ".whl"):
		parts := strings.Split(strings.TrimSuffix(file, ".whl"), "-")
		if len(parts) < 5 || pipNormalize(parts[0]) != project {
			return "", false
		}
		return parts[1], true
	default:
		for _, ext := range []string{".tar.gz", ".zip", ".tar.bz2", ".tgz", ".tar.xz"} {
			if !strings.HasSuffix(file, ext) {
				continue
			}
			stem := strings.TrimSuffix(file, ext)
			for i := strings.Index(stem, "-"); i >= 0; {
				if pipNormalize(stem[:i]) == project {
					return stem[i+1:], true
				}
				j := strings.Index(stem[i+1:], "-")
				if j < 0 {
					break
				}
				i += j + 1
			}
		}
	}
	return "", false
}

// pipSameVersion compares versions the way a file name and a lock file may spell
// them differently: case, a leading "v", "_" for "-", trailing ".0" release
// segments.
func pipSameVersion(a, b string) bool {
	return pipCanonicalVersion(a) == pipCanonicalVersion(b)
}

func pipCanonicalVersion(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "v")
	v = strings.ReplaceAll(v, "_", "-")
	rel := v
	rest := ""
	for i, r := range v {
		if (r < '0' || r > '9') && r != '.' {
			rel, rest = v[:i], v[i:]
			break
		}
	}
	for strings.HasSuffix(rel, ".0") {
		rel = strings.TrimSuffix(rel, ".0")
	}
	return rel + rest
}

// --- NuGet -------------------------------------------------------------------

// nuget: "<PackageBaseAddress>/<id>/<version>/<id>.<version>.nupkg", lower-case
// (any ".nupkg" path is the payload, pkgmgr nuget.go). The base address comes
// from the feed's service index, whose URLs the backend rewrites to the proxy.
// packages.lock.json's contentHash leaves a signed package's signature out, so
// it is not a hash of the bytes served.
func locateNuGet(ctx context.Context, env Env, dep lockfiles.Dependency, up Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	base := ""
	if doc, err := fetchDocument(ctx, env, up, "/v3/index.json", "application/json"); err == nil {
		var idx struct {
			Resources []struct {
				ID   string `json:"@id"`
				Type any    `json:"@type"`
			} `json:"resources"`
		}
		if json.Unmarshal(doc.Body, &idx) == nil {
			for _, r := range idx.Resources {
				if !nugetTypeIs(r.Type, "PackageBaseAddress/3.0.0") {
					continue
				}
				if p, ok := proxyPath(up, r.ID); ok {
					base = strings.TrimRight(p, "/")
					break
				}
			}
		}
	} else if IsUnsupported(err) {
		return nil, nil, err
	}
	if base == "" {
		return nil, nil, fmt.Errorf("locate: the service index of upstream %q names no package base address this proxy serves", up.Name)
	}
	id := strings.ToLower(dep.Name)
	ver := strings.ToLower(dep.Version)
	if i := strings.IndexByte(ver, '+'); i >= 0 {
		ver = ver[:i] // build metadata is not part of a NuGet package path
	}
	file := id + "." + ver + ".nupkg"
	p := base + "/" + segment(id) + "/" + segment(ver) + "/" + segment(file)
	return []Artifact{{Path: p, Role: "package", File: file, Expect: dep.Digests}}, nil, nil
}

// nugetTypeIs matches a service-index resource type, which is a string or a
// list of strings.
func nugetTypeIs(t any, want string) bool {
	switch v := t.(type) {
	case string:
		return v == want
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// --- Maven -------------------------------------------------------------------

var (
	pomParentRE    = regexp.MustCompile(`(?is)<parent>.*?</parent>`)
	pomCommentRE   = regexp.MustCompile(`(?s)<!--.*?-->`)
	pomPackagingRE = regexp.MustCompile(`(?is)<packaging>\s*([^<\s]+)\s*</packaging>`)
)

// mavenExtensions maps a POM packaging to the extension of its main artifact.
var mavenExtensions = map[string]string{
	"jar": "jar", "bundle": "jar", "maven-plugin": "jar", "ejb": "jar", "eclipse-plugin": "jar",
	"hk2-jar": "jar", "orbit": "jar", "test-jar": "jar", "java-source": "jar", "javadoc": "jar",
	"war": "war", "ear": "ear", "rar": "rar", "aar": "aar", "nar": "nar", "zip": "zip",
}

// maven: "/<group path>/<artifact>/<version>/<artifact>-<version>.<ext>" (maven
// path.go). The POM is fetched first: it is part of what a build downloads, and
// its packaging names the main artifact's extension ("pom" has none). The
// backend checks every file against the repository's checksum sidecars.
func locateMaven(ctx context.Context, env Env, dep lockfiles.Dependency, up Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	group, artifact, ok := strings.Cut(dep.Name, ":")
	if !ok || group == "" || artifact == "" || strings.Contains(artifact, ":") {
		return nil, nil, fmt.Errorf("locate: %q is not a Maven coordinate (group:artifact)", dep.Name)
	}
	dir := "/" + strings.ReplaceAll(group, ".", "/") + "/" + segment(artifact) + "/" + segment(dep.Version) + "/"
	stem := artifact + "-" + dep.Version
	pomPath := dir + segment(stem+".pom")
	arts := []Artifact{{Path: pomPath, Role: "pom", File: stem + ".pom"}}

	doc, err := fetchDocument(ctx, env, up, pomPath, "")
	if err != nil {
		if IsUnsupported(err) {
			return nil, nil, err
		}
		return nil, nil, err
	}
	packaging := "jar"
	body := pomCommentRE.ReplaceAllString(pomParentRE.ReplaceAllString(string(doc.Body), ""), "")
	if m := pomPackagingRE.FindStringSubmatch(body); m != nil {
		packaging = strings.ToLower(m[1])
	}
	var notes []string
	if packaging == "pom" {
		return arts, []string{"packaging \"pom\": the POM is the whole artifact"}, nil
	}
	ext, known := mavenExtensions[packaging]
	if !known {
		ext = "jar"
		notes = append(notes, fmt.Sprintf("packaging %q: assumed a .jar main artifact", packaging))
	}
	arts = append(arts, Artifact{Path: dir + segment(stem+"."+ext), Role: "package", File: stem + "." + ext, Optional: !known})
	return arts, append(notes, "the backend verifies each file against the repository's checksum files"), nil
}

// --- Docker / OCI ------------------------------------------------------------

// ociAccept asks for an image index or manifest list first.
const ociAccept = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

// ociManifest is the part of an image index or manifest read here.
type ociManifest struct {
	MediaType string `json:"mediaType"`
	Manifests []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Platform  *struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
			Variant      string `json:"variant"`
		} `json:"platform"`
	} `json:"manifests"`
	Config *struct {
		Digest string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		MediaType string   `json:"mediaType"`
		Digest    string   `json:"digest"`
		URLs      []string `json:"urls"`
	} `json:"layers"`
}

var ociDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// sha256Expect turns "sha256:<hex>" into the digest the bytes must have.
func sha256Expect(d string) []lockfiles.Digest {
	return []lockfiles.Digest{{Algorithm: "sha256", Value: strings.TrimPrefix(d, "sha256:")}}
}

// docker: "/v2/<repository>/manifests/<digest>" then "/v2/<repository>/blobs/
// <digest>" (docker reference.go). An image index is walked to the manifests
// of the selected platforms (all, unless platforms are configured), and each
// manifest to its config and layers. Every object is addressed by its digest,
// which the backend checks.
func locateDocker(ctx context.Context, env Env, dep lockfiles.Dependency, up Upstream) ([]Artifact, []string, error) {
	if err := requireCoordinate(dep); err != nil {
		return nil, nil, err
	}
	if !ociDigestRE.MatchString(dep.Version) {
		return nil, nil, unsupported("image %s is referenced by tag, not digest: there is no exact version to pin", dep.Name)
	}
	repo := strings.Trim(dep.Name, "/")
	manifestPath := func(d string) string { return "/v2/" + repo + "/manifests/" + d }
	blobPath := func(d string) string { return "/v2/" + repo + "/blobs/" + d }

	top, err := fetchDocument(ctx, env, up, manifestPath(dep.Version), ociAccept)
	if err != nil {
		return nil, nil, err
	}
	var m ociManifest
	if err := json.Unmarshal(top.Body, &m); err != nil {
		return nil, nil, fmt.Errorf("locate: reading manifest %s of %s: %w", dep.Version, repo, err)
	}
	arts := []Artifact{}
	var notes []string
	seen := map[string]bool{}
	addBlob := func(role, d string) {
		if !ociDigestRE.MatchString(d) || seen[d] {
			return
		}
		seen[d] = true
		arts = append(arts, Artifact{Path: blobPath(d), Role: role, File: d, Expect: sha256Expect(d)})
	}
	addImage := func(im ociManifest) {
		if im.Config != nil {
			addBlob("config", im.Config.Digest)
		}
		for _, l := range im.Layers {
			if len(l.URLs) > 0 || strings.Contains(l.MediaType, "foreign") {
				notes = append(notes, "a non-distributable (foreign) layer is not fetched: "+l.Digest)
				continue
			}
			addBlob("layer", l.Digest)
		}
	}

	if len(m.Manifests) == 0 {
		arts = append(arts, Artifact{Path: manifestPath(dep.Version), Role: "manifest", File: dep.Version, Accept: ociAccept, Expect: sha256Expect(dep.Version)})
		addImage(m)
		return arts, notes, nil
	}
	arts = append(arts, Artifact{Path: manifestPath(dep.Version), Role: "index", File: dep.Version, Accept: ociAccept, Expect: sha256Expect(dep.Version)})
	selected := 0
	for _, child := range m.Manifests {
		if !ociDigestRE.MatchString(child.Digest) {
			continue
		}
		if child.Platform == nil || child.Platform.OS == "unknown" {
			continue // an attestation or other non-image manifest
		}
		if len(env.Platforms) > 0 && !platformSelected(env.Platforms, child.Platform.OS, child.Platform.Architecture, child.Platform.Variant) {
			continue
		}
		doc, err := fetchDocument(ctx, env, up, manifestPath(child.Digest), ociAccept)
		if err != nil {
			arts = append(arts, Artifact{Path: manifestPath(child.Digest), Role: "manifest", File: child.Digest, Accept: ociAccept,
				Error: err.Error()})
			continue
		}
		var cm ociManifest
		if err := json.Unmarshal(doc.Body, &cm); err != nil {
			return nil, nil, fmt.Errorf("locate: reading manifest %s of %s: %w", child.Digest, repo, err)
		}
		selected++
		arts = append(arts, Artifact{Path: manifestPath(child.Digest), Role: "manifest", File: child.Digest, Accept: ociAccept, Expect: sha256Expect(child.Digest)})
		addImage(cm)
		if len(arts) > env.maxArtifacts() {
			break
		}
	}
	if selected == 0 {
		return nil, nil, fmt.Errorf("locate: image index %s of %s lists no manifest of a selected platform", dep.Version, repo)
	}
	notes = append(notes, fmt.Sprintf("image index: %d platform manifest(s) pinned", selected))
	return arts, notes, nil
}

func platformSelected(platforms []Platform, os, arch, variant string) bool {
	for _, p := range platforms {
		if p.OS == strings.ToLower(os) && p.Arch == strings.ToLower(arch) && (p.Variant == "" || p.Variant == strings.ToLower(variant)) {
			return true
		}
	}
	return false
}
