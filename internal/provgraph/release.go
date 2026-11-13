package provgraph

import (
	"sort"
	"strings"
	"time"
)

// Releases (Task 180): the repository registry tells the graph which tagged
// commits of which repositories ship which package versions. A release is a
// node ("release:<repo>@<commit>") with a shipped-in edge from every version
// its lock files pin, so the graph answers "shipped in release X" for a
// version and "which releases does this CVE reach" for a blast radius.
//
// Release nodes carry their tenant: the graph's other nodes are package facts
// anyone may read, a release names a tenant's repository, so a tenant-bound
// reader is shown its own tenant's releases only (ScopeReleases).

const (
	// NodeRelease is a release: a commit of a tracked repository that a tag
	// points (or pointed) at.
	NodeRelease NodeKind = "release"
	// EdgeShippedIn connects a version to a release whose lock files pin it.
	EdgeShippedIn EdgeKind = "shipped-in"
)

// ReleaseEvent describes one release for ingestion.
type ReleaseEvent struct {
	Repo   string
	Commit string
	Tenant string
	// Tags point at the commit now; State is "current" or "historical".
	Tags  []string
	State string
	// Status is the release's pinning status (pinned, partial, failed).
	Status string
	// Dependencies are the versions the release pins; Statuses their
	// pinning status, by index.
	Dependencies []ArtifactRef
	Statuses     []string
	Time         time.Time
}

func releaseID(repo, commit string) string {
	return "release:" + repo + "@" + strings.ToLower(strings.TrimSpace(commit))
}

// IngestRelease folds a release into the graph. Re-ingesting a release
// updates its node (a release becomes historical when its tag moves away) and
// adds edges for dependencies pinned since.
func (s *Service) IngestRelease(ev ReleaseEvent) {
	if strings.TrimSpace(ev.Repo) == "" || strings.TrimSpace(ev.Commit) == "" {
		return
	}
	now := ev.Time
	if now.IsZero() {
		now = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rid := releaseID(ev.Repo, ev.Commit)
	label := ev.Repo + "@" + shortSHA(ev.Commit)
	if len(ev.Tags) > 0 {
		label = ev.Repo + "@" + strings.Join(ev.Tags, ",")
	}
	n := s.g.upsertNode(rid, NodeRelease, label, map[string]string{
		"repo":   ev.Repo,
		"commit": ev.Commit,
		"tenant": ev.Tenant,
		"state":  ev.State,
		"status": ev.Status,
	}, now)
	// Tags may become empty (historical): set them explicitly.
	n.Attrs["tags"] = strings.Join(ev.Tags, ",")
	for i, dep := range ev.Dependencies {
		if strings.TrimSpace(dep.Name) == "" || strings.TrimSpace(dep.Version) == "" {
			continue
		}
		pkgID := packageID(dep.Ecosystem, dep.Name)
		s.g.upsertNode(pkgID, NodePackage, dep.Name, map[string]string{"ecosystem": dep.Ecosystem, "name": dep.Name}, now)
		verID := versionID(dep.Ecosystem, dep.Name, dep.Version)
		s.g.upsertNode(verID, NodeVersion, dep.Name+"@"+dep.Version, map[string]string{
			"ecosystem": dep.Ecosystem, "name": dep.Name, "version": dep.Version, "digest": dep.Digest,
		}, now)
		s.g.upsertEdge(pkgID, EdgeHasVersion, verID, nil)
		status := ""
		if i < len(ev.Statuses) {
			status = ev.Statuses[i]
		}
		s.g.upsertEdge(verID, EdgeShippedIn, rid, map[string]string{"status": status})
	}
	s.count.Add(1)
}

// ShippedIn is a release that ships a version.
type ShippedIn struct {
	ID     string   `json:"id"`
	Repo   string   `json:"repo"`
	Commit string   `json:"commit"`
	Tenant string   `json:"tenant,omitempty"`
	Tags   []string `json:"tags,omitempty"`
	State  string   `json:"state,omitempty"`
	Status string   `json:"status,omitempty"`
	// Version is the version of the queried package the release ships (a
	// blast radius names the affected one).
	Version string `json:"version,omitempty"`
	// DependencyStatus is whether the release pinned it.
	DependencyStatus string `json:"dependencyStatus,omitempty"`
}

// ReleasesOf returns the releases shipping a version (every version when
// version is empty), visible to tenant ("" sees all).
func (s *Service) ReleasesOf(tenant, ecosystem, name, version string) []ShippedIn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var versions []string
	if version != "" {
		versions = []string{versionID(ecosystem, name, version)}
	} else {
		for _, e := range s.g.outEdgesOfKind(packageID(ecosystem, name), EdgeHasVersion) {
			versions = append(versions, e.To)
		}
	}
	var out []ShippedIn
	for _, vid := range versions {
		out = append(out, s.releasesOfVersionLocked(tenant, vid)...)
	}
	sortShipped(out)
	return out
}

func (s *Service) releasesOfVersionLocked(tenant, vid string) []ShippedIn {
	vn, ok := s.g.node(vid)
	if !ok {
		return nil
	}
	var out []ShippedIn
	for _, e := range s.g.outEdgesOfKind(vid, EdgeShippedIn) {
		n, ok := s.g.node(e.To)
		if !ok || (tenant != "" && n.Attrs["tenant"] != tenant) {
			continue
		}
		r := ShippedIn{ID: n.ID, Repo: n.Attrs["repo"], Commit: n.Attrs["commit"], Tenant: n.Attrs["tenant"],
			State: n.Attrs["state"], Status: n.Attrs["status"], Version: vn.Attrs["version"], DependencyStatus: e.Attrs["status"]}
		if t := n.Attrs["tags"]; t != "" {
			r.Tags = strings.Split(t, ",")
		}
		out = append(out, r)
	}
	return out
}

func sortShipped(list []ShippedIn) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Repo != list[j].Repo {
			return list[i].Repo < list[j].Repo
		}
		if list[i].Commit != list[j].Commit {
			return list[i].Commit < list[j].Commit
		}
		return list[i].Version < list[j].Version
	})
}

// releasesForLocked returns the releases shipping any of the given versions.
func (s *Service) releasesForLocked(versionIDs []string) []ShippedIn {
	seen := map[string]bool{}
	var out []ShippedIn
	for _, vid := range versionIDs {
		for _, r := range s.releasesOfVersionLocked("", vid) {
			key := r.ID + "\x00" + r.Version
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, r)
		}
	}
	sortShipped(out)
	return out
}

// ScopeReleases returns the document without the release nodes (and their
// edges) of tenants other than tenant; "" keeps everything.
func (d Document) ScopeReleases(tenant string) Document {
	if tenant == "" {
		return d
	}
	drop := map[string]bool{}
	nodes := d.Nodes[:0:0]
	for _, n := range d.Nodes {
		if n.Kind == NodeRelease && n.Attrs["tenant"] != tenant {
			drop[n.ID] = true
			continue
		}
		nodes = append(nodes, n)
	}
	edges := d.Edges[:0:0]
	for _, e := range d.Edges {
		if drop[e.From] || drop[e.To] {
			continue
		}
		edges = append(edges, e)
	}
	d.Nodes, d.Edges = nodes, edges
	return d
}

// ScopeReleases drops the releases of tenants other than tenant ("" keeps all).
func (r BlastResult) ScopeReleases(tenant string) BlastResult {
	if tenant == "" {
		return r
	}
	kept := r.Releases[:0:0]
	for _, rel := range r.Releases {
		if rel.Tenant == tenant {
			kept = append(kept, rel)
		}
	}
	r.Releases = kept
	return r
}
