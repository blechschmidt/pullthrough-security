package provgraph

import (
	"errors"
	"sort"
	"strings"
)

// ErrNotFound indicates a queried node (CVE, commit, or artifact) is not present
// in the graph.
var ErrNotFound = errors.New("provgraph: node not found")

// SeedKind selects what a blast-radius query is seeded from.
type SeedKind string

const (
	// SeedCVE seeds the blast radius from a vulnerability advisory id.
	SeedCVE SeedKind = "cve"
	// SeedCommit seeds the blast radius from a source commit SHA.
	SeedCommit SeedKind = "commit"
)

// AffectedArtifact is one cached artifact within a blast radius, annotated with
// whether it is directly affected (built from the commit / directly vulnerable)
// or transitively affected (depends on something that is) and its dependency
// distance from the seed.
type AffectedArtifact struct {
	ID        string `json:"id"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Digest    string `json:"digest,omitempty"`
	Direct    bool   `json:"direct"`
	Distance  int    `json:"distance"`
}

// BlastResult is the outcome of a blast-radius query.
type BlastResult struct {
	Seed      string             `json:"seed"`
	SeedKind  SeedKind           `json:"seedKind"`
	SeedID    string             `json:"seedId"`
	Found     bool               `json:"found"`
	Total     int                `json:"total"`
	Direct    int                `json:"direct"`
	Artifacts []AffectedArtifact `json:"artifacts"`
}

// BlastRadius returns every cached artifact affected by the given seed (a CVE
// advisory id or a commit SHA). Artifacts directly affected — versions
// vulnerable to the CVE, or versions built from the commit — are the starting
// set; the radius then expands along reverse depends-on edges so transitive
// consumers of an affected artifact are included. Results are ordered direct
// first, then by ascending dependency distance, then by id.
func (s *Service) BlastRadius(kind SeedKind, id string) (BlastResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var seedNode string
	var directEdges []*Edge
	switch kind {
	case SeedCVE:
		seedNode = cveID(id)
		directEdges = s.g.inEdgesOfKind(seedNode, EdgeAffectedByCVE)
	case SeedCommit:
		seedNode = commitID(id)
		directEdges = s.g.inEdgesOfKind(seedNode, EdgeBuiltFromCommit)
	default:
		return BlastResult{}, errors.New("provgraph: unknown seed kind " + string(kind))
	}

	res := BlastResult{Seed: id, SeedKind: kind, SeedID: seedNode, Artifacts: []AffectedArtifact{}}
	if _, ok := s.g.node(seedNode); !ok {
		return res, ErrNotFound
	}
	res.Found = true

	// distance[node] is the dependency hops from a directly-affected version.
	distance := make(map[string]int)
	queue := make([]string, 0, len(directEdges))
	for _, e := range directEdges {
		if _, seen := distance[e.From]; seen {
			continue
		}
		distance[e.From] = 0
		queue = append(queue, e.From)
	}

	// Reverse-BFS over depends-on: a dependent of an affected version is affected.
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		d := distance[cur]
		for _, e := range s.g.inEdgesOfKind(cur, EdgeDependsOn) {
			if _, seen := distance[e.From]; seen {
				continue
			}
			distance[e.From] = d + 1
			queue = append(queue, e.From)
		}
	}

	for id, d := range distance {
		n, ok := s.g.node(id)
		if !ok || n.Kind != NodeVersion {
			continue
		}
		a := AffectedArtifact{
			ID:        n.ID,
			Ecosystem: n.Attrs["ecosystem"],
			Name:      n.Attrs["name"],
			Version:   n.Attrs["version"],
			Digest:    n.Attrs["digest"],
			Direct:    d == 0,
			Distance:  d,
		}
		res.Artifacts = append(res.Artifacts, a)
		if a.Direct {
			res.Direct++
		}
	}
	sortAffected(res.Artifacts)
	res.Total = len(res.Artifacts)
	return res, nil
}

// Dependent is one artifact that depends on a queried artifact.
type Dependent struct {
	ID        string `json:"id"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Direct    bool   `json:"direct"`
	Distance  int    `json:"distance"`
}

// DepResult is the outcome of a reverse-dependency query.
type DepResult struct {
	Artifact   string      `json:"artifact"`
	Found      bool        `json:"found"`
	Total      int         `json:"total"`
	Direct     int         `json:"direct"`
	Dependents []Dependent `json:"dependents"`
}

// ReverseDependencies returns every cached artifact that depends on the given
// artifact, directly or transitively, ordered direct first then by distance.
func (s *Service) ReverseDependencies(ecosystem, name, version string) (DepResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	target := versionID(ecosystem, name, version)
	res := DepResult{Artifact: target, Dependents: []Dependent{}}
	if _, ok := s.g.node(target); !ok {
		return res, ErrNotFound
	}
	res.Found = true

	distance := map[string]int{target: 0}
	queue := []string{target}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		d := distance[cur]
		for _, e := range s.g.inEdgesOfKind(cur, EdgeDependsOn) {
			if _, seen := distance[e.From]; seen {
				continue
			}
			distance[e.From] = d + 1
			queue = append(queue, e.From)
		}
	}

	for id, d := range distance {
		if d == 0 {
			continue // the queried artifact itself
		}
		n, ok := s.g.node(id)
		if !ok || n.Kind != NodeVersion {
			continue
		}
		dep := Dependent{
			ID:        n.ID,
			Ecosystem: n.Attrs["ecosystem"],
			Name:      n.Attrs["name"],
			Version:   n.Attrs["version"],
			Direct:    d == 1,
			Distance:  d,
		}
		res.Dependents = append(res.Dependents, dep)
		if dep.Direct {
			res.Direct++
		}
	}
	sort.Slice(res.Dependents, func(i, j int) bool {
		if res.Dependents[i].Distance != res.Dependents[j].Distance {
			return res.Dependents[i].Distance < res.Dependents[j].Distance
		}
		return res.Dependents[i].ID < res.Dependents[j].ID
	})
	res.Total = len(res.Dependents)
	return res, nil
}

// ForwardDependencies returns the direct dependencies (depends-on edges) of the
// given artifact: the concrete (ecosystem, name, version) coordinates it was
// recorded as depending on. It is the forward counterpart of
// ReverseDependencies and backs predictive pre-warming of a recently-pulled
// package's dependencies (Task 134). Returns ErrNotFound when the artifact
// itself is unknown.
func (s *Service) ForwardDependencies(ecosystem, name, version string) (DepResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	src := versionID(ecosystem, name, version)
	res := DepResult{Artifact: src, Dependents: []Dependent{}}
	n, ok := s.g.node(src)
	if !ok {
		return res, ErrNotFound
	}
	res.Found = true
	_ = n

	for _, e := range s.g.outEdgesOfKind(src, EdgeDependsOn) {
		dep, ok := s.g.node(e.To)
		if !ok || dep.Kind != NodeVersion {
			continue
		}
		res.Dependents = append(res.Dependents, Dependent{
			ID:        dep.ID,
			Ecosystem: dep.Attrs["ecosystem"],
			Name:      dep.Attrs["name"],
			Version:   dep.Attrs["version"],
			Direct:    true,
			Distance:  1,
		})
	}
	sort.Slice(res.Dependents, func(i, j int) bool {
		return res.Dependents[i].ID < res.Dependents[j].ID
	})
	res.Direct = len(res.Dependents)
	res.Total = len(res.Dependents)
	return res, nil
}

// PathStep is one hop on a path from an artifact to a commit.
type PathStep struct {
	From string   `json:"from"`
	To   string   `json:"to"`
	Kind EdgeKind `json:"kind"`
}

// PathResult is the outcome of a path-to-commit query.
type PathResult struct {
	Artifact  string     `json:"artifact"`
	Found     bool       `json:"found"`
	CommitID  string     `json:"commitId,omitempty"`
	CommitSHA string     `json:"commitSha,omitempty"`
	Nodes     []string   `json:"nodes"`
	Steps     []PathStep `json:"steps"`
}

// PathToCommit returns a shortest path from the given artifact to a source
// commit it originates from. It prefers the artifact's own built-from-commit
// edge; when the artifact has no direct provenance it follows depends-on edges
// to reach a dependency that does, modeling "this artifact's code ultimately
// traces back to that commit". Returns Found=false (and a nil error) when no
// commit is reachable, and ErrNotFound when the artifact itself is unknown.
func (s *Service) PathToCommit(ecosystem, name, version string) (PathResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	start := versionID(ecosystem, name, version)
	res := PathResult{Artifact: start, Nodes: []string{}, Steps: []PathStep{}}
	if _, ok := s.g.node(start); !ok {
		return res, ErrNotFound
	}

	// BFS following built-from-commit and depends-on edges; the first commit node
	// reached yields the shortest path.
	type crumb struct {
		prev string
		edge *Edge
	}
	visited := map[string]crumb{start: {}}
	queue := []string{start}
	var commitNode string
	for len(queue) > 0 && commitNode == "" {
		cur := queue[0]
		queue = queue[1:]
		// Prefer commit edges so a direct provenance link wins over a longer
		// dependency detour at the same BFS frontier.
		edges := append(s.g.outEdgesOfKind(cur, EdgeBuiltFromCommit), s.g.outEdgesOfKind(cur, EdgeDependsOn)...)
		for _, e := range edges {
			if _, seen := visited[e.To]; seen {
				continue
			}
			visited[e.To] = crumb{prev: cur, edge: e}
			n, ok := s.g.node(e.To)
			if ok && n.Kind == NodeCommit {
				commitNode = e.To
				break
			}
			queue = append(queue, e.To)
		}
	}

	if commitNode == "" {
		return res, nil
	}

	// Reconstruct the path from start to the commit.
	var steps []PathStep
	nodes := []string{commitNode}
	for cur := commitNode; cur != start; {
		c := visited[cur]
		steps = append(steps, PathStep{From: c.prev, To: cur, Kind: c.edge.Kind})
		nodes = append(nodes, c.prev)
		cur = c.prev
	}
	// Reverse both into start->commit order.
	for i, j := 0, len(steps)-1; i < j; i, j = i+1, j-1 {
		steps[i], steps[j] = steps[j], steps[i]
	}
	for i, j := 0, len(nodes)-1; i < j; i, j = i+1, j-1 {
		nodes[i], nodes[j] = nodes[j], nodes[i]
	}
	res.Found = true
	res.CommitID = commitNode
	res.CommitSHA = strings.TrimPrefix(commitNode, "commit:")
	if n, ok := s.g.node(commitNode); ok {
		if sha := n.Attrs["sha"]; sha != "" {
			res.CommitSHA = sha
		}
	}
	res.Nodes = nodes
	res.Steps = steps
	return res, nil
}

// sortAffected orders affected artifacts direct-first, then by ascending
// distance, then by id, for a stable, useful presentation.
func sortAffected(a []AffectedArtifact) {
	sort.Slice(a, func(i, j int) bool {
		if a[i].Direct != a[j].Direct {
			return a[i].Direct
		}
		if a[i].Distance != a[j].Distance {
			return a[i].Distance < a[j].Distance
		}
		return a[i].ID < a[j].ID
	})
}
