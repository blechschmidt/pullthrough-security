package provgraph

// Document is the self-contained JSON serialization of the whole graph, suitable
// for offline analysis and for the admin force-directed visualization to render.
type Document struct {
	Nodes []Node   `json:"nodes"`
	Edges []Edge   `json:"edges"`
	Stats Snapshot `json:"stats"`
}

// Snapshot reports graph size for metrics and the admin overview. The per-kind
// maps let operators see the shape of the supply-chain graph at a glance.
type Snapshot struct {
	Nodes          int            `json:"nodes"`
	Edges          int            `json:"edges"`
	NodesByKind    map[string]int `json:"nodesByKind"`
	EdgesByKind    map[string]int `json:"edgesByKind"`
	EventsIngested int64          `json:"eventsIngested"`
}

// Export returns a deterministic, fully-detached copy of the graph as a
// Document. The returned slices and maps share no state with the live graph, so
// the caller may serialize it without holding any lock.
func (s *Service) Export() Document {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Document{
		Nodes: s.g.snapshotNodes(),
		Edges: s.g.snapshotEdges(),
		Stats: s.snapshotLocked(),
	}
}

// Snapshot returns current graph-size metrics.
func (s *Service) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshotLocked()
}

// snapshotLocked computes the size metrics; the caller must hold at least the
// read lock.
func (s *Service) snapshotLocked() Snapshot {
	byNode := map[string]int{}
	for _, n := range s.g.nodes {
		byNode[string(n.Kind)]++
	}
	byEdge := map[string]int{}
	for _, e := range s.g.edges {
		byEdge[string(e.Kind)]++
	}
	return Snapshot{
		Nodes:          len(s.g.nodes),
		Edges:          len(s.g.edges),
		NodesByKind:    byNode,
		EdgesByKind:    byEdge,
		EventsIngested: s.count.Load(),
	}
}
