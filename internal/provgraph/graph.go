package provgraph

import (
	"sort"
	"time"
)

// Node is a single vertex in the supply-chain graph. Attrs carries kind-specific
// detail (ecosystem, name, version, digest, severity, repository, verified, ...)
// so the export and visualization can render nodes without bespoke per-kind
// fields.
type Node struct {
	ID        string            `json:"id"`
	Kind      NodeKind          `json:"kind"`
	Label     string            `json:"label"`
	Attrs     map[string]string `json:"attrs,omitempty"`
	FirstSeen time.Time         `json:"firstSeen"`
	LastSeen  time.Time         `json:"lastSeen"`
}

// Edge is a typed, directed relationship between two nodes.
type Edge struct {
	From  string            `json:"from"`
	To    string            `json:"to"`
	Kind  EdgeKind          `json:"kind"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

// graph is the in-memory adjacency structure. It is not safe for concurrent use
// on its own; the owning Service serializes access with a RWMutex.
type graph struct {
	nodes map[string]*Node
	// edges holds the deduplicated edge set keyed by (from|kind|to).
	edges map[string]*Edge
	// out and in index edges by source and destination node for traversal.
	out map[string][]*Edge
	in  map[string][]*Edge
}

func newGraph() *graph {
	return &graph{
		nodes: make(map[string]*Node),
		edges: make(map[string]*Edge),
		out:   make(map[string][]*Edge),
		in:    make(map[string][]*Edge),
	}
}

// upsertNode inserts the node when absent, or merges new label/attributes into
// the existing one. It always advances LastSeen to now and never regresses an
// existing FirstSeen. Returns the stored node.
func (g *graph) upsertNode(id string, kind NodeKind, label string, attrs map[string]string, now time.Time) *Node {
	n, ok := g.nodes[id]
	if !ok {
		n = &Node{ID: id, Kind: kind, Label: label, Attrs: map[string]string{}, FirstSeen: now}
		g.nodes[id] = n
	}
	if label != "" {
		n.Label = label
	}
	// Merge non-empty attributes, letting later observations refine earlier ones.
	for k, v := range attrs {
		if v == "" {
			continue
		}
		if n.Attrs == nil {
			n.Attrs = map[string]string{}
		}
		n.Attrs[k] = v
	}
	n.LastSeen = now
	return n
}

// edgeKey builds the deduplication key for a directed, typed edge.
func edgeKey(from string, kind EdgeKind, to string) string {
	return from + "\x00" + string(kind) + "\x00" + to
}

// upsertEdge inserts the edge when absent (indexing it for traversal) or merges
// attributes into the existing one. Self-loops are ignored.
func (g *graph) upsertEdge(from string, kind EdgeKind, to string, attrs map[string]string) {
	if from == "" || to == "" || from == to {
		return
	}
	key := edgeKey(from, kind, to)
	e, ok := g.edges[key]
	if !ok {
		e = &Edge{From: from, To: to, Kind: kind, Attrs: map[string]string{}}
		g.edges[key] = e
		g.out[from] = append(g.out[from], e)
		g.in[to] = append(g.in[to], e)
	}
	for k, v := range attrs {
		if v == "" {
			continue
		}
		if e.Attrs == nil {
			e.Attrs = map[string]string{}
		}
		e.Attrs[k] = v
	}
}

// node returns the stored node and whether it exists.
func (g *graph) node(id string) (*Node, bool) {
	n, ok := g.nodes[id]
	return n, ok
}

// outEdgesOfKind returns the outgoing edges of from with the given kind.
func (g *graph) outEdgesOfKind(from string, kind EdgeKind) []*Edge {
	var out []*Edge
	for _, e := range g.out[from] {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// inEdgesOfKind returns the incoming edges of to with the given kind.
func (g *graph) inEdgesOfKind(to string, kind EdgeKind) []*Edge {
	var out []*Edge
	for _, e := range g.in[to] {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// snapshotNodes returns a deterministically ordered copy of every node.
func (g *graph) snapshotNodes() []Node {
	out := make([]Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		out = append(out, copyNode(n))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// snapshotEdges returns a deterministically ordered copy of every edge.
func (g *graph) snapshotEdges() []Edge {
	out := make([]Edge, 0, len(g.edges))
	for _, e := range g.edges {
		out = append(out, copyEdge(e))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].To < out[j].To
	})
	return out
}

func copyNode(n *Node) Node {
	c := *n
	if n.Attrs != nil {
		c.Attrs = make(map[string]string, len(n.Attrs))
		for k, v := range n.Attrs {
			c.Attrs[k] = v
		}
	}
	return c
}

func copyEdge(e *Edge) Edge {
	c := *e
	if e.Attrs != nil {
		c.Attrs = make(map[string]string, len(e.Attrs))
		for k, v := range e.Attrs {
			c.Attrs[k] = v
		}
	}
	return c
}
