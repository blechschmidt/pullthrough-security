package grpcapi

import (
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/queryapi"
)

// coord is the resolved identity of a package coordinate, joined from the
// federated query model. Found reports whether the query model actually held the
// coordinate; when false the caller falls back to the arguments it was given so
// an RPC can still consult its detail provider for an as-yet-unscanned package.
type coord struct {
	Tenant     string
	Ecosystem  string
	Name       string
	Version    string
	Coordinate string
	Digest     string
	Found      bool
	Row        map[string]any
}

// pkgKey returns the best string to address the coordinate in name-keyed stores
// (findings, attestbundle): the normalized coordinate when known, else
// name@version, else the bare name.
func (c coord) pkgKey() string {
	if c.Coordinate != "" {
		return c.Coordinate
	}
	if c.Name != "" && c.Version != "" {
		return c.Name + "@" + c.Version
	}
	return c.Name
}

// resolve looks the coordinate up in the federated query model, scoped to
// tenant. It reuses the query engine's field registry (selecting the full row)
// so the per-coordinate join is identical to the one the GraphQL and MCP
// surfaces expose, and it inherits the engine's cost bounds. The
// most-recently-seen matching row wins.
//
// name is required by callers; version and ecosystem narrow the match when
// supplied. The returned coord always carries the caller-provided identity even
// when Found is false, so detail providers can still be consulted.
func (s *Server) resolve(tenant, ecosystem, name, version string) (coord, error) {
	out := coord{
		Tenant:    tenant,
		Ecosystem: strings.TrimSpace(ecosystem),
		Name:      strings.TrimSpace(name),
		Version:   strings.TrimSpace(version),
	}
	if out.Name == "" {
		return out, nil
	}

	preds := []queryapi.Filter{{Field: "name", Op: "eq", Value: out.Name}}
	if out.Version != "" {
		preds = append(preds, queryapi.Filter{Field: "version", Op: "eq", Value: out.Version})
	}
	if out.Ecosystem != "" {
		preds = append(preds, queryapi.Filter{Field: "ecosystem", Op: "eq", Value: out.Ecosystem})
	}
	var where *queryapi.Filter
	if len(preds) == 1 {
		where = &preds[0]
	} else {
		where = &queryapi.Filter{And: preds}
	}

	q := queryapi.Query{
		Tenant:  tenant,
		Select:  []string{"*"},
		Where:   where,
		OrderBy: []queryapi.Order{{Field: "lastSeen", Desc: true}},
		Limit:   1,
	}
	res, err := s.backend.Query(q)
	if err != nil {
		return out, err
	}
	if len(res.Rows) == 0 {
		return out, nil
	}

	row := res.Rows[0]
	out.Row = row
	out.Found = true
	if v := rowStr(row, "ecosystem"); v != "" {
		out.Ecosystem = v
	}
	if v := rowStr(row, "name"); v != "" {
		out.Name = v
	}
	if v := rowStr(row, "version"); v != "" {
		out.Version = v
	}
	out.Coordinate = rowStr(row, "coordinate")
	out.Digest = rowStr(row, "digest")
	if out.Coordinate == "" {
		out.Coordinate = out.pkgKey()
	}
	return out, nil
}

// coordinateMatches reports whether an assessment/document identity addresses c.
func coordinateMatches(coordinate, name, version string, c coord) bool {
	if c.Coordinate != "" && strings.EqualFold(coordinate, c.Coordinate) {
		return true
	}
	if c.Name != "" && strings.EqualFold(name, c.Name) {
		return c.Version == "" || strings.EqualFold(version, c.Version)
	}
	return false
}

// rowStr extracts a string field from a projected query row.
func rowStr(row map[string]any, key string) string {
	if row == nil {
		return ""
	}
	if v, ok := row[key].(string); ok {
		return v
	}
	return ""
}

// rowBool extracts a bool field from a projected query row.
func rowBool(row map[string]any, key string) bool {
	if row == nil {
		return false
	}
	if v, ok := row[key].(bool); ok {
		return v
	}
	return false
}

// rowNum extracts a numeric field from a projected query row, normalizing the
// int/int64/float64 boxings the projector emits to a float64.
func rowNum(row map[string]any, key string) float64 {
	if row == nil {
		return 0
	}
	switch v := row[key].(type) {
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case float64:
		return v
	default:
		return 0
	}
}

// rowInt extracts a numeric field as an int.
func rowInt(row map[string]any, key string) int { return int(rowNum(row, key)) }

// rowList extracts a string-list field from a projected query row.
func rowList(row map[string]any, key string) []string {
	if row == nil {
		return nil
	}
	switch v := row[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
