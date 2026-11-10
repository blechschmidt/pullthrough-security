package queryapi

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Query is the JSON request the federated endpoint accepts. It is intentionally
// small and dependency-free: a projection (Select), a boolean predicate tree
// (Where), ordering, and pagination. Tenant is a convenience shorthand that is
// ANDed onto Where as `tenant eq <Tenant>`, so RBAC/scoping callers can pin a
// tenant without composing a filter.
type Query struct {
	Tenant  string   `json:"tenant,omitempty"`
	Select  []string `json:"select,omitempty"`
	Where   *Filter  `json:"where,omitempty"`
	OrderBy []Order  `json:"orderBy,omitempty"`
	Limit   int      `json:"limit,omitempty"`
	Offset  int      `json:"offset,omitempty"`
}

// Order is one sort key. Desc selects descending order (default ascending).
type Order struct {
	Field string `json:"field"`
	Desc  bool   `json:"desc,omitempty"`
}

// Filter is a node in the predicate tree. It is either a composite (exactly one
// of And/Or/Not is set) or a leaf (Field/Op/Value). The shape keeps the wire
// format readable: {"and":[{"field":"riskBand","op":"in","value":["high","critical"]}, ...]}.
type Filter struct {
	And   []Filter `json:"and,omitempty"`
	Or    []Filter `json:"or,omitempty"`
	Not   *Filter  `json:"not,omitempty"`
	Field string   `json:"field,omitempty"`
	Op    string   `json:"op,omitempty"`
	Value any      `json:"value,omitempty"`
}

// QueryError is a typed, client-facing validation/execution error. Code is a
// stable machine-readable token; the endpoint maps it to HTTP 400.
type QueryError struct {
	Code string
	Msg  string
}

func (e *QueryError) Error() string { return e.Msg }

func newErr(code, format string, a ...any) *QueryError {
	return &QueryError{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// isLeaf reports whether f is a leaf predicate (references a field).
func (f *Filter) isLeaf() bool { return f.Field != "" }

// validate checks the whole query against the field registry and engine bounds,
// returning the effective (clamped) limit/offset and the resolved projection.
// It rejects unknown fields/operators, malformed predicates, and negative
// pagination. It returns the number of leaf predicates for cost accounting.
func (q *Query) validate(e *Engine) (sel []string, predicates int, err error) {
	// Projection.
	sel, err = resolveSelect(q.Select)
	if err != nil {
		return nil, 0, err
	}
	// Ordering.
	for _, o := range q.OrderBy {
		f, ok := fieldIndex[o.Field]
		if !ok {
			return nil, 0, newErr("invalid_field", "orderBy references unknown field %q", o.Field)
		}
		_ = f
	}
	// Pagination.
	if q.Limit < 0 {
		return nil, 0, newErr("invalid_limit", "limit must be >= 0")
	}
	if q.Offset < 0 {
		return nil, 0, newErr("invalid_offset", "offset must be >= 0")
	}
	// Predicate tree.
	if q.Where != nil {
		predicates, err = validateFilter(q.Where, 0)
		if err != nil {
			return nil, 0, err
		}
	}
	if strings.TrimSpace(q.Tenant) != "" {
		predicates++ // the implicit tenant predicate
	}
	return sel, predicates, nil
}

const maxFilterDepth = 32

func validateFilter(f *Filter, depth int) (int, error) {
	if depth > maxFilterDepth {
		return 0, newErr("filter_too_deep", "filter nesting exceeds %d levels", maxFilterDepth)
	}
	composites := 0
	if len(f.And) > 0 {
		composites++
	}
	if len(f.Or) > 0 {
		composites++
	}
	if f.Not != nil {
		composites++
	}
	if f.isLeaf() {
		composites++
	}
	if composites == 0 {
		return 0, newErr("empty_filter", "filter node has neither a predicate nor a boolean combinator")
	}
	if composites > 1 {
		return 0, newErr("ambiguous_filter", "filter node must be exactly one of: leaf (field/op), and, or, not")
	}

	switch {
	case len(f.And) > 0:
		return validateChildren(f.And, depth)
	case len(f.Or) > 0:
		return validateChildren(f.Or, depth)
	case f.Not != nil:
		return validateFilter(f.Not, depth+1)
	default:
		return 1, validateLeaf(f)
	}
}

func validateChildren(children []Filter, depth int) (int, error) {
	total := 0
	for i := range children {
		n, err := validateFilter(&children[i], depth+1)
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

func validateLeaf(f *Filter) error {
	fld, ok := fieldIndex[f.Field]
	if !ok {
		return newErr("invalid_field", "unknown field %q", f.Field)
	}
	if !fld.Filterable {
		return newErr("not_filterable", "field %q is projectable but not filterable", f.Field)
	}
	op := strings.ToLower(strings.TrimSpace(f.Op))
	if op == "" {
		return newErr("missing_operator", "field %q requires an op", f.Field)
	}
	valid := false
	for _, o := range operatorsFor(fld.Kind) {
		if o == op {
			valid = true
			break
		}
	}
	if !valid {
		return newErr("invalid_operator", "operator %q is not valid for field %q (%s)", op, f.Field, fld.Kind)
	}
	f.Op = op
	// Operators that take a list value must receive one.
	switch op {
	case "in", "nin":
		if _, ok := f.Value.([]any); !ok {
			return newErr("invalid_value", "operator %q on field %q requires a list value", op, f.Field)
		}
	}
	return nil
}

func resolveSelect(sel []string) ([]string, error) {
	if len(sel) == 0 {
		return append([]string(nil), defaultSelect...), nil
	}
	out := make([]string, 0, len(sel))
	seen := make(map[string]bool)
	for _, name := range sel {
		name = strings.TrimSpace(name)
		if name == "*" {
			out = out[:0]
			for _, f := range fieldList {
				out = append(out, f.Name)
			}
			return out, nil
		}
		if _, ok := fieldIndex[name]; !ok {
			return nil, newErr("invalid_field", "select references unknown field %q", name)
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out, nil
}

// --- evaluation -------------------------------------------------------------

// eval evaluates the predicate tree against a record.
func (f *Filter) eval(r *Record) bool {
	switch {
	case len(f.And) > 0:
		for i := range f.And {
			if !f.And[i].eval(r) {
				return false
			}
		}
		return true
	case len(f.Or) > 0:
		for i := range f.Or {
			if f.Or[i].eval(r) {
				return true
			}
		}
		return false
	case f.Not != nil:
		return !f.Not.eval(r)
	default:
		return evalLeaf(r, f.Field, f.Op, f.Value)
	}
}

func evalLeaf(r *Record, field, op string, val any) bool {
	fld, ok := fieldIndex[field]
	if !ok {
		return false
	}
	cur := fld.get(r)

	switch fld.Kind {
	case KindString:
		return evalString(toStr(cur), op, val)
	case KindNumber:
		f, _ := toFloat(cur)
		return evalNumber(f, op, val)
	case KindBool:
		return evalBool(toBool(cur), op, val)
	case KindList:
		return evalList(toList(cur), op, val)
	default:
		return false
	}
}

func evalString(cur, op string, val any) bool {
	lc := strings.ToLower(cur)
	switch op {
	case "eq":
		return lc == strings.ToLower(toStr(val))
	case "ne":
		return lc != strings.ToLower(toStr(val))
	case "contains":
		return strings.Contains(lc, strings.ToLower(toStr(val)))
	case "prefix":
		return strings.HasPrefix(lc, strings.ToLower(toStr(val)))
	case "in":
		for _, v := range toAnyList(val) {
			if lc == strings.ToLower(toStr(v)) {
				return true
			}
		}
		return false
	case "nin":
		for _, v := range toAnyList(val) {
			if lc == strings.ToLower(toStr(v)) {
				return false
			}
		}
		return true
	case "exists":
		return toBool(val) == (cur != "")
	}
	return false
}

func evalNumber(cur float64, op string, val any) bool {
	switch op {
	case "eq":
		v, ok := toFloat(val)
		return ok && cur == v
	case "ne":
		v, ok := toFloat(val)
		return !ok || cur != v
	case "gt":
		v, ok := toFloat(val)
		return ok && cur > v
	case "gte":
		v, ok := toFloat(val)
		return ok && cur >= v
	case "lt":
		v, ok := toFloat(val)
		return ok && cur < v
	case "lte":
		v, ok := toFloat(val)
		return ok && cur <= v
	case "in":
		for _, v := range toAnyList(val) {
			if f, ok := toFloat(v); ok && cur == f {
				return true
			}
		}
		return false
	case "nin":
		for _, v := range toAnyList(val) {
			if f, ok := toFloat(v); ok && cur == f {
				return false
			}
		}
		return true
	case "exists":
		return toBool(val) == (cur != 0)
	}
	return false
}

func evalBool(cur bool, op string, val any) bool {
	switch op {
	case "eq":
		return cur == toBool(val)
	case "ne":
		return cur != toBool(val)
	case "exists":
		return toBool(val) == cur
	}
	return false
}

func evalList(cur []string, op string, val any) bool {
	switch op {
	case "contains":
		target := strings.ToLower(toStr(val))
		for _, e := range cur {
			if strings.ToLower(e) == target {
				return true
			}
		}
		return false
	case "in":
		set := lowerSet(toAnyList(val))
		for _, e := range cur {
			if set[strings.ToLower(e)] {
				return true
			}
		}
		return false
	case "nin":
		set := lowerSet(toAnyList(val))
		for _, e := range cur {
			if set[strings.ToLower(e)] {
				return false
			}
		}
		return true
	case "exists":
		return toBool(val) == (len(cur) > 0)
	}
	return false
}

// --- ordering & projection --------------------------------------------------

// orderRecords sorts the matched records by the query's order keys. The sort is
// stable and falls back to the canonical (tenant, ecosystem, coordinate) key so
// output is deterministic even without an explicit order.
func orderRecords(recs []*Record, orders []Order) {
	sort.SliceStable(recs, func(i, j int) bool {
		for _, o := range orders {
			c := compareField(recs[i], recs[j], o.Field)
			if c == 0 {
				continue
			}
			if o.Desc {
				return c > 0
			}
			return c < 0
		}
		// Deterministic tiebreaker.
		ki := recordKey(recs[i].Tenant, recs[i].Ecosystem, recs[i].Coordinate)
		kj := recordKey(recs[j].Tenant, recs[j].Ecosystem, recs[j].Coordinate)
		return ki < kj
	})
}

func compareField(a, b *Record, field string) int {
	fld, ok := fieldIndex[field]
	if !ok {
		return 0
	}
	switch fld.Kind {
	case KindNumber:
		fa, _ := toFloat(fld.get(a))
		fb, _ := toFloat(fld.get(b))
		switch {
		case fa < fb:
			return -1
		case fa > fb:
			return 1
		default:
			return 0
		}
	case KindBool:
		ba, bb := toBool(fld.get(a)), toBool(fld.get(b))
		switch {
		case !ba && bb:
			return -1
		case ba && !bb:
			return 1
		default:
			return 0
		}
	case KindTime:
		ta, _ := fld.get(a).(time.Time)
		tb, _ := fld.get(b).(time.Time)
		switch {
		case ta.Before(tb):
			return -1
		case ta.After(tb):
			return 1
		default:
			return 0
		}
	default: // string, list
		return strings.Compare(strings.ToLower(toStr(fld.get(a))), strings.ToLower(toStr(fld.get(b))))
	}
}

// project renders a record into an output row containing only the selected
// fields, normalizing values for JSON (times as RFC3339, lists as []string,
// numbers as their natural type).
func project(r *Record, sel []string) map[string]any {
	row := make(map[string]any, len(sel))
	for _, name := range sel {
		fld := fieldIndex[name]
		v := fld.get(r)
		switch fld.Kind {
		case KindTime:
			t, _ := v.(time.Time)
			if t.IsZero() {
				row[name] = nil
			} else {
				row[name] = t.UTC().Format(time.RFC3339)
			}
		case KindList:
			lst := toList(v)
			if lst == nil {
				lst = []string{}
			}
			row[name] = lst
		default:
			row[name] = v
		}
	}
	return row
}

// --- value coercion ---------------------------------------------------------

func toStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	case bool:
		if t {
			return "true"
		}
		return "false"
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case int32:
		return float64(t), true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	default:
		return 0, false
	}
}

func toBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true") || t == "1"
	case float64:
		return t != 0
	case nil:
		// An omitted value on an exists predicate defaults to "must be present".
		return true
	default:
		return false
	}
}

func toList(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case nil:
		return nil
	default:
		return nil
	}
}

func toAnyList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	if v == nil {
		return nil
	}
	return []any{v}
}

func lowerSet(vs []any) map[string]bool {
	m := make(map[string]bool, len(vs))
	for _, v := range vs {
		m[strings.ToLower(toStr(v))] = true
	}
	return m
}
