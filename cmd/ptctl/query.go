package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/queryapi"
)

// runQuery implements `ptctl query`: a thin client over the proxy's read-only
// federated query API (Task 67). It accepts either a full JSON query document
// (via --file, stdin, or a positional argument) or a set of convenience flags
// that compose a simple AND-of-leaves query, then renders the result as an
// aligned table (default) or raw JSON.
func runQuery(args []string) error {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	var (
		file     = fs.String("file", "", "read the query document from this file (\"-\" for stdin)")
		selectF  = fs.String("select", "", "comma-separated fields to project (default: the schema's default set; \"*\" for all)")
		orderF   = fs.String("order", "", "comma-separated sort fields; prefix a field with '-' for descending")
		limit    = fs.Int("limit", 0, "maximum rows to return (0 = server default)")
		offset   = fs.Int("offset", 0, "rows to skip (for pagination)")
		asJSON   = fs.Bool("json", false, "emit the raw JSON result instead of a table")
		schema   = fs.Bool("schema", false, "print the query schema (fields, operators, bounds) and exit")
		fields   = fs.Bool("fields", false, "print the queryable field names and exit")
		filterMu multiFlag
	)
	fs.Var(&filterMu, "where", "a leaf predicate as field:op:value (repeatable, ANDed). Example: -where riskBand:in:high,critical")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl query [flags] [<query-json>]")
		fmt.Fprintln(os.Stderr, "\nAsk cross-cutting questions over the proxy's federated security data model.")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  # Coordinates served to acme in the last 24h, block-adjacent, unverified sig, >5 downstream paths:")
		fmt.Fprintln(os.Stderr, "  ptctl query --tenant acme \\")
		fmt.Fprintln(os.Stderr, "    -where servedAgeSec:lt:86400 -where blockAdjacent:eq:true \\")
		fmt.Fprintln(os.Stderr, "    -where signatureVerified:eq:false -where downstreamPaths:gt:5 \\")
		fmt.Fprintln(os.Stderr, "    --select coordinate,riskBand,downstreamPaths --order -downstreamPaths")
		fmt.Fprintln(os.Stderr, "  # Run a saved query document:")
		fmt.Fprintln(os.Stderr, "  ptctl query --file query.json")
		fmt.Fprintln(os.Stderr, "  echo '{\"select\":[\"*\"],\"limit\":5}' | ptctl query --file -")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	// --fields is answerable locally from the compiled-in schema registry, so it
	// works without a configured proxy URL.
	if *fields {
		for _, n := range queryapi.FieldNames() {
			fmt.Fprintln(os.Stdout, n)
		}
		return nil
	}

	c, err := newClient(g)
	if err != nil {
		return err
	}

	if *schema {
		return printSchema(c, *asJSON)
	}

	q, err := buildQuery(fs, *file, *selectF, *orderF, *limit, *offset, c.tenant, filterMu)
	if err != nil {
		return err
	}

	var res queryapi.Result
	if err := c.postJSON(c.adminURL("api/query", nil), q, &res); err != nil {
		return err
	}

	if *asJSON {
		return emitJSON(res)
	}
	renderTable(os.Stdout, res)
	return nil
}

// buildQuery assembles the query from a raw document (file/stdin/positional) or,
// absent one, from the convenience flags.
func buildQuery(fs *flag.FlagSet, file, selectF, orderF string, limit, offset int, tenant string, filters multiFlag) (queryapi.Query, error) {
	// Raw document mode takes precedence: --file, stdin via "-", or a positional
	// JSON argument.
	raw, err := readRawQuery(file, fs.Arg(0))
	if err != nil {
		return queryapi.Query{}, err
	}
	if raw != "" {
		var q queryapi.Query
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&q); err != nil {
			return queryapi.Query{}, fmt.Errorf("parsing query document: %w", err)
		}
		// Flags still layer on top so `--limit`/`--tenant` can override a saved doc.
		applyOverrides(&q, selectF, orderF, limit, offset, tenant)
		return q, nil
	}

	// Builder mode.
	q := queryapi.Query{Tenant: tenant, Limit: limit, Offset: offset}
	if sel := splitCSV(selectF); len(sel) > 0 {
		q.Select = sel
	}
	if ord, err := parseOrder(orderF); err != nil {
		return queryapi.Query{}, err
	} else {
		q.OrderBy = ord
	}
	if len(filters) > 0 {
		conj := make([]queryapi.Filter, 0, len(filters))
		for _, f := range filters {
			leaf, err := parseLeaf(f)
			if err != nil {
				return queryapi.Query{}, err
			}
			conj = append(conj, leaf)
		}
		if len(conj) == 1 {
			q.Where = &conj[0]
		} else {
			q.Where = &queryapi.Filter{And: conj}
		}
	}
	return q, nil
}

func applyOverrides(q *queryapi.Query, selectF, orderF string, limit, offset int, tenant string) {
	if sel := splitCSV(selectF); len(sel) > 0 {
		q.Select = sel
	}
	if ord, err := parseOrder(orderF); err == nil && len(ord) > 0 {
		q.OrderBy = ord
	}
	if limit > 0 {
		q.Limit = limit
	}
	if offset > 0 {
		q.Offset = offset
	}
	if tenant != "" && q.Tenant == "" {
		q.Tenant = tenant
	}
}

func readRawQuery(file, positional string) (string, error) {
	if file == "-" {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			return "", fmt.Errorf("reading query from stdin: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("reading query file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if p := strings.TrimSpace(positional); strings.HasPrefix(p, "{") {
		return p, nil
	}
	return "", nil
}

// parseLeaf turns a "field:op:value" flag into a leaf predicate. The value is
// coerced: a comma-separated value with the in/nin operators becomes a list;
// "true"/"false" become booleans; a numeric value becomes a number; everything
// else stays a string.
func parseLeaf(spec string) (queryapi.Filter, error) {
	parts := strings.SplitN(spec, ":", 3)
	if len(parts) < 2 {
		return queryapi.Filter{}, fmt.Errorf("invalid -where %q: expected field:op[:value]", spec)
	}
	field := strings.TrimSpace(parts[0])
	op := strings.TrimSpace(parts[1])
	leaf := queryapi.Filter{Field: field, Op: op}
	if len(parts) == 3 {
		leaf.Value = coerceValue(op, parts[2])
	} else {
		// exists shorthand: `-where served:exists` means "must be present".
		leaf.Value = true
	}
	return leaf, nil
}

func coerceValue(op, raw string) any {
	if op == "in" || op == "nin" {
		items := splitCSV(raw)
		out := make([]any, 0, len(items))
		for _, it := range items {
			out = append(out, scalar(it))
		}
		return out
	}
	return scalar(raw)
}

func scalar(s string) any {
	switch strings.ToLower(s) {
	case "true":
		return true
	case "false":
		return false
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		return n
	}
	return s
}

func parseOrder(spec string) ([]queryapi.Order, error) {
	parts := splitCSV(spec)
	if len(parts) == 0 {
		return nil, nil
	}
	out := make([]queryapi.Order, 0, len(parts))
	for _, p := range parts {
		desc := false
		if strings.HasPrefix(p, "-") {
			desc = true
			p = strings.TrimPrefix(p, "-")
		}
		if p == "" {
			return nil, fmt.Errorf("invalid --order entry (empty field name)")
		}
		out = append(out, queryapi.Order{Field: p, Desc: desc})
	}
	return out, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func printSchema(c *client, asJSON bool) error {
	var s queryapi.Schema
	if err := c.getJSON(c.adminURL("api/query/schema", nil), &s); err != nil {
		return err
	}
	if asJSON {
		return emitJSON(s)
	}
	w := os.Stdout
	fmt.Fprintf(w, "Federated query schema (defaultLimit=%d maxLimit=%d maxScan=%d)\n\n", s.DefaultLimit, s.MaxLimit, s.MaxScan)
	srcs := make([]string, 0, len(s.Sources))
	for k, v := range s.Sources {
		if v {
			srcs = append(srcs, k)
		}
	}
	sort.Strings(srcs)
	fmt.Fprintf(w, "Wired sources: %s\n\n", strings.Join(srcs, ", "))
	fmt.Fprintln(w, "FIELD\tKIND\tFILTER\tOPERATORS")
	for _, f := range s.Fields {
		ops := strings.Join(f.Operators, ",")
		filt := "yes"
		if !f.Filterable {
			filt = "no"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", f.Name, f.Kind, filt, ops)
	}
	return nil
}

func emitJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// renderTable prints the result rows as an aligned, whitespace-separated table,
// followed by a summary line carrying the pagination/cost bookkeeping.
func renderTable(w io.Writer, res queryapi.Result) {
	if len(res.Rows) == 0 {
		fmt.Fprintln(w, "(no matching coordinates)")
	} else {
		cols := res.Fields
		widths := make([]int, len(cols))
		for i, c := range cols {
			widths[i] = len(c)
		}
		cells := make([][]string, 0, len(res.Rows))
		for _, row := range res.Rows {
			line := make([]string, len(cols))
			for i, col := range cols {
				s := cellString(row[col])
				line[i] = s
				if len(s) > widths[i] {
					widths[i] = len(s)
				}
			}
			cells = append(cells, line)
		}
		printRow(w, cols, widths)
		for _, line := range cells {
			printRow(w, line, widths)
		}
	}
	trunc := ""
	if res.Truncated {
		trunc = " (truncated)"
	}
	fmt.Fprintf(w, "\n%d/%d rows%s  offset=%d limit=%d  scanned=%d cost=%d\n",
		res.Returned, res.Total, trunc, res.Offset, res.Limit, res.Scanned, res.Cost)
}

func printRow(w io.Writer, cells []string, widths []int) {
	parts := make([]string, len(cells))
	for i, c := range cells {
		parts[i] = pad(c, widths[i])
	}
	fmt.Fprintln(w, strings.TrimRight(strings.Join(parts, "  "), " "))
}

func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// cellString renders a projected JSON value compactly for the table.
func cellString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		// Render integers without a trailing ".0".
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	case []any:
		ss := make([]string, 0, len(t))
		for _, e := range t {
			ss = append(ss, cellString(e))
		}
		return strings.Join(ss, ",")
	default:
		return fmt.Sprintf("%v", t)
	}
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
