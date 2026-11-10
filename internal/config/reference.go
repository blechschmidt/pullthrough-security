package config

import (
	"fmt"
	"reflect"
	"strings"
	"time"
)

// GenerateReference renders the configuration reference as Markdown, derived
// entirely from the Config struct's shape (yaml tags, field types) and the
// values returned by Default(). Because it is generated from code, the reference
// cannot silently drift from the schema: `make config-reference-check` fails CI
// when the committed docs/configuration-reference.md no longer matches this
// output.
//
// The document is deterministic: top-level sections follow struct declaration
// order, nested structs are flattened into dotted YAML paths in declaration
// order, and no Go map is iterated (map-typed fields are documented via a "*"
// key placeholder), so repeated runs are byte-identical.
func GenerateReference() string {
	var b strings.Builder
	b.WriteString("# Configuration reference (generated)\n\n")
	b.WriteString("<!-- GENERATED FILE — DO NOT EDIT.\n")
	b.WriteString("     Regenerate with `make config-reference-gen`.\n")
	b.WriteString("     Source of truth: internal/config (struct tags + Default()). -->\n\n")
	b.WriteString("This reference is generated from the configuration struct definitions and\n")
	b.WriteString("their compiled-in defaults, so it always matches the running code. Every\n")
	b.WriteString("setting is shown with its YAML path, type, and default value. Everything is\n")
	b.WriteString("off by default: a minimal config (a `server` address, a `cache`, and one or\n")
	b.WriteString("more `upstreams`) runs the proxy as a plain caching mirror.\n\n")
	b.WriteString("For prose, examples, and value-substitution rules (`${ENV}`, `enc:v1:`,\n")
	b.WriteString("`PTS_*`), see [configuration.md](configuration.md).\n\n")
	b.WriteString("Validate a candidate config before rollout with `pullthrough verify-config\n")
	b.WriteString("-config <file>` or `ptctl config validate <file>`.\n\n")

	cfgType := reflect.TypeOf(Config{})
	def := reflect.ValueOf(Default())

	for i := 0; i < cfgType.NumField(); i++ {
		field := cfgType.Field(i)
		if !field.IsExported() {
			continue
		}
		name, opts := yamlName(field)
		if name == "-" {
			continue
		}
		// Inline top-level fields (none today) would have no section header; skip
		// the header but still document their leaves under the parent path.
		section := name
		var rows []docRow
		collectRows(&rows, section, field.Type, def.Field(i), opts.inline, 0)
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(&b, "## `%s`\n\n", section)
		writeTable(&b, rows)
		b.WriteString("\n")
	}
	return b.String()
}

// docRow is one documented leaf setting.
type docRow struct {
	path    string
	typ     string
	deflt   string
	comment string
}

// yamlOpts captures the parsed modifiers from a yaml struct tag.
type yamlOpts struct {
	inline    bool
	omitempty bool
}

// yamlName returns the YAML key for a struct field and its tag options, applying
// the gopkg.in/yaml.v3 default (lower-cased field name) when no tag is present.
func yamlName(f reflect.StructField) (string, yamlOpts) {
	tag := f.Tag.Get("yaml")
	if tag == "" {
		return strings.ToLower(f.Name), yamlOpts{}
	}
	parts := strings.Split(tag, ",")
	name := parts[0]
	var opts yamlOpts
	for _, p := range parts[1:] {
		switch p {
		case "inline":
			opts.inline = true
		case "omitempty":
			opts.omitempty = true
		}
	}
	if name == "" {
		name = strings.ToLower(f.Name)
	}
	return name, opts
}

const maxReferenceDepth = 12

// collectRows walks a (possibly nested) type, appending a docRow for every leaf
// setting reachable from path. Nested structs are flattened into dotted paths;
// maps and slices of structs are documented once via a "*"/"[]" placeholder
// segment (their element fields have no fixed default).
func collectRows(out *[]docRow, path string, t reflect.Type, def reflect.Value, inline bool, depth int) {
	if depth > maxReferenceDepth {
		return
	}
	t = deref(t)

	// Duration is an int64 underneath; treat it as a scalar, not a struct.
	if t == durationType {
		*out = append(*out, docRow{path: path, typ: "duration", deflt: formatDefault(def)})
		return
	}

	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if !field.IsExported() {
				continue
			}
			name, opts := yamlName(field)
			if name == "-" {
				continue
			}
			childPath := name
			if !opts.inline && path != "" {
				childPath = path + "." + name
			} else if opts.inline {
				childPath = path
			}
			var childDef reflect.Value
			if def.IsValid() && def.Kind() == reflect.Struct {
				childDef = def.Field(i)
			}
			collectRows(out, childPath, field.Type, childDef, opts.inline, depth+1)
		}
	case reflect.Map:
		elem := deref(t.Elem())
		keyDesc := path + ".<" + t.Key().Kind().String() + ">"
		if elem.Kind() == reflect.Struct && elem != durationType {
			// Document the element struct's fields under a key placeholder.
			collectRows(out, keyDesc, elem, reflect.Value{}, false, depth+1)
		} else {
			*out = append(*out, docRow{path: path, typ: typeString(t), deflt: "{}"})
		}
	case reflect.Slice:
		elem := deref(t.Elem())
		if elem.Kind() == reflect.Struct && elem != durationType {
			collectRows(out, path+"[]", elem, reflect.Value{}, false, depth+1)
		} else {
			*out = append(*out, docRow{path: path, typ: typeString(t), deflt: formatDefault(def)})
		}
	default:
		*out = append(*out, docRow{path: path, typ: typeString(t), deflt: formatDefault(def)})
	}
}

var durationType = reflect.TypeOf(time.Duration(0))

func deref(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t
}

// typeString renders a friendly, stable type name for the reference table.
func typeString(t reflect.Type) string {
	t = deref(t)
	if t == durationType {
		return "duration"
	}
	switch t.Kind() {
	case reflect.Bool:
		return "bool"
	case reflect.String:
		return "string"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "int"
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "uint"
	case reflect.Float32, reflect.Float64:
		return "float"
	case reflect.Slice:
		return "[]" + typeString(t.Elem())
	case reflect.Map:
		return "map[" + typeString(t.Key()) + "]" + typeString(t.Elem())
	case reflect.Struct:
		return "object"
	default:
		return t.Kind().String()
	}
}

// formatDefault renders a leaf's default value for the reference table. Absent
// or zero values render as an em dash so the common "off by default" case is
// visually quiet.
func formatDefault(v reflect.Value) string {
	if !v.IsValid() {
		return "—"
	}
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return "—"
		}
		v = v.Elem()
	}
	if v.Type() == durationType {
		d := time.Duration(v.Int())
		if d == 0 {
			return "0s"
		}
		return d.String()
	}
	switch v.Kind() {
	case reflect.Bool:
		return fmt.Sprintf("%t", v.Bool())
	case reflect.String:
		s := v.String()
		if s == "" {
			return "—"
		}
		return "`" + s + "`"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return fmt.Sprintf("%d", v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return fmt.Sprintf("%d", v.Uint())
	case reflect.Float32, reflect.Float64:
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", v.Float()), "0"), ".")
	case reflect.Slice, reflect.Array:
		if v.Len() == 0 {
			return "[]"
		}
		parts := make([]string, 0, v.Len())
		for i := 0; i < v.Len(); i++ {
			parts = append(parts, strings.Trim(formatDefault(v.Index(i)), "`"))
		}
		return "`[" + strings.Join(parts, ", ") + "]`"
	case reflect.Map:
		if v.Len() == 0 {
			return "{}"
		}
		return fmt.Sprintf("(%d entries)", v.Len())
	default:
		return "—"
	}
}

// writeTable emits a Markdown table of rows in their collected (declaration)
// order. Paths are escaped for the pipe-delimited table.
func writeTable(b *strings.Builder, rows []docRow) {
	b.WriteString("| Setting | Type | Default |\n")
	b.WriteString("|---------|------|---------|\n")
	for _, r := range rows {
		fmt.Fprintf(b, "| `%s` | %s | %s |\n", r.path, r.typ, r.deflt)
	}
}

// referenceFieldCount reports how many leaf settings the reference documents.
// Used by tests to assert the generator covers the whole surface.
func referenceFieldCount() int {
	cfgType := reflect.TypeOf(Config{})
	def := reflect.ValueOf(Default())
	var rows []docRow
	for i := 0; i < cfgType.NumField(); i++ {
		field := cfgType.Field(i)
		if !field.IsExported() {
			continue
		}
		name, opts := yamlName(field)
		if name == "-" {
			continue
		}
		collectRows(&rows, name, field.Type, def.Field(i), opts.inline, 0)
	}
	return len(rows)
}
