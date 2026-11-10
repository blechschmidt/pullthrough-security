package config

import "reflect"

// YAMLPathExists reports whether the given dotted YAML path resolves to a field
// in the Config schema. It walks the Config struct by its yaml tags (mirroring
// the resolution in GenerateReference), descending through nested structs,
// pointers, and the element type of maps and slices of structs. A map or
// slice-of-struct segment may be traversed either directly by the container
// field's key or through its element's fields, so both `vulnerabilities.vex`
// and `upstreams.type` resolve.
//
// It exists so documentation generators and their staleness tests (for example
// internal/gatedoc) can assert that a documented config path still names a real
// setting, turning a renamed or removed config key into a failing test rather
// than silently stale docs.
func YAMLPathExists(path string) bool {
	if path == "" {
		return false
	}
	return pathExistsIn(reflect.TypeOf(Config{}), splitPath(path), 0)
}

// splitPath splits a dotted path into its segments.
func splitPath(path string) []string {
	var segs []string
	start := 0
	for i := 0; i < len(path); i++ {
		if path[i] == '.' {
			segs = append(segs, path[start:i])
			start = i + 1
		}
	}
	segs = append(segs, path[start:])
	return segs
}

// pathExistsIn reports whether segs[idx:] resolves within type t.
func pathExistsIn(t reflect.Type, segs []string, idx int) bool {
	if idx >= len(segs) {
		return true
	}
	t = deref(t)

	switch t.Kind() {
	case reflect.Struct:
		// Duration is a struct-free scalar; a path cannot descend into it.
		if t == durationType {
			return false
		}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if !field.IsExported() {
				continue
			}
			name, opts := yamlName(field)
			if name == "-" {
				continue
			}
			if opts.inline {
				// Inlined fields contribute their leaves at the current level.
				if pathExistsIn(field.Type, segs, idx) {
					return true
				}
				continue
			}
			if name == segs[idx] {
				return pathExistsIn(field.Type, segs, idx+1)
			}
		}
		return false
	case reflect.Map:
		// A map/slice element's fields may be addressed directly (the key/index is
		// implicit, e.g. `upstreams.type`) or through an explicit placeholder
		// segment (e.g. `upstreams.<string>.type`). Accept either form.
		return pathExistsIn(t.Elem(), segs, idx) || pathExistsIn(t.Elem(), segs, idx+1)
	case reflect.Slice:
		return pathExistsIn(t.Elem(), segs, idx) || pathExistsIn(t.Elem(), segs, idx+1)
	default:
		return false
	}
}
