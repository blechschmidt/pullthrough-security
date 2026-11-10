package tracing

// Attr is a single span/resource attribute. Values are one of string, int64,
// bool, or float64; other types are rendered as their string form at export.
type Attr struct {
	Key   string
	Value any
}

// String constructs a string-valued attribute.
func String(key, value string) Attr { return Attr{Key: key, Value: value} }

// Int constructs an int64-valued attribute from an int.
func Int(key string, value int) Attr { return Attr{Key: key, Value: int64(value)} }

// Int64 constructs an int64-valued attribute.
func Int64(key string, value int64) Attr { return Attr{Key: key, Value: value} }

// Bool constructs a bool-valued attribute.
func Bool(key string, value bool) Attr { return Attr{Key: key, Value: value} }

// Float64 constructs a double-valued attribute.
func Float64(key string, value float64) Attr { return Attr{Key: key, Value: value} }

// StringIf returns a string attribute only when value is non-empty, and a
// zero Attr (empty key) otherwise. The exporter skips empty-key attributes, so
// passing one for an absent optional coordinate emits nothing on the wire.
func StringIf(key, value string) Attr {
	if value == "" {
		return Attr{}
	}
	return Attr{Key: key, Value: value}
}
