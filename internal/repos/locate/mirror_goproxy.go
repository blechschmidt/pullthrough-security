package locate

// GoEscapePath applies the module proxy protocol's case encoding to a module
// path or version — an upper-case letter becomes "!" and its lower-case form
// ("github.com/BurntSushi/toml" is "github.com/!burnt!sushi/toml") — exactly
// as the Go locator spells the paths it names. The full-mirror feed adapter
// (Task 190) reads a module's "@v/list" at the path escaped this way. A path
// with a "!" or a non-ASCII character cannot be escaped and is an error.
func GoEscapePath(s string) (string, error) { return goEscape(s) }
