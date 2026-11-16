//go:build race

package fullmirror

// raceEnabled says the race detector runs: it slows the large tests down
// tenfold, so they scale down, and makes their memory figures meaningless.
const raceEnabled = true
