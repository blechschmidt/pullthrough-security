//go:build race

package yum

// streamRaceEnabled says the race detector runs: it slows the large tests down
// tenfold, so they scale down, and makes their memory figures meaningless.
const streamRaceEnabled = true
