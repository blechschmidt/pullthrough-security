//go:build !race

package update

// raceEnabled says the race detector runs: it slows the timed tests down
// several times over.
const raceEnabled = false
