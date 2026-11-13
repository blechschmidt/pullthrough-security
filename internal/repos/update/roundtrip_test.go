package update

import (
	"bytes"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// roundTripCase is a lock file whose every pinned dependency is moved to a
// made-up version and back.
type roundTripCase struct {
	dir, lock string
	// to names the made-up version for a dependency's version.
	to func(string) string
	// forward and back build the two changes of a dependency.
	forward, back func(d lockfiles.Dependency, to string) Change
}

// TestRoundTrip: moving a dependency to another version and back gives the
// lock file it started from, byte for byte — for every registry dependency
// of every fixture of npm, pip and Cargo. Each move passes Verify.
func TestRoundTrip(t *testing.T) {
	npmCase := func(dir string) roundTripCase {
		return roundTripCase{dir: dir, lock: "package-lock.json",
			to: func(v string) string { return v + "-rt.1" },
			forward: func(d lockfiles.Dependency, to string) Change {
				return npmUpdate(d.Name, d.Version, to, fakeSHA512(d.Name+to))
			},
			back: func(d lockfiles.Dependency, to string) Change {
				return npmUpdate(d.Name, to, d.Version, d.Digests[0].Value)
			}}
	}
	pipCase := func(dir string) roundTripCase {
		return roundTripCase{dir: dir, lock: "requirements.txt",
			to: func(v string) string { return v + ".post7" },
			forward: func(d lockfiles.Dependency, to string) Change {
				return pipUpdate(d.Name, d.Version, to, fakeSHA256(d.Name+to))
			},
			back: func(d lockfiles.Dependency, to string) Change {
				var hs []string
				for _, dg := range d.Digests {
					hs = append(hs, dg.Value)
				}
				if len(hs) == 0 {
					hs = []string{fakeSHA256("unused")}
				}
				return pipUpdate(d.Name, to, d.Version, hs...)
			}}
	}
	cargoCase := func(dir string) roundTripCase {
		return roundTripCase{dir: dir, lock: "Cargo.lock",
			to: func(v string) string { return v + "-rt.1" },
			forward: func(d lockfiles.Dependency, to string) Change {
				return cargoUpdate(d.Name, d.Version, to, fakeSHA256(d.Name+to))
			},
			back: func(d lockfiles.Dependency, to string) Change {
				return cargoUpdate(d.Name, to, d.Version, d.Digests[0].Value)
			}}
	}
	cases := []roundTripCase{
		npmCase("npm-v1"), npmCase("npm-v2"), npmCase("npm-v3"), npmCase("npm-workspaces-v2"), npmCase("npm-workspaces-v3"),
		pipCase("pip-hashes"), pipCase("pip-plain"),
		cargoCase("cargo-v1"), cargoCase("cargo-v3"), cargoCase("cargo-v4"),
	}
	for _, tc := range cases {
		for _, side := range []string{"before", "after"} {
			t.Run(tc.dir+"/"+side, func(t *testing.T) {
				data := fixture(t, tc.dir, side, tc.lock)
				files := map[string][]byte{tc.lock: data}
				u := NativeUpdater(lockfiles.ParseFile(nil, nil, tc.lock, data).Type + "/" + tc.lock)
				moved := 0
				for _, d := range lockfiles.ParseFiles(nil, nil, files)[0].Dependencies {
					if d.Source != lockfiles.SourceRegistry {
						continue
					}
					to := tc.to(d.Version)
					forward := tc.forward(d, to)
					there := apply(t, u, tc.lock, files, []Change{forward})
					if bytes.Equal(there[tc.lock], data) {
						t.Fatalf("moving %s %s changed nothing", d.Name, d.Version)
					}
					back := apply(t, u, tc.lock, there, []Change{tc.back(d, to)})
					sameBytes(t, d.Name+" "+d.Version+" there and back", back[tc.lock], data)
					moved++
				}
				if moved < 4 {
					t.Fatalf("only %d dependencies moved", moved)
				}
			})
		}
	}
}

// TestRoundTripGo: go.mod comes back byte for byte; go.sum keeps the made-up
// version's go.mod hash, as it keeps every old version's.
func TestRoundTripGo(t *testing.T) {
	files := map[string][]byte{
		"go.mod": fixture(t, "go-modules", "before", "go.mod"),
		"go.sum": fixture(t, "go-modules", "before", "go.sum"),
	}
	u := NativeUpdater("go/go.sum")
	parsed := lockfiles.ParseFiles(nil, nil, files)
	moved := 0
	for _, d := range parsed[0].Dependencies {
		var zip, mod string
		for _, dg := range d.Digests {
			if dg.Of == "go.mod" {
				mod = dg.Value
			} else {
				zip = dg.Value
			}
		}
		to := d.Version + "-rt.1"
		there := apply(t, u, "go.sum", files, []Change{goUpdate(d.Name, d.Version, to, fakeH1(d.Name+"zip"), fakeH1(d.Name+"mod"))})
		back := apply(t, u, "go.sum", there, []Change{goUpdate(d.Name, to, d.Version, zip, mod)})
		sameBytes(t, d.Name+" go.mod", back["go.mod"], files["go.mod"])
		var lines []string
		for _, l := range strings.SplitAfter(string(back["go.sum"]), "\n") {
			if !strings.HasPrefix(l, d.Name+" "+to+"/go.mod ") {
				lines = append(lines, l)
			}
		}
		sameBytes(t, d.Name+" go.sum", []byte(strings.Join(lines, "")), files["go.sum"])
		sumSorted(t, there["go.sum"])
		sumSorted(t, back["go.sum"])
		moved++
	}
	if moved != 4 {
		t.Fatalf("%d modules moved, want the 4 go.mod requires", moved)
	}
}

// sumSorted checks that go.sum is in the go command's order.
func sumSorted(t *testing.T, sum []byte) {
	t.Helper()
	var prev sumLine
	for i, l := range strings.Split(strings.TrimSuffix(string(sum), "\n"), "\n") {
		f := strings.Fields(l)
		cur := sumLine{module: f[0], version: f[1]}
		if i > 0 && goSumLess(cur, prev) {
			t.Fatalf("go.sum line %d is out of order: %s", i+1, l)
		}
		prev = cur
	}
}
