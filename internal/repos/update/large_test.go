package update

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestLargeFiles: the largest lock files of each format are rewritten in one
// pass, and a hostile requirement spread over a million lines is refused
// without being taken apart.
func TestLargeFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("builds large lock files")
	}
	timed := func(t *testing.T, what string, size int, run func() error) {
		t.Helper()
		start := time.Now()
		err := run()
		took := time.Since(start)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		t.Logf("%s: %d MB in %v", what, size>>20, took)
		if !raceEnabled && took > 2*time.Second {
			t.Errorf("%s: %d MB took %v", what, size>>20, took)
		}
	}

	var req bytes.Buffer
	for i := 0; req.Len() < 30<<20; i++ {
		fmt.Fprintf(&req, "pkg-%d==1.0.%d \\\n    --hash=sha256:%s \\\n    --hash=sha256:%s\n    # via app\n", i, i%9, fakeSHA256("a"), fakeSHA256("b"))
	}
	req.WriteString("idna==3.7 \\\n    --hash=sha256:" + fakeSHA256("i") + "\n")
	timed(t, "requirements.txt", req.Len(), func() error {
		_, err := NativeUpdater("pip/requirements.txt").Apply("requirements.txt", map[string][]byte{"requirements.txt": req.Bytes()},
			[]Change{pipUpdate("idna", "3.7", "3.8", fakeSHA256("new")), pipUpdate("pkg-77", "1.0.5", "1.0.6", fakeSHA256("p"))})
		return err
	})

	var lock bytes.Buffer
	lock.WriteString("version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n")
	for i := 0; i < 60_000; i++ {
		fmt.Fprintf(&lock, " \"crate-%06d\",\n", i)
	}
	lock.WriteString("]\n")
	for i := 0; lock.Len() < 15<<20; i++ {
		fmt.Fprintf(&lock, "\n[[package]]\nname = \"crate-%06d\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"%s\"\ndependencies = [\n \"itoa\",\n]\n", i, fakeSHA256("c"))
	}
	lock.WriteString("\n[[package]]\nname = \"itoa\"\nversion = \"1.0.10\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"" + fakeSHA256("i") + "\"\n")
	timed(t, "Cargo.lock", lock.Len(), func() error {
		_, err := NativeUpdater("cargo/Cargo.lock").Apply("Cargo.lock", map[string][]byte{"Cargo.lock": lock.Bytes()}, cargoUpdates[:1])
		return err
	})

	var sum bytes.Buffer
	for i := 0; sum.Len() < 30<<20; i++ {
		fmt.Fprintf(&sum, "example.com/m%07d v1.0.0 h1:%s\nexample.com/m%07d v1.0.0/go.mod h1:%s\n", i, fakeH1("z"), i, fakeH1("m"))
	}
	mod := "module x\n\nrequire example.com/m0000777 v1.0.0\n"
	timed(t, "go.sum", sum.Len(), func() error {
		_, err := NativeUpdater("go/go.mod").Apply("go.mod", map[string][]byte{"go.mod": []byte(mod), "go.sum": sum.Bytes()},
			[]Change{goUpdate("example.com/m0000777", "v1.0.0", "v1.0.1", fakeH1("z1"), fakeH1("m1"))})
		return err
	})

	hostile := "idna==3.7 " + strings.Repeat("\\\n", 1_000_000) + "\n"
	start := time.Now()
	_, err := NativeUpdater("pip/requirements.txt").Apply("requirements.txt", map[string][]byte{"requirements.txt": []byte(hostile)},
		[]Change{pipUpdate("idna", "3.7", "3.8", fakeSHA256("x"))})
	if err == nil || !strings.Contains(err.Error(), "more than 10000 lines") {
		t.Fatalf("a requirement over a million lines: %v", err)
	}
	if took := time.Since(start); !raceEnabled && took > 2*time.Second {
		t.Errorf("refusing it took %v", took)
	}
}
