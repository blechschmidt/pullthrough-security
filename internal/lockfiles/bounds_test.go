package lockfiles

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// A lock file naming more dependencies than MaxDependenciesPerFile is refused
// as a whole (Task 180): the scans run inside the proxy, and a format of one
// short line per dependency would otherwise turn a few megabytes of a hostile
// file into gigabytes of memory.
func TestHostileLockFileIsRefusedNotHoarded(t *testing.T) {
	var buf bytes.Buffer
	for i := 0; i <= MaxDependenciesPerFile; i++ {
		fmt.Fprintf(&buf, "p%d==1\n", i)
	}
	f := ParseFile(nil, nil, "requirements.txt", buf.Bytes())
	if f.Error == "" || !strings.Contains(f.Error, "more than") || len(f.Dependencies) != 0 {
		t.Fatalf("error %q, %d dependencies", f.Error, len(f.Dependencies))
	}
	// At the bound it is read.
	buf.Reset()
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&buf, "p%d==1\n", i)
	}
	if f := ParseFile(nil, nil, "requirements.txt", buf.Bytes()); f.Error != "" || len(f.Dependencies) != 1000 {
		t.Fatalf("a normal file: %q %d", f.Error, len(f.Dependencies))
	}
}
