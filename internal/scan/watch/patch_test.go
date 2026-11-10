package watch

import "testing"

const sampleDiff = `diff --git a/main.go b/main.go
index 111..222 100644
--- a/main.go
+++ b/main.go
@@ -1,3 +1,4 @@
 package main
+import "fmt"
 func main() {}
-// old
diff --git a/secret.txt b/secret.txt
new file mode 100644
index 000..333
--- /dev/null
+++ b/secret.txt
@@ -0,0 +1,2 @@
+AKIA1234567890ABCDEF
+line two
diff --git a/old.txt b/old.txt
deleted file mode 100644
index 444..000
--- a/old.txt
+++ /dev/null
@@ -1 +0,0 @@
-gone
diff --git a/image.png b/image.png
new file mode 100644
index 000..555
Binary files /dev/null and b/image.png differ
`

func TestParsePatch(t *testing.T) {
	files := parsePatch(sampleDiff, 0, 0)
	if len(files) != 4 {
		t.Fatalf("file count = %d, want 4", len(files))
	}

	byPath := map[string]int{}
	for i, f := range files {
		byPath[f.Path] = i
	}

	main := files[byPath["main.go"]]
	if main.Status != "M" {
		t.Errorf("main.go status = %q, want M", main.Status)
	}
	if main.Additions != 1 || main.Deletions != 1 {
		t.Errorf("main.go +%d -%d, want +1 -1", main.Additions, main.Deletions)
	}
	if main.Patch == "" {
		t.Errorf("main.go patch empty")
	}

	secret := files[byPath["secret.txt"]]
	if secret.Status != "A" {
		t.Errorf("secret.txt status = %q, want A", secret.Status)
	}
	if secret.Additions != 2 {
		t.Errorf("secret.txt additions = %d, want 2", secret.Additions)
	}

	old := files[byPath["old.txt"]]
	if old.Status != "D" {
		t.Errorf("old.txt status = %q, want D", old.Status)
	}

	img := files[byPath["image.png"]]
	if !img.Binary {
		t.Errorf("image.png not marked binary")
	}
	if img.Patch != "" {
		t.Errorf("binary file should not retain patch text")
	}
}

func TestParsePatchRename(t *testing.T) {
	const d = `diff --git a/from.txt b/to.txt
similarity index 95%
rename from from.txt
rename to to.txt
index 111..222 100644
--- a/from.txt
+++ b/to.txt
@@ -1 +1 @@
-hello
+hello world
`
	files := parsePatch(d, 0, 0)
	if len(files) != 1 {
		t.Fatalf("file count = %d, want 1", len(files))
	}
	f := files[0]
	if f.Status != "R" {
		t.Errorf("status = %q, want R", f.Status)
	}
	if f.Path != "to.txt" {
		t.Errorf("path = %q, want to.txt", f.Path)
	}
	if f.OldPath != "from.txt" {
		t.Errorf("oldPath = %q, want from.txt", f.OldPath)
	}
}

func TestParsePatchMaxFiles(t *testing.T) {
	files := parsePatch(sampleDiff, 2, 0)
	if len(files) != 2 {
		t.Fatalf("file count = %d, want 2 (capped)", len(files))
	}
}

func TestParsePatchTruncate(t *testing.T) {
	files := parsePatch(sampleDiff, 0, 20)
	for _, f := range files {
		if f.Binary {
			continue
		}
		if len(f.Patch) > 60 { // 20 + truncation marker
			t.Fatalf("patch not truncated: %d bytes", len(f.Patch))
		}
	}
}

func TestParseCommitMeta(t *testing.T) {
	// Fields separated by US (0x1f); body last.
	meta := "abc123\x1fp1 p2\x1fAlice\x1falice@example.com\x1f2024-01-02T03:04:05Z\x1fBob\x1fbob@example.com\x1f2024-01-02T03:04:06Z\x1fSubject line\n\nBody text\n"
	c, err := parseCommitMeta(meta)
	if err != nil {
		t.Fatalf("parseCommitMeta: %v", err)
	}
	if c.SHA != "abc123" {
		t.Errorf("sha = %q", c.SHA)
	}
	if len(c.Parents) != 2 || c.Parents[0] != "p1" {
		t.Errorf("parents = %v", c.Parents)
	}
	if c.AuthorName != "Alice" || c.AuthorEmail != "alice@example.com" {
		t.Errorf("author = %q <%q>", c.AuthorName, c.AuthorEmail)
	}
	if c.CommitterName != "Bob" {
		t.Errorf("committer = %q", c.CommitterName)
	}
	if c.Subject() != "Subject line" {
		t.Errorf("subject = %q", c.Subject())
	}
	if c.AuthorDate.IsZero() || c.CommitDate.IsZero() {
		t.Errorf("dates not parsed")
	}
}
