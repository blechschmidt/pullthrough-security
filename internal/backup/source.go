package backup

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MetadataSource describes one durable sidecar store to capture in a backup, as a
// filesystem path that is either a single file or a directory tree. The backup
// package is deliberately decoupled from the proxy's configuration: the CLI/admin
// layer translates config (audit File, provenance StoreDir, VEX Dir, …) into this
// generic descriptor, exactly as the mirror subsystem keeps the cache and
// provenance stores generic. New stores are added by appending a descriptor, with
// no change to the snapshot format.
type MetadataSource struct {
	// Name is the logical, stable identifier recorded in the manifest and used to
	// match a source to its restore target root. It must be unique within a backup
	// and is restricted to a safe character set (letters, digits, '-', '_').
	Name string
	// Path is the source root on disk: a single file or a directory.
	Path string
	// Optional, when true, lets a backup proceed even if Path does not exist
	// (the source contributes no files). Almost every metadata store is optional
	// because the corresponding subsystem may be disabled.
	Optional bool
}

// validName reports whether a source name is safe to embed in a manifest and to
// match against restore targets. Keeping it conservative avoids any ambiguity
// when names are used as map keys or in diagnostics.
func validName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// validateSources checks that source names are non-empty, valid, and unique.
func validateSources(sources []MetadataSource) error {
	seen := make(map[string]bool, len(sources))
	for _, s := range sources {
		if !validName(s.Name) {
			return fmt.Errorf("backup: invalid metadata source name %q (allowed: letters, digits, '-', '_')", s.Name)
		}
		if seen[s.Name] {
			return fmt.Errorf("backup: duplicate metadata source name %q", s.Name)
		}
		seen[s.Name] = true
	}
	return nil
}

// scannedFile is one captured file within a source, with its slash-separated
// relative path and the absolute path it was read from.
type scannedFile struct {
	relPath string
	absPath string
	size    int64
	mode    fs.FileMode
}

// scanSource enumerates the regular files reachable from a source root,
// returning them sorted by relative path for deterministic output. A
// single-file source yields one entry with the file's base name as its relative
// path. A directory source is walked recursively; symlinks and irregular files
// are skipped (only regular file content is portable and meaningful to restore).
// A missing path is an error unless the source is Optional, in which case it
// yields no files.
func scanSource(src MetadataSource) (kind string, files []scannedFile, err error) {
	info, statErr := os.Stat(src.Path)
	if statErr != nil {
		if os.IsNotExist(statErr) && src.Optional {
			return "tree", nil, nil
		}
		if os.IsNotExist(statErr) {
			return "", nil, fmt.Errorf("backup: metadata source %q path %q does not exist", src.Name, src.Path)
		}
		return "", nil, fmt.Errorf("backup: stating metadata source %q: %w", src.Name, statErr)
	}

	if !info.IsDir() {
		return "file", []scannedFile{{
			relPath: filepath.Base(src.Path),
			absPath: src.Path,
			size:    info.Size(),
			mode:    info.Mode().Perm(),
		}}, nil
	}

	root := filepath.Clean(src.Path)
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			return nil
		}
		// Only regular files carry portable content; skip symlinks, sockets, etc.
		if !d.Type().IsRegular() {
			return nil
		}
		fi, ferr := d.Info()
		if ferr != nil {
			return ferr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		files = append(files, scannedFile{
			relPath: filepath.ToSlash(rel),
			absPath: path,
			size:    fi.Size(),
			mode:    fi.Mode().Perm(),
		})
		return nil
	})
	if walkErr != nil {
		return "", nil, fmt.Errorf("backup: walking metadata source %q: %w", src.Name, walkErr)
	}

	sort.Slice(files, func(i, j int) bool { return files[i].relPath < files[j].relPath })
	return "tree", files, nil
}

// safeJoin joins a restore target root with a relative path from the manifest,
// rejecting any path that is absolute or that would escape the root via ".."
// components (defence against a malicious or corrupt manifest). A backup's own
// paths are always clean relative paths, so a rejection here means the snapshot
// is not trustworthy and must not be applied.
func safeJoin(root, relPath string) (string, error) {
	local := filepath.FromSlash(relPath)
	if filepath.IsAbs(local) {
		return "", fmt.Errorf("backup: refusing to restore absolute path %q", relPath)
	}
	for _, part := range strings.Split(filepath.ToSlash(local), "/") {
		if part == ".." {
			return "", fmt.Errorf("backup: refusing to restore path %q containing '..'", relPath)
		}
	}
	joined := filepath.Join(root, local)
	rootClean := filepath.Clean(root)
	// Belt-and-suspenders: the cleaned join must still be confined to root.
	if joined != rootClean && !strings.HasPrefix(joined, rootClean+string(filepath.Separator)) {
		return "", fmt.Errorf("backup: refusing to restore path %q outside target root", relPath)
	}
	return joined, nil
}
