//go:build integration
// +build integration

package fullmirror

// CRAN: the adapter polls src/contrib/PACKAGES.gz (the plain PACKAGES where a
// repository has none) conditionally and diffs it against a stored copy; each
// package's current version is mirrored as its source tarball. The feed is the
// stub repository's own PACKAGES, rebuilt — with a new ETag and a later
// Last-Modified — whenever a package is published; settle zero.
//
// The adapter keeps the validators of the document that answered, its ETag
// and its Last-Modified, in the cursor with the copy: after asking for
// PACKAGES.gz again (404), the restarted proxy's first request for PACKAGES
// carries the ones the stub answered with before the stop (conditionalPoll,
// feedkit.go).

func init() {
	poll := conditionalPoll{path: "/src/contrib/PACKAGES"}
	register(row{
		Type:    "cran",
		Feed:    "the repository's `src/contrib/PACKAGES` (no `.gz`), polled conditionally",
		Start:   func(*feedEnv) error { return nil },
		Publish: poll.publish,
		Options: func(*feedEnv) map[string]string {
			return map[string]string{"settle": "0s"}
		},
		Resumed: poll.resumed,
	})
}
