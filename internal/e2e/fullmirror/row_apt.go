//go:build integration
// +build integration

package fullmirror

// APT: the adapter polls each suite's InRelease conditionally and reads, by
// hash and verified, the Packages indexes whose SHA-256 changed, diffing a
// stored copy. The feed is the stub archive's own dists/stable tree, rebuilt
// — a new Packages, a newly signed InRelease naming its hashes — whenever a
// package is published. Feed options: the suite, component and architecture
// the archive has.
//
// The adapter keeps InRelease's validators, its ETag and its Last-Modified,
// in the cursor with the copy (feed_apt.go readRelease): the restarted proxy's
// first request for InRelease carries the ones the stub answered with before
// the stop (conditionalPoll, below).

func init() {
	poll := conditionalPoll{path: "/dists/stable/InRelease"}
	register(row{
		Type:    "apt",
		Feed:    "the archive's `dists/stable/InRelease` and the Packages files it names, polled conditionally",
		Start:   func(*feedEnv) error { return nil },
		Publish: poll.publish,
		Options: func(*feedEnv) map[string]string {
			return map[string]string{"suites": "stable", "components": "main", "architectures": "amd64"}
		},
		Resumed: poll.resumed,
	})
}
