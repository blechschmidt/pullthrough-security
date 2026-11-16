//go:build integration
// +build integration

package fullmirror

// YUM: the adapter polls repodata/repomd.xml conditionally and, when the
// primary it names changed, streams the primary into a stored copy it diffs.
// The feed is the stub repository's own repodata, rebuilt — a new primary
// under a new name, repomd.xml with a new ETag and a later Last-Modified —
// whenever a package is published.
//
// The adapter keeps repomd.xml's validators, its ETag and its Last-Modified,
// in the cursor with the copy (feed_yum.go readIndex): the restarted proxy's
// first request for repomd.xml carries the ones the stub answered with before
// the stop (conditionalPoll, feedkit.go).

func init() {
	poll := conditionalPoll{path: "/repodata/repomd.xml"}
	register(row{
		Type:    "yum",
		Feed:    "the repository's `repodata/repomd.xml` and the primary it names, polled conditionally",
		Start:   func(*feedEnv) error { return nil },
		Publish: poll.publish,
		Options: func(*feedEnv) map[string]string { return nil },
		Resumed: poll.resumed,
	})
}
