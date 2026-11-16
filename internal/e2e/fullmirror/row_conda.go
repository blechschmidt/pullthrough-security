//go:build integration
// +build integration

package fullmirror

// Conda: the adapter polls each followed subdir's repodata.json.zst (the plain
// repodata.json where a channel has none) conditionally and diffs it against a
// stored copy. The feed is the stub channel's own noarch/repodata.json,
// rebuilt — with a new ETag and a later Last-Modified — whenever a package is
// published; the channel has no .zst, which the adapter asks for at every poll
// and is told 404. Feed options: the subdirs the channel has, settle zero.
//
// The adapter keeps, per subdir, the validators of the document that answered
// — its ETag and its Last-Modified — in the cursor with the copy: the
// restarted proxy's first request for noarch/repodata.json, the subdir the
// packages are published in, carries the ones the stub answered with before
// the stop (conditionalPoll, feedkit.go). (linux-64's, which lists nothing,
// is answered 304 at every poll and keeps the Last-Modified of its first
// read.)

func init() {
	poll := conditionalPoll{path: "/noarch/repodata.json"}
	register(row{
		Type:    "conda",
		Feed:    "the channel's `noarch/repodata.json` (no `.zst`), polled conditionally",
		Start:   func(*feedEnv) error { return nil },
		Publish: poll.publish,
		Options: func(*feedEnv) map[string]string {
			return map[string]string{"subdirs": "noarch,linux-64", "settle": "0s"}
		},
		Resumed: poll.resumed,
	})
}
