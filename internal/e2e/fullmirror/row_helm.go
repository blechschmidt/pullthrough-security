//go:build integration
// +build integration

package fullmirror

// Helm: the adapter polls the chart repository's index.yaml conditionally and
// diffs it against a stored copy, one record per chart version. The feed is
// the stub registry's own index.yaml, rebuilt — with a new ETag and a later
// Last-Modified — whenever a chart is published; nothing is served in front
// of it. A version is reported once it has been listed for feed option settle,
// which the suite sets to zero.
//
// The adapter keeps the index's validators, its ETag and its Last-Modified, in
// the cursor with the copy, and sends them unless a version held back by
// settle is due (never, with settle zero): the restarted proxy's first request
// for index.yaml carries the ones the stub answered with before the stop
// (conditionalPoll, feedkit.go).

func init() {
	poll := conditionalPoll{path: "/index.yaml"}
	register(row{
		Type:    "helm",
		Feed:    "the repository's `index.yaml`, polled conditionally (ETag, Last-Modified)",
		Start:   func(*feedEnv) error { return nil },
		Publish: poll.publish,
		Options: func(*feedEnv) map[string]string {
			return map[string]string{"settle": "0s"}
		},
		Resumed: poll.resumed,
	})
}
