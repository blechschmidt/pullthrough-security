//go:build integration
// +build integration

package fullmirror

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/e2e/pkgscan"
)

// Helpers the rows' feeds share.

// writeJSON answers with v as a JSON document.
func writeJSON(w http.ResponseWriter, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// requestURI returns the request URI of a line of MirrorStub.Requests,
// "<method> <uri> -> <status>".
func requestURI(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ""
	}
	return fields[1]
}

// requestPath returns the path of a line of MirrorStub.Requests, without the
// query.
func requestPath(line string) string {
	path, _, _ := strings.Cut(requestURI(line), "?")
	return path
}

// How the restarted proxy read the feed. Resumed is handed the lines of the
// requests the stub received from the restarted proxy; how it asked — the
// validators and the range it sent — is in the stub's log (pkgscan.Request).
// The runner notes where in the log the restarted proxy's requests begin
// (restartLogKey), once the first proxy has stopped and before the late
// package is published; restartLog returns the log from there on.

// restartLogKey is the key under which the runner keeps (feedEnv.set) the
// position in the stub's log where the restarted proxy's requests begin.
const restartLogKey = "restart-log"

// restartLog returns the stub's log of the requests Resumed is handed: from
// where the runner noted the restart, request for request the lines it took.
func restartLog(env *feedEnv, requests []string) ([]pkgscan.Request, error) {
	from, ok := env.get(restartLogKey).(int)
	if !ok {
		return nil, fmt.Errorf("the runner noted no restart")
	}
	log := env.Stub.Log()
	if len(log)-from < len(requests) {
		return nil, fmt.Errorf("the stub's log holds %d requests after the restart, fewer than the %d the suite took", len(log)-from, len(requests))
	}
	log = log[from : from+len(requests)]
	for i, line := range requests {
		if log[i].String() != line {
			return nil, fmt.Errorf("the stub's log after the restart is not the requests the suite took: %s where it took %s", log[i], line)
		}
	}
	return log, nil
}

// conditionalPoll is the Resumed check of a row whose adapter polls an index
// document conditionally, keeping the validators of the copy it read last in
// its cursor: the restarted proxy's first request for the document carries
// the validators the stub answered it with before the stop — If-None-Match
// with its ETag and If-Modified-Since with its Last-Modified, both of which
// every such adapter sends (pollfeed.go httpValidators.set) — rather than read
// it afresh. An adapter that lost its cursor's validators, or its copy, across
// the restart asks unconditionally.
type conditionalPoll struct {
	// path is the document's request path.
	path string
}

// publish notes, at every publication while the proxy runs, the validators
// the stub serves the document with: the last ones are those of the copy the
// mirror holds when it is stopped. The late package is published while it is
// stopped; the validators then stay those of the copy.
func (c conditionalPoll) publish(env *feedEnv, added []publication) error {
	for _, p := range added {
		if p.Variant == pkgLate {
			return nil
		}
	}
	status, _, hdr := env.Stub.Fetch(c.path)
	if status != http.StatusOK || hdr.Get("ETag") == "" || hdr.Get("Last-Modified") == "" {
		return fmt.Errorf("the stub registry answers %s with %d, ETag %q, Last-Modified %q", c.path, status, hdr.Get("ETag"), hdr.Get("Last-Modified"))
	}
	env.set("validators "+c.path, http.Header{"If-None-Match": {hdr.Get("ETag")}, "If-Modified-Since": {hdr.Get("Last-Modified")}})
	return nil
}

// resumed checks the restarted proxy's first request for the document.
func (c conditionalPoll) resumed(env *feedEnv, requests []string) error {
	want, ok := env.get("validators " + c.path).(http.Header)
	if !ok {
		return fmt.Errorf("no validators of %s were noted before the restart", c.path)
	}
	log, err := restartLog(env, requests)
	if err != nil {
		return err
	}
	for _, r := range log {
		if path, _, _ := strings.Cut(r.URI, "?"); path != c.path {
			continue
		}
		for _, h := range []string{"If-None-Match", "If-Modified-Since"} {
			if got := r.Header.Get(h); got != want.Get(h) {
				return fmt.Errorf("the restarted proxy's first request for %s carried %s %q, want %q, which the stub answered it with before the stop (%s)", c.path, h, got, want.Get(h), r)
			}
		}
		return nil
	}
	return fmt.Errorf("the restarted proxy did not ask for %s", c.path)
}
