//go:build integration
// +build integration

package fullmirror

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// pip: the adapter follows PyPI's journal through the XML-RPC API — POST
// <index>/pypi, changelog_since_serial(serial) for the rows after the serial it
// stored, changelog_last_serial() for the head — after listing the index's
// projects from the PEP 691 JSON project list (GET <index>/simple/ with Accept
// application/vnd.pypi.simple.v1+json), whose meta._last-serial is where the
// changelog continues. Each project's versions come from its simple page, read
// through the proxy. The row runs the adapter's default mode, auto, which
// follows the changelog where the index serves one.
//
// The stub serves both as Warehouse does, computed from the publications at
// request time: the journal of a new project's first upload — "create", "add
// Owner …", "new release" and "add py3 file <wheel>", one serial each, stamped
// with the upload's second — in the XML-RPC wire format Python's xmlrpc
// marshaller writes (a method it does not have is a -32601 fault), and the
// project list with each project's last serial, the global one in
// meta._last-serial and X-PyPI-Last-Serial. The simple pages and the wheels
// are the stub registry's own: the pages link the wheels on its files host
// (the upstream's filesUrl).

func init() {
	register(row{
		Type:    "pip",
		Feed:    "XML-RPC `changelog_since_serial`/`changelog_last_serial` at `/pypi`, PEP 691 JSON project list with `_last-serial` at `/simple/`",
		Start:   pipFeedStart,
		Options: func(*feedEnv) map[string]string { return map[string]string{"settle": "0s"} },
		Resumed: pipResumed,
	})
}

// pipJournalRow is one row of the stub index's journal, as
// changelog_since_serial returns it: [name, version or nil, time, action,
// serial].
type pipJournalRow struct {
	name    string
	version string // "" for nil
	time    int64
	action  string
	serial  int64
	variant string
}

// pipOwner is the user every fixture project is uploaded by.
const pipOwner = "pte2e-maintainer"

// pipJournal is the journal of the packages published so far, in serial
// order: the rows Warehouse writes for the first upload of a new project.
func pipJournal(pubs []publication) []pipJournalRow {
	var rows []pipJournalRow
	add := func(p publication, version, action string) {
		rows = append(rows, pipJournalRow{name: p.Pkg.Name, version: version, time: p.Time.Unix(), action: action,
			serial: int64(len(rows) + 1), variant: p.Variant})
	}
	for _, p := range pubs {
		add(p, "", "create")
		add(p, "", "add Owner "+pipOwner)
		add(p, p.Pkg.Version, "new release")
		add(p, p.Pkg.Version, "add py3 file "+path.Base(p.Pkg.Path))
	}
	return rows
}

// pipCall is one XML-RPC call the stub answered: the method, its integer
// arguments, and the journal's last serial when it was answered — which
// packages were published by then.
type pipCall struct {
	method string
	args   []int64
	head   int64
}

func (c pipCall) String() string {
	args := make([]string, len(c.args))
	for i, a := range c.args {
		args[i] = strconv.FormatInt(a, 10)
	}
	return c.method + "(" + strings.Join(args, ", ") + ")"
}

// pipCallLog records the XML-RPC calls the stub answered, in the order it
// answered them, for Resumed: the stub's request log holds no request bodies.
type pipCallLog struct {
	mu    sync.Mutex
	calls []pipCall
}

func (l *pipCallLog) add(c pipCall) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, c)
}

// all returns the calls answered so far.
func (l *pipCallLog) all() []pipCall {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]pipCall(nil), l.calls...)
}

func pipFeedStart(env *feedEnv) error {
	calls := &pipCallLog{}
	env.set("calls", calls)
	env.Stub.Handle("/pypi", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rows := pipJournal(env.Publications())
		head := int64(0)
		if len(rows) > 0 {
			head = rows[len(rows)-1].serial
		}
		method, args, err := pipParseCall(raw)
		calls.add(pipCall{method: method, args: args, head: head})
		if err != nil {
			pipWriteFault(w, -32700, "parse error; "+err.Error())
			return
		}
		switch method {
		case "changelog_last_serial":
			pipWriteResponse(w, pipXMLInt(head))
		case "changelog_since_serial":
			if len(args) != 1 {
				pipWriteFault(w, -32602, "client error; serial: Input should be a valid integer")
				return
			}
			// Warehouse answers the rows after the serial, oldest first, at
			// most 50,000 a call.
			var b strings.Builder
			n := 0
			for _, row := range rows {
				if row.serial <= args[0] || n == 50000 {
					continue
				}
				n++
				version := "<value><nil/></value>"
				if row.version != "" {
					version = pipXMLString(row.version)
				}
				b.WriteString(pipXMLArray(pipXMLString(row.name) + version + pipXMLInt(row.time) +
					pipXMLString(row.action) + pipXMLInt(row.serial)))
			}
			pipWriteResponse(w, pipXMLArray(b.String()))
		default:
			pipWriteFault(w, -32601, "server error; requested method not found")
		}
	})
	env.Stub.Handle("/simple/", func(w http.ResponseWriter, r *http.Request) {
		rows := pipJournal(env.Publications())
		serials := map[string]int64{}
		head := int64(0)
		for _, row := range rows {
			serials[row.name], head = row.serial, row.serial
		}
		names := make([]string, 0, len(serials))
		for n := range serials {
			names = append(names, n)
		}
		sort.Strings(names)
		var body []byte
		// PyPI negotiates the format: PEP 691 JSON for a client that asks
		// for it, the PEP 503 HTML index otherwise.
		if strings.Contains(r.Header.Get("Accept"), "application/vnd.pypi.simple.v1+json") {
			projects := make([]map[string]any, 0, len(names))
			for _, n := range names {
				projects = append(projects, map[string]any{"name": n, "_last-serial": serials[n]})
			}
			var err error
			if body, err = json.Marshal(map[string]any{
				"meta":     map[string]any{"_last-serial": head, "api-version": "1.4"},
				"projects": projects,
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
		} else {
			var b bytes.Buffer
			b.WriteString("<!DOCTYPE html>\n<html>\n  <head>\n    <meta name=\"pypi:repository-version\" content=\"1.4\">\n" +
				"    <title>Simple index</title>\n  </head>\n  <body>\n")
			for _, n := range names {
				fmt.Fprintf(&b, "    <a href=\"/simple/%s/\">%s</a>\n", n, n)
			}
			b.WriteString("  </body>\n</html>\n")
			body = b.Bytes()
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		}
		sum := sha256.Sum256(body)
		w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:12])+`"`)
		w.Header().Set("Vary", "Accept")
		w.Header().Set("X-PyPI-Last-Serial", strconv.FormatInt(head, 10))
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body))
	})
	return nil
}

// pipParseCall reads an XML-RPC methodCall whose params are integers.
func pipParseCall(raw []byte) (string, []int64, error) {
	var call struct {
		XMLName xml.Name `xml:"methodCall"`
		Method  string   `xml:"methodName"`
		Params  []struct {
			Int *string `xml:"value>int"`
			I4  *string `xml:"value>i4"`
		} `xml:"params>param"`
	}
	if err := xml.Unmarshal(raw, &call); err != nil {
		return "", nil, err
	}
	var args []int64
	for _, p := range call.Params {
		v := p.Int
		if v == nil {
			v = p.I4
		}
		if v == nil {
			return call.Method, nil, fmt.Errorf("a parameter that is not an integer")
		}
		n, err := strconv.ParseInt(strings.TrimSpace(*v), 10, 64)
		if err != nil {
			return call.Method, nil, err
		}
		args = append(args, n)
	}
	return strings.TrimSpace(call.Method), args, nil
}

// The XML-RPC wire format, as Python's xmlrpc.client marshaller writes it
// (Warehouse's XML-RPC API answers with it).

func pipXMLInt(n int64) string { return "<value><int>" + strconv.FormatInt(n, 10) + "</int></value>\n" }

func pipXMLString(s string) string {
	s = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
	return "<value><string>" + s + "</string></value>\n"
}

func pipXMLArray(values string) string {
	return "<value><array><data>\n" + values + "</data></array></value>\n"
}

func pipWriteResponse(w http.ResponseWriter, value string) {
	w.Header().Set("Content-Type", "text/xml; charset=UTF-8")
	_, _ = io.WriteString(w, "<?xml version='1.0'?>\n<methodResponse>\n<params>\n<param>\n"+value+"</param>\n</params>\n</methodResponse>\n")
}

func pipWriteFault(w http.ResponseWriter, code int64, message string) {
	w.Header().Set("Content-Type", "text/xml; charset=UTF-8")
	_, _ = io.WriteString(w, "<?xml version='1.0'?>\n<methodResponse>\n<fault>\n<value><struct>\n"+
		"<member>\n<name>faultCode</name>\n"+pipXMLInt(code)+"</member>\n"+
		"<member>\n<name>faultString</name>\n"+pipXMLString(message)+"</member>\n"+
		"</struct></value>\n</fault>\n</methodResponse>\n")
}

// pipResumed: the restarted mirror's first XML-RPC call was
// changelog_since_serial of the serial it had stored — the malicious
// package's last row — none of its calls asked for rows from before it, and it
// did not read the project list. The restarted mirror's calls are told by
// what they were answered from, not by their place in the stub's log: those
// answered while the journal held the late package's rows, which were
// published once the first proxy had stopped.
func pipResumed(env *feedEnv, requests []string) error {
	for _, line := range requests {
		if requestPath(line) == "/simple/" {
			return fmt.Errorf("the project list was read again: %s", line)
		}
	}
	var stored, head int64
	for _, row := range pipJournal(env.Publications()) {
		if row.variant == pkgMalicious {
			stored = row.serial
		}
		head = row.serial
	}
	var restarted []pipCall
	for _, c := range env.get("calls").(*pipCallLog).all() {
		if c.head == head {
			restarted = append(restarted, c)
		}
	}
	switch {
	case len(restarted) == 0:
		return fmt.Errorf("the restarted mirror made no XML-RPC call")
	case restarted[0].method != "changelog_since_serial" || len(restarted[0].args) != 1 || restarted[0].args[0] != stored:
		return fmt.Errorf("the restarted mirror's first XML-RPC call was %s, want changelog_since_serial(%d): the serial it had stored", restarted[0], stored)
	}
	for _, c := range restarted {
		if c.method == "changelog_since_serial" && len(c.args) == 1 && c.args[0] < stored {
			return fmt.Errorf("the restarted mirror called %s, asking for rows from before the serial it had stored (%d)", c, stored)
		}
	}
	return nil
}
