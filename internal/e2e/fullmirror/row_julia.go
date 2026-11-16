//go:build integration
// +build integration

package fullmirror

import (
	"bytes"
	"net/http"
	"time"
)

// Julia: the adapter diffs the Pkg server's registry snapshots: /registries
// names each registry's current tree hash, and a registry whose hash changed is
// read through the proxy (/registry/<uuid>/<hash>) and its Registry.toml and
// Versions.toml files indexed. The feed is the stub Pkg server's own
// /registries and registry tarball, rebuilt — a new tree hash — whenever a
// package is published; each version is mirrored as its package tarball.
//
// A Pkg server answers /registries with a redirect (302) to the list of the
// flavour the client prefers, /registries.<flavour>: "conservative", the
// default — a snapshot the storage servers hold every resource of — or
// "eager", the newest, named by the header Julia-Registry-Preference, which
// the adapter sends (feed option flavor) and the client follows. The LLM
// package-scan suite's Pkg server answers /registries with the list itself, so
// the stub serves the redirect in front of it and both flavoured lists — the
// registry's own list, served as the registry serves it: its storage holds
// every resource the registry names, so its conservative snapshot is its
// newest.
//
// The adapter reads the list unconditionally — the list itself is its cursor
// — so this row has no Resumed check of how it was read. A restarted adapter
// that lost the index it stored of the cursor's snapshot finds its cursor
// invalid and enumerates the registry again, which the suite's own checks of
// the restart catch.

func init() {
	register(row{
		Type:    "julia",
		Feed:    "the Pkg server's `/registries` (302 to `/registries.<flavour>`) and registry snapshots (tree hashes)",
		Start:   juliaFeedStart,
		Options: func(*feedEnv) map[string]string { return nil },
		Notes: []string{
			"no Resumed check of its own: the adapter reads /registries unconditionally (the list is its cursor), so a restart shows in nothing it sends; a lost stored index invalidates the cursor, which the suite's no-new-enumeration checks catch",
		},
	})
}

func juliaFeedStart(env *feedEnv) error {
	env.Stub.Handle("/registries", func(w http.ResponseWriter, r *http.Request) {
		// Any preference but eager gets the default.
		flavour := "conservative"
		if r.Header.Get("Julia-Registry-Preference") == "eager" {
			flavour = "eager"
		}
		http.Redirect(w, r, "/registries."+flavour, http.StatusFound)
	})
	for _, flavour := range []string{"conservative", "eager"} {
		env.Stub.Handle("/registries."+flavour, func(w http.ResponseWriter, r *http.Request) {
			status, body, hdr := env.Stub.Fetch("/registries")
			if status != http.StatusOK {
				http.Error(w, "the stub registry serves no registry list", http.StatusInternalServerError)
				return
			}
			for _, h := range []string{"Content-Type", "ETag"} {
				if v := hdr.Get(h); v != "" {
					w.Header().Set(h, v)
				}
			}
			modTime, _ := http.ParseTime(hdr.Get("Last-Modified"))
			http.ServeContent(w, r, "", modTime.UTC().Truncate(time.Second), bytes.NewReader(body))
		})
	}
	return nil
}
