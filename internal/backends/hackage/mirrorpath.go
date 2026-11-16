package hackage

// SdistPath returns the path, relative to the upstream's mount, of a release's
// source tarball in the short form cabal-install and Stack request:
// "/package/<name>-<version>.tar.gz". The backend caches each spelling of an
// sdist path under its own key, so the full mirror (Task 190) must fetch the
// form clients ask for, not the long "/package/<id>/<id>.tar.gz" one.
//
// ok is false when name or version is not one the backend accepts, or when
// the built path would not classify back as the sdist of exactly that name and
// version: the path is checked with classify, the parser Resolve uses, so what
// SdistPath returns is a path Resolve caches under that coordinate.
func SdistPath(name, version string) (path string, ok bool) {
	if !validPackageName(name) || !validVersion(version) {
		return "", false
	}
	p := "/package/" + name + "-" + version + sdistExt
	r, ok := classify(p)
	if !ok || r.kind != kindSdist || r.name != name || r.version != version {
		return "", false
	}
	return p, true
}
