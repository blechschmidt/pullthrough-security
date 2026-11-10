package terraform

import "strings"

// The Terraform/OpenTofu registry exposes two protocols off a discovery
// document. The route prefix "/v1/<name>" is stripped before classification, so
// the backend sees the registry-native paths (which themselves begin with
// "/v1/") plus the service-discovery well-known path.
//
// Service discovery (synthesized by the proxy, pointing the client back at this
// backend's mount):
//
//	GET /.well-known/terraform.json
//
// Module registry protocol:
//
//	GET /v1/modules/{ns}/{name}/{system}/versions                 version list (live)
//	GET /v1/modules/{ns}/{name}/{system}/{version}/download       X-Terraform-Get (rewritten)
//	GET /v1/modules/{ns}/{name}/{system}/download                 latest download (live)
//	GET /v1/modules/{ns}/{name}/{system}/{version}/archive        source archive (proxy-synthetic, cached)
//
// Provider registry protocol:
//
//	GET /v1/providers/{ns}/{type}/versions                        version list (live)
//	GET /v1/providers/{ns}/{type}/{version}/download/{os}/{arch}  package descriptor (rewritten)
//	GET .../{os}/{arch}/zip                                       provider ZIP (proxy-synthetic, verified+cached)
//	GET .../{os}/{arch}/shasums                                   SHASUMS manifest (proxy-synthetic, cached)
//	GET .../{os}/{arch}/shasums.sig                               SHASUMS signature (proxy-synthetic, cached)
//
// Any other /v1/modules or /v1/providers path is treated as live registry
// metadata (search, get-latest, etc.) and proxied unmodified.

// resourceKind enumerates the classes of resource a Terraform registry path can
// address.
type resourceKind int

const (
	kindOther resourceKind = iota
	// kindDiscovery is the service-discovery well-known document, synthesized by
	// the proxy to advertise this backend's module/provider endpoints.
	kindDiscovery
	// kindModuleVersions is a module version-list document (live).
	kindModuleVersions
	// kindModuleDownload is the module download endpoint whose X-Terraform-Get is
	// rewritten to the proxy archive endpoint (live).
	kindModuleDownload
	// kindModuleArchive is the proxy-synthetic module source archive: fetched from
	// the resolved X-Terraform-Get and cached.
	kindModuleArchive
	// kindModuleMeta is any other module-API path, proxied live.
	kindModuleMeta
	// kindProviderVersions is a provider version-list document (live).
	kindProviderVersions
	// kindProviderDownload is the provider package descriptor whose artifact URLs
	// are rewritten to proxy-synthetic endpoints (live).
	kindProviderDownload
	// kindProviderZip is the proxy-synthetic provider ZIP: fetched, SHA-256- and
	// signature-verified against the signed SHASUMS, and cached.
	kindProviderZip
	// kindProviderShasums is the proxy-synthetic SHASUMS manifest (cached).
	kindProviderShasums
	// kindProviderShasumsSig is the proxy-synthetic SHASUMS signature (cached).
	kindProviderShasumsSig
	// kindProviderMeta is any other provider-API path, proxied live.
	kindProviderMeta
)

// resource is the parsed classification of an inbound Terraform registry path.
type resource struct {
	kind      resourceKind
	namespace string
	name      string // module name (modules) or provider type (providers)
	system    string // module target system (modules only)
	version   string
	os        string // provider target OS (providers only)
	arch      string // provider target arch (providers only)
}

const (
	discoveryPath = ".well-known/terraform.json"
)

// classify parses an inbound path (route prefix already stripped, leading slash
// retained) into a resource. It returns ok=false for paths that cannot be
// expressed in the Terraform registry layout.
func classify(p string) (resource, bool) {
	clean := strings.Trim(p, "/")
	if clean == "" {
		return resource{}, false
	}
	segs := strings.Split(clean, "/")
	for _, s := range segs {
		// Reject empty segments and any path traversal; the upstream URL is built
		// from the cleaned path, so every segment must be inert.
		if s == "" || s == "." || s == ".." {
			return resource{}, false
		}
	}

	if clean == discoveryPath {
		return resource{kind: kindDiscovery}, true
	}

	if len(segs) < 2 || segs[0] != "v1" {
		return resource{}, false
	}
	switch segs[1] {
	case "modules":
		return classifyModule(segs)
	case "providers":
		return classifyProvider(segs)
	default:
		return resource{}, false
	}
}

// classifyModule parses a /v1/modules/... path.
func classifyModule(segs []string) (resource, bool) {
	// /v1/modules/{ns}/{name}/{system}/...
	if len(segs) < 5 {
		return resource{kind: kindModuleMeta}, true
	}
	r := resource{namespace: segs[2], name: segs[3], system: segs[4]}
	switch len(segs) {
	case 6:
		switch segs[5] {
		case "versions":
			r.kind = kindModuleVersions
			return r, true
		case "download":
			r.kind = kindModuleDownload // latest-version download
			return r, true
		}
	case 7:
		r.version = segs[5]
		switch segs[6] {
		case "download":
			r.kind = kindModuleDownload
			return r, true
		case "archive":
			r.kind = kindModuleArchive
			return r, true
		}
	}
	r.kind = kindModuleMeta
	r.version = ""
	return r, true
}

// classifyProvider parses a /v1/providers/... path.
func classifyProvider(segs []string) (resource, bool) {
	// /v1/providers/{ns}/{type}/...
	if len(segs) < 5 {
		return resource{kind: kindProviderMeta}, true
	}
	r := resource{namespace: segs[2], name: segs[3]}
	if len(segs) == 5 && segs[4] == "versions" {
		r.kind = kindProviderVersions
		return r, true
	}
	// /v1/providers/{ns}/{type}/{version}/download/{os}/{arch}[/zip|/shasums|/shasums.sig]
	if len(segs) >= 8 && segs[5] == "download" {
		r.version = segs[4]
		r.os = segs[6]
		r.arch = segs[7]
		if len(segs) == 8 {
			r.kind = kindProviderDownload
			return r, true
		}
		if len(segs) == 9 {
			switch segs[8] {
			case "zip":
				r.kind = kindProviderZip
				return r, true
			case "shasums":
				r.kind = kindProviderShasums
				return r, true
			case "shasums.sig":
				r.kind = kindProviderShasumsSig
				return r, true
			}
		}
	}
	r.kind = kindProviderMeta
	return r, true
}

// coordinateName returns the logical artifact name for the admission gates:
// "{ns}/{name}/{system}" for modules, "{ns}/{type}" for providers. The version
// is carried separately on the Coordinate.
func (r resource) coordinateName() string {
	switch {
	case r.isModule():
		if r.namespace == "" || r.name == "" || r.system == "" {
			return ""
		}
		return r.namespace + "/" + r.name + "/" + r.system
	case r.isProvider():
		if r.namespace == "" || r.name == "" {
			return ""
		}
		return r.namespace + "/" + r.name
	default:
		return ""
	}
}

func (r resource) isModule() bool {
	switch r.kind {
	case kindModuleVersions, kindModuleDownload, kindModuleArchive, kindModuleMeta:
		return true
	default:
		return false
	}
}

func (r resource) isProvider() bool {
	switch r.kind {
	case kindProviderVersions, kindProviderDownload, kindProviderZip,
		kindProviderShasums, kindProviderShasumsSig, kindProviderMeta:
		return true
	default:
		return false
	}
}

// cacheable reports whether the resolved resource may be cached. Only the
// immutable proxy-synthetic artifacts (the module archive, the provider ZIP, and
// the SHASUMS manifest/signature) are cached; version lists, download
// descriptors, discovery, and registry metadata are served live.
func (r resource) cacheable() bool {
	switch r.kind {
	case kindModuleArchive, kindProviderZip, kindProviderShasums, kindProviderShasumsSig:
		return true
	default:
		return false
	}
}

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindDiscovery:
		return "discovery"
	case kindModuleVersions:
		return "module-versions"
	case kindModuleDownload:
		return "module-download"
	case kindModuleArchive:
		return "module-archive"
	case kindModuleMeta:
		return "module-meta"
	case kindProviderVersions:
		return "provider-versions"
	case kindProviderDownload:
		return "provider-download"
	case kindProviderZip:
		return "provider-zip"
	case kindProviderShasums:
		return "provider-shasums"
	case kindProviderShasumsSig:
		return "provider-shasums-sig"
	case kindProviderMeta:
		return "provider-meta"
	default:
		return "other"
	}
}
