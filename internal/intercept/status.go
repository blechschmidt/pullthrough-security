package intercept

// Status describes the interception listeners and their routing table, for the
// admin API.
type Status struct {
	// ForwardProxy, NATHTTPS and NATHTTP are the configured listen addresses
	// ("" for a listener that is not run).
	ForwardProxy string `json:"forwardProxy"`
	NATHTTPS     string `json:"natHttps"`
	NATHTTP      string `json:"natHttp"`
	// Routes is the routing table.
	Routes []Rule `json:"routes"`
	// HostNames are the exact hostnames the proxy intercepts: what a network
	// must send to the NAT listeners (a DNS zone, a hosts file). Wildcard rules
	// are not listed.
	HostNames []string `json:"hostNames"`
	// Wildcards are the wildcard rules ("*.example.com"), which a hosts file
	// cannot express.
	Wildcards []string `json:"wildcards,omitempty"`
	// CASubject is the subject of the CA the leaf certificates are minted by.
	CASubject string `json:"caSubject"`
	// PassthroughUnmatched and AllowPlainHTTP echo the configuration.
	PassthroughUnmatched bool `json:"passthroughUnmatched"`
	AllowPlainHTTP       bool `json:"allowPlainHttp"`
	// Counters are the interception counters.
	Counters MetricsSnapshot `json:"counters"`
}

// Status reports the proxy's listeners, routing table and counters.
func (p *Proxy) Status() Status {
	s := Status{
		ForwardProxy:         p.listenAddr,
		NATHTTPS:             p.natAddr,
		NATHTTP:              p.natHTTPAddr,
		Routes:               p.router.Rules(),
		HostNames:            p.router.HostNames(),
		CASubject:            p.ca.Subject(),
		PassthroughUnmatched: p.passthru,
		AllowPlainHTTP:       p.plainHTTP,
		Counters:             p.metrics.Snapshot(),
	}
	if s.Routes == nil {
		s.Routes = []Rule{}
	}
	if s.HostNames == nil {
		s.HostNames = []string{}
	}
	for _, r := range s.Routes {
		if len(r.Rule) > 2 && r.Rule[:2] == "*." {
			host, _, _ := ParseRule(r.Rule)
			if len(s.Wildcards) == 0 || s.Wildcards[len(s.Wildcards)-1] != host {
				s.Wildcards = append(s.Wildcards, host)
			}
		}
	}
	return s
}

// CACertPEM returns the PEM of the CA clients must trust.
func (p *Proxy) CACertPEM() []byte { return p.ca.CertPEM() }
