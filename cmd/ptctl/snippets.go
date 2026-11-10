package main

import "github.com/blechschmidt/pullthrough-security/internal/onboard"

// snippet is one generated client-configuration artifact. The generator logic
// lives in internal/onboard so the CLI and the tenant self-service portal share
// a single source of truth; this alias keeps the CLI's existing call sites.
type snippet = onboard.Snippet

// snippetContext carries the resolved inputs every generator needs.
type snippetContext struct {
	proxyBase string // e.g. https://proxy.example.com (no trailing slash)
	host      string // e.g. proxy.example.com[:port]
	tenant    string
	token     string
}

// snippetsFor produces the client-config snippets for one backend, delegating to
// the shared onboard package.
func snippetsFor(ctx snippetContext, b backend) []snippet {
	return onboard.For(onboard.Context{
		ProxyBase: ctx.proxyBase,
		Host:      ctx.host,
		Tenant:    ctx.tenant,
		Token:     ctx.token,
	}, onboard.Backend{Name: b.Name, Type: b.Type, URL: b.URL})
}

// withUserinfo embeds a token as the userinfo of a URL when a token is set.
func withUserinfo(raw, token string) string {
	return onboard.WithUserinfo(raw, token)
}

// orUnknown renders an empty backend type as "unknown" for display.
func orUnknown(t string) string {
	if t == "" {
		return "unknown"
	}
	return t
}
