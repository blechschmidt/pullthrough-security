package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
)

// CodeRedemption is the token-endpoint request of an OpenID Connect relying
// party that swaps an authorization code for tokens (RFC 6749 §4.1.3).
type CodeRedemption struct {
	// TokenEndpoint is the provider's token endpoint.
	TokenEndpoint string
	// Code and Verifier are the authorization code and the PKCE code verifier
	// of the sign-in it belongs to.
	Code     string
	Verifier string
	// RedirectURL is the redirect URI the code was issued for. The provider
	// compares it with the one of the authorization request.
	RedirectURL string
	// ClientID identifies the client. ClientSecret, when set, authenticates it
	// with HTTP Basic (RFC 6749 §2.3.1); empty makes it a public client, which
	// PKCE alone binds the code to.
	ClientID     string
	ClientSecret string
}

// TokenResponse is the provider's answer to a code redemption: whatever the
// HTTP status, as long as the body was a JSON object. Only the members a relying
// party needs are read, and only those that are strings by the specification;
// a provider's own spelling of anything else (Azure AD's v1 endpoint sends
// "expires_in" as a string) cannot make an answer unreadable.
type TokenResponse struct {
	// StatusCode is the HTTP status of the answer.
	StatusCode int `json:"-"`

	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	// ErrorCodes is Microsoft Entra ID's list of AADSTS numbers, kept as sent:
	// it is read only by hasEntraCode, which tolerates any shape.
	ErrorCodes json.RawMessage `json:"error_codes"`

	// CrossOrigin reports that the request this answers carried an Origin
	// header (see CodeRedeemer).
	CrossOrigin bool `json:"-"`
}

// maxTokenResponse bounds what is read of a token-endpoint answer.
const maxTokenResponse = 1 << 20

// Microsoft Entra ID's AADSTS numbers for the two halves of its rule on
// cross-origin redemption (see CodeRedeemer).
const (
	// entraCrossOriginOnly: a code issued to a redirect URI registered on the
	// "Single-page application" platform may only be redeemed cross-origin.
	entraCrossOriginOnly = 9002327
	// entraNoCrossOrigin: cross-origin redemption is permitted only for that
	// platform.
	entraNoCrossOrigin = 9002326
)

// CodeRedeemer redeems the authorization codes of one client. It is safe for
// concurrent use; the zero value uses http.DefaultClient.
//
// It knows one provider-specific rule. Microsoft Entra ID types each redirect
// URI by the platform it was registered under, and redeems a code issued to a
// "Single-page application" URI only in a cross-origin request — one that
// carries an Origin header. A server-side relying party sends none, and Entra
// refuses with AADSTS9002327. The rule has an inverse: a code issued to a "Web"
// or "Mobile and desktop" URI redeemed with an Origin header is refused with
// AADSTS9002326. So the header is never sent before Entra has asked for it.
//
// A public client refused with AADSTS9002327 asks again at once, with the
// origin of its redirect URI as the Origin, and remembers that its redirect URI
// needs it: every later redemption sends the header on the first attempt
// (until a refusal with AADSTS9002326 says the registration changed). Should
// the refused attempt have spent the code, the immediate second attempt fails
// and the user's next sign-in succeeds. A confidential client is never retried
// that way: Entra does not accept a client secret in a cross-origin
// redemption, and a registration that needs one should have no secret.
type CodeRedeemer struct {
	// Client performs the requests. Nil means http.DefaultClient.
	Client *http.Client

	// crossOrigin is set once the provider has said that this client's codes
	// are redeemed only cross-origin.
	crossOrigin atomic.Bool
}

// Redeem posts a code redemption to the token endpoint and returns the answer.
// It returns an error only when no answer could be read: the request failed, or
// the body is not JSON. A refusal is an answer; the caller decides what it
// means.
func (c *CodeRedeemer) Redeem(ctx context.Context, req CodeRedemption) (*TokenResponse, error) {
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	origin := ""
	if req.ClientSecret == "" {
		origin = originOf(req.RedirectURL)
	}
	if origin == "" {
		return postCodeRedemption(ctx, client, req, "")
	}

	if c.crossOrigin.Load() {
		tr, err := postCodeRedemption(ctx, client, req, origin)
		if err != nil || !tr.hasEntraCode(entraNoCrossOrigin) {
			return tr, err
		}
		// The redirect URI has been registered on another platform since.
		c.crossOrigin.Store(false)
		return postCodeRedemption(ctx, client, req, "")
	}
	tr, err := postCodeRedemption(ctx, client, req, "")
	if err != nil || !tr.hasEntraCode(entraCrossOriginOnly) {
		return tr, err
	}
	c.crossOrigin.Store(true)
	return postCodeRedemption(ctx, client, req, origin)
}

func postCodeRedemption(ctx context.Context, client *http.Client, req CodeRedemption, origin string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", req.Code)
	form.Set("redirect_uri", req.RedirectURL)
	form.Set("code_verifier", req.Verifier)
	// Sent by a confidential client too: it lets a provider identify the
	// client before it has decided how to authenticate it.
	form.Set("client_id", req.ClientID)

	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, req.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hr.Header.Set("Accept", "application/json")
	if origin != "" {
		hr.Header.Set("Origin", origin)
	}
	if req.ClientSecret != "" {
		// RFC 6749 §2.3.1: the id and the secret are form-encoded first.
		hr.SetBasicAuth(url.QueryEscape(req.ClientID), url.QueryEscape(req.ClientSecret))
	}
	resp, err := client.Do(hr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	if err != nil {
		return nil, fmt.Errorf("reading the token endpoint's answer: %w", err)
	}
	tr := &TokenResponse{}
	if err := json.Unmarshal(data, tr); err != nil {
		return nil, fmt.Errorf("the token endpoint answered %d with a body that is not JSON", resp.StatusCode)
	}
	tr.StatusCode = resp.StatusCode
	tr.CrossOrigin = origin != ""
	return tr, nil
}

// hasEntraCode reports whether the answer is a refusal that carries the given
// Microsoft Entra ID AADSTS number. The numbers are Microsoft's stable
// identifiers for an error, unlike the prose around them; a false positive
// costs one more request, not a wrong decision.
func (tr *TokenResponse) hasEntraCode(code int64) bool {
	if tr == nil || tr.Error == "" {
		return false
	}
	var codes []json.Number
	dec := json.NewDecoder(strings.NewReader(string(tr.ErrorCodes)))
	dec.UseNumber()
	if len(tr.ErrorCodes) > 0 && dec.Decode(&codes) == nil {
		for _, c := range codes {
			if n, err := c.Int64(); err == nil && n == code {
				return true
			}
		}
	}
	return strings.Contains(tr.ErrorDescription, fmt.Sprintf("AADSTS%d", code))
}

// originOf returns the scheme://host[:port] of a URL, or "" when it has none.
func originOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + u.Host
}

// IssuerMismatch is the error of a discovery document that declares an issuer
// other than the configured one. OpenID Connect Discovery §4.3 forbids using
// such a document: it could direct sign-ins to endpoints of someone else's
// choosing. The message says how to configure a provider that publishes its
// metadata under an alias of its issuer, as Microsoft Entra ID does for a
// tenant addressed by its domain name.
func IssuerMismatch(discoveryURL, declared, configured string) error {
	return fmt.Errorf("the discovery document at %s declares issuer %q, not the configured %q; "+
		"tokens carry the declared one, so if %s is an alias of the provider you mean "+
		"(Microsoft Entra ID publishes https://login.microsoftonline.com/<tenant domain>/v2.0 "+
		"under the tenant ID), set issuer to %q and discoveryUrl to %q",
		discoveryURL, declared, configured, discoveryURL, declared, discoveryURL)
}
