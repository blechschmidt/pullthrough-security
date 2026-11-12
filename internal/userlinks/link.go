package userlinks

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Bounds on what a record stores. Everything in a record except the times and
// the hash was written by an identity provider or typed by a user.
const (
	maxSubjectLen = 256
	maxNameLen    = 128
	maxEmailLen   = 254
	maxTeamLen    = 128
	maxRoleLen    = 128
	maxRoles      = 64
	maxIssuerLen  = 512
	maxLabelLen   = 64
	maxReasonLen  = 256
	maxAddrLen    = 64
	maxAgentLen   = 128
)

// Identity is who a link belongs to, as the identity provider described them
// when they signed in.
type Identity struct {
	// Subject is what the download log, the audit trail and every other record
	// call the user: by default their e-mail address (Config.OIDC.SubjectClaim).
	Subject string `json:"subject"`
	// Name and Email are for display.
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	// Team is the tenant the user belongs to. It selects quotas, rate limits and
	// per-tenant policy, exactly as a static token's team does.
	Team string `json:"team,omitempty"`
	// Roles are the RBAC roles the user holds on the pull path (auth.roles).
	Roles []string `json:"roles,omitempty"`
	// Issuer is the identity provider that vouched for the user, and
	// OIDCSubject its own stable identifier for them ("sub") — which does not
	// change when an e-mail address does.
	Issuer      string `json:"issuer,omitempty"`
	OIDCSubject string `json:"oidcSubject,omitempty"`
}

// ErrBadSubject is returned for an identity whose subject cannot be used as
// one: it is empty, too long, or contains control or invisible characters.
var ErrBadSubject = errors.New("userlinks: the identity has no usable subject")

// normalize bounds and cleans an identity. The subject is the one field that is
// not repaired: it is the key every record is found by, and a subject that had
// to be altered to be storable would be a different subject. Such an identity
// is refused.
func (id Identity) normalize() (Identity, error) {
	subject := CanonicalSubject(id.Subject)
	if subject == "" || len(subject) > maxSubjectLen || cleanText(subject, maxSubjectLen) != subject {
		return Identity{}, ErrBadSubject
	}
	out := Identity{
		Subject:     subject,
		Name:        cleanText(id.Name, maxNameLen),
		Email:       cleanText(id.Email, maxEmailLen),
		Team:        cleanText(id.Team, maxTeamLen),
		Issuer:      cleanText(id.Issuer, maxIssuerLen),
		OIDCSubject: cleanText(id.OIDCSubject, maxSubjectLen),
	}
	seen := map[string]struct{}{}
	for _, role := range id.Roles {
		role = cleanText(role, maxRoleLen)
		if role == "" {
			continue
		}
		if _, dup := seen[role]; dup {
			continue
		}
		seen[role] = struct{}{}
		out.Roles = append(out.Roles, role)
		if len(out.Roles) == maxRoles {
			break
		}
	}
	sort.Strings(out.Roles)
	return out, nil
}

// subjectKey is the object key of a user's records: a hash of the subject,
// which can be any text, in the characters object names are made of.
func subjectKey(subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(sum[:16])
}

// Link is one personal link as the registry stores it. It is written once, when
// the link is created, and never changed: revoking a link adds a Revocation
// next to it.
type Link struct {
	// ID is the link's public identifier (see linkIDFromHash).
	ID string `json:"id"`
	// TokenHash is the SHA-256 of the link's token. The token itself is not
	// stored anywhere.
	TokenHash string `json:"tokenHash"`
	Identity
	// Label is the name the user gave the link ("laptop", "ci").
	Label string `json:"label,omitempty"`
	// CreatedAt is when the link was created; ExpiresAt when it stops working.
	// A zero ExpiresAt means it does not expire.
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt,omitzero"`
	// CreatedFrom is the client address the link was created from.
	CreatedFrom string `json:"createdFrom,omitempty"`
	// IssuedBy names the administrator who issued the link on the user's
	// behalf. It is empty for a link the user created after signing in.
	IssuedBy string `json:"issuedBy,omitempty"`
}

// validate checks a link read from the store. The store is the registry's own,
// but it is also a directory an operator can edit and a bucket other software
// can write to; a record that does not hold together is skipped, not trusted.
func (l *Link) validate(hash string) error {
	if !validHex(l.TokenHash, sha256.Size*2) {
		return errors.New("the token hash is not a SHA-256")
	}
	if hash != "" && l.TokenHash != hash {
		return errors.New("the token hash does not match the object's name")
	}
	if l.ID != linkIDFromHash(l.TokenHash) {
		return errors.New("the id does not belong to the token hash")
	}
	if l.CreatedAt.IsZero() {
		return errors.New("the creation time is missing")
	}
	id, err := l.Identity.normalize()
	if err != nil {
		return err
	}
	l.Identity = id
	l.Label = cleanText(l.Label, maxLabelLen)
	l.CreatedFrom = cleanText(l.CreatedFrom, maxAddrLen)
	l.IssuedBy = cleanText(l.IssuedBy, maxSubjectLen)
	return nil
}

// expired reports whether the link's lifetime is over at now.
func (l *Link) expired(now time.Time) bool {
	return !l.ExpiresAt.IsZero() && !now.Before(l.ExpiresAt)
}

// Revocation records that one link was revoked. Its presence is what matters;
// the rest is for whoever asks why.
type Revocation struct {
	ID        string    `json:"id"`
	Subject   string    `json:"subject,omitempty"`
	RevokedAt time.Time `json:"revokedAt"`
	// By is who revoked it: the user themselves, or an administrator.
	By     string `json:"by,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Block invalidates everything issued to one user up to a moment in time: every
// link created at or before NotBefore, and every sign-in session started by
// then. It is how "revoke all of this user's links" is said in one write that
// also covers a link another replica created a second ago, and how a user who
// left is signed out of the self-service page.
//
// It is a watermark, not a ban: a user who can still sign in at the identity
// provider can sign in again afterwards and create new links.
type Block struct {
	Subject   string    `json:"subject"`
	NotBefore time.Time `json:"notBefore"`
	By        string    `json:"by,omitempty"`
	Reason    string    `json:"reason,omitempty"`
}

// Usage is when a link was last used, and from where.
type Usage struct {
	LastUsedAt time.Time `json:"lastUsedAt"`
	LastAddr   string    `json:"lastAddr,omitempty"`
	LastAgent  string    `json:"lastAgent,omitempty"`
}

// merge folds another observation of the same link into u: the later one wins.
func (u Usage) merge(other Usage) Usage {
	if other.LastUsedAt.After(u.LastUsedAt) {
		return other
	}
	return u
}

// usageFile is one replica's usage object: what it has seen of each link.
type usageFile struct {
	Node      string           `json:"node"`
	UpdatedAt time.Time        `json:"updatedAt"`
	Links     map[string]Usage `json:"links"`
}

// State is what a link is good for right now.
type State string

const (
	// StateActive: the link works.
	StateActive State = "active"
	// StateExpired: the link's lifetime is over.
	StateExpired State = "expired"
	// StateRevoked: the link was revoked — itself, or with everything else that
	// was issued to its user.
	StateRevoked State = "revoked"
)

// Info is a link as the console and the APIs show it: the record, its state,
// and when it was last used. It carries no token and no token hash.
type Info struct {
	ID string `json:"id"`
	Identity
	Label       string     `json:"label,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	CreatedFrom string     `json:"createdFrom,omitempty"`
	IssuedBy    string     `json:"issuedBy,omitempty"`

	State State `json:"state"`
	// RevokedAt, RevokedBy and RevokeReason explain a revoked link.
	RevokedAt    *time.Time `json:"revokedAt,omitempty"`
	RevokedBy    string     `json:"revokedBy,omitempty"`
	RevokeReason string     `json:"revokeReason,omitempty"`

	// LastUsedAt, LastAddr and LastAgent say when the link was last used, from
	// which address and by which client tool — as seen by any replica.
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	LastAddr   string     `json:"lastAddr,omitempty"`
	LastAgent  string     `json:"lastAgent,omitempty"`
}

// cleanText returns s without control and invisible format characters or
// invalid UTF-8, trimmed, and cut to at most max bytes on a rune boundary.
//
// Format characters — bidirectional overrides, zero-width joiners — are removed
// and not merely escaped: these strings are names and labels shown to people
// deciding whose link something is, and a name must not be able to render as
// another one.
func cleanText(s string, max int) string {
	plain := len(s) <= max
	if plain {
		for i := 0; i < len(s); i++ {
			if c := s[i]; c < 0x20 || c >= 0x7f {
				plain = false
				break
			}
		}
	}
	if plain {
		return strings.TrimSpace(s)
	}
	var b strings.Builder
	b.Grow(min(len(s), max))
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) ||
			r == ' ' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if len(out) <= max {
		return out
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(out[cut]) {
		cut--
	}
	return strings.TrimSpace(out[:cut])
}

// timePtr returns a pointer to t, or nil for the zero time.
func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// lowerASCII lower-cases the ASCII letters of s and leaves every other
// character as it is. Unicode case mapping is deliberately not used on names:
// it maps characters of other scripts onto ASCII letters (U+212A KELVIN SIGN
// becomes "k"), which would let one account's address become another's.
func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// CanonicalSubject is the spelling under which the registry knows a user. An
// identity provider's "sub" is case-sensitive and is taken as it is; a subject
// that is an e-mail address — what users are called by default — is not, and
// is lower-cased (ASCII only), as at sign-in. An operator who types
// "Alice@Example.com" means the user who signed in as alice@example.com.
func CanonicalSubject(subject string) string {
	subject = strings.TrimSpace(subject)
	if strings.Contains(subject, "@") {
		return lowerASCII(subject)
	}
	return subject
}

// objectNames of the registry's layout.
func linkObject(hash string) string     { return "link/" + hash }
func revokedObject(id string) string    { return "revoked/" + id }
func blockObject(subject string) string { return "block/" + subjectKey(subject) }
func usageObject(node string) string    { return "usage/" + node }

// nodeName turns a replica's name into one an object can be named after.
func nodeName(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	var b strings.Builder
	for i := 0; i < len(raw) && b.Len() < 100; i++ {
		c := raw[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_':
			b.WriteByte(c)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.TrimLeft(b.String(), ".-")
	if out == "" {
		return "node"
	}
	return out
}

// errorf formats a registry error.
func errorf(format string, args ...any) error {
	return fmt.Errorf("userlinks: "+format, args...)
}
