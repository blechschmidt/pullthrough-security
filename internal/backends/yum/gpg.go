package yum

import (
	"bytes"
	"errors"
	"fmt"

	//lint:ignore SA1019 x/crypto/openpgp is frozen but remains the only in-tree
	// implementation of detached PGP verification; it is used here purely to
	// validate a repository's repomd.xml signature against an operator-pinned
	// trusted key, layered on top of the checksum content chain as defense in depth.
	"golang.org/x/crypto/openpgp"
)

// GPG validation of repomd.xml is the cryptographic root of an RPM repository's
// trust: it binds the metadata manifest (and therefore the whole primary/.rpm
// checksum chain) to a key the operator pins out of band. The proxy verifies it
// when — and only when — a trusted keyring is configured for the upstream;
// otherwise it falls back to the checksum content chain alone (recorded via
// metrics). A configured-but-invalid signature is a hard failure: repomd.xml is
// refused rather than served, so a stripped or forged signature cannot downgrade
// the repository to unsigned.

// keyring wraps a parsed set of trusted public keys for an upstream. A nil
// *keyring means no GPG enforcement is configured.
type keyring struct {
	entities openpgp.EntityList
}

// loadKeyring parses one or more ASCII-armored (or binary) public keys. An empty
// input yields a nil keyring (enforcement disabled); a non-empty but unparseable
// input is an error so a misconfigured key fails fast at startup.
func loadKeyring(armored []byte) (*keyring, error) {
	if len(bytes.TrimSpace(armored)) == 0 {
		return nil, nil
	}
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		el, err = openpgp.ReadKeyRing(bytes.NewReader(armored))
		if err != nil {
			return nil, fmt.Errorf("yum: parsing GPG keyring: %w", err)
		}
	}
	if len(el) == 0 {
		return nil, errors.New("yum: GPG keyring contains no keys")
	}
	return &keyring{entities: el}, nil
}

// enabled reports whether GPG enforcement is configured.
func (k *keyring) enabled() bool { return k != nil && len(k.entities) > 0 }

// verifyDetached validates a detached signature (repomd.xml.asc) over the
// repomd.xml bytes against the keyring, accepting both the armored and binary
// signature encodings.
func (k *keyring) verifyDetached(signed, sig []byte) error {
	if !k.enabled() {
		return nil
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(k.entities, bytes.NewReader(signed), bytes.NewReader(sig)); err == nil {
		return nil
	}
	if _, err := openpgp.CheckDetachedSignature(k.entities, bytes.NewReader(signed), bytes.NewReader(sig)); err != nil {
		return fmt.Errorf("yum: repomd.xml signature is not from a trusted key: %w", err)
	}
	return nil
}
