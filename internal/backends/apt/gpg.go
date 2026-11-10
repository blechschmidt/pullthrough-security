package apt

import (
	"bytes"
	"errors"
	"fmt"

	//lint:ignore SA1019 x/crypto/openpgp is frozen but remains the only in-tree
	// implementation of detached/clearsign PGP verification; it is used here purely
	// to validate repository Release signatures against an operator-pinned trusted
	// key, layered on top of the SHA-256 content chain as defense in depth.
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/clearsign"
)

// GPG validation of the Release file is the cryptographic root of an APT
// repository's trust: it binds the SHA-256 file table (and therefore the whole
// index/.deb digest chain) to a key the operator pins out of band. The proxy
// verifies it when — and only when — a trusted keyring is configured for the
// upstream; otherwise it falls back to the SHA-256 content chain alone (recorded
// via metrics). A configured-but-invalid signature is a hard failure: the
// document is refused rather than served, so a stripped or forged signature
// cannot downgrade the repository to unsigned.

// keyring wraps a parsed set of trusted public keys for an upstream. A nil
// *keyring means no GPG enforcement is configured.
type keyring struct {
	entities openpgp.EntityList
}

// loadKeyring parses one or more ASCII-armored (or binary) public keys into a
// keyring. An empty input yields a nil keyring (GPG enforcement disabled). A
// non-empty but unparseable input is an error so a misconfigured key fails fast
// at startup rather than silently disabling verification.
func loadKeyring(armored []byte) (*keyring, error) {
	if len(bytes.TrimSpace(armored)) == 0 {
		return nil, nil
	}
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armored))
	if err != nil {
		// Fall back to a binary keyring before giving up.
		el, err = openpgp.ReadKeyRing(bytes.NewReader(armored))
		if err != nil {
			return nil, fmt.Errorf("apt: parsing GPG keyring: %w", err)
		}
	}
	if len(el) == 0 {
		return nil, errors.New("apt: GPG keyring contains no keys")
	}
	return &keyring{entities: el}, nil
}

// enabled reports whether GPG enforcement is configured.
func (k *keyring) enabled() bool { return k != nil && len(k.entities) > 0 }

// verifyClearsigned validates an inline-clearsigned document (InRelease) against
// the keyring, returning nil on a good signature from a trusted key.
func (k *keyring) verifyClearsigned(data []byte) error {
	if !k.enabled() {
		return nil
	}
	block, _ := clearsign.Decode(data)
	if block == nil {
		return errors.New("apt: InRelease is not a valid PGP clearsigned document")
	}
	if _, err := openpgp.CheckDetachedSignature(k.entities, bytes.NewReader(block.Bytes), block.ArmoredSignature.Body); err != nil {
		return fmt.Errorf("apt: InRelease signature is not from a trusted key: %w", err)
	}
	return nil
}

// verifyDetached validates a detached signature (Release.gpg) over the Release
// bytes against the keyring. It accepts both the armored and binary signature
// encodings APT mirrors publish.
func (k *keyring) verifyDetached(signed, sig []byte) error {
	if !k.enabled() {
		return nil
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(k.entities, bytes.NewReader(signed), bytes.NewReader(sig)); err == nil {
		return nil
	}
	if _, err := openpgp.CheckDetachedSignature(k.entities, bytes.NewReader(signed), bytes.NewReader(sig)); err != nil {
		return fmt.Errorf("apt: Release signature is not from a trusted key: %w", err)
	}
	return nil
}
