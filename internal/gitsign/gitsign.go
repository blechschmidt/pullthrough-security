// Package gitsign signs Git commits the way git itself does with
// gpg.format=ssh (Task 182): an SSHSIG signature (OpenSSH's PROTOCOL.sshsig)
// in the "git" namespace over the commit object without its signature header,
// armored exactly as `ssh-keygen -Y sign` writes it. Git stores that text in
// the commit's "gpgsig" header, and `git verify-commit` with
// gpg.format=ssh and an allowed-signers file checks it through ssh-keygen.
//
// Signing happens in process: neither gpg nor ssh-keygen is run, and the
// private key never reaches a file or another process. The repository
// maintenance updater signs the commits it pushes with it (see
// watch.CommitSigner).
//
// Supported keys are the ones git users sign with: Ed25519, ECDSA on the
// NIST curves P-256, P-384 and P-521, and RSA of at least 2048 bits, which —
// as ssh-keygen does — signs with rsa-sha2-512 rather than SHA-1. Every
// primitive used (SHA-512, Ed25519, ECDSA, RSA PKCS #1 v1.5) is FIPS 186-5 /
// 180-4 approved and comes from the standard library.
package gitsign

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// The SSHSIG format (OpenSSH PROTOCOL.sshsig).
const (
	sigMagic   = "SSHSIG"
	sigVersion = 1
	// Namespace is the signature namespace git signs and verifies commits in
	// (`ssh-keygen -Y sign -n git`). A signature made for another namespace
	// does not verify as a commit signature, and the other way round.
	Namespace = "git"
	// sigHash is the hash the message is reduced with before signing:
	// ssh-keygen's default, and what git's signatures carry.
	sigHash = "sha512"

	armorBegin = "-----BEGIN SSH SIGNATURE-----"
	armorEnd   = "-----END SSH SIGNATURE-----"
	// armorWidth is the length of a base64 line in ssh-keygen's armor
	// (sshbuf_dtob64 wraps at 70 columns).
	armorWidth = 70

	// minRSABits is the smallest RSA key accepted: what FIPS 186-5 and
	// current OpenSSH guidance call the minimum.
	minRSABits = 2048
)

// SSHSigner signs commits with an OpenSSH private key in the SSHSIG format git
// uses for gpg.format=ssh. It is safe for concurrent use.
type SSHSigner struct {
	signer ssh.AlgorithmSigner
	// algo is the signature algorithm: the key type, except for RSA, which
	// signs with rsa-sha2-512.
	algo string
	pub  ssh.PublicKey
}

// NewSSHSigner parses an SSH private key — the OpenSSH format ssh-keygen
// writes ("-----BEGIN OPENSSH PRIVATE KEY-----"), or PKCS #1, PKCS #8 or SEC 1
// PEM — and returns a signer for it. passphrase decrypts an encrypted key; it
// may be nil for one that is not encrypted (and is ignored for a key that turns
// out not to be). Ed25519, ECDSA (P-256, P-384, P-521) and RSA keys of at
// least 2048 bits are accepted; anything else — DSA, security-key ("sk-")
// keys, short RSA keys — is refused.
func NewSSHSigner(privateKeyPEM []byte, passphrase []byte) (*SSHSigner, error) {
	raw, err := parsePrivateKey(privateKeyPEM, passphrase)
	if err != nil {
		return nil, err
	}
	var algo string
	switch k := raw.(type) {
	case *ed25519.PrivateKey:
		if k == nil || len(*k) != ed25519.PrivateKeySize {
			return nil, errors.New("gitsign: malformed Ed25519 key")
		}
		raw, algo = *k, ssh.KeyAlgoED25519
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return nil, errors.New("gitsign: malformed Ed25519 key")
		}
		algo = ssh.KeyAlgoED25519
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			algo = ssh.KeyAlgoECDSA256
		case elliptic.P384():
			algo = ssh.KeyAlgoECDSA384
		case elliptic.P521():
			algo = ssh.KeyAlgoECDSA521
		default:
			return nil, fmt.Errorf("gitsign: ECDSA keys must be on P-256, P-384 or P-521, not %s", k.Curve.Params().Name)
		}
	case *rsa.PrivateKey:
		if bits := k.N.BitLen(); bits < minRSABits {
			return nil, fmt.Errorf("gitsign: the RSA key has %d bits; at least %d are required", bits, minRSABits)
		}
		// As ssh-keygen does: an RSA key signs with SHA-512, never with the
		// SHA-1 of the "ssh-rsa" algorithm.
		algo = ssh.KeyAlgoRSASHA512
	default:
		return nil, fmt.Errorf("gitsign: unsupported key type %T (use an Ed25519, ECDSA or RSA key)", raw)
	}
	s, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, fmt.Errorf("gitsign: %w", err)
	}
	as, ok := s.(ssh.AlgorithmSigner)
	if !ok {
		return nil, fmt.Errorf("gitsign: the key cannot sign with %s", algo)
	}
	return &SSHSigner{signer: as, algo: algo, pub: s.PublicKey()}, nil
}

// parsePrivateKey decodes the key, decrypting it with passphrase when it is
// encrypted. Errors never quote the key.
func parsePrivateKey(pemBytes, passphrase []byte) (any, error) {
	if len(passphrase) == 0 {
		k, err := ssh.ParseRawPrivateKey(pemBytes)
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, errors.New("gitsign: the signing key is encrypted; a passphrase is required")
		}
		if err != nil {
			return nil, fmt.Errorf("gitsign: parsing the signing key: %w", err)
		}
		return k, nil
	}
	k, err := ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase)
	if err == nil {
		return k, nil
	}
	// A passphrase configured for a key that is not encrypted is not needed:
	// such a key parses without it. An encrypted key does not, and keeps the
	// error the passphrase got (a wrong passphrase, say).
	if plain, perr := ssh.ParseRawPrivateKey(pemBytes); perr == nil {
		return plain, nil
	}
	return nil, fmt.Errorf("gitsign: decrypting the signing key: %w", err)
}

// SignCommit signs payload — a commit object without its "gpgsig" header — and
// returns the armored signature git stores in that header: the text
// `ssh-keygen -Y sign -n git` writes, ending with a newline.
func (s *SSHSigner) SignCommit(payload []byte) ([]byte, error) {
	digest := sha512.Sum512(payload)
	sig, err := s.signer.SignWithAlgorithm(rand.Reader, signedData(digest[:]), s.algo)
	if err != nil {
		return nil, fmt.Errorf("gitsign: signing: %w", err)
	}
	if sig.Format != s.algo || len(sig.Rest) != 0 {
		return nil, fmt.Errorf("gitsign: the key signed with %q, not %q", sig.Format, s.algo)
	}
	return armor(signatureBlob(s.pub.Marshal(), ssh.Marshal(sig))), nil
}

// PublicKey returns the signing key's public half as an authorized_keys line
// ("ssh-ed25519 AAAA…", without a comment) — what an allowed-signers file
// lists after the signer's principal, and what a forge is given to show the
// commits as verified.
func (s *SSHSigner) PublicKey() string {
	return strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(s.pub)), "\n")
}

// Fingerprint returns the public key's SHA-256 fingerprint as ssh-keygen -l
// prints it ("SHA256:…") — what git's verify-commit names the key by.
func (s *SSHSigner) Fingerprint() string { return ssh.FingerprintSHA256(s.pub) }

// Algorithm returns the signature algorithm the signer uses ("ssh-ed25519",
// "ecdsa-sha2-nistp256", "rsa-sha2-512", …).
func (s *SSHSigner) Algorithm() string { return s.algo }

// signedData is the blob an SSHSIG signature signs: the magic, the namespace,
// the reserved field, the hash algorithm and the message's hash.
func signedData(digest []byte) []byte {
	b := []byte(sigMagic)
	b = appendString(b, []byte(Namespace))
	b = appendString(b, nil) // reserved
	b = appendString(b, []byte(sigHash))
	return appendString(b, digest)
}

// signatureBlob is the SSHSIG signature: the magic, the version, the public key,
// the namespace, the reserved field, the hash algorithm and the signature (the
// SSH wire encoding of its format and blob).
func signatureBlob(publicKey, signature []byte) []byte {
	b := []byte(sigMagic)
	b = binary.BigEndian.AppendUint32(b, sigVersion)
	b = appendString(b, publicKey)
	b = appendString(b, []byte(Namespace))
	b = appendString(b, nil) // reserved
	b = appendString(b, []byte(sigHash))
	return appendString(b, signature)
}

// appendString appends an SSH "string": a big-endian uint32 length and the
// bytes.
func appendString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

// armor writes blob the way ssh-keygen does: the BEGIN line, the standard
// (padded) base64 of the blob in lines of 70 characters, the END line, each
// line ending with a newline.
func armor(blob []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(blob)
	var b strings.Builder
	b.Grow(len(enc) + len(enc)/armorWidth + len(armorBegin) + len(armorEnd) + 4)
	b.WriteString(armorBegin)
	b.WriteByte('\n')
	for len(enc) > armorWidth {
		b.WriteString(enc[:armorWidth])
		b.WriteByte('\n')
		enc = enc[armorWidth:]
	}
	b.WriteString(enc)
	b.WriteByte('\n')
	b.WriteString(armorEnd)
	b.WriteByte('\n')
	return []byte(b.String())
}
