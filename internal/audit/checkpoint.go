package audit

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Checkpoint is a signed tree head (STH): a commitment to the Merkle root over
// the first TreeSize records of the log at a point in time. Periodically sealing
// and persisting a Checkpoint is what makes a retroactive edit or deletion
// detectable even to a verifier who does not hold the chain's HMAC key — the
// recomputed root for that prefix would no longer match the sealed RootHash, and
// (when signed) the signature anchors the checkpoint to the operator's key.
type Checkpoint struct {
	// Origin identifies the log, so a checkpoint cannot be replayed against a
	// different log. It is part of the signed material.
	Origin string `json:"origin"`
	// TreeSize is the number of records covered by this checkpoint.
	TreeSize uint64 `json:"treeSize"`
	// RootHash is the hex-encoded Merkle root over the first TreeSize records.
	RootHash string `json:"rootHash"`
	// SealedAt is when the checkpoint was produced.
	SealedAt time.Time `json:"sealedAt"`
	// KeyID identifies the signing key (empty when unsigned).
	KeyID string `json:"keyId,omitempty"`
	// Signature is the base64-encoded signature over signingBytes (empty when
	// unsigned).
	Signature string `json:"signature,omitempty"`
}

// signingBytes returns the canonical, deterministic byte string a Checkpoint's
// signature is computed over. It deliberately excludes KeyID and Signature.
func (c Checkpoint) signingBytes() []byte {
	// A newline-delimited, field-order-fixed encoding (the "checkpoint" note
	// format Sigstore/Go-sumdb use): origin, tree size, root, seal time.
	var b []byte
	b = append(b, c.Origin...)
	b = append(b, '\n')
	b = append(b, strconv.FormatUint(c.TreeSize, 10)...)
	b = append(b, '\n')
	b = append(b, c.RootHash...)
	b = append(b, '\n')
	b = append(b, strconv.FormatInt(c.SealedAt.UTC().UnixNano(), 10)...)
	b = append(b, '\n')
	return b
}

// Signed reports whether the checkpoint carries a signature.
func (c Checkpoint) Signed() bool { return c.Signature != "" }

// Signer signs checkpoints with an operator-supplied private key. The same key
// material conventions as sigverify's trust bundle apply: ECDSA, RSA, and
// Ed25519 keys are supported, and the corresponding public key (loadable via
// sigverify.ParsePublicKeyPEM) verifies the resulting checkpoints.
type Signer struct {
	priv  crypto.Signer
	keyID string
}

// LoadSigner parses a PEM-encoded private key (PKCS#8, SEC1 "EC PRIVATE KEY", or
// PKCS#1 "RSA PRIVATE KEY") and returns a checkpoint Signer.
func LoadSigner(pemData []byte) (*Signer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("audit: no PEM block found in signing key")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("audit: unsupported signing key PEM block type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("audit: parsing signing key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("audit: signing key of type %T does not implement crypto.Signer", key)
	}
	switch signer.Public().(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
	default:
		return nil, fmt.Errorf("audit: unsupported signing key type %T", signer.Public())
	}
	return &Signer{priv: signer, keyID: keyID(signer.Public())}, nil
}

// LoadSignerFile reads and parses a PEM private key from path.
func LoadSignerFile(path string) (*Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("audit: reading signing key: %w", err)
	}
	return LoadSigner(data)
}

// KeyID returns the signer's key identifier.
func (s *Signer) KeyID() string { return s.keyID }

// PublicKey returns the signer's public key, for callers that want to verify.
func (s *Signer) PublicKey() crypto.PublicKey { return s.priv.Public() }

// sign computes and attaches the signature (and KeyID) to a checkpoint.
func (s *Signer) sign(c *Checkpoint) error {
	c.KeyID = s.keyID
	sig, err := signMessage(s.priv, c.signingBytes())
	if err != nil {
		return fmt.Errorf("audit: signing checkpoint: %w", err)
	}
	c.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// signMessage signs msg with the appropriate scheme for the key type: Ed25519
// signs the message directly; ECDSA and RSA sign its SHA-256 digest.
func signMessage(priv crypto.Signer, msg []byte) ([]byte, error) {
	switch priv.Public().(type) {
	case ed25519.PublicKey:
		return priv.Sign(rand.Reader, msg, crypto.Hash(0))
	default:
		digest := sha256.Sum256(msg)
		return priv.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
}

// VerifyCheckpointSignature verifies a checkpoint's signature against pub. pub
// may be obtained from sigverify.ParsePublicKeyPEM, so the audit log reuses the
// same trust material as the signature-verification gate. It returns nil on a
// valid signature.
func VerifyCheckpointSignature(pub crypto.PublicKey, c Checkpoint) error {
	if c.Signature == "" {
		return fmt.Errorf("audit: checkpoint is unsigned")
	}
	sig, err := base64.StdEncoding.DecodeString(c.Signature)
	if err != nil {
		return fmt.Errorf("audit: decoding checkpoint signature: %w", err)
	}
	msg := c.signingBytes()
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(k, msg, sig) {
			return fmt.Errorf("audit: checkpoint signature invalid (ed25519)")
		}
		return nil
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(msg)
		if !ecdsa.VerifyASN1(k, digest[:], sig) {
			return fmt.Errorf("audit: checkpoint signature invalid (ecdsa)")
		}
		return nil
	case *rsa.PublicKey:
		digest := sha256.Sum256(msg)
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig); err != nil {
			return fmt.Errorf("audit: checkpoint signature invalid (rsa): %w", err)
		}
		return nil
	default:
		return fmt.Errorf("audit: unsupported public key type %T", pub)
	}
}

// keyID derives a short, stable identifier from a public key: the first 8 bytes
// of the SHA-256 of its PKIX/DER encoding, hex-encoded.
func keyID(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}

// CheckpointStore is the durable destination for sealed checkpoints. Persisting
// checkpoints out-of-band from the record log is what lets an auditor later
// detect a wholesale rewrite of the record file.
type CheckpointStore interface {
	// Append durably persists one checkpoint.
	Append(ctx context.Context, cp Checkpoint) error
	// All returns every persisted checkpoint, ordered by tree size.
	All(ctx context.Context) ([]Checkpoint, error)
	// Close flushes and releases resources.
	Close() error
}

// MemoryCheckpointStore keeps checkpoints in memory. It is safe for concurrent
// use and is the default when no checkpoint file is configured.
type MemoryCheckpointStore struct {
	mu  sync.Mutex
	cps []Checkpoint
}

// NewMemoryCheckpointStore returns an empty in-memory checkpoint store.
func NewMemoryCheckpointStore() *MemoryCheckpointStore { return &MemoryCheckpointStore{} }

// Append stores a copy of the checkpoint.
func (m *MemoryCheckpointStore) Append(_ context.Context, cp Checkpoint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cps = append(m.cps, cp)
	return nil
}

// All returns a snapshot of stored checkpoints.
func (m *MemoryCheckpointStore) All(_ context.Context) ([]Checkpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Checkpoint, len(m.cps))
	copy(out, m.cps)
	return out, nil
}

// Close is a no-op for the memory store.
func (m *MemoryCheckpointStore) Close() error { return nil }

// FileCheckpointStore is an append-only, newline-delimited-JSON checkpoint store
// backed by a file. Writes are serialized and fsynced.
type FileCheckpointStore struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// NewFileCheckpointStore opens (creating if needed) the checkpoint file for
// appending, with 0600 permissions.
func NewFileCheckpointStore(path string) (*FileCheckpointStore, error) {
	if path == "" {
		return nil, fmt.Errorf("audit: checkpoint store path is required")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("audit: creating checkpoint dir: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: opening checkpoint file: %w", err)
	}
	return &FileCheckpointStore{f: f, path: path}, nil
}

// Append writes one checkpoint as a JSON line and fsyncs it.
func (s *FileCheckpointStore) Append(_ context.Context, cp Checkpoint) error {
	line, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(line); err != nil {
		return err
	}
	return s.f.Sync()
}

// All reads and parses every persisted checkpoint, ordered by tree size.
func (s *FileCheckpointStore) All(_ context.Context) ([]Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return readCheckpointFile(s.path)
}

// Close closes the underlying file.
func (s *FileCheckpointStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// ReadCheckpoints reads and parses every checkpoint from a checkpoint file,
// ordered by tree size. It is used by the verify-audit CLI and does not require
// an open store.
func ReadCheckpoints(path string) ([]Checkpoint, error) {
	return readCheckpointFile(path)
}

func readCheckpointFile(path string) ([]Checkpoint, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: reading checkpoints: %w", err)
	}
	defer f.Close()

	var cps []Checkpoint
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var cp Checkpoint
		if err := json.Unmarshal(line, &cp); err != nil {
			return nil, fmt.Errorf("audit: corrupt checkpoint record: %w", err)
		}
		cps = append(cps, cp)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sortCheckpoints(cps)
	return cps, nil
}

func sortCheckpoints(cps []Checkpoint) {
	// Insertion order is already by tree size for append-only stores; sort
	// defensively in case of out-of-order files.
	for i := 1; i < len(cps); i++ {
		for j := i; j > 0 && cps[j-1].TreeSize > cps[j].TreeSize; j-- {
			cps[j-1], cps[j] = cps[j], cps[j-1]
		}
	}
}
