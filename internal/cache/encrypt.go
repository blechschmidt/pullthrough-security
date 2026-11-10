package cache

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// This file implements the at-rest encryption envelope (Task 141): a Store
// decorator that transparently encrypts artifact bytes with AES-256-GCM before
// they reach the durable byte store (filesystem or S3), and decrypts them on the
// way back out. It is an envelope scheme:
//
//   - Each object is encrypted with a fresh, random 256-bit data-encryption key
//     (DEK) generated per write.
//   - The DEK is itself wrapped (encrypted) with a key-encryption key (KEK)
//     resolved through the Task 133 secrets provider abstraction (env/file/vault),
//     and the wrapped DEK is stored in the object's metadata sidecar alongside the
//     KEK id that wrapped it. The KEK never touches disk.
//
// It composes with the compaction/dedup decorator (Task 125): the wiring places
// this layer INNERMOST (wrapping the durable store) and compaction OUTERMOST, so
// compression and cross-artifact chunk deduplication both run over plaintext and
// are entirely unaffected — this layer only encrypts whatever physical bytes
// compaction hands it, one encrypted object (or chunk) at a time.
//
// The digest-over-plaintext invariant is preserved: this layer records, in the
// sidecar, the digest and length of the bytes it was handed (its "plaintext")
// and restores them onto the Record it projects back to the caller, so cache
// addressing, dedup, read-time integrity verification (Task 107), and range
// serving (Task 75) all keep working against the logical content — never the
// ciphertext. The inner store's own digest (computed over ciphertext) is an
// implementation detail that never escapes this layer.
//
// Payloads are encrypted as a sequence of independently authenticated frames
// (a STREAM-style construction) so arbitrarily large artifacts encrypt and
// decrypt with bounded memory, and so truncation, reordering, and bit-flips are
// all detected by GCM authentication rather than trusted.

// Reserved metadata keys persisted in Record.Extra. They form the per-object
// encryption sidecar: how to unwrap the DEK and reverse the transform. They are
// stripped from the Record projected back to the caller so they never leak into
// Stat.Metadata. The "pte." prefix (pull-through encryption) is reserved: any
// caller-supplied key with this prefix is dropped on write. The prefix is
// disjoint from the compaction layer's "ptc." prefix, so the two decorators
// never collide.
const (
	metaEncFmt     = "pte.fmt"     // storage format marker: "aesgcm" (else plaintext/legacy)
	metaEncAlg     = "pte.alg"     // AEAD algorithm name ("AES-256-GCM")
	metaEncKEK     = "pte.kek"     // id of the KEK that wrapped this object's DEK
	metaEncDEK     = "pte.dek"     // base64(wrapNonce || GCM-sealed DEK)
	metaEncPDigest = "pte.pdigest" // digest over the plaintext bytes ("sha256:...")
	metaEncPSize   = "pte.psize"   // plaintext length in bytes
	metaEncFrame   = "pte.fs"      // streaming frame size used for this object

	pteReservedPrefix = "pte."

	encFmtAES = "aesgcm"
	encAlgAES = "AES-256-GCM"

	// dekLen is the data-encryption-key length: 32 bytes selects AES-256.
	dekLen = 32
	// kekLen is the derived key-encryption-key length (AES-256).
	kekLen = 32
	// gcmNonceLen is the AES-GCM nonce length (96 bits, the approved default).
	gcmNonceLen = 12
	// gcmTagLen is the AES-GCM authentication tag length (128 bits).
	gcmTagLen = 16

	// defaultFrameSize is the plaintext size of each streaming AEAD frame. 64 KiB
	// balances per-frame overhead (16-byte tag + 5-byte header) against memory.
	defaultFrameSize = 64 * 1024
	// maxFrameSize bounds the configurable frame size so a hostile or corrupt
	// sidecar cannot force an unbounded allocation on read.
	maxFrameSize = 16 * 1024 * 1024

	// hkdfInfo domain-separates passphrase-derived KEKs for this subsystem.
	hkdfInfo = "pullthrough-cache-kek-v1"
)

// encStreamMagic prefixes every encrypted payload so a misrouted or corrupt blob
// is rejected before any frame is processed. It is not security-critical (each
// frame is independently authenticated); it is a fail-fast sanity marker.
var encStreamMagic = []byte("PTEAES1\n")

// ErrEncryptionDisabled is returned by the rotation/stat forwarding helpers when
// no encryption layer is present in the cache stack.
var ErrEncryptionDisabled = errors.New("cache: at-rest encryption is not enabled")

// KEK is a named key-encryption key. ID is the stable, operator-chosen label
// recorded in each object's sidecar so the right KEK can be found to unwrap it;
// Key is the raw 32-byte AES-256 key material (never persisted).
type KEK struct {
	ID  string
	Key []byte
}

// EncryptOptions configures an at-rest encryption Store decorator.
type EncryptOptions struct {
	// Primary is the active KEK used to wrap the DEK of every new object. Its ID
	// is recorded in the sidecar.
	Primary KEK
	// Previous holds additional KEKs retained only to unwrap (decrypt) objects
	// written under a prior key, so a KEK rotation can proceed incrementally
	// without a flag day. They are never used to wrap new objects.
	Previous []KEK
	// FrameSize is the streaming AEAD frame plaintext size. Defaults to 64 KiB;
	// clamped to [1 KiB, maxFrameSize].
	FrameSize int
	// FIPS reports that FIPS 140-3 mode is active. AES-256-GCM, SHA-256, and
	// HKDF-SHA256 are all FIPS 140-3 approved, so the primitives are unchanged;
	// the flag is recorded in the status report and asserts the digest algorithm
	// is approved. Actual module enforcement is delegated to the Go FIPS module
	// (see internal/fips), consistent with the rest of the codebase.
	FIPS bool
	// SpoolDir stages the encrypted output of a write so its length is known
	// before the backend write. Defaults to the OS temp directory.
	SpoolDir string
}

// EncryptionStats is an immutable snapshot of the encryption layer's cumulative
// counters and configuration, exported both to Prometheus and to the
// admin/ptctl status report.
type EncryptionStats struct {
	Enabled       bool   `json:"enabled"`
	Algorithm     string `json:"algorithm"`
	KeyDerivation string `json:"keyDerivation"`
	PrimaryKeyID  string `json:"primaryKeyId"`
	// KnownKeyIDs lists every KEK id the layer can unwrap with (primary first),
	// so an operator can confirm a prior key is still configured before rotating.
	KnownKeyIDs    []string `json:"knownKeyIds"`
	FIPS           bool     `json:"fips"`
	FrameSizeBytes int      `json:"frameSizeBytes"`

	ObjectsEncrypted int64 `json:"objectsEncrypted"`
	ObjectsDecrypted int64 `json:"objectsDecrypted"`
	BytesEncrypted   int64 `json:"bytesEncrypted"`
	BytesDecrypted   int64 `json:"bytesDecrypted"`
	DEKsWrapped      int64 `json:"deksWrapped"`
	DecryptFailures  int64 `json:"decryptFailures"`

	// Rotations counts completed KEK rotations; RewrappedObjects is the lifetime
	// total of objects whose DEK was re-wrapped to a new KEK.
	Rotations        int64     `json:"rotations"`
	RewrappedObjects int64     `json:"rewrappedObjects"`
	LastRotation     time.Time `json:"lastRotation,omitempty"`
}

// KEKRotationReport summarizes a single KEK rotation pass. It is redaction-safe:
// it carries only counts and (cache-key) identifiers, never key material.
type KEKRotationReport struct {
	PrimaryKeyID   string    `json:"primaryKeyId"`
	StartedAt      time.Time `json:"startedAt"`
	Duration       string    `json:"duration"`
	Scanned        int       `json:"scanned"`
	AlreadyCurrent int       `json:"alreadyCurrent"`
	Rewrapped      int       `json:"rewrapped"`
	Skipped        int       `json:"skipped"`
	Errors         int       `json:"errors"`
	// SampleErrors holds a bounded sample of human-readable error descriptions
	// (each naming only a cache key and reason, never a secret).
	SampleErrors []string `json:"sampleErrors,omitempty"`
	// Unsupported is set when the inner store cannot update metadata in place, so
	// rotation could not re-wrap without re-encrypting payloads.
	Unsupported bool `json:"unsupported,omitempty"`
}

// EncryptionStatSource is implemented by a cache (directly or via forwarding
// decorators) that can report at-rest encryption statistics.
type EncryptionStatSource interface {
	EncryptionStats() EncryptionStats
}

// EncryptionController is the administrative surface the encryption layer
// exposes: a status snapshot and a trigger to rotate the key-encryption key
// (re-wrapping every object's DEK to the active KEK without re-encrypting the
// payload). The cache decorators forward it down to the encryptStore.
type EncryptionController interface {
	EncryptionStatSource
	RotateKEK(ctx context.Context) (KEKRotationReport, error)
}

// metadataUpdater is the optional Store capability the key-rotation path needs:
// persist an updated Record (the re-wrapped sidecar) without rewriting the
// content blob. The filesystem store implements it; stores that cannot update
// metadata in place (e.g. the object-storage backend) do not, and rotation
// reports Unsupported for them.
type metadataUpdater interface {
	UpdateMetadata(ctx context.Context, rec Record) error
}

// encryptStore decorates an inner Store with transparent AES-256-GCM at-rest
// encryption using per-object data keys wrapped by a configured KEK.
type encryptStore struct {
	inner     Store
	primary   KEK
	byID      map[string][]byte // KEK id -> key bytes (primary + previous), for unwrap
	keyOrder  []string          // KEK ids, primary first, for reporting
	frameSize int
	fips      bool
	spoolDir  string

	// rotateMu serializes KEK rotations; reads and writes proceed concurrently
	// with (and during) a rotation.
	rotateMu sync.Mutex

	// Cumulative counters (atomic, lock-free).
	objectsEncrypted atomic.Int64
	objectsDecrypted atomic.Int64
	bytesEncrypted   atomic.Int64
	bytesDecrypted   atomic.Int64
	deksWrapped      atomic.Int64
	decryptFailures  atomic.Int64
	rotations        atomic.Int64
	rewrapped        atomic.Int64
	lastRotationUnix atomic.Int64
}

var _ Store = (*encryptStore)(nil)
var _ EncryptionController = (*encryptStore)(nil)

// NewEncryptStore wraps inner with the at-rest encryption layer. It validates
// the KEK material (each key must be exactly 32 bytes) and that KEK ids are
// unique and non-empty.
func NewEncryptStore(inner Store, opts EncryptOptions) (*encryptStore, error) {
	if inner == nil {
		return nil, errors.New("cache: encryption layer requires an inner store")
	}
	if strings.TrimSpace(opts.Primary.ID) == "" {
		return nil, errors.New("cache: encryption requires a primary KEK id (cache.encryption.keyId)")
	}
	if len(opts.Primary.Key) != kekLen {
		return nil, fmt.Errorf("cache: encryption primary KEK must be %d bytes, got %d", kekLen, len(opts.Primary.Key))
	}
	s := &encryptStore{
		inner:     inner,
		primary:   opts.Primary,
		byID:      make(map[string][]byte),
		frameSize: opts.FrameSize,
		fips:      opts.FIPS,
		spoolDir:  opts.SpoolDir,
	}
	if s.frameSize <= 0 {
		s.frameSize = defaultFrameSize
	}
	if s.frameSize < 1024 {
		s.frameSize = 1024
	}
	if s.frameSize > maxFrameSize {
		s.frameSize = maxFrameSize
	}
	// Register the primary first, then any previous keys, rejecting duplicates.
	register := func(k KEK) error {
		id := strings.TrimSpace(k.ID)
		if id == "" {
			return errors.New("cache: encryption KEK id must not be empty")
		}
		if len(k.Key) != kekLen {
			return fmt.Errorf("cache: encryption KEK %q must be %d bytes, got %d", id, kekLen, len(k.Key))
		}
		if _, dup := s.byID[id]; dup {
			return fmt.Errorf("cache: encryption KEK id %q is configured more than once", id)
		}
		s.byID[id] = k.Key
		s.keyOrder = append(s.keyOrder, id)
		return nil
	}
	if err := register(opts.Primary); err != nil {
		return nil, err
	}
	for _, k := range opts.Previous {
		if err := register(k); err != nil {
			return nil, err
		}
	}
	// AES-256-GCM, SHA-256, and HKDF-SHA256 are all FIPS 140-3 approved. Assert the
	// digest we use for the plaintext fixity baseline is approved when FIPS mode is
	// requested; this is defense-in-depth (the Go module enforces the primitives).
	if s.fips && !fipsHashApproved("sha256") {
		return nil, errors.New("cache: encryption cannot run under FIPS mode; sha256 unexpectedly reported non-approved")
	}
	return s, nil
}

// fipsHashApproved mirrors the approved-hash check without importing internal/fips
// (which would create an awkward dependency direction for a leaf crypto helper).
// SHA-2 family identifiers are FIPS 140-3 approved.
func fipsHashApproved(algo string) bool {
	switch strings.ToLower(strings.TrimSpace(algo)) {
	case "sha224", "sha256", "sha384", "sha512", "sha512-224", "sha512-256":
		return true
	default:
		return false
	}
}

// EncryptionStats returns a snapshot of the cumulative counters and config.
func (s *encryptStore) EncryptionStats() EncryptionStats {
	st := EncryptionStats{
		Enabled:          true,
		Algorithm:        encAlgAES,
		KeyDerivation:    "envelope (per-object DEK wrapped by KEK)",
		PrimaryKeyID:     s.primary.ID,
		KnownKeyIDs:      append([]string(nil), s.keyOrder...),
		FIPS:             s.fips,
		FrameSizeBytes:   s.frameSize,
		ObjectsEncrypted: s.objectsEncrypted.Load(),
		ObjectsDecrypted: s.objectsDecrypted.Load(),
		BytesEncrypted:   s.bytesEncrypted.Load(),
		BytesDecrypted:   s.bytesDecrypted.Load(),
		DEKsWrapped:      s.deksWrapped.Load(),
		DecryptFailures:  s.decryptFailures.Load(),
		Rotations:        s.rotations.Load(),
		RewrappedObjects: s.rewrapped.Load(),
	}
	if u := s.lastRotationUnix.Load(); u > 0 {
		st.LastRotation = time.Unix(u, 0).UTC()
	}
	return st
}

// Put implements Store: it encrypts the content with a fresh per-object DEK,
// wraps the DEK with the primary KEK, and records the sidecar.
func (s *encryptStore) Put(ctx context.Context, rec Record, r io.Reader) (Record, error) {
	if rec.Key == "" {
		return Record{}, errors.New("cache: Put requires a non-empty key")
	}
	// Never let a caller inject our reserved sidecar keys.
	stripEncReserved(&rec)

	dek := make([]byte, dekLen)
	if _, err := rand.Read(dek); err != nil {
		return Record{}, fmt.Errorf("cache: generating data-encryption key: %w", err)
	}
	defer zero(dek)
	wrapped, err := wrapDEK(s.primary.Key, dek)
	if err != nil {
		return Record{}, fmt.Errorf("cache: wrapping data-encryption key: %w", err)
	}

	tmp, err := os.CreateTemp(s.spoolDir, "pte-*")
	if err != nil {
		return Record{}, fmt.Errorf("cache: staging encrypted blob: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	psize, pdigest, err := s.encryptStream(tmp, r, dek)
	if err != nil {
		return Record{}, fmt.Errorf("cache: encrypting blob for %q: %w", rec.Key, err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return Record{}, err
	}

	setEncReserved(&rec, s.primary.ID, wrapped, pdigest, psize, s.frameSize)
	stored, err := s.inner.Put(ctx, rec, tmp)
	if err != nil {
		return Record{}, err
	}
	committed = true
	_ = tmp.Close()
	_ = os.Remove(tmpName)

	s.objectsEncrypted.Add(1)
	s.bytesEncrypted.Add(psize)
	s.deksWrapped.Add(1)
	return s.outward(stored), nil
}

// Get implements Store, transparently decrypting an encrypted object. A legacy
// or plaintext entry (no encryption sidecar) is returned verbatim.
func (s *encryptStore) Get(ctx context.Context, key string) (io.ReadCloser, Record, error) {
	rc, rec, err := s.inner.Get(ctx, key)
	if err != nil {
		return nil, Record{}, err
	}
	if encReservedStr(rec, metaEncFmt) != encFmtAES {
		return rc, s.outward(rec), nil
	}
	dek, derr := s.recoverDEK(rec)
	if derr != nil {
		rc.Close()
		s.decryptFailures.Add(1)
		return nil, Record{}, derr
	}
	aead, aerr := newGCM(dek)
	zero(dek)
	if aerr != nil {
		rc.Close()
		return nil, Record{}, fmt.Errorf("cache: initializing decryptor for %q: %w", key, aerr)
	}
	fsz := int(encReservedInt(rec, metaEncFrame))
	if fsz <= 0 || fsz > maxFrameSize {
		fsz = s.frameSize
	}
	dr := &decryptReader{src: rc, aead: aead, frameSize: fsz, store: s, key: key}
	return dr, s.outward(rec), nil
}

// Stat implements Store.
func (s *encryptStore) Stat(ctx context.Context, key string) (Record, error) {
	rec, err := s.inner.Stat(ctx, key)
	if err != nil {
		return Record{}, err
	}
	return s.outward(rec), nil
}

// SetAccessed implements Store.
func (s *encryptStore) SetAccessed(ctx context.Context, key string, t time.Time) error {
	return s.inner.SetAccessed(ctx, key, t)
}

// Delete implements Store.
func (s *encryptStore) Delete(ctx context.Context, key string) error {
	return s.inner.Delete(ctx, key)
}

// List implements Store, projecting each record outward (restoring plaintext
// size/digest and stripping the sidecar).
func (s *encryptStore) List(ctx context.Context) ([]Record, error) {
	recs, err := s.inner.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range recs {
		recs[i] = s.outward(recs[i])
	}
	return recs, nil
}

// Close implements Store.
func (s *encryptStore) Close() error { return s.inner.Close() }

// RotateKEK re-wraps every encrypted object's DEK to the active (primary) KEK
// WITHOUT re-encrypting the payload: it unwraps each object's DEK with the KEK
// that originally wrapped it and re-wraps it with the primary, updating only the
// sidecar metadata. Objects already wrapped by the primary are skipped. Objects
// whose original KEK is no longer configured cannot be re-wrapped and are
// reported as errors (configure the old key under previousKeys to rotate them).
//
// It requires a store that can update metadata in place (metadataUpdater); on a
// store that cannot, it reports Unsupported and makes no changes.
func (s *encryptStore) RotateKEK(ctx context.Context) (KEKRotationReport, error) {
	s.rotateMu.Lock()
	defer s.rotateMu.Unlock()

	start := time.Now()
	rep := KEKRotationReport{PrimaryKeyID: s.primary.ID, StartedAt: start.UTC()}

	updater, ok := s.inner.(metadataUpdater)
	if !ok {
		rep.Unsupported = true
		rep.Duration = time.Since(start).String()
		return rep, nil
	}

	// Operate on the RAW inner records (sidecar intact, ciphertext digest/size),
	// never the outward-projected view, so the persisted metadata stays correct.
	recs, err := s.inner.List(ctx)
	if err != nil {
		return rep, fmt.Errorf("cache: listing objects for rotation: %w", err)
	}

	for _, rec := range recs {
		if err := ctx.Err(); err != nil {
			rep.Duration = time.Since(start).String()
			return rep, err
		}
		if encReservedStr(rec, metaEncFmt) != encFmtAES {
			continue // plaintext/legacy entry (e.g. encryption enabled later)
		}
		rep.Scanned++
		kekID := encReservedStr(rec, metaEncKEK)
		if kekID == s.primary.ID {
			rep.AlreadyCurrent++
			continue
		}
		oldKey, known := s.byID[kekID]
		if !known {
			rep.Errors++
			s.sampleErr(&rep, rec.Key, fmt.Sprintf("KEK %q not configured", kekID))
			continue
		}
		wrapped := encReservedStr(rec, metaEncDEK)
		dek, uerr := unwrapDEK(oldKey, wrapped)
		if uerr != nil {
			rep.Errors++
			s.sampleErr(&rep, rec.Key, "unwrap failed")
			continue
		}
		rewrapped, werr := wrapDEK(s.primary.Key, dek)
		zero(dek)
		if werr != nil {
			rep.Errors++
			s.sampleErr(&rep, rec.Key, "rewrap failed")
			continue
		}

		// Re-read immediately before writing to narrow the window against a
		// concurrent overwrite of the same key: if the stored wrapped DEK changed
		// under us (a Put replaced the object), skip rather than clobber it.
		fresh, serr := s.inner.Stat(ctx, rec.Key)
		if serr != nil {
			rep.Skipped++
			continue
		}
		if encReservedStr(fresh, metaEncDEK) != wrapped || encReservedStr(fresh, metaEncKEK) != kekID {
			rep.Skipped++
			continue
		}
		setEncField(&fresh, metaEncKEK, s.primary.ID)
		setEncField(&fresh, metaEncDEK, rewrapped)
		if uerr := updater.UpdateMetadata(ctx, fresh); uerr != nil {
			rep.Errors++
			s.sampleErr(&rep, rec.Key, "metadata update failed")
			continue
		}
		rep.Rewrapped++
		s.rewrapped.Add(1)
		s.deksWrapped.Add(1)
	}

	s.rotations.Add(1)
	s.lastRotationUnix.Store(time.Now().Unix())
	rep.Duration = time.Since(start).String()
	return rep, nil
}

func (s *encryptStore) sampleErr(rep *KEKRotationReport, key, reason string) {
	const maxSamples = 16
	if len(rep.SampleErrors) >= maxSamples {
		return
	}
	rep.SampleErrors = append(rep.SampleErrors, fmt.Sprintf("%s: %s", key, reason))
}

// recoverDEK unwraps an object's DEK using the KEK named in its sidecar.
func (s *encryptStore) recoverDEK(rec Record) ([]byte, error) {
	kekID := encReservedStr(rec, metaEncKEK)
	key, ok := s.byID[kekID]
	if !ok {
		return nil, fmt.Errorf("cache: no key-encryption-key %q available to unwrap object (configure it under cache.encryption.previousKeys)", kekID)
	}
	dek, err := unwrapDEK(key, encReservedStr(rec, metaEncDEK))
	if err != nil {
		return nil, fmt.Errorf("cache: unwrapping data key (kek %q): %w", kekID, err)
	}
	if len(dek) != dekLen {
		return nil, errors.New("cache: unwrapped data key has unexpected length")
	}
	return dek, nil
}

// outward projects a persisted Record back to the caller: it restores the
// plaintext size and digest for an encrypted entry and strips the encryption
// sidecar. A plaintext/legacy entry is returned unchanged except for sidecar
// stripping (there is none to strip).
func (s *encryptStore) outward(rec Record) Record {
	if encReservedStr(rec, metaEncFmt) == encFmtAES {
		if d := encReservedStr(rec, metaEncPDigest); d != "" {
			rec.Digest = d
		}
		rec.Size = encReservedInt(rec, metaEncPSize)
	}
	if len(rec.Extra) > 0 {
		for k := range rec.Extra {
			if strings.HasPrefix(k, pteReservedPrefix) {
				delete(rec.Extra, k)
			}
		}
		if len(rec.Extra) == 0 {
			rec.Extra = nil
		}
	}
	return rec
}

// encryptStream encrypts all of src into dst as a framed, authenticated stream,
// returning the plaintext length and digest. It streams with bounded memory and
// marks the final frame so truncation is detectable on read.
func (s *encryptStore) encryptStream(dst io.Writer, src io.Reader, dek []byte) (int64, string, error) {
	aead, err := newGCM(dek)
	if err != nil {
		return 0, "", err
	}
	if _, err := dst.Write(encStreamMagic); err != nil {
		return 0, "", err
	}

	h := sha256.New()
	var plainSize int64
	var frameIdx uint64

	emit := func(data []byte, last bool) error {
		nonce := streamNonce(frameIdx, last)
		ct := aead.Seal(nil, nonce[:], data, nil)
		var hdr [5]byte
		binary.BigEndian.PutUint32(hdr[0:4], uint32(len(ct)))
		if last {
			hdr[4] = 1
		}
		if _, err := dst.Write(hdr[:]); err != nil {
			return err
		}
		if _, err := dst.Write(ct); err != nil {
			return err
		}
		frameIdx++
		return nil
	}

	// One-frame lookahead so the final frame is marked as last (which is required
	// to detect truncation on read) even when the plaintext length is an exact
	// multiple of the frame size.
	have := false
	cur := make([]byte, s.frameSize)
	curLen := 0
	for {
		next := make([]byte, s.frameSize)
		n, rerr := io.ReadFull(src, next)
		if n > 0 {
			h.Write(next[:n])
			plainSize += int64(n)
			if have {
				if err := emit(cur[:curLen], false); err != nil {
					return 0, "", err
				}
			}
			cur, curLen, have = next, n, true
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return 0, "", rerr
		}
	}
	if have {
		if err := emit(cur[:curLen], true); err != nil {
			return 0, "", err
		}
	} else {
		// Empty content: a single empty final frame, so an empty object is still a
		// well-formed, authenticated stream (and round-trips to zero bytes).
		if err := emit(nil, true); err != nil {
			return 0, "", err
		}
	}

	return plainSize, "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// --- decrypting reader ------------------------------------------------------

// decryptReader lazily reads the framed ciphertext from the inner store and
// decrypts it frame by frame. It is forward-only (not seekable); the serve layer
// spools it to a temp file when a byte-range request needs random access, as it
// already does for the S3 backend and the compaction layer's chunk reader.
type decryptReader struct {
	src       io.ReadCloser
	aead      cipher.AEAD
	frameSize int
	store     *encryptStore
	key       string

	buf           bytes.Buffer
	frameIdx      uint64
	done          bool
	headerChecked bool
	err           error
}

func (d *decryptReader) Read(p []byte) (int, error) {
	for d.buf.Len() == 0 {
		if d.err != nil {
			return 0, d.err
		}
		if d.done {
			return 0, io.EOF
		}
		d.fill()
	}
	return d.buf.Read(p)
}

func (d *decryptReader) fill() {
	if !d.headerChecked {
		magic := make([]byte, len(encStreamMagic))
		if _, err := io.ReadFull(d.src, magic); err != nil {
			d.fail(fmt.Errorf("cache: reading encryption header for %q: %w", d.key, err))
			return
		}
		if !bytes.Equal(magic, encStreamMagic) {
			d.fail(fmt.Errorf("cache: object %q is not a recognized encrypted stream", d.key))
			return
		}
		d.headerChecked = true
	}

	var hdr [5]byte
	if _, err := io.ReadFull(d.src, hdr[:]); err != nil {
		if err == io.EOF {
			// A clean EOF before a frame marked last means the stream was truncated.
			d.fail(fmt.Errorf("cache: encrypted stream for %q is truncated", d.key))
		} else {
			d.fail(err)
		}
		return
	}
	clen := binary.BigEndian.Uint32(hdr[0:4])
	last := hdr[4] == 1
	if clen < gcmTagLen || int(clen) > d.frameSize+gcmTagLen {
		d.fail(fmt.Errorf("cache: encrypted frame length %d out of range for %q", clen, d.key))
		return
	}
	ct := make([]byte, clen)
	if _, err := io.ReadFull(d.src, ct); err != nil {
		d.fail(fmt.Errorf("cache: reading encrypted frame for %q: %w", d.key, err))
		return
	}
	nonce := streamNonce(d.frameIdx, last)
	pt, err := d.aead.Open(nil, nonce[:], ct, nil)
	if err != nil {
		if d.store != nil {
			d.store.decryptFailures.Add(1)
		}
		d.fail(fmt.Errorf("cache: authenticating encrypted frame for %q: %w", d.key, err))
		return
	}
	d.frameIdx++
	if n := len(pt); n > 0 {
		d.buf.Write(pt)
		if d.store != nil {
			d.store.bytesDecrypted.Add(int64(n))
		}
	}
	if last {
		d.done = true
		if d.store != nil {
			d.store.objectsDecrypted.Add(1)
		}
	}
}

func (d *decryptReader) fail(err error) {
	if d.err == nil {
		d.err = err
	}
}

func (d *decryptReader) Close() error { return d.src.Close() }

// --- crypto helpers ---------------------------------------------------------

// newGCM builds an AES-256-GCM AEAD from a 32-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// streamNonce derives the 96-bit GCM nonce for a frame: a big-endian frame
// counter plus a final-frame flag in the last byte. Because each object uses a
// unique random DEK, (key, nonce) pairs are globally unique; the counter
// prevents frame reordering and the flag makes truncation (a missing final
// frame) detectable.
func streamNonce(frameIdx uint64, last bool) [gcmNonceLen]byte {
	var n [gcmNonceLen]byte
	binary.BigEndian.PutUint64(n[0:8], frameIdx)
	if last {
		n[gcmNonceLen-1] = 1
	}
	return n
}

// wrapDEK encrypts a DEK under a KEK with AES-256-GCM and a fresh random nonce,
// returning base64(nonce || sealed).
func wrapDEK(kek, dek []byte) (string, error) {
	aead, err := newGCM(kek)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcmNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, nonce, dek, nil)
	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// unwrapDEK reverses wrapDEK.
func unwrapDEK(kek []byte, wrapped string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(wrapped)
	if err != nil {
		return nil, fmt.Errorf("decoding wrapped key: %w", err)
	}
	if len(raw) < gcmNonceLen+gcmTagLen {
		return nil, errors.New("wrapped key is too short")
	}
	aead, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	nonce, sealed := raw[:gcmNonceLen], raw[gcmNonceLen:]
	return aead.Open(nil, nonce, sealed, nil)
}

// DeriveKEK turns resolved KEK material into a 32-byte AES-256 key according to
// the configured encoding:
//
//   - "base64" (default): standard-base64 of exactly 32 raw bytes.
//   - "hex": hex of exactly 32 raw bytes.
//   - "raw": the material is used verbatim and must be exactly 32 bytes.
//   - "passphrase": an arbitrary string, stretched to 32 bytes with HKDF-SHA256
//     (salt = the KEK id, so distinct ids yield distinct keys from one phrase).
//
// id is used as the HKDF salt and for error messages; material is the secret and
// is never logged.
func DeriveKEK(id, material, encoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "base64":
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(material))
		if err != nil {
			return nil, fmt.Errorf("cache: KEK %q is not valid base64: %w", id, err)
		}
		if len(b) != kekLen {
			return nil, fmt.Errorf("cache: KEK %q must decode to %d bytes, got %d", id, kekLen, len(b))
		}
		return b, nil
	case "hex":
		b, err := hex.DecodeString(strings.TrimSpace(material))
		if err != nil {
			return nil, fmt.Errorf("cache: KEK %q is not valid hex: %w", id, err)
		}
		if len(b) != kekLen {
			return nil, fmt.Errorf("cache: KEK %q must decode to %d bytes, got %d", id, kekLen, len(b))
		}
		return b, nil
	case "raw":
		if len(material) != kekLen {
			return nil, fmt.Errorf("cache: raw KEK %q must be exactly %d bytes, got %d", id, kekLen, len(material))
		}
		return []byte(material), nil
	case "passphrase":
		if strings.TrimSpace(material) == "" {
			return nil, fmt.Errorf("cache: passphrase KEK %q is empty", id)
		}
		key, err := hkdf.Key(sha256.New, []byte(material), []byte(id), hkdfInfo, kekLen)
		if err != nil {
			return nil, fmt.Errorf("cache: deriving KEK %q: %w", id, err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("cache: unknown KEK encoding %q (want base64, hex, raw, or passphrase)", encoding)
	}
}

// zero wipes a key slice after use (best-effort hygiene).
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// --- reserved-metadata helpers ----------------------------------------------

func stripEncReserved(rec *Record) {
	for k := range rec.Extra {
		if strings.HasPrefix(k, pteReservedPrefix) {
			delete(rec.Extra, k)
		}
	}
}

func setEncReserved(rec *Record, kekID, wrappedDEK, pdigest string, psize int64, frameSize int) {
	if rec.Extra == nil {
		rec.Extra = make(map[string]string, 7)
	}
	rec.Extra[metaEncFmt] = encFmtAES
	rec.Extra[metaEncAlg] = encAlgAES
	rec.Extra[metaEncKEK] = kekID
	rec.Extra[metaEncDEK] = wrappedDEK
	rec.Extra[metaEncPDigest] = pdigest
	rec.Extra[metaEncPSize] = strconv.FormatInt(psize, 10)
	rec.Extra[metaEncFrame] = strconv.Itoa(frameSize)
}

func setEncField(rec *Record, key, value string) {
	if rec.Extra == nil {
		rec.Extra = make(map[string]string, 1)
	}
	rec.Extra[key] = value
}

func encReservedStr(rec Record, key string) string {
	if rec.Extra == nil {
		return ""
	}
	return rec.Extra[key]
}

func encReservedInt(rec Record, key string) int64 {
	v, _ := strconv.ParseInt(encReservedStr(rec, key), 10, 64)
	return v
}

// --- decorator forwarding ---------------------------------------------------
//
// The at-rest encryption layer sits innermost in the Store stack (below the
// compaction layer), so the admin API and Prometheus bridge reach it through a
// chain of forwarding methods: IntegrityCache -> (SealedCache ->)
// FilesystemCache -> compactStore -> encryptStore. Each decorator forwards
// EncryptionStats/RotateKEK to its inner component, reporting a disabled snapshot
// when no encryption layer is present.

func forwardEncryptionStats(inner any) EncryptionStats {
	if src, ok := inner.(EncryptionStatSource); ok {
		return src.EncryptionStats()
	}
	return EncryptionStats{Enabled: false, Algorithm: "none"}
}

func forwardRotateKEK(ctx context.Context, inner any) (KEKRotationReport, error) {
	if ctl, ok := inner.(EncryptionController); ok {
		return ctl.RotateKEK(ctx)
	}
	return KEKRotationReport{}, ErrEncryptionDisabled
}

// EncryptionStats forwards the at-rest encryption layer's statistics (Task 141).
func (s *compactStore) EncryptionStats() EncryptionStats { return forwardEncryptionStats(s.inner) }

// RotateKEK forwards a KEK rotation to the inner encryption layer (Task 141).
func (s *compactStore) RotateKEK(ctx context.Context) (KEKRotationReport, error) {
	return forwardRotateKEK(ctx, s.inner)
}

// EncryptionStats forwards the at-rest encryption layer's statistics (Task 141).
func (c *FilesystemCache) EncryptionStats() EncryptionStats { return forwardEncryptionStats(c.store) }

// RotateKEK forwards a KEK rotation to the underlying store (Task 141).
func (c *FilesystemCache) RotateKEK(ctx context.Context) (KEKRotationReport, error) {
	return forwardRotateKEK(ctx, c.store)
}

// EncryptionStats forwards the at-rest encryption layer's statistics (Task 141).
func (c *IntegrityCache) EncryptionStats() EncryptionStats { return forwardEncryptionStats(c.inner) }

// RotateKEK forwards a KEK rotation through the integrity wrapper (Task 141).
func (c *IntegrityCache) RotateKEK(ctx context.Context) (KEKRotationReport, error) {
	return forwardRotateKEK(ctx, c.inner)
}

// EncryptionStats forwards the at-rest encryption layer's statistics (Task 141).
func (s *SealedCache) EncryptionStats() EncryptionStats { return forwardEncryptionStats(s.inner) }

// RotateKEK forwards a KEK rotation through the sealed wrapper (Task 141).
func (s *SealedCache) RotateKEK(ctx context.Context) (KEKRotationReport, error) {
	return forwardRotateKEK(ctx, s.inner)
}
