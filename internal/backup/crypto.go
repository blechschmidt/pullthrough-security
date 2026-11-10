package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"
)

// The optional encryption envelope wraps the tar snapshot so a backup can be
// stored on untrusted media (tape, removable disk, an object bucket) while
// remaining confidential and tamper-evident. The design is a chunked AEAD stream
// so arbitrarily large snapshots encrypt and decrypt in bounded memory:
//
//	envelopeMagic                      (fixed 8 bytes, plaintext)
//	uint32 headerLen | header JSON     (plaintext: algorithm, KDF params, salt, nonce)
//	repeated frames:
//	  byte final-flag | uint32 ctLen | ciphertext(+GCM tag)
//
// Each frame is sealed with AES-256-GCM under a per-frame nonce (an 8-byte random
// base concatenated with a 4-byte big-endian counter) and authenticates, via its
// additional data, both the frame counter and the final-flag. Binding the counter
// detects reordering and the final-flag detects truncation: a stream that ends
// without a frame whose final-flag is set is rejected as truncated.

const (
	envelopeMagicStr = "PTBKENC1"
	encAlgorithm     = "AES-256-GCM"
	kdfScrypt        = "scrypt"
	kdfRaw           = "raw"
	encChunkSize     = 1 << 20 // 1 MiB plaintext per frame
	keyLen           = 32      // AES-256

	// scrypt cost parameters (interactive-strength, ~ standard recommendations).
	scryptN = 1 << 15
	scryptR = 8
	scryptP = 1
)

var envelopeMagic = []byte(envelopeMagicStr)

// envelopeHeader is the plaintext, self-describing preamble of an encrypted
// snapshot. It carries everything a reader needs to derive the key and decrypt,
// except the secret itself (passphrase or raw key), which is supplied
// out-of-band by the operator.
type envelopeHeader struct {
	Algorithm string `json:"algorithm"`
	KDF       string `json:"kdf"`
	Salt      []byte `json:"salt,omitempty"`
	N         int    `json:"n,omitempty"`
	R         int    `json:"r,omitempty"`
	P         int    `json:"p,omitempty"`
	NonceBase []byte `json:"nonceBase"`
	ChunkSize int    `json:"chunkSize"`
}

// EncryptionKey holds the secret material for an encrypted backup. Exactly one of
// Passphrase or RawKey must be set. A passphrase is stretched with scrypt and a
// random per-snapshot salt; a raw key must be exactly 32 bytes and is used
// directly (for KMS/HSM-managed key workflows).
type EncryptionKey struct {
	Passphrase []byte
	RawKey     []byte
}

// derive turns the operator secret and header into the 32-byte AES key.
func (k EncryptionKey) derive(h *envelopeHeader) ([]byte, error) {
	switch {
	case len(k.Passphrase) > 0 && len(k.RawKey) > 0:
		return nil, errors.New("backup: encryption key must be either a passphrase or a raw key, not both")
	case len(k.RawKey) > 0:
		if len(k.RawKey) != keyLen {
			return nil, fmt.Errorf("backup: raw encryption key must be %d bytes, got %d", keyLen, len(k.RawKey))
		}
		return append([]byte(nil), k.RawKey...), nil
	case len(k.Passphrase) > 0:
		key, err := scrypt.Key(k.Passphrase, h.Salt, h.N, h.R, h.P, keyLen)
		if err != nil {
			return nil, fmt.Errorf("backup: deriving key: %w", err)
		}
		return key, nil
	default:
		return nil, errors.New("backup: encryption requested but no passphrase or raw key supplied")
	}
}

// IsSet reports whether any secret material is present.
func (k EncryptionKey) IsSet() bool { return len(k.Passphrase) > 0 || len(k.RawKey) > 0 }

// frameNonce computes the 12-byte GCM nonce for a frame: the 8-byte random base
// followed by the 4-byte big-endian counter.
func frameNonce(base []byte, counter uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce, base)
	binary.BigEndian.PutUint32(nonce[8:], counter)
	return nonce
}

// frameAAD authenticates the frame's ordinal and final-flag so reordering or
// truncation is detected at decryption.
func frameAAD(counter uint32, final bool) []byte {
	aad := make([]byte, 5)
	binary.BigEndian.PutUint32(aad, counter)
	if final {
		aad[4] = 1
	}
	return aad
}

// encWriter is the streaming encryptor returned by newEncryptingWriter. Callers
// write plaintext and must Close to flush the trailing frame (which carries the
// final-flag).
type encWriter struct {
	w       io.Writer
	gcm     cipher.AEAD
	base    []byte
	counter uint32
	buf     []byte
	err     error
	closed  bool
}

// newEncryptingWriter writes the plaintext envelope header to w and returns a
// WriteCloser that seals subsequent writes as AEAD frames.
func newEncryptingWriter(w io.Writer, key EncryptionKey) (io.WriteCloser, error) {
	h := &envelopeHeader{
		Algorithm: encAlgorithm,
		ChunkSize: encChunkSize,
		NonceBase: make([]byte, 8),
	}
	if len(key.RawKey) > 0 {
		h.KDF = kdfRaw
	} else if len(key.Passphrase) > 0 {
		h.KDF = kdfScrypt
		h.Salt = make([]byte, 16)
		h.N, h.R, h.P = scryptN, scryptR, scryptP
		if _, err := rand.Read(h.Salt); err != nil {
			return nil, fmt.Errorf("backup: generating salt: %w", err)
		}
	}
	if _, err := rand.Read(h.NonceBase); err != nil {
		return nil, fmt.Errorf("backup: generating nonce base: %w", err)
	}

	derived, err := key.derive(h)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(derived)
	if err != nil {
		return nil, err
	}

	if _, err := w.Write(envelopeMagic); err != nil {
		return nil, fmt.Errorf("backup: writing envelope magic: %w", err)
	}
	hdrBytes, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("backup: encoding envelope header: %w", err)
	}
	if err := writeUint32(w, uint32(len(hdrBytes))); err != nil {
		return nil, err
	}
	if _, err := w.Write(hdrBytes); err != nil {
		return nil, fmt.Errorf("backup: writing envelope header: %w", err)
	}

	return &encWriter{w: w, gcm: gcm, base: h.NonceBase, buf: make([]byte, 0, encChunkSize)}, nil
}

func (e *encWriter) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	written := 0
	for len(p) > 0 {
		space := encChunkSize - len(e.buf)
		n := len(p)
		if n > space {
			n = space
		}
		e.buf = append(e.buf, p[:n]...)
		p = p[n:]
		written += n
		if len(e.buf) == encChunkSize {
			if err := e.flushFrame(false); err != nil {
				e.err = err
				return written, err
			}
		}
	}
	return written, nil
}

// flushFrame seals and writes the buffered plaintext as one frame.
func (e *encWriter) flushFrame(final bool) error {
	nonce := frameNonce(e.base, e.counter)
	ct := e.gcm.Seal(nil, nonce, e.buf, frameAAD(e.counter, final))
	var flag [1]byte
	if final {
		flag[0] = 1
	}
	if _, err := e.w.Write(flag[:]); err != nil {
		return fmt.Errorf("backup: writing frame flag: %w", err)
	}
	if err := writeUint32(e.w, uint32(len(ct))); err != nil {
		return err
	}
	if _, err := e.w.Write(ct); err != nil {
		return fmt.Errorf("backup: writing ciphertext frame: %w", err)
	}
	e.counter++
	e.buf = e.buf[:0]
	return nil
}

func (e *encWriter) Close() error {
	if e.closed {
		return nil
	}
	e.closed = true
	if e.err != nil {
		return e.err
	}
	// Always emit a final frame (possibly carrying the last partial buffer, or
	// empty) so the reader can prove the stream was not truncated.
	return e.flushFrame(true)
}

// decReader is the streaming decryptor returned by newDecryptingReader.
type decReader struct {
	r       io.Reader
	gcm     cipher.AEAD
	base    []byte
	counter uint32
	buf     []byte
	done    bool
	err     error
}

// newDecryptingReader reads and validates the plaintext envelope header from r,
// derives the key, and returns a Reader yielding the decrypted plaintext.
func newDecryptingReader(r io.Reader, key EncryptionKey) (io.Reader, error) {
	magic := make([]byte, len(envelopeMagic))
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, fmt.Errorf("backup: reading envelope magic: %w", err)
	}
	if string(magic) != envelopeMagicStr {
		return nil, errors.New("backup: not an encrypted snapshot (bad magic)")
	}

	hdrLen, err := readUint32(r)
	if err != nil {
		return nil, err
	}
	if hdrLen == 0 || hdrLen > 1<<16 {
		return nil, fmt.Errorf("backup: implausible envelope header length %d", hdrLen)
	}
	hdrBytes := make([]byte, hdrLen)
	if _, err := io.ReadFull(r, hdrBytes); err != nil {
		return nil, fmt.Errorf("backup: reading envelope header: %w", err)
	}
	var h envelopeHeader
	if err := json.Unmarshal(hdrBytes, &h); err != nil {
		return nil, fmt.Errorf("backup: decoding envelope header: %w", err)
	}
	if h.Algorithm != encAlgorithm {
		return nil, fmt.Errorf("backup: unsupported encryption algorithm %q", h.Algorithm)
	}
	if len(h.NonceBase) != 8 {
		return nil, errors.New("backup: malformed envelope (bad nonce base)")
	}

	derived, err := key.derive(&h)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(derived)
	if err != nil {
		return nil, err
	}
	return &decReader{r: r, gcm: gcm, base: h.NonceBase}, nil
}

func (d *decReader) Read(p []byte) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	if len(d.buf) == 0 {
		if d.done {
			return 0, io.EOF
		}
		if err := d.nextFrame(); err != nil {
			d.err = err
			return 0, err
		}
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}

// nextFrame reads, authenticates, and decrypts the next frame into the buffer.
func (d *decReader) nextFrame() error {
	finalByte := make([]byte, 1)
	if _, err := io.ReadFull(d.r, finalByte); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// The stream ended without a final-flagged frame: truncation.
			return errors.New("backup: encrypted snapshot is truncated (no final frame)")
		}
		return fmt.Errorf("backup: reading frame flag: %w", err)
	}
	final := finalByte[0] == 1

	ctLen, err := readUint32(d.r)
	if err != nil {
		return err
	}
	if ctLen > encChunkSize+64 { // plaintext chunk + GCM tag headroom
		return fmt.Errorf("backup: implausible ciphertext frame length %d", ctLen)
	}
	ct := make([]byte, ctLen)
	if _, err := io.ReadFull(d.r, ct); err != nil {
		return fmt.Errorf("backup: reading ciphertext frame: %w", err)
	}

	nonce := frameNonce(d.base, d.counter)
	pt, err := d.gcm.Open(nil, nonce, ct, frameAAD(d.counter, final))
	if err != nil {
		return fmt.Errorf("backup: frame %d failed authentication (wrong key or tampering): %w", d.counter, err)
	}
	d.counter++
	d.buf = pt
	if final {
		d.done = true
	}
	return nil
}

// newGCM builds an AES-256-GCM AEAD from a 32-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("backup: initializing cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("backup: initializing GCM: %w", err)
	}
	return gcm, nil
}

func writeUint32(w io.Writer, v uint32) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	if _, err := w.Write(b[:]); err != nil {
		return fmt.Errorf("backup: writing length prefix: %w", err)
	}
	return nil
}

func readUint32(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, fmt.Errorf("backup: reading length prefix: %w", err)
	}
	return binary.BigEndian.Uint32(b[:]), nil
}
