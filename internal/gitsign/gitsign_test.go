package gitsign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// payload is shaped like what git signs: a commit object without its gpgsig
// header.
const payload = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
	"parent 2c51a19bcf5cc20aad1b8371031586c6b7e45df8\n" +
	"author Pullthrough <bot@example.com> 1700000000 +0100\n" +
	"committer Pullthrough <bot@example.com> 1700000000 +0100\n" +
	"\n" +
	"Update lock files\n"

func keygen(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	return path
}

// generateKey has ssh-keygen write a new key pair and returns the private
// key's path and its PEM.
func generateKey(t *testing.T, passphrase string, args ...string) (string, []byte) {
	t.Helper()
	bin := keygen(t)
	path := filepath.Join(t.TempDir(), "key")
	cmd := exec.Command(bin, append([]string{"-q", "-N", passphrase, "-C", "test", "-f", path}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen %v: %v\n%s", args, err, out)
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, pemBytes
}

// verifyWithSSHKeygen runs `ssh-keygen -Y verify` the way git does and returns
// its error.
func verifyWithSSHKeygen(t *testing.T, publicKey string, sig []byte, namespace string, message []byte) error {
	t.Helper()
	dir := t.TempDir()
	allowed := filepath.Join(dir, "allowed_signers")
	if err := os.WriteFile(allowed, []byte("test "+publicKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sigPath := filepath.Join(dir, "sig")
	if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(keygen(t), "-Y", "verify", "-f", allowed, "-I", "test", "-n", namespace, "-s", sigPath)
	cmd.Stdin = bytes.NewReader(message)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New(strings.TrimSpace(string(out)))
	}
	return nil
}

// Every supported key type signs what ssh-keygen verifies as a "git"
// signature of the payload — and of nothing else.
func TestSignaturesVerifyWithSSHKeygen(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		algo string
	}{
		{"ed25519", []string{"-t", "ed25519"}, "ssh-ed25519"},
		{"ecdsa-p256", []string{"-t", "ecdsa", "-b", "256"}, "ecdsa-sha2-nistp256"},
		{"ecdsa-p384", []string{"-t", "ecdsa", "-b", "384"}, "ecdsa-sha2-nistp384"},
		{"ecdsa-p521", []string{"-t", "ecdsa", "-b", "521"}, "ecdsa-sha2-nistp521"},
		{"rsa-2048", []string{"-t", "rsa", "-b", "2048"}, "rsa-sha2-512"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, key := generateKey(t, "", tc.args...)
			s, err := NewSSHSigner(key, nil)
			if err != nil {
				t.Fatal(err)
			}
			if s.Algorithm() != tc.algo {
				t.Fatalf("algorithm %q, want %q", s.Algorithm(), tc.algo)
			}
			sig, err := s.SignCommit([]byte(payload))
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyWithSSHKeygen(t, s.PublicKey(), sig, "git", []byte(payload)); err != nil {
				t.Fatalf("ssh-keygen refused the signature: %v\n%s", err, sig)
			}
			if err := verifyWithSSHKeygen(t, s.PublicKey(), sig, "git", []byte(payload+"tampered")); err == nil {
				t.Fatal("the signature verified for another message")
			}
			if err := verifyWithSSHKeygen(t, s.PublicKey(), sig, "file", []byte(payload)); err == nil {
				t.Fatal("the signature verified in another namespace")
			}
			checkStructure(t, s, sig, []byte(payload))
		})
	}
}

// Ed25519 and RSA PKCS #1 v1.5 signatures are deterministic, so the armored
// text must equal ssh-keygen's byte for byte: same fields, same base64 line
// width, same newlines.
func TestSignatureIsByteIdenticalToSSHKeygen(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"ed25519", []string{"-t", "ed25519"}},
		{"rsa-2048", []string{"-t", "rsa", "-b", "2048"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, key := generateKey(t, "", tc.args...)
			s, err := NewSSHSigner(key, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, msg := range []string{payload, "", strings.Repeat("x", 4097)} {
				ours, err := s.SignCommit([]byte(msg))
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(keygen(t), "-Y", "sign", "-f", path, "-n", "git")
				cmd.Stdin = strings.NewReader(msg)
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				if err := cmd.Run(); err != nil {
					t.Fatalf("ssh-keygen -Y sign: %v\n%s", err, stderr.String())
				}
				if !bytes.Equal(ours, stdout.Bytes()) {
					t.Fatalf("signature differs from ssh-keygen's:\nours:\n%s\nssh-keygen:\n%s", ours, stdout.Bytes())
				}
			}
		})
	}
}

func TestPublicKeyAndFingerprintMatchSSHKeygen(t *testing.T) {
	path, key := generateKey(t, "", "-t", "ed25519")
	s, err := NewSSHSigner(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(path + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(pub))
	if want := fields[0] + " " + fields[1]; s.PublicKey() != want {
		t.Fatalf("public key %q, want %q", s.PublicKey(), want)
	}
	out, err := exec.Command(keygen(t), "-l", "-E", "sha256", "-f", path+".pub").Output()
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Fields(string(out))[1]; s.Fingerprint() != want {
		t.Fatalf("fingerprint %q, want %q", s.Fingerprint(), want)
	}
}

func TestEncryptedKey(t *testing.T) {
	_, key := generateKey(t, "correct horse", "-t", "ed25519")
	if _, err := NewSSHSigner(key, nil); err == nil || !strings.Contains(err.Error(), "passphrase is required") {
		t.Fatalf("an encrypted key without a passphrase: %v", err)
	}
	if _, err := NewSSHSigner(key, []byte("wrong")); err == nil {
		t.Fatal("an encrypted key opened with the wrong passphrase")
	}
	s, err := NewSSHSigner(key, []byte("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.SignCommit([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyWithSSHKeygen(t, s.PublicKey(), sig, "git", []byte(payload)); err != nil {
		t.Fatal(err)
	}

	// A passphrase configured for a key that is not encrypted is not needed.
	_, plain := generateKey(t, "", "-t", "ed25519")
	if _, err := NewSSHSigner(plain, []byte("unused")); err != nil {
		t.Fatalf("an unencrypted key with a passphrase: %v", err)
	}
}

func TestRefusedKeys(t *testing.T) {
	if _, err := NewSSHSigner([]byte("not a key"), nil); err == nil {
		t.Fatal("garbage was accepted as a key")
	}
	_, short := generateKey(t, "", "-t", "rsa", "-b", "1024")
	if _, err := NewSSHSigner(short, nil); err == nil || !strings.Contains(err.Error(), "at least 2048") {
		t.Fatalf("a 1024-bit RSA key: %v", err)
	}
	// A key must never be quoted in an error.
	_, key := generateKey(t, "pw", "-t", "ed25519")
	block, _ := pem.Decode(key)
	_, err := NewSSHSigner(key, []byte("wrong"))
	if err == nil || strings.Contains(err.Error(), base64.StdEncoding.EncodeToString(block.Bytes)[:16]) {
		t.Fatalf("error %v", err)
	}
}

// A key in PKCS #8 or the OpenSSH format, made in Go: the signature checks
// out without ssh-keygen too.
func TestSignatureStructureWithoutSSHKeygen(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSSHSigner(pem.EncodeToMemory(block), nil)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.SignCommit([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	checkStructure(t, s, sig, []byte(payload))
}

// Keys in the PEM encodings other tools write — PKCS #8, SEC 1, PKCS #1 —
// sign as well as OpenSSH ones; an ECDSA key on a curve git users cannot sign
// with is refused.
func TestPEMKeyEncodings(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(edKey)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(p256)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		block *pem.Block
		algo  string
	}{
		{"pkcs8 ed25519", &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}, "ssh-ed25519"},
		{"sec1 p256", &pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}, "ecdsa-sha2-nistp256"},
		{"pkcs1 rsa", &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}, "rsa-sha2-512"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewSSHSigner(pem.EncodeToMemory(tc.block), nil)
			if err != nil {
				t.Fatal(err)
			}
			if s.Algorithm() != tc.algo {
				t.Fatalf("algorithm %q, want %q", s.Algorithm(), tc.algo)
			}
			sig, err := s.SignCommit([]byte(payload))
			if err != nil {
				t.Fatal(err)
			}
			checkStructure(t, s, sig, []byte(payload))
		})
	}

	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Skipf("no P-224 key in this mode: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(p224)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSSHSigner(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil); err == nil || !strings.Contains(err.Error(), "P-224") {
		t.Fatalf("a P-224 key: %v", err)
	}
}

// checkStructure parses an armored signature field by field and verifies it
// over the payload with the signer's public key.
func checkStructure(t *testing.T, s *SSHSigner, armored, message []byte) {
	t.Helper()
	text := string(armored)
	if !strings.HasPrefix(text, armorBegin+"\n") || !strings.HasSuffix(text, "\n"+armorEnd+"\n") {
		t.Fatalf("armor:\n%s", text)
	}
	lines := strings.Split(strings.TrimSuffix(strings.TrimPrefix(text, armorBegin+"\n"), armorEnd+"\n"), "\n")
	lines = lines[:len(lines)-1] // the newline ending the last base64 line
	for i, l := range lines {
		if len(l) > armorWidth || (i < len(lines)-1 && len(l) != armorWidth) {
			t.Fatalf("base64 line %d is %d characters", i, len(l))
		}
	}
	blob, err := base64.StdEncoding.DecodeString(strings.Join(lines, ""))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(blob, []byte(sigMagic)) {
		t.Fatal("no SSHSIG magic")
	}
	rest := blob[len(sigMagic):]
	if binary.BigEndian.Uint32(rest) != sigVersion {
		t.Fatal("wrong version")
	}
	rest = rest[4:]
	var fields [][]byte
	for len(rest) > 0 {
		n := binary.BigEndian.Uint32(rest)
		fields = append(fields, rest[4:4+n])
		rest = rest[4+n:]
	}
	if len(fields) != 5 {
		t.Fatalf("%d fields", len(fields))
	}
	pub, err := ssh.ParsePublicKey(fields[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub.Marshal(), s.pub.Marshal()) {
		t.Fatal("the signature carries another public key")
	}
	if string(fields[1]) != "git" || len(fields[2]) != 0 || string(fields[3]) != "sha512" {
		t.Fatalf("namespace %q reserved %q hash %q", fields[1], fields[2], fields[3])
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(fields[4], &sig); err != nil {
		t.Fatal(err)
	}
	if sig.Format != s.Algorithm() {
		t.Fatalf("signature format %q, want %q", sig.Format, s.Algorithm())
	}
	digest := sha512.Sum512(message)
	if err := pub.Verify(signedData(digest[:]), &sig); err != nil {
		t.Fatalf("the signature does not verify: %v", err)
	}
	tampered := sha512.Sum512(append(append([]byte{}, message...), 'x'))
	if err := pub.Verify(signedData(tampered[:]), &sig); err == nil {
		t.Fatal("the signature verifies for another message")
	}
}
