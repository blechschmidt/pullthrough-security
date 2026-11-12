//go:build integration
// +build integration

package pkgscan

import (
	"bytes"
	"compress/gzip"
	"sync"

	//lint:ignore SA1019 x/crypto/openpgp is frozen, but it is what the apt and
	// yum backends verify repository signatures with; the stubs sign with the
	// same implementation.
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/clearsign"
)

// The APT and YUM stub repositories are signed, as real ones are: an APT
// repository publishes its Release file clearsigned (InRelease), a YUM
// repository a detached, ASCII-armored signature of repodata/repomd.xml
// (repomd.xml.asc). Both rows configure the upstream with the signing key's
// public half (`settings.gpgKey`, the operator pinning the repository key), so
// the proxy verifies the root of the repository's digest chain on every
// metadata pull — the way a production deployment runs — and a signature that
// did not verify would fail the row's metadata requests.
//
// One key serves every OS-repository row of a test process. It is made on
// first use: an OpenPGP key cannot be derived from a fixed seed with this
// library, and generating one per row would cost a second of CPU each.

var (
	osRepoKeyOnce sync.Once
	osRepoEntity  *openpgp.Entity
	osRepoPubKey  string
	osRepoKeyErr  error
)

// osRepoKey returns the repository signing key and its ASCII-armored public
// key, generating them on first use.
func osRepoKey() (*openpgp.Entity, string, error) {
	osRepoKeyOnce.Do(func() {
		ent, err := openpgp.NewEntity("pullthrough pkgscan e2e", "stub repository signing key", "pkgscan-e2e@example.invalid", nil)
		if err != nil {
			osRepoKeyErr = err
			return
		}
		var pub bytes.Buffer
		w, err := armor.Encode(&pub, openpgp.PublicKeyType, nil)
		if err != nil {
			osRepoKeyErr = err
			return
		}
		if err := ent.Serialize(w); err != nil {
			osRepoKeyErr = err
			return
		}
		if err := w.Close(); err != nil {
			osRepoKeyErr = err
			return
		}
		osRepoEntity, osRepoPubKey = ent, pub.String()
	})
	return osRepoEntity, osRepoPubKey, osRepoKeyErr
}

// osRepoSettings is the `settings:` block of an APT or YUM upstream: the
// repository key, pinned. The key exists by the time a proxy is configured —
// the row's registry, built first, made it — so a failure here is a broken
// invariant, not a condition to configure around.
func osRepoSettings(string) map[string]string {
	_, pub, err := osRepoKey()
	if err != nil {
		panic("pkgscan: the repository signing key is unavailable: " + err.Error())
	}
	return map[string]string{"gpgKey": pub}
}

// osRepoClearsign returns text clearsigned with the repository key: the text,
// readable as it stands, between an armor header and the signature (how APT's
// InRelease is published).
func osRepoClearsign(text []byte) ([]byte, error) {
	ent, _, err := osRepoKey()
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	w, err := clearsign.Encode(&out, ent.PrivateKey, nil)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(text); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// osRepoDetachSign returns an ASCII-armored detached signature of data made
// with the repository key (how YUM's repomd.xml.asc and APT's Release.gpg are
// published).
func osRepoDetachSign(data []byte) ([]byte, error) {
	ent, _, err := osRepoKey()
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&out, ent, bytes.NewReader(data), nil); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// osRepoGzipStored compresses an index document with gzip at level 0: a valid
// gzip stream whose deflate blocks are stored rather than compressed. A client
// inflates it like any other, and the backend verifies and parses it as it
// does any gzip-compressed index — while the index text stays readable in the
// very bytes the proxy serves, so a step can assert what the client is told
// (the path and the digest of each package). A stored block holds up to 64 KiB;
// the stub indices are a few KiB, so no asserted line is split across two.
func osRepoGzipStored(data []byte) []byte {
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.NoCompression)
	if err != nil {
		panic("pkgscan: gzip level 0: " + err.Error()) // a constant, valid level
	}
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}
