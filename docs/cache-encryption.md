# At-rest cache encryption

The pull-through proxy can transparently encrypt every artifact byte it stores
on disk (or in S3) with **AES-256-GCM**, so a stolen disk, backup, or object-
storage bucket yields only ciphertext. Encryption is an opt-in `Store` decorator
(`internal/cache/encrypt.go`) that sits beneath the caching layer and is
invisible to the serve path: reads decrypt transparently and return the original
bytes.

## How it works (envelope encryption)

- Each cached object is encrypted with a **fresh, random 256-bit
  data-encryption key (DEK)** generated per write.
- The DEK is **wrapped (encrypted) with a key-encryption key (KEK)** and stored,
  together with a per-object nonce, in the object's metadata sidecar. The KEK
  itself is resolved through the [secrets provider](configuration.md) abstraction
  (`env://`, `file://`, `vault://…`) and **never touches disk**.
- Payloads are encrypted as a sequence of independently authenticated frames (a
  STREAM-style construction), so arbitrarily large artifacts encrypt and decrypt
  with **bounded memory**, and truncation, reordering, and bit-flips are all
  caught by GCM authentication on read.

### Digest-over-plaintext invariant

The layer records the digest and length of the **plaintext** and restores them
onto the record it returns, so cache addressing, cross-artifact deduplication,
[read-time integrity verification](range-streaming.md), and range serving all
keep working against the logical content — never the ciphertext. The content
address a client sees is unchanged whether or not encryption is enabled.

### Composition with compression & dedup

At-rest encryption composes with the transparent
[compression + deduplication](configuration-reference.md) layer (`cache.compression`).
Encryption is wired **innermost** (closest to the durable store) and compaction
**outermost**, so compression and chunk dedup both run over plaintext and are
entirely unaffected — encryption merely encrypts whatever physical bytes
compaction hands it, one object or chunk at a time.

## Configuration

```yaml
cache:
  backend: filesystem        # or s3; not supported with the memory backend
  encryption:
    enabled: true
    keyId: "2025-primary"     # stable label recorded in each object's sidecar
    keyRef: "vault://secret/data/pullthrough/cache-kek#key"
    keyEncoding: "base64"     # base64 (default) | hex | raw | passphrase
    # Optional streaming frame size (default 64 KiB):
    frameSizeBytes: 65536
    # Keys retained ONLY to decrypt objects written under a prior KEK, so a
    # rotation can proceed incrementally without a flag day:
    previousKeys:
      - keyId: "2024-primary"
        keyRef: "file:///etc/pullthrough/old-cache-kek"
        keyEncoding: "base64"
```

`keyEncoding` interprets the resolved KEK material:

| encoding     | material                                                       |
|--------------|----------------------------------------------------------------|
| `base64`     | standard base64 of exactly 32 raw bytes (default)              |
| `hex`        | hex of exactly 32 raw bytes                                    |
| `raw`        | exactly 32 bytes used verbatim                                 |
| `passphrase` | any string, stretched to 32 bytes with HKDF-SHA256 (salt = id) |

Generate a base64 KEK:

```sh
head -c 32 /dev/urandom | base64
```

## FIPS mode

AES-256-GCM, SHA-256, and HKDF-SHA256 are all FIPS 140-3 approved. When
[FIPS mode](fips-compliance.md) is enabled the primitives are unchanged and the
module performs the actual enforcement; the encryption status report reflects
the active crypto mode.

## Key rotation (re-wrap without re-encrypting)

Rotating the KEK **does not re-encrypt payloads**. The proxy unwraps each
object's DEK with the KEK that originally wrapped it and re-wraps that DEK with
the new active KEK, updating only the metadata sidecar — the (potentially
multi-gigabyte) encrypted payload is never rewritten.

1. Add the new KEK as `keyId`/`keyRef` and move the old key under
   `previousKeys`, then restart/reload.
2. Trigger the re-wrap:

   ```sh
   ptctl cache-encryption rotate
   ```

3. Once every object reports as re-wrapped, the old key can be removed from
   `previousKeys`.

Objects whose original KEK is no longer configured cannot be read or re-wrapped;
keep a retiring key under `previousKeys` until a rotation reports zero errors.

In-place re-wrap requires a store that can update metadata without rewriting the
blob (the filesystem backend). On a backend that cannot (object storage),
`rotate` reports `unsupported` and makes no changes.

## Operations

```sh
ptctl cache-encryption status      # algorithm, primary/known KEKs, counters
ptctl cache-encryption rotate      # re-wrap all objects to the active KEK
```

Both are thin clients over the admin API
(`GET /api/cache/encryption`, `POST /api/cache/encryption/rotate`).

### Metrics

| metric                                                | meaning                                                  |
|-------------------------------------------------------|----------------------------------------------------------|
| `pullthrough_cache_encryption_enabled`                | 1 when the envelope is active                            |
| `pullthrough_cache_encryption_objects_encrypted_total`| objects encrypted on write                               |
| `pullthrough_cache_encryption_objects_decrypted_total`| objects fully decrypted on serve                         |
| `pullthrough_cache_encryption_bytes_encrypted_total`  | plaintext bytes encrypted                                |
| `pullthrough_cache_encryption_bytes_decrypted_total`  | plaintext bytes decrypted                                |
| `pullthrough_cache_encryption_deks_wrapped_total`     | DEKs wrapped (on write and on rotation re-wrap)          |
| `pullthrough_cache_encryption_decrypt_failures_total` | auth failures (missing KEK, tampering, bit-rot)          |
| `pullthrough_cache_encryption_rewrapped_objects_total`| objects re-wrapped by rotations                          |
| `pullthrough_cache_encryption_rotations_total`        | completed KEK rotations                                  |

## Caveats

- **Do not disable encryption on a cache that already contains encrypted
  entries** without a migration: the encrypted blobs can only be read while the
  encryption layer (and the KEK) are present. Newly written entries would be
  plaintext while old ones stay encrypted.
- Encryption applies to the `filesystem` and `s3` backends only; the in-memory
  backend has no durable store to encrypt.
