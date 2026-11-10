package cache

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"
)

// This file implements the transparent storage-efficiency layer (Task 125): a
// Store decorator that compresses compressible blobs and, optionally,
// deduplicates content at the chunk level across artifacts. It sits between the
// generic caching layer (FilesystemCache: index, LRU/TTL, single-flight) and the
// durable byte store (FilesystemStore or S3Store), so it is invisible to the
// serve path and to every gate above it:
//
//   - Reads decompress / reassemble transparently and return the original bytes.
//   - The content digest recorded for each entry is computed over the ORIGINAL
//     (uncompressed) bytes, so read-time integrity verification and self-healing
//     (Task 107), the SBOM/fixity baseline, and range serving (Task 75) all keep
//     working against the logical content the client actually receives.
//   - Stat.Size is the logical (uncompressed) length, so Content-Length, range
//     math, and the GC/eviction size accounting (Task 39) are unchanged.
//
// Already-compressed content (images, archives, zstd/gzip streams) is detected
// with a magic-byte + entropy heuristic and stored verbatim, so the layer never
// wastes CPU re-compressing incompressible data nor inflates it.

// Reserved metadata keys persisted in Record.Extra. They describe how a blob is
// physically stored so a read can reverse the transform. They are stripped from
// the Record projected back to the caller so they never leak into Stat.Metadata
// or distort an upper layer. The "ptc." prefix (pull-through compaction) is
// reserved: any caller-supplied key with this prefix is dropped on write.
const (
	metaFmt     = "ptc.fmt"     // storage format: raw | compressed | manifest
	metaUSize   = "ptc.usize"   // logical (uncompressed) size in bytes
	metaUDigest = "ptc.udigest" // logical content digest ("sha256:...")
	metaCSize   = "ptc.csize"   // physical stored size in bytes
	metaCodec   = "ptc.codec"   // compression codec name (when compressed)
	metaChunks  = "ptc.chunks"  // chunk count (manifest only)

	ptcReservedPrefix = "ptc."

	fmtRaw      = "raw"        // stored verbatim (incompressible or tiny)
	fmtComp     = "compressed" // single compressed blob
	fmtManifest = "manifest"   // chunk manifest (dedup)

	// chunkKeyPrefix namespaces the cache keys under which deduplicated chunks
	// are stored in the inner store. The NUL bytes keep it disjoint from every
	// real cache key (content addresses and logical coordinates are printable),
	// so chunks never collide with — and are always filtered out of listings of
	// — logical entries.
	chunkKeyPrefix = "\x00ptc.chunk\x00"
)

// CompactOptions configures a compacting Store decorator.
type CompactOptions struct {
	// Codec selects the compression algorithm. "zstd" is the only non-trivial
	// codec; "none"/"" disables compression (dedup can still be enabled). Unknown
	// values are rejected by NewCompactStore.
	Codec string
	// Level is the zstd compression level (1=fastest .. 19=smallest; 3 is a good
	// default balancing speed and ratio). Out-of-range values are clamped.
	Level int
	// MinSizeBytes skips compression for blobs smaller than this (the framing
	// overhead is not worth it). Defaults to 256 when zero.
	MinSizeBytes int64
	// Dedup enables cross-artifact chunk-level deduplication. It requires a
	// single-writer store: it maintains an in-memory chunk reference count that
	// is authoritative only for one process, so it MUST NOT be enabled on a
	// store shared by multiple writers (the S3/HA backend) — NewCompactStore
	// returns an error in that case. Compression alone is safe on a shared store.
	Dedup bool
	// Shared reports that the inner store is shared by multiple writers (HA S3).
	// It gates Dedup off and is set by the wiring layer from the backend config.
	Shared bool
	// SpoolDir is where the compression path stages its temporary output so the
	// physical length and digest are known before the backend write. Defaults to
	// the OS temp directory.
	SpoolDir string
}

// CompactionStats is an immutable snapshot of the compaction layer's cumulative
// counters, exported both to Prometheus and to the admin/ptctl space-savings
// report. All byte counters are cumulative over the process lifetime (they count
// what was written through the layer), so CompressionRatio reflects lifetime
// effectiveness rather than the instantaneous on-disk footprint.
type CompactionStats struct {
	Enabled      bool   `json:"enabled"`
	Codec        string `json:"codec"`
	Level        int    `json:"level"`
	MinSizeBytes int64  `json:"minSizeBytes"`
	DedupEnabled bool   `json:"dedupEnabled"`

	// EntriesCompressed / EntriesStoredRaw count logical blobs written compressed
	// vs stored verbatim (incompressible or below MinSizeBytes).
	EntriesCompressed int64 `json:"entriesCompressed"`
	EntriesStoredRaw  int64 `json:"entriesStoredRaw"`

	// LogicalBytes is the total uncompressed content written through the layer.
	LogicalBytes int64 `json:"logicalBytes"`
	// PhysicalBytes is the total bytes actually written to the backend (after
	// compression and dedup). It never double-counts a deduplicated chunk.
	PhysicalBytes int64 `json:"physicalBytes"`
	// CompressionRatio is LogicalBytes/PhysicalBytes (>1 means a net saving; 0
	// when nothing has been written yet).
	CompressionRatio float64 `json:"compressionRatio"`
	// SavedBytes is LogicalBytes-PhysicalBytes: the total footprint reduction
	// from compression and dedup combined.
	SavedBytes int64 `json:"savedBytes"`

	// DedupChunksWritten / DedupChunksReused count unique chunks persisted vs
	// references satisfied by an already-stored chunk.
	DedupChunksWritten int64 `json:"dedupChunksWritten"`
	DedupChunksReused  int64 `json:"dedupChunksReused"`
	// DedupSavingsBytes is the logical bytes that did not need to be written
	// because the chunk was already present (cumulative at ingest).
	DedupSavingsBytes int64 `json:"dedupSavingsBytes"`
	// UniqueChunks is the current number of distinct chunks held (live gauge).
	UniqueChunks int64 `json:"uniqueChunks"`
}

// compactStore decorates an inner Store with transparent compression and
// optional chunk-level deduplication.
type compactStore struct {
	inner    Store
	codec    *zstdCodec // nil when compression is disabled
	minSize  int64
	dedup    bool
	spoolDir string

	// Cumulative counters (atomic, lock-free).
	entriesCompressed atomic.Int64
	entriesRaw        atomic.Int64
	logicalBytes      atomic.Int64
	physicalBytes     atomic.Int64
	chunksWritten     atomic.Int64
	chunksReused      atomic.Int64
	dedupSavings      atomic.Int64

	// refs guards the chunk reference index; populated only in dedup mode.
	mu   sync.Mutex
	refs map[string]*chunkMeta // chunk digest -> live reference metadata
}

// chunkMeta is the in-memory reference record for a single deduplicated chunk.
type chunkMeta struct {
	refcount int64
	logSize  int64 // uncompressed chunk length
	physSize int64 // bytes the chunk occupies in the backend
}

var _ Store = (*compactStore)(nil)

// CompactionStatSource is implemented by a cache (directly or via forwarding
// decorators) that can report compaction statistics. The observability and
// admin layers consult it through an interface assertion.
type CompactionStatSource interface {
	CompactionStats() CompactionStats
}

// NewCompactStore wraps inner with the compaction layer. It returns an error for
// an unknown codec, or if Dedup is requested on a shared store.
func NewCompactStore(inner Store, opts CompactOptions) (*compactStore, error) {
	if inner == nil {
		return nil, errors.New("cache: compaction layer requires an inner store")
	}
	if opts.Dedup && opts.Shared {
		return nil, errors.New("cache: chunk deduplication cannot be enabled on a shared (multi-writer) store; it relies on a single-writer reference count")
	}
	s := &compactStore{
		inner:    inner,
		minSize:  opts.MinSizeBytes,
		dedup:    opts.Dedup,
		spoolDir: opts.SpoolDir,
	}
	if s.minSize <= 0 {
		s.minSize = 256
	}
	switch strings.ToLower(strings.TrimSpace(opts.Codec)) {
	case "", "none", "off":
		// compression disabled
	case "zstd":
		c, err := newZstdCodec(opts.Level)
		if err != nil {
			return nil, err
		}
		s.codec = c
	default:
		return nil, fmt.Errorf("cache: unknown compression codec %q (supported: zstd, none)", opts.Codec)
	}
	if !s.dedup && s.codec == nil {
		return nil, errors.New("cache: compaction layer enabled with neither compression nor dedup")
	}
	if s.dedup {
		s.refs = make(map[string]*chunkMeta)
		if err := s.rebuildChunkIndex(context.Background()); err != nil {
			return nil, fmt.Errorf("cache: rebuilding dedup chunk index: %w", err)
		}
	}
	return s, nil
}

// CompactionStats returns a snapshot of the cumulative counters.
func (s *compactStore) CompactionStats() CompactionStats {
	logical := s.logicalBytes.Load()
	physical := s.physicalBytes.Load()
	ratio := 0.0
	if physical > 0 {
		ratio = float64(logical) / float64(physical)
	}
	st := CompactionStats{
		Enabled:            true,
		MinSizeBytes:       s.minSize,
		DedupEnabled:       s.dedup,
		EntriesCompressed:  s.entriesCompressed.Load(),
		EntriesStoredRaw:   s.entriesRaw.Load(),
		LogicalBytes:       logical,
		PhysicalBytes:      physical,
		CompressionRatio:   ratio,
		SavedBytes:         logical - physical,
		DedupChunksWritten: s.chunksWritten.Load(),
		DedupChunksReused:  s.chunksReused.Load(),
		DedupSavingsBytes:  s.dedupSavings.Load(),
	}
	if s.codec != nil {
		st.Codec = s.codec.name()
		st.Level = s.codec.lvl
	} else {
		st.Codec = "none"
	}
	if s.dedup {
		s.mu.Lock()
		st.UniqueChunks = int64(len(s.refs))
		s.mu.Unlock()
	}
	return st
}

// Put implements Store.
func (s *compactStore) Put(ctx context.Context, rec Record, r io.Reader) (Record, error) {
	if rec.Key == "" {
		return Record{}, errors.New("cache: Put requires a non-empty key")
	}
	// Never let a caller inject our reserved metadata keys.
	stripReserved(&rec)
	if s.dedup {
		return s.putDedup(ctx, rec, r)
	}
	return s.putCompressed(ctx, rec, r)
}

// putCompressed stores a single (optionally compressed) blob. It stages the
// physical bytes to a temp file so the logical size + digest are known before
// the backend write, then overrides the backend's size/digest with the logical
// ones on the way out.
func (s *compactStore) putCompressed(ctx context.Context, rec Record, r io.Reader) (Record, error) {
	// Peek the head of the stream to decide whether compression is worthwhile.
	br := bufio.NewReaderSize(r, sniffLen)
	head, _ := br.Peek(sniffLen)
	compress := s.codec != nil && s.shouldCompress(rec.ContentType, head)

	tmp, err := os.CreateTemp(s.spoolDir, "ptc-*")
	if err != nil {
		return Record{}, fmt.Errorf("cache: staging compacted blob: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	hw := &hashCounter{h: sha256.New()}
	src := io.TeeReader(br, hw) // logical bytes flow through the hasher+counter

	var physical int64
	codecName := ""
	format := fmtRaw
	if compress {
		n, cerr := s.codec.compressStream(tmp, src)
		if cerr != nil {
			return Record{}, fmt.Errorf("cache: compressing blob for %q: %w", rec.Key, cerr)
		}
		physical = n
		codecName = s.codec.name()
		format = fmtComp
	} else {
		n, cerr := io.Copy(tmp, src)
		if cerr != nil {
			return Record{}, fmt.Errorf("cache: staging blob for %q: %w", rec.Key, cerr)
		}
		physical = n
	}
	usize := hw.n
	udigest := hw.digest()

	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return Record{}, err
	}

	setReserved(&rec, format, usize, udigest, physical, codecName, 0)
	stored, err := s.inner.Put(ctx, rec, tmp)
	if err != nil {
		return Record{}, err
	}
	committed = true
	_ = tmp.Close()
	_ = os.Remove(tmpName)

	s.logicalBytes.Add(usize)
	s.physicalBytes.Add(physical)
	if compress {
		s.entriesCompressed.Add(1)
	} else {
		s.entriesRaw.Add(1)
	}
	return s.outward(stored), nil
}

// putDedup chunks the stream, stores each unique chunk once, and persists a
// manifest (the list of chunk digests) as the logical entry.
func (s *compactStore) putDedup(ctx context.Context, rec Record, r io.Reader) (Record, error) {
	// Capture the previous manifest (if the key already holds one) so that an
	// overwrite with identical content does not leak chunk references.
	oldChunks := s.readManifestChunks(ctx, rec.Key)

	hw := &hashCounter{h: sha256.New()}
	ck := newChunker(io.TeeReader(r, hw))

	var manifestEntries []manifestEntry
	// Track what we referenced so we can roll back on a later failure.
	var added []string
	rollback := func() {
		s.releaseChunks(ctx, added)
	}

	for {
		chunk, err := ck.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			rollback()
			return Record{}, fmt.Errorf("cache: chunking blob for %q: %w", rec.Key, err)
		}
		cp := append([]byte(nil), chunk...) // next() reuses its buffer
		digest := chunkDigest(cp)
		if err := s.referenceChunk(ctx, digest, cp); err != nil {
			rollback()
			return Record{}, err
		}
		added = append(added, digest)
		manifestEntries = append(manifestEntries, manifestEntry{digest: digest, size: int64(len(cp))})
	}

	usize := hw.n
	udigest := hw.digest()
	manifestBytes := encodeManifest(manifestEntries)

	setReserved(&rec, fmtManifest, usize, udigest, int64(len(manifestBytes)), "", len(manifestEntries))
	stored, err := s.inner.Put(ctx, rec, bytes.NewReader(manifestBytes))
	if err != nil {
		rollback()
		return Record{}, err
	}

	// The new manifest is durable; now it is safe to release the chunks the old
	// manifest held (a no-op for identical content, which nets to zero change).
	if len(oldChunks) > 0 {
		s.releaseChunks(ctx, oldChunks)
	}

	s.logicalBytes.Add(usize)
	s.physicalBytes.Add(int64(len(manifestBytes)))
	s.entriesCompressed.Add(1)
	return s.outward(stored), nil
}

// referenceChunk ensures a chunk is stored and increments its reference count.
func (s *compactStore) referenceChunk(ctx context.Context, digest string, data []byte) error {
	s.mu.Lock()
	if cm := s.refs[digest]; cm != nil {
		cm.refcount++
		s.mu.Unlock()
		s.chunksReused.Add(1)
		s.dedupSavings.Add(int64(len(data)))
		return nil
	}
	s.mu.Unlock()

	// Store the chunk (compressed when worthwhile) outside the lock.
	physical, err := s.encodeChunk(ctx, digest, data)
	if err != nil {
		return err
	}

	s.mu.Lock()
	// Re-check: a concurrent writer may have stored the same chunk meanwhile. Our
	// just-written duplicate is harmless — it is content-addressed by the same
	// key, so the inner store holds exactly one copy; just adopt the reference.
	if cm := s.refs[digest]; cm != nil {
		cm.refcount++
		s.mu.Unlock()
		s.chunksReused.Add(1)
		s.dedupSavings.Add(int64(len(data)))
		return nil
	}
	s.refs[digest] = &chunkMeta{refcount: 1, logSize: int64(len(data)), physSize: physical}
	s.mu.Unlock()
	s.chunksWritten.Add(1)
	s.physicalBytes.Add(physical)
	return nil
}

// encodeChunk persists one chunk to the inner store, compressing it when the
// heuristic says it is worthwhile. It returns the physical size written.
func (s *compactStore) encodeChunk(ctx context.Context, digest string, data []byte) (physical int64, err error) {
	format := fmtRaw
	codecName := ""
	body := data
	if s.codec != nil && int64(len(data)) >= s.minSize && s.shouldCompress("", data) {
		comp := s.codec.compressBuf(data)
		if len(comp) < len(data) {
			body = comp
			format = fmtComp
			codecName = s.codec.name()
		}
	}
	crec := Record{Key: chunkKeyPrefix + digest}
	setReserved(&crec, format, int64(len(data)), digest, int64(len(body)), codecName, 0)
	if _, err := s.inner.Put(ctx, crec, bytes.NewReader(body)); err != nil {
		return 0, fmt.Errorf("cache: writing chunk %s: %w", digest, err)
	}
	return int64(len(body)), nil
}

// releaseChunks decrements the reference count of each chunk and deletes any
// that drop to zero. Unknown chunks are ignored.
func (s *compactStore) releaseChunks(ctx context.Context, digests []string) {
	var orphans []string
	s.mu.Lock()
	for _, d := range digests {
		cm := s.refs[d]
		if cm == nil {
			continue
		}
		cm.refcount--
		if cm.refcount > 0 {
			continue
		}
		delete(s.refs, d)
		orphans = append(orphans, d)
	}
	s.mu.Unlock()
	for _, d := range orphans {
		_ = s.inner.Delete(ctx, chunkKeyPrefix+d)
	}
}

// Get implements Store, reversing the physical transform.
func (s *compactStore) Get(ctx context.Context, key string) (io.ReadCloser, Record, error) {
	rc, rec, err := s.inner.Get(ctx, key)
	if err != nil {
		return nil, Record{}, err
	}
	switch reservedFmt(rec) {
	case fmtManifest:
		mf, derr := decodeManifest(rc)
		rc.Close()
		if derr != nil {
			return nil, Record{}, fmt.Errorf("cache: decoding manifest for %q: %w", key, derr)
		}
		return s.newChunkReader(ctx, mf), s.outward(rec), nil
	case fmtComp:
		dr, derr := s.codec.decompress(rc)
		if derr != nil {
			rc.Close()
			return nil, Record{}, fmt.Errorf("cache: opening decompressor for %q: %w", key, derr)
		}
		return &decompressReadCloser{dec: dr, underlying: rc}, s.outward(rec), nil
	default:
		// fmtRaw or a legacy entry written before this layer existed.
		return rc, s.outward(rec), nil
	}
}

// Stat implements Store.
func (s *compactStore) Stat(ctx context.Context, key string) (Record, error) {
	rec, err := s.inner.Stat(ctx, key)
	if err != nil {
		return Record{}, err
	}
	return s.outward(rec), nil
}

// SetAccessed implements Store.
func (s *compactStore) SetAccessed(ctx context.Context, key string, t time.Time) error {
	return s.inner.SetAccessed(ctx, key, t)
}

// Delete implements Store, releasing a manifest's chunk references.
func (s *compactStore) Delete(ctx context.Context, key string) error {
	if s.dedup {
		if chunks := s.readManifestChunks(ctx, key); len(chunks) > 0 {
			s.releaseChunks(ctx, chunks)
		}
	}
	return s.inner.Delete(ctx, key)
}

// List implements Store, hiding internal chunk entries and projecting logical
// size/digest back onto each record.
func (s *compactStore) List(ctx context.Context) ([]Record, error) {
	recs, err := s.inner.List(ctx)
	if err != nil {
		return nil, err
	}
	out := recs[:0]
	for _, rec := range recs {
		if strings.HasPrefix(rec.Key, chunkKeyPrefix) {
			continue
		}
		out = append(out, s.outward(rec))
	}
	return out, nil
}

// Close implements Store.
func (s *compactStore) Close() error {
	var cerr error
	if s.codec != nil {
		s.codec.close()
	}
	if err := s.inner.Close(); err != nil {
		cerr = err
	}
	return cerr
}

// readManifestChunks returns the chunk digests referenced by key's manifest, or
// nil when key is absent or not a manifest.
func (s *compactStore) readManifestChunks(ctx context.Context, key string) []string {
	rc, rec, err := s.inner.Get(ctx, key)
	if err != nil {
		return nil
	}
	defer rc.Close()
	if reservedFmt(rec) != fmtManifest {
		return nil
	}
	mf, err := decodeManifest(rc)
	if err != nil {
		return nil
	}
	digests := make([]string, len(mf))
	for i, e := range mf {
		digests[i] = e.digest
	}
	return digests
}

// rebuildChunkIndex reconstructs the in-memory chunk reference count from the
// durable store at startup: it registers every stored chunk, then walks every
// manifest and counts references. Chunks left with zero references (orphaned by
// a crash between a chunk write and its manifest write, or between a manifest
// delete and a chunk delete) are swept so they do not leak space.
func (s *compactStore) rebuildChunkIndex(ctx context.Context) error {
	recs, err := s.inner.List(ctx)
	if err != nil {
		return err
	}
	for _, rec := range recs {
		if !strings.HasPrefix(rec.Key, chunkKeyPrefix) {
			continue
		}
		digest := strings.TrimPrefix(rec.Key, chunkKeyPrefix)
		s.refs[digest] = &chunkMeta{
			refcount: 0,
			logSize:  reservedInt(rec, metaUSize),
			physSize: rec.Size,
		}
	}
	for _, rec := range recs {
		if strings.HasPrefix(rec.Key, chunkKeyPrefix) || reservedFmt(rec) != fmtManifest {
			continue
		}
		for _, d := range s.readManifestChunks(ctx, rec.Key) {
			if cm := s.refs[d]; cm != nil {
				cm.refcount++
			}
		}
	}
	for digest, cm := range s.refs {
		if cm.refcount == 0 {
			delete(s.refs, digest)
			_ = s.inner.Delete(ctx, chunkKeyPrefix+digest)
		}
	}
	return nil
}

// outward projects a persisted Record back to the caller: it restores the
// logical size and digest and strips the reserved compaction metadata.
func (s *compactStore) outward(rec Record) Record {
	if u := reservedInt(rec, metaUSize); u > 0 || reservedStr(rec, metaUSize) == "0" {
		rec.Size = u
	}
	if d := reservedStr(rec, metaUDigest); d != "" {
		rec.Digest = d
	}
	if len(rec.Extra) > 0 {
		for k := range rec.Extra {
			if strings.HasPrefix(k, ptcReservedPrefix) {
				delete(rec.Extra, k)
			}
		}
		if len(rec.Extra) == 0 {
			rec.Extra = nil
		}
	}
	return rec
}

// --- reserved-metadata helpers ---

func stripReserved(rec *Record) {
	for k := range rec.Extra {
		if strings.HasPrefix(k, ptcReservedPrefix) {
			delete(rec.Extra, k)
		}
	}
}

func setReserved(rec *Record, format string, usize int64, udigest string, csize int64, codecName string, chunks int) {
	if rec.Extra == nil {
		rec.Extra = make(map[string]string, 6)
	}
	rec.Extra[metaFmt] = format
	rec.Extra[metaUSize] = strconv.FormatInt(usize, 10)
	rec.Extra[metaUDigest] = udigest
	rec.Extra[metaCSize] = strconv.FormatInt(csize, 10)
	if codecName != "" {
		rec.Extra[metaCodec] = codecName
	}
	if chunks > 0 {
		rec.Extra[metaChunks] = strconv.Itoa(chunks)
	}
}

func reservedFmt(rec Record) string { return reservedStr(rec, metaFmt) }

func reservedStr(rec Record, key string) string {
	if rec.Extra == nil {
		return ""
	}
	return rec.Extra[key]
}

func reservedInt(rec Record, key string) int64 {
	v, _ := strconv.ParseInt(reservedStr(rec, key), 10, 64)
	return v
}

// --- compression heuristic ---

// sniffLen is how many leading bytes the heuristic inspects. It is large enough
// that the Shannon-entropy estimate over the sample is reliable: a few hundred
// bytes spread over 256 symbols under-counts entropy badly, so a multi-kilobyte
// window is needed to avoid judging genuinely incompressible data compressible.
const sniffLen = 16 * 1024

// entropyMinSample is the smallest sample for which the entropy test is trusted;
// below it the decision falls through to compression (tiny blobs are gated by
// MinSizeBytes anyway, and mis-compressing a tiny blob is harmless).
const entropyMinSample = 1024

// shouldCompress reports whether content is worth compressing. It skips
// content whose media type or leading magic bytes mark it as already compressed
// (images, video, archives, compressed streams), and content whose sampled
// Shannon entropy is close to the 8 bits/byte ceiling (incompressible). An empty
// sample is treated as compressible (tiny content is gated by MinSizeBytes).
func (s *compactStore) shouldCompress(contentType string, sample []byte) bool {
	if isCompressedContentType(contentType) {
		return false
	}
	if hasCompressedMagic(sample) {
		return false
	}
	if len(sample) >= entropyMinSample && sampleEntropy(sample) > 7.8 {
		return false
	}
	return true
}

// compressedMagic lists leading byte signatures of already-compressed or media
// formats that gain nothing (and cost CPU) from a second compression pass.
var compressedMagic = [][]byte{
	{0x1f, 0x8b},                         // gzip
	{0x28, 0xb5, 0x2f, 0xfd},             // zstd
	{0x42, 0x5a, 0x68},                   // bzip2 "BZh"
	{0xfd, 0x37, 0x7a, 0x58, 0x5a},       // xz
	{0x04, 0x22, 0x4d, 0x18},             // lz4 frame
	{0x50, 0x4b, 0x03, 0x04},             // zip / jar / whl / docx
	{0x50, 0x4b, 0x05, 0x06},             // empty zip
	{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}, // 7z
	{0xff, 0xd8, 0xff},                   // jpeg
	{0x89, 0x50, 0x4e, 0x47},             // png
	{0x47, 0x49, 0x46, 0x38},             // gif
	{0x52, 0x49, 0x46, 0x46},             // riff (webp/wav/avi)
	{0x77, 0x4f, 0x46, 0x32},             // woff2
	{0x00, 0x61, 0x73, 0x6d},             // wasm
	{0x25, 0x50, 0x44, 0x46},             // pdf (often has compressed streams)
}

func hasCompressedMagic(b []byte) bool {
	for _, m := range compressedMagic {
		if len(b) >= len(m) && bytes.Equal(b[:len(m)], m) {
			return true
		}
	}
	// ISO-BMFF (mp4/mov/m4a): bytes 4..8 == "ftyp".
	if len(b) >= 12 && bytes.Equal(b[4:8], []byte("ftyp")) {
		return true
	}
	return false
}

func isCompressedContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "application/gzip", "application/x-gzip", "application/zip",
		"application/x-zstd", "application/x-xz", "application/x-bzip2",
		"application/x-7z-compressed", "application/x-rar-compressed",
		"application/java-archive", "application/octet-stream+zstd",
		"application/wasm":
		return true
	}
	if strings.HasPrefix(ct, "image/") || strings.HasPrefix(ct, "video/") || strings.HasPrefix(ct, "audio/") {
		// SVG is text; everything else in these families is already compressed.
		return ct != "image/svg+xml"
	}
	return false
}

// sampleEntropy estimates the Shannon entropy (bits per byte, 0..8) of b.
func sampleEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	n := float64(len(b))
	var h float64
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * math.Log2(p)
	}
	return h
}

// --- hashing helper ---

// hashCounter tees bytes through a running digest while counting them.
type hashCounter struct {
	h hash.Hash
	n int64
}

func (c *hashCounter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return c.h.Write(p)
}

func (c *hashCounter) digest() string {
	return "sha256:" + hex.EncodeToString(c.h.Sum(nil))
}

// --- manifest encoding ---

// manifestEntry is one chunk reference in a manifest.
type manifestEntry struct {
	digest string // chunk content digest ("sha256:...")
	size   int64  // uncompressed chunk length
}

// manifestMagic prefixes a manifest blob so a legacy/raw entry can never be
// mistaken for one even if the format marker were lost.
var manifestMagic = []byte("PTCM1\n")

// encodeManifest serializes a chunk list: a magic header, then one line per
// chunk "<size> <digest>\n". The format is compact, append-only, and trivially
// streamable.
func encodeManifest(entries []manifestEntry) []byte {
	var buf bytes.Buffer
	buf.Write(manifestMagic)
	for _, e := range entries {
		buf.WriteString(strconv.FormatInt(e.size, 10))
		buf.WriteByte(' ')
		buf.WriteString(e.digest)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// decodeManifest parses a manifest blob.
func decodeManifest(r io.Reader) ([]manifestEntry, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(data, manifestMagic) {
		return nil, errors.New("not a chunk manifest")
	}
	body := data[len(manifestMagic):]
	var entries []manifestEntry
	for _, line := range bytes.Split(body, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		sp := bytes.IndexByte(line, ' ')
		if sp <= 0 {
			return nil, fmt.Errorf("malformed manifest line %q", line)
		}
		size, perr := strconv.ParseInt(string(line[:sp]), 10, 64)
		if perr != nil {
			return nil, fmt.Errorf("malformed manifest size %q: %w", line[:sp], perr)
		}
		entries = append(entries, manifestEntry{digest: string(line[sp+1:]), size: size})
	}
	return entries, nil
}

// --- chunk reassembly reader ---

// newChunkReader returns a forward-only reader that lazily opens, decompresses,
// and concatenates the manifest's chunks in order. It is not seekable; the serve
// layer spools it to a temp file when a byte-range request needs random access,
// exactly as it does for the S3 backend's forward-only bodies.
func (s *compactStore) newChunkReader(ctx context.Context, mf []manifestEntry) io.ReadCloser {
	return &chunkReader{s: s, ctx: ctx, entries: mf}
}

type chunkReader struct {
	s       *compactStore
	ctx     context.Context
	entries []manifestEntry
	idx     int
	cur     io.ReadCloser
	err     error
}

func (cr *chunkReader) Read(p []byte) (int, error) {
	if cr.err != nil {
		return 0, cr.err
	}
	for {
		if cr.cur == nil {
			if cr.idx >= len(cr.entries) {
				return 0, io.EOF
			}
			rc, rec, err := cr.s.inner.Get(cr.ctx, chunkKeyPrefix+cr.entries[cr.idx].digest)
			if err != nil {
				cr.err = fmt.Errorf("cache: reading chunk %s: %w", cr.entries[cr.idx].digest, err)
				return 0, cr.err
			}
			if reservedFmt(rec) == fmtComp {
				dr, derr := cr.s.codec.decompress(rc)
				if derr != nil {
					rc.Close()
					cr.err = derr
					return 0, cr.err
				}
				cr.cur = &decompressReadCloser{dec: dr, underlying: rc}
			} else {
				cr.cur = rc
			}
			cr.idx++
		}
		n, err := cr.cur.Read(p)
		if err == io.EOF {
			cr.cur.Close()
			cr.cur = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (cr *chunkReader) Close() error {
	if cr.cur != nil {
		err := cr.cur.Close()
		cr.cur = nil
		return err
	}
	return nil
}

// decompressReadCloser closes both the decompressor and the underlying backend
// reader it was wrapping.
type decompressReadCloser struct {
	dec        io.ReadCloser
	underlying io.ReadCloser
}

func (d *decompressReadCloser) Read(p []byte) (int, error) { return d.dec.Read(p) }

func (d *decompressReadCloser) Close() error {
	err := d.dec.Close()
	if cerr := d.underlying.Close(); err == nil {
		err = cerr
	}
	return err
}

// chunkDigest returns the content digest key for a chunk.
func chunkDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// --- zstd codec ---

// zstdCodec wraps the klauspost/compress zstd encoder/decoder. A single encoder
// and decoder are shared for the buffer (EncodeAll/DecodeAll) paths, which are
// safe for concurrent use; the streaming paths allocate a fresh writer/reader
// per call.
type zstdCodec struct {
	lvl     int
	level   zstd.EncoderLevel
	encoder *zstd.Encoder // for EncodeAll (chunk buffers)
	decoder *zstd.Decoder // for DecodeAll and streaming reads
}

func newZstdCodec(level int) (*zstdCodec, error) {
	if level <= 0 {
		level = 3
	}
	if level > 19 {
		level = 19
	}
	lvl := zstd.EncoderLevelFromZstd(level)
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(lvl), zstd.WithEncoderConcurrency(1))
	if err != nil {
		return nil, fmt.Errorf("cache: initializing zstd encoder: %w", err)
	}
	dec, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(0))
	if err != nil {
		enc.Close()
		return nil, fmt.Errorf("cache: initializing zstd decoder: %w", err)
	}
	return &zstdCodec{lvl: level, level: lvl, encoder: enc, decoder: dec}, nil
}

func (z *zstdCodec) name() string { return "zstd" }

// compressStream compresses all of src into dst, returning the bytes written.
func (z *zstdCodec) compressStream(dst io.Writer, src io.Reader) (int64, error) {
	cw := &countWriter{w: dst}
	zw, err := zstd.NewWriter(cw, zstd.WithEncoderLevel(z.level), zstd.WithEncoderConcurrency(1))
	if err != nil {
		return 0, err
	}
	if _, err := io.Copy(zw, src); err != nil {
		zw.Close()
		return cw.n, err
	}
	if err := zw.Close(); err != nil {
		return cw.n, err
	}
	return cw.n, nil
}

// compressBuf compresses p and returns the result (uses the shared encoder).
func (z *zstdCodec) compressBuf(p []byte) []byte {
	return z.encoder.EncodeAll(p, make([]byte, 0, len(p)/2+64))
}

// decompress wraps src with a streaming decompressor. The returned closer must
// be closed; closing it does NOT close src (the caller's wrapper handles that).
func (z *zstdCodec) decompress(src io.Reader) (io.ReadCloser, error) {
	dr, err := zstd.NewReader(src, zstd.WithDecoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	return dr.IOReadCloser(), nil
}

func (z *zstdCodec) close() {
	if z.encoder != nil {
		z.encoder.Close()
	}
	if z.decoder != nil {
		z.decoder.Close()
	}
}

// countWriter counts the bytes written through it.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
