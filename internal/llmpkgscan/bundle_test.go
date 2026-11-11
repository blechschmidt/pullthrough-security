package llmpkgscan

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

// The round trip an air-gap transfer makes: verdicts reached where the provider
// is reachable are exported for the artifacts a bundle carries, imported into a
// second instance's store, and enforced there without a single model call.
func TestVerdictsTravelAcrossAnAirGap(t *testing.T) {
	ctx := context.Background()
	evil, good, other := maliciousPackage(), benignPackage(), pkgscantest.TarGz(map[string]string{"x/y.txt": "not in the bundle\n"})
	im := maliciousImage(t)

	// The connected side scans.
	connectedStore := NewMemoryStore(0)
	connected := newService(t, &pkgscantest.Provider{}, func(c *Config) { c.Store = connectedStore })
	assess(t, connected, request(evil, "evil-pad", "1.0.0", nil))
	assess(t, connected, request(good, "left-pad", "1.3.0", nil))
	assess(t, connected, request(other, "other", "1.0.0", nil))
	assess(t, connected, im.request())

	// The bundle carries the two packages and the image's manifest — not "other".
	carried := map[string]bool{pkgscantest.Digest(evil): true, pkgscantest.Digest(good): true, pkgscantest.Digest(im.manifest): true}
	exported, err := ExportVerdicts(ctx, connectedStore, carried)
	if err != nil {
		t.Fatalf("ExportVerdicts: %v", err)
	}
	if len(exported) != 3 {
		t.Fatalf("exported %d verdicts, want 3 (one per carried artifact)", len(exported))
	}
	for i := 1; i < len(exported); i++ {
		if exported[i-1].Digest > exported[i].Digest {
			t.Errorf("exported verdicts are not ordered by digest: a bundle must be reproducible")
		}
	}
	for _, bv := range exported {
		if !carried[bv.Digest] {
			t.Errorf("a verdict for %s, which the bundle does not carry, was exported", bv.Digest)
		}
	}

	// The disconnected side: same model, no provider it can reach.
	airgapStore := NewMemoryStore(0)
	for _, bv := range exported {
		if _, err := ImportVerdict(ctx, airgapStore, bv.Digest, bv.Record); err != nil {
			t.Fatalf("ImportVerdict(%s): %v", bv.Digest, err)
		}
	}
	unreachable := &pkgscantest.Provider{Err: errors.New("no route to host")}
	airgapped := newService(t, unreachable, func(c *Config) {
		c.Store = airgapStore
		c.FailMode = FailClosed
	})

	rep := assess(t, airgapped, request(evil, "evil-pad", "1.0.0", nil))
	if !rep.Cached || rep.Disposition != DispositionMalicious || airgapped.Gate(rep).Served() {
		t.Errorf("the malicious package behind the air gap: cached=%v disposition=%s; want it refused from the imported verdict", rep.Cached, rep.Disposition)
	}
	rep = assess(t, airgapped, request(good, "left-pad", "1.3.0", nil))
	if !rep.Cached || rep.Disposition != DispositionBenign || !airgapped.Gate(rep).Served() {
		t.Errorf("the benign package behind the air gap: cached=%v disposition=%s (unscanned %+v); want it admitted from the imported verdict", rep.Cached, rep.Disposition, rep.Unscanned)
	}
	// The image's verdict brings its blob index with it: the layers are refused
	// behind the gap as they are in front of it. (The index is built from the
	// store when the gate starts; an import runs before the server does.)
	restarted := newService(t, unreachable, func(c *Config) { c.Store = airgapStore })
	if st := restarted.BlobStatus(ctx, im.layers[1]); !st.Refused {
		t.Errorf("after import and a start, the implicated layer's status = %+v, want it refused", st)
	}
	if st := restarted.BlobStatus(ctx, im.layers[0]); !st.Covered || st.Refused {
		t.Errorf("after import and a start, the base layer's status = %+v, want covered and not refused", st)
	}

	// What the bundle did not carry has no verdict there: the fail mode decides.
	rep = assess(t, airgapped, request(other, "other", "1.0.0", nil))
	if rep.Scanned() || airgapped.Gate(rep).Served() {
		t.Errorf("an artifact without an imported verdict: scanned=%v served=%v; want unscanned and refused under fail-closed", rep.Scanned(), airgapped.Gate(rep).Served())
	}
}

// A different model on the importing side means the imported verdicts are not
// the ones it looks for: it must not treat them as its own.
func TestImportedVerdictIsNotFoundUnderAnotherModel(t *testing.T) {
	ctx := context.Background()
	evil := maliciousPackage()
	src := NewMemoryStore(0)
	assess(t, newService(t, &pkgscantest.Provider{}, func(c *Config) { c.Store = src }), request(evil, "evil-pad", "1.0.0", nil))
	exported, _ := ExportVerdicts(ctx, src, map[string]bool{pkgscantest.Digest(evil): true})
	dst := NewMemoryStore(0)
	if _, err := ImportVerdict(ctx, dst, exported[0].Digest, exported[0].Record); err != nil {
		t.Fatal(err)
	}
	p := &pkgscantest.Provider{}
	other := newService(t, p, func(c *Config) {
		c.Store = dst
		c.Model = "a-different-model"
	})
	rep := assess(t, other, request(evil, "evil-pad", "1.0.0", nil))
	if rep.Cached || p.Calls() != 1 {
		t.Errorf("cached=%v, model calls=%d: a verdict reached by another model was served as this one's", rep.Cached, p.Calls())
	}
}

// A record is filed only as the verdict of the artifact, model and prompt
// version it names: nothing in a bundle can place a verdict under another
// artifact's key, or turn a refusal into an admission by editing a field.
func TestImportVerdictRejectsRecordsThatAreNotWhatTheyClaim(t *testing.T) {
	ctx := context.Background()
	evil, good := maliciousPackage(), benignPackage()
	src := NewMemoryStore(0)
	svc := newService(t, &pkgscantest.Provider{}, func(c *Config) { c.Store = src })
	assess(t, svc, request(evil, "evil-pad", "1.0.0", nil))
	assess(t, svc, request(good, "left-pad", "1.3.0", nil))
	exported, err := ExportVerdicts(ctx, src, map[string]bool{pkgscantest.Digest(evil): true, pkgscantest.Digest(good): true})
	if err != nil || len(exported) != 2 {
		t.Fatalf("ExportVerdicts: %d, %v", len(exported), err)
	}
	var evilRec, goodRec BundledVerdict
	for _, bv := range exported {
		if bv.Digest == pkgscantest.Digest(evil) {
			evilRec = bv
		} else {
			goodRec = bv
		}
	}
	mutate := func(rec []byte, f func(v *Verdict)) []byte {
		var v Verdict
		if err := json.Unmarshal(rec, &v); err != nil {
			t.Fatal(err)
		}
		f(&v)
		out, _ := json.Marshal(&v)
		return out
	}

	cases := []struct {
		name   string
		digest string
		record []byte
		want   string
	}{
		// The benign package's verdict, presented as the malicious one's.
		{"another artifact's verdict", evilRec.Digest, goodRec.Record, "not about the artifact"},
		// The same, with the digest field rewritten to match: the key gives it away.
		{"digest rewritten to match", evilRec.Digest, mutate(goodRec.Record, func(v *Verdict) { v.Digest = evilRec.Digest }), "not the key"},
		// Digest and key both rewritten — but the key is derived, not chosen.
		{"key copied from the other record", evilRec.Digest, mutate(goodRec.Record, func(v *Verdict) {
			var e Verdict
			_ = json.Unmarshal(evilRec.Record, &e)
			v.Digest, v.Key = e.Digest, e.Key
		}), ""},
		{"a variant that does not match the key", evilRec.Digest, mutate(evilRec.Record, func(v *Verdict) { v.Scope = ScopeMetadataOnly }), "not the key"},
		{"an image kind on a package verdict", evilRec.Digest, mutate(evilRec.Record, func(v *Verdict) { v.Kind = KindImage }), "not the key"},
		{"another model under the same key", evilRec.Digest, mutate(evilRec.Record, func(v *Verdict) { v.Model = "other" }), "not the key"},
		{"another prompt version under the same key", evilRec.Digest, mutate(evilRec.Record, func(v *Verdict) { v.PromptVersion++ }), "not the key"},
		{"an unknown verdict", evilRec.Digest, mutate(evilRec.Record, func(v *Verdict) { v.Verdict = "fine" }), "unknown verdict"},
		{"a confidence above one", evilRec.Digest, mutate(evilRec.Record, func(v *Verdict) { v.Confidence = 1.5 }), "confidence"},
		{"a negative confidence", evilRec.Digest, mutate(evilRec.Record, func(v *Verdict) { v.Confidence = -0.1 }), "confidence"},
		{"an unknown scope", evilRec.Digest, mutate(evilRec.Record, func(v *Verdict) { v.Scope = "everything" }), "unknown scope"},
		{"no model", evilRec.Digest, mutate(evilRec.Record, func(v *Verdict) { v.Model = "" }), "no model"},
		{"a non-sha256 digest", evilRec.Digest, mutate(evilRec.Record, func(v *Verdict) { v.Digest = "md5:abc" }), "not a sha256 digest"},
		{"a blob that is not a digest", evilRec.Digest, mutate(evilRec.Record, func(v *Verdict) { v.Blobs = []string{"../../etc/passwd"} }), "not a sha256 digest"},
		{"not JSON", evilRec.Digest, []byte("{not json"), "not valid JSON"},
		{"an oversized record", evilRec.Digest, []byte(`{"key":"` + strings.Repeat("a", maxBundleVerdictBytes) + `"}`), "over the"},
		{"a digest the bundle did not state", "sha256:" + strings.Repeat("0", 64), evilRec.Record, "not about the artifact"},
		{"no digest at all", "", evilRec.Record, "not about the artifact"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dst := NewMemoryStore(0)
			v, err := ImportVerdict(ctx, dst, tc.digest, tc.record)
			if tc.name == "key copied from the other record" {
				// Internally consistent now — it IS a record under the malicious
				// artifact's key — but what it claims is "benign": that is the one
				// thing validation cannot catch, and why verdicts are imported only
				// from a bundle whose manifest digest was verified out of band.
				if err != nil {
					t.Fatalf("a self-consistent record was rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("the record was accepted as %+v", v)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
			if all, _ := dst.List(ctx); len(all) != 0 {
				t.Errorf("a rejected record left %d verdicts in the store", len(all))
			}
		})
	}

	// NaN is not a confidence.
	nan := Verdict{Digest: evilRec.Digest, Verdict: VerdictBenign, Confidence: math.NaN(), Model: "m", PromptVersion: PromptVersion}
	if validateBundledVerdict(&nan) == nil {
		t.Error("a NaN confidence was accepted")
	}
}

// A verdict this instance already holds is not replaced by a bundle: an
// imported "benign" must not overwrite a local "malicious".
func TestImportVerdictKeepsTheLocalVerdict(t *testing.T) {
	ctx := context.Background()
	evil := maliciousPackage()
	local := NewMemoryStore(0)
	assess(t, newService(t, &pkgscantest.Provider{}, func(c *Config) { c.Store = local }), request(evil, "evil-pad", "1.0.0", nil))
	exported, _ := ExportVerdicts(ctx, local, map[string]bool{pkgscantest.Digest(evil): true})

	// The same record claiming benign.
	var v Verdict
	_ = json.Unmarshal(exported[0].Record, &v)
	v.Verdict, v.Evidence = VerdictBenign, nil
	forged, _ := json.Marshal(&v)

	got, err := ImportVerdict(ctx, local, exported[0].Digest, forged)
	if !errors.Is(err, ErrVerdictPresent) {
		t.Fatalf("err = %v, want ErrVerdictPresent", err)
	}
	if got == nil || got.Verdict != VerdictMalicious {
		t.Errorf("returned verdict = %+v, want the stored malicious one", got)
	}
	stored, _ := local.Get(ctx, v.Key)
	if stored.Verdict != VerdictMalicious {
		t.Errorf("the local verdict was overwritten with %q", stored.Verdict)
	}
}

func TestExportVerdictsEdges(t *testing.T) {
	ctx := context.Background()
	if out, err := ExportVerdicts(ctx, nil, map[string]bool{"sha256:" + strings.Repeat("a", 64): true}); err != nil || out != nil {
		t.Errorf("nil store: %v, %v", out, err)
	}
	store := NewMemoryStore(0)
	if out, err := ExportVerdicts(ctx, store, nil); err != nil || out != nil {
		t.Errorf("no digests: %v, %v", out, err)
	}
	// A stored record that would not survive import is not exported.
	h := strings.Repeat("b", 64)
	_ = store.Put(ctx, &Verdict{Key: CacheKey(h, "m", PromptVersion), Digest: "sha256:" + h, Verdict: "odd", Model: "m", PromptVersion: PromptVersion})
	if out, _ := ExportVerdicts(ctx, store, map[string]bool{"sha256:" + h: true}); len(out) != 0 {
		t.Errorf("an invalid stored record was exported: %d", len(out))
	}
	if _, err := ImportVerdict(ctx, nil, "sha256:"+h, []byte("{}")); err == nil {
		t.Error("ImportVerdict without a store succeeded")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_ = store.Put(ctx, &Verdict{Key: CacheKey(h, "m", PromptVersion), Digest: "sha256:" + h, Verdict: VerdictBenign, Model: "m", PromptVersion: PromptVersion})
	if _, err := ExportVerdicts(canceled, store, map[string]bool{"sha256:" + h: true}); err == nil {
		t.Error("ExportVerdicts ignored a canceled context")
	}
}

func TestVariantOf(t *testing.T) {
	for want, v := range map[string]*Verdict{
		variantFull:         {Kind: KindArchive},
		variantMetadataOnly: {Kind: KindArchive, Scope: ScopeMetadataOnly},
		variantImage:        {Kind: KindImage, Scope: ScopeMetadataOnly},
	} {
		if got := variantOf(v); got != want {
			t.Errorf("variantOf(%+v) = %q, want %q", v, got, want)
		}
	}
	if variantOf(&Verdict{Kind: KindImage}) != variantImage || variantOf(&Verdict{Kind: KindFile}) != variantFull {
		t.Error("variantOf does not match variantFor")
	}
}
