package userlinks

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Sync refreshes the registry from the store: it learns the links, revocations
// and blocks other replicas wrote, forgets what was deleted, and removes the
// records whose time is up.
//
// One listing tells it what exists; only objects it has not seen, or whose
// version changed, are read. When the listing fails nothing changes — the
// registry keeps answering from what it knows, and what it knows keeps being
// enforced. When an object cannot be read, everything else is still applied and
// the error is returned.
//
// Two things are applied even when their content cannot be read, because their
// meaning is "no": a revocation counts by existing, and a block that cannot be
// parsed is taken to block everything issued to its user so far. A block that
// cannot be read at the moment keeps meaning what it meant when it last could
// be; one never read before blocks everything issued so far, until it can be.
//
// Records whose time is up are removed only after a refresh that read
// everything it had to: what could not be read is no ground for deciding that
// something else may go.
func (r *Registry) Sync(ctx context.Context) error {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()
	r.stats.syncs.Add(1)

	// Everything added to memory from here on carries this generation, and is
	// therefore not mistaken for "deleted from the store" when the listing below
	// — taken a moment earlier — does not show it yet.
	r.mu.Lock()
	r.gen++
	gen := r.gen
	knownLinks := make(map[string]struct{}, len(r.byHash))
	for hash := range r.byHash {
		knownLinks[hash] = struct{}{}
	}
	knownRevoked := make(map[string]struct{}, len(r.revoked))
	for id := range r.revoked {
		knownRevoked[id] = struct{}{}
	}
	knownBlocks := make(map[string]string, len(r.blocks))
	for key, b := range r.blocks {
		knownBlocks[key] = b.version
	}
	knownUsage := make(map[string]string, len(r.remoteUsage))
	for node, u := range r.remoteUsage {
		knownUsage[node] = u.version
	}
	skipped := make(map[string]string, len(r.skipped))
	for name, version := range r.skipped {
		skipped[name] = version
	}
	ownUsageRead, ownUsageVersion := r.ownUsageRead, r.ownUsageVersion
	r.mu.Unlock()

	now := r.now()
	objects, err := r.store.List(ctx)
	if err != nil {
		r.stats.syncErrors.Add(1)
		r.stats.storeErrors.Add(1)
		r.mu.Lock()
		r.lastSyncErr = err
		r.mu.Unlock()
		return err
	}

	var (
		listedLinks   = map[string]struct{}{}
		listedRevoked = map[string]struct{}{}
		listedBlocks  = map[string]struct{}{}
		listedUsage   = map[string]struct{}{}
		stillSkipped  = map[string]string{}

		newLinks   []Link
		newRevoked []Revocation
		newBlocks  = map[string]*blockEntry{}
		newUsage   = map[string]remoteUsage{}
		firstErr   error

		// This replica's own usage object: whether the listing shows it, whether
		// it was read (or found to need no reading) during this refresh, and
		// what it says.
		ownUsageListed bool
		ownUsageSeen   bool
		ownUsage       map[string]Usage
	)
	// read fetches one object. A read that fails for a reason other than the
	// object being gone is remembered as the refresh's error and reported as
	// "could not be read", which callers treat according to what the object is.
	read := func(name string) ([]byte, bool) {
		data, err := r.store.Get(ctx, name)
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				r.stats.storeErrors.Add(1)
				if firstErr == nil {
					firstErr = err
				}
			}
			return nil, false
		}
		return data, true
	}
	// skip records that an object cannot be used. It is logged the first time
	// that version of it is met.
	skip := func(obj Object, why string) {
		stillSkipped[obj.Name] = obj.Version
		if skipped[obj.Name] != obj.Version {
			r.stats.skipped.Add(1)
			r.logger.Warn("personal links: ignoring a stored record that cannot be used",
				"object", obj.Name, "reason", why)
		}
	}

	for _, obj := range objects {
		kind, key, _ := strings.Cut(obj.Name, "/")
		switch kind {
		case "link":
			listedLinks[key] = struct{}{}
			if _, known := knownLinks[key]; known {
				continue
			}
			if skipped[obj.Name] == obj.Version {
				stillSkipped[obj.Name] = obj.Version
				continue
			}
			data, ok := read(obj.Name)
			if !ok {
				continue // gone again, or unreadable right now: the next refresh retries
			}
			var link Link
			if err := json.Unmarshal(data, &link); err != nil {
				skip(obj, "it is not valid JSON")
				continue
			}
			if err := link.validate(key); err != nil {
				skip(obj, err.Error())
				continue
			}
			newLinks = append(newLinks, link)

		case "revoked":
			if !ValidLinkID(key) {
				continue
			}
			listedRevoked[key] = struct{}{}
			if _, known := knownRevoked[key]; known {
				continue
			}
			// The revocation holds because the object exists. What it says — who,
			// when, why — is detail, and a revocation whose detail cannot be read
			// is still one.
			rev := Revocation{ID: key}
			if data, ok := read(obj.Name); ok {
				_ = json.Unmarshal(data, &rev)
				rev.ID = key
				rev.By = cleanText(rev.By, maxSubjectLen)
				rev.Reason = cleanText(rev.Reason, maxReasonLen)
				rev.Subject = cleanText(rev.Subject, maxSubjectLen)
			}
			if rev.RevokedAt.IsZero() {
				rev.RevokedAt = now.UTC()
			}
			newRevoked = append(newRevoked, rev)

		case "block":
			listedBlocks[key] = struct{}{}
			version, known := knownBlocks[key]
			if known && version == obj.Version && version != "" {
				continue
			}
			var block Block
			data, ok := read(obj.Name)
			if !ok {
				// Not read: a store error, or gone since the listing. What this
				// replica already knows of the block stands, and the record is
				// read again next time. Without anything known, a block says
				// "nothing before T", and without T the reading that cannot let a
				// revoked link through is "nothing before now" — a fallback,
				// replaced by the first real reading. (The subject is not needed:
				// blocks are found by their key.)
				if !known {
					newBlocks[key] = &blockEntry{
						block:    Block{NotBefore: now.UTC(), Reason: "the block record could not be read"},
						fallback: true,
					}
				}
				continue
			}
			if json.Unmarshal(data, &block) != nil || block.NotBefore.IsZero() || subjectKey(block.Subject) != key {
				// Damaged. Everything issued to the user up to now is taken to be
				// revoked, for as long as the record stays as it is: its version
				// is kept, so it is not read again until it changes.
				if skipped[obj.Name] != obj.Version {
					r.stats.skipped.Add(1)
					r.logger.Warn("personal links: a block record cannot be read; "+
						"treating everything issued to its user so far as revoked", "object", obj.Name)
				}
				stillSkipped[obj.Name] = obj.Version
				newBlocks[key] = &blockEntry{
					block:    Block{NotBefore: now.UTC(), Reason: "the block record could not be read"},
					version:  obj.Version,
					fallback: true,
				}
				continue
			}
			block.By = cleanText(block.By, maxSubjectLen)
			block.Reason = cleanText(block.Reason, maxReasonLen)
			newBlocks[key] = &blockEntry{block: block, version: obj.Version}

		case "usage":
			if key == r.node {
				// The object this replica writes. It is read when the replica
				// starts — that is what it had seen before it was restarted — and
				// again whenever it changed. The replica's own writes change it;
				// so do the writes of another replica that was, by mistake or for
				// lack of a better name, given the same one. Reading those back
				// and merging them is what keeps two such replicas from erasing
				// each other's observations.
				ownUsageListed = true
				if ownUsageRead && obj.Version == ownUsageVersion {
					ownUsageSeen = true
					continue
				}
				data, err := r.store.Get(ctx, obj.Name)
				switch {
				case errors.Is(err, ErrNotFound):
					ownUsageListed = false // gone between the listing and now
				case err != nil:
					// Not read. The next refresh tries again, and until one
					// succeeds this replica does not write over the object.
					r.stats.storeErrors.Add(1)
					if firstErr == nil {
						firstErr = err
					}
				default:
					var file usageFile
					_ = json.Unmarshal(data, &file) // an object that says nothing has nothing to merge
					ownUsage = cleanUsage(file.Links)
					ownUsageSeen, ownUsageVersion = true, obj.Version
				}
				continue
			}
			listedUsage[key] = struct{}{}
			if version, known := knownUsage[key]; known && version == obj.Version {
				continue
			}
			data, ok := read(obj.Name)
			if !ok {
				continue
			}
			var file usageFile
			if json.Unmarshal(data, &file) != nil {
				continue
			}
			newUsage[key] = remoteUsage{version: obj.Version, updatedAt: file.UpdatedAt, links: cleanUsage(file.Links)}
		}
	}

	r.mu.Lock()
	for i := range newLinks {
		link := newLinks[i]
		if _, present := r.byHash[link.TokenHash]; present {
			continue
		}
		e := &entry{link: link, gen: gen}
		r.byHash[link.TokenHash] = e
		r.byID[link.ID] = e
	}
	for i := range newRevoked {
		if _, present := r.revoked[newRevoked[i].ID]; !present {
			r.revoked[newRevoked[i].ID] = &revocationEntry{rev: newRevoked[i], gen: gen}
		}
	}
	var rewrite []Block
	for key, b := range newBlocks {
		b.gen = gen
		// A watermark never moves backwards in memory. One this replica holds
		// that is later than the stored one — set here while the object was
		// being read, or overwritten in the store by a replica that had not
		// seen it — stays, unconfirmed, and is compared again next time; and it
		// is written back, so that the store does not keep the earlier one.
		// Only a fallback gives way to a real reading, however much earlier.
		if cur := r.blocks[key]; cur != nil && (!cur.fallback || b.fallback) && cur.block.NotBefore.After(b.block.NotBefore) {
			cur.version = ""
			if !cur.fallback && cur.block.Subject != "" && !b.fallback {
				rewrite = append(rewrite, cur.block)
			}
			continue
		}
		r.blocks[key] = b
	}
	for node, u := range newUsage {
		r.remoteUsage[node] = u
	}

	// What is no longer in the store is no longer in the registry — except what
	// was added while this refresh ran, which the listing could not show yet.
	for hash, e := range r.byHash {
		if _, listed := listedLinks[hash]; !listed && e.gen < gen {
			delete(r.byHash, hash)
			delete(r.byID, e.link.ID)
		}
	}
	listedLinkIDs := make(map[string]struct{}, len(listedLinks))
	for hash := range listedLinks {
		listedLinkIDs[linkIDFromHash(hash)] = struct{}{}
	}
	for id, rev := range r.revoked {
		if _, listed := listedRevoked[id]; listed || rev.gen >= gen {
			continue
		}
		// A revocation is never deleted while its link exists (see collect). A
		// listing that shows the link and not its revocation was taken while
		// the two were being removed — the link a moment before its
		// revocation — and the revocation stands until the link is gone too.
		if _, linkListed := listedLinkIDs[id]; linkListed {
			continue
		}
		delete(r.revoked, id)
	}
	for key, b := range r.blocks {
		if _, listed := listedBlocks[key]; !listed && b.gen < gen {
			delete(r.blocks, key)
		}
	}
	for node := range r.remoteUsage {
		if _, listed := listedUsage[node]; !listed {
			delete(r.remoteUsage, node)
		}
	}
	r.skipped = stillSkipped
	r.synced = true
	r.lastSync = now
	r.lastSyncErr = firstErr
	switch {
	case !ownUsageListed:
		r.ownUsageRead, r.ownUsageVersion = true, "" // there is nothing to read
	case ownUsageSeen:
		r.ownUsageRead, r.ownUsageVersion = true, ownUsageVersion
	}
	r.mu.Unlock()

	if ownUsage != nil {
		r.usageMu.Lock()
		for id, u := range ownUsage {
			r.usage[id] = r.usage[id].merge(u)
		}
		// The object is meant to say everything this replica has seen. Where it
		// does not — a replica of the same name wrote over it — it is written
		// again, with what both have seen.
		for id, u := range r.usage {
			if stored, ok := ownUsage[id]; !ok || !stored.LastUsedAt.Equal(u.LastUsedAt) {
				r.usageDirty = true
				break
			}
		}
		r.usageMu.Unlock()
	}
	for _, block := range rewrite {
		if data, err := json.Marshal(block); err == nil {
			if err := r.store.Put(ctx, blockObject(block.Subject), data); err != nil {
				r.stats.storeErrors.Add(1)
				if firstErr == nil {
					firstErr = err
				}
			}
		}
	}
	if firstErr != nil {
		r.stats.syncErrors.Add(1)
		// Deleting records is decided from what this refresh read. A record it
		// could not read is no evidence that another may go: a link whose
		// record could not be read looks like a link that is gone, and its
		// revocation like one that may go with it.
		return firstErr
	}

	if gate := r.leader.Load(); gate == nil || (*gate)() {
		r.collect(ctx, now, listedLinkIDs)
	}
	return nil
}

// cleanUsage bounds a usage map read from the store.
func cleanUsage(in map[string]Usage) map[string]Usage {
	out := make(map[string]Usage, len(in))
	for id, u := range in {
		if !ValidLinkID(id) || u.LastUsedAt.IsZero() {
			continue
		}
		out[id] = Usage{
			LastUsedAt: u.LastUsedAt,
			LastAddr:   cleanText(u.LastAddr, maxAddrLen),
			LastAgent:  cleanText(u.LastAgent, maxAgentLen),
		}
	}
	return out
}

// collect deletes the records whose time is up:
//
//   - a link that stopped working more than retainEnded ago — because it
//     expired, or because it was revoked;
//   - a revocation whose link is gone — not in listedLinks, the identifiers of
//     the links the refresh's listing showed. A revocation therefore outlives
//     its link by at least one refresh: a replica listing the store while the
//     two are removed sees the link with its revocation, or neither, and never
//     the link alone;
//   - a block that no longer blocks anything: no link it covers exists any
//     more, and every session it ended would have expired by itself;
//   - the usage object of a replica that has not written for staleUsageAge,
//     after folding what it saw into this replica's own.
//
// Every deletion is idempotent and every replica would come to the same
// conclusion, so it does not matter which one does it, or whether two do.
func (r *Registry) collect(ctx context.Context, now time.Time, listedLinks map[string]struct{}) {
	var (
		dropLinks   []*entry
		dropRevoked []string
		foldUsage   []string
	)
	cutoff := now.Add(-retainEnded)

	r.mu.RLock()
	for _, e := range r.byID {
		var ended time.Time
		if rev := r.revoked[e.link.ID]; rev != nil {
			ended = rev.rev.RevokedAt
		} else if b := r.blocks[subjectKey(e.link.Subject)]; b != nil && !b.fallback && !e.link.CreatedAt.After(b.block.NotBefore) {
			// A fallback watermark is no knowledge of when the link ended; it
			// refuses the link, but does not let it be deleted.
			ended = b.block.NotBefore
		}
		if e.link.expired(now) && (ended.IsZero() || e.link.ExpiresAt.Before(ended)) {
			ended = e.link.ExpiresAt
		}
		if !ended.IsZero() && ended.Before(cutoff) {
			dropLinks = append(dropLinks, e)
		}
	}
	for id, rev := range r.revoked {
		_, linked := r.byID[id]
		_, listed := listedLinks[id]
		if !linked && !listed && rev.rev.RevokedAt.Before(cutoff) {
			dropRevoked = append(dropRevoked, id)
		}
	}
	for node, u := range r.remoteUsage {
		if !u.updatedAt.IsZero() && u.updatedAt.Before(now.Add(-staleUsageAge)) {
			foldUsage = append(foldUsage, node)
		}
	}
	r.mu.RUnlock()

	deleteObject := func(name string) bool {
		if err := r.store.Delete(ctx, name); err != nil {
			r.stats.storeErrors.Add(1)
			r.logger.Debug("personal links: deleting an ended record failed", "object", name, "error", err)
			return false
		}
		r.stats.deleted.Add(1)
		return true
	}

	for _, e := range dropLinks {
		// The link alone: its revocation is removed by a later pass, once no
		// listing shows the link any more (a revocation without its link is
		// harmless; a link without its revocation would work again).
		if !deleteObject(linkObject(e.link.TokenHash)) {
			continue
		}
		r.mu.Lock()
		delete(r.byHash, e.link.TokenHash)
		delete(r.byID, e.link.ID)
		r.mu.Unlock()
	}
	for _, id := range dropRevoked {
		if deleteObject(revokedObject(id)) {
			r.mu.Lock()
			delete(r.revoked, id)
			r.mu.Unlock()
		}
	}

	// Blocks are judged only now, against the links that are actually left: a
	// block is needed for as long as a link it covers exists — including one
	// whose deletion just failed — or a session it ended could otherwise still
	// be alive. Deleting it any earlier would bring a revoked link back.
	var dropBlocks []string
	sessionsOver := now.Add(-r.sessTTL).Add(-retainEnded)
	r.mu.RLock()
	covered := make(map[string]struct{})
	for _, e := range r.byID {
		key := subjectKey(e.link.Subject)
		if b := r.blocks[key]; b != nil && !e.link.CreatedAt.After(b.block.NotBefore) {
			covered[key] = struct{}{}
		}
	}
	for key, b := range r.blocks {
		if _, needed := covered[key]; needed || b.version == "" {
			continue
		}
		if _, damaged := r.skipped["block/"+key]; damaged {
			continue // left for an operator to look at
		}
		if b.block.NotBefore.Before(sessionsOver) {
			dropBlocks = append(dropBlocks, key)
		}
	}
	r.mu.RUnlock()
	for _, key := range dropBlocks {
		if deleteObject("block/" + key) {
			r.mu.Lock()
			delete(r.blocks, key)
			r.mu.Unlock()
		}
	}

	for _, node := range foldUsage {
		r.mu.RLock()
		links := r.remoteUsage[node].links
		r.mu.RUnlock()
		r.usageMu.Lock()
		for id, u := range links {
			r.usage[id] = r.usage[id].merge(u)
		}
		r.usageDirty = true
		r.usageMu.Unlock()
		if deleteObject(usageObject(node)) {
			r.mu.Lock()
			delete(r.remoteUsage, node)
			r.mu.Unlock()
		}
	}
}
