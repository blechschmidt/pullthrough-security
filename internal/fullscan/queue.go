package fullscan

import (
	"container/heap"
	"time"
)

// The scan queue: one FIFO heap per priority class, ordered by the sequence
// number an item got when it was queued, and one heap of items waiting out a
// backoff, ordered by when they are due. An item is in at most one heap; a due
// item moves to its class. Items of a paused upstream are parked when they
// come up and put back on resume.

// delayedHeap is the index of the heap of items waiting out a backoff.
const delayedHeap = int(numPriorities)

type readyHeap []*Item

func (h readyHeap) Len() int { return len(h) }
func (h readyHeap) Less(i, j int) bool {
	if h[i].Seq != h[j].Seq {
		return h[i].Seq < h[j].Seq
	}
	return h[i].Key < h[j].Key
}
func (h readyHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].hi, h[j].hi = i, j
}
func (h *readyHeap) Push(x any) {
	it := x.(*Item)
	it.hi = len(*h)
	*h = append(*h, it)
}
func (h *readyHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	it.hi = -1
	return it
}

type delayHeap []*Item

func (h delayHeap) Len() int { return len(h) }
func (h delayHeap) Less(i, j int) bool {
	if !h[i].NotBefore.Equal(h[j].NotBefore) {
		return h[i].NotBefore.Before(h[j].NotBefore)
	}
	return h[i].Seq < h[j].Seq
}
func (h delayHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].hi, h[j].hi = i, j
}
func (h *delayHeap) Push(x any) {
	it := x.(*Item)
	it.hi = len(*h)
	*h = append(*h, it)
}
func (h *delayHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	it.hi = -1
	return it
}

// queue holds the pending items. It is not safe for concurrent use: the
// service guards it with its mutex.
type queue struct {
	ready   [numPriorities]readyHeap
	delayed delayHeap
	// parked are the items of paused upstreams, by upstream.
	parked map[string]map[*Item]struct{}
}

func newQueue() *queue { return &queue{parked: map[string]map[*Item]struct{}{}} }

// push queues a pending item: in its class, or among the delayed ones while
// its NotBefore lies ahead.
func (q *queue) push(it *Item, now time.Time) {
	q.remove(it)
	if it.Priority < 0 || it.Priority >= numPriorities {
		it.Priority = PriorityBackfill
	}
	if it.NotBefore.After(now) {
		it.hq = delayedHeap
		heap.Push(&q.delayed, it)
		return
	}
	it.hq = int(it.Priority)
	heap.Push(&q.ready[it.Priority], it)
}

// remove takes an item out of whatever heap holds it (and unparks it).
func (q *queue) remove(it *Item) {
	if it.parked {
		if set := q.parked[it.Upstream]; set != nil {
			delete(set, it)
			if len(set) == 0 {
				delete(q.parked, it.Upstream)
			}
		}
		it.parked = false
	}
	switch {
	case it.hq == delayedHeap && it.hi >= 0 && it.hi < len(q.delayed) && q.delayed[it.hi] == it:
		heap.Remove(&q.delayed, it.hi)
	case it.hq >= 0 && it.hq < int(numPriorities):
		h := &q.ready[it.hq]
		if it.hi >= 0 && it.hi < len(*h) && (*h)[it.hi] == it {
			heap.Remove(h, it.hi)
		}
	}
	it.hq, it.hi = -1, -1
}

// promote moves the delayed items that are due to their classes.
func (q *queue) promote(now time.Time) {
	for len(q.delayed) > 0 && !q.delayed[0].NotBefore.After(now) {
		it := heap.Pop(&q.delayed).(*Item)
		it.hq = int(it.Priority)
		heap.Push(&q.ready[it.Priority], it)
	}
}

// pop returns the next item to scan: the first due one of the highest class
// whose upstream is not paused. Items of a paused upstream are parked on the
// way.
func (q *queue) pop(now time.Time, paused func(upstream string) bool) *Item {
	q.promote(now)
	for p := range q.ready {
		h := &q.ready[p]
		for h.Len() > 0 {
			it := heap.Pop(h).(*Item)
			it.hq = -1
			if paused != nil && paused(it.Upstream) {
				it.parked = true
				set := q.parked[it.Upstream]
				if set == nil {
					set = map[*Item]struct{}{}
					q.parked[it.Upstream] = set
				}
				set[it] = struct{}{}
				continue
			}
			return it
		}
	}
	return nil
}

// unpark puts the parked items back: of one upstream, or of every one when
// upstream is empty. Items that left the queue meanwhile are dropped.
func (q *queue) unpark(upstream string, now time.Time) {
	for name, items := range q.parked {
		if upstream != "" && name != upstream {
			continue
		}
		delete(q.parked, name)
		for it := range items {
			it.parked = false
			if it.State == StatePending && !it.busy {
				q.push(it, now)
			}
		}
	}
}

// unparkUnless puts back the parked items of every upstream paused no longer:
// a pause lifted on another replica, or between this step's read of the
// control file and its pop.
func (q *queue) unparkUnless(paused func(string) bool, now time.Time) {
	for name := range q.parked {
		if paused == nil || !paused(name) {
			q.unpark(name, now)
		}
	}
}

// nextDue is when the first delayed item is due (zero: none).
func (q *queue) nextDue() time.Time {
	if len(q.delayed) == 0 {
		return time.Time{}
	}
	return q.delayed[0].NotBefore
}

// sizes reports the items queued per class, the delayed ones and the parked
// ones.
func (q *queue) sizes() (ready [numPriorities]int, delayed, parked int) {
	for p := range q.ready {
		ready[p] = q.ready[p].Len()
	}
	for _, items := range q.parked {
		parked += len(items)
	}
	return ready, len(q.delayed), parked
}
