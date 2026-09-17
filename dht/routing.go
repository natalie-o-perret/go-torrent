package dht

import (
	"bytes"
	"net/netip"
	"sort"
	"sync"
	"time"
)

type routingBucket struct {
	prefix  ID
	bits    int
	entries []Contact
	changed time.Time
}

// RoutingTable is a bounded K-bucket routing table. AddVerified is the only
// insertion path: callers must first verify reachability from the contact's
// advertised endpoint.
type RoutingTable struct {
	mu          sync.RWMutex
	local       ID
	buckets     []routingBucket
	maxContacts int
	goodFor     time.Duration
	total       int
}

// NewRoutingTable creates an empty routing table.
func NewRoutingTable(local ID, maxContacts int, goodFor time.Duration) *RoutingTable {
	if maxContacts <= 0 {
		maxContacts = K * IDLength * 8
	}
	if goodFor <= 0 {
		goodFor = 15 * time.Minute
	}
	return &RoutingTable{
		local:       local,
		buckets:     []routingBucket{{}},
		maxContacts: maxContacts,
		goodFor:     goodFor,
	}
}

// AddVerified records a response received from id at endpoint.
func (table *RoutingTable) AddVerified(id ID, endpoint netip.AddrPort, now time.Time) bool {
	return table.add(Contact{ID: id, Addr: endpoint, LastResponse: now}, now)
}

func (table *RoutingTable) restore(contact Contact, now time.Time) bool {
	contact.Failures = 0
	contact.LastQuery = time.Time{}
	return table.add(contact, now)
}

func (table *RoutingTable) add(contact Contact, now time.Time) bool {
	contact.Addr = normalizeEndpoint(contact.Addr)
	if contact.ID == table.local || !validEndpoint(contact.Addr) {
		return false
	}

	table.mu.Lock()
	defer table.mu.Unlock()

	// A verified endpoint supersedes an older identity at that endpoint.
	table.removeLocked(func(existing Contact) bool {
		return existing.ID != contact.ID && existing.Addr == contact.Addr
	})
	for bucketIndex := range table.buckets {
		for entryIndex := range table.buckets[bucketIndex].entries {
			if table.buckets[bucketIndex].entries[entryIndex].ID == contact.ID {
				table.buckets[bucketIndex].entries[entryIndex] = contact
				table.buckets[bucketIndex].changed = now
				return true
			}
		}
	}
	for {
		bucketIndex := table.findBucketLocked(contact.ID)
		bucket := &table.buckets[bucketIndex]
		if len(bucket.entries) < K {
			if table.total >= table.maxContacts {
				return false
			}
			bucket.entries = append(bucket.entries, contact)
			bucket.changed = now
			table.total++
			return true
		}
		for entryIndex, existing := range bucket.entries {
			if existing.Liveness(now, table.goodFor) == Bad {
				bucket.entries[entryIndex] = contact
				bucket.changed = now
				return true
			}
		}
		if bucket.bits >= IDLength*8 || !bucketMatches(*bucket, table.local) {
			return false
		}
		table.splitLocked(bucketIndex, now)
	}
}

// ObserveQuery refreshes a previously verified contact after an incoming
// query. Unknown endpoints are deliberately not inserted.
func (table *RoutingTable) ObserveQuery(id ID, endpoint netip.AddrPort, now time.Time) bool {
	endpoint = normalizeEndpoint(endpoint)
	table.mu.Lock()
	defer table.mu.Unlock()
	for bucketIndex := range table.buckets {
		for entryIndex := range table.buckets[bucketIndex].entries {
			contact := &table.buckets[bucketIndex].entries[entryIndex]
			if contact.ID == id && contact.Addr == endpoint {
				contact.LastQuery = now
				return true
			}
		}
	}
	return false
}

// ObserveFailure records a failed query to a specific verified contact.
func (table *RoutingTable) ObserveFailure(id ID, endpoint netip.AddrPort) bool {
	endpoint = normalizeEndpoint(endpoint)
	table.mu.Lock()
	defer table.mu.Unlock()
	for bucketIndex := range table.buckets {
		for entryIndex := range table.buckets[bucketIndex].entries {
			contact := &table.buckets[bucketIndex].entries[entryIndex]
			if contact.ID == id && contact.Addr == endpoint {
				if contact.Failures < 2 {
					contact.Failures++
				}
				return true
			}
		}
	}
	return false
}

// Closest returns at most limit contacts ordered by XOR distance. If goodOnly
// is true, questionable and bad contacts are excluded.
func (table *RoutingTable) Closest(target ID, limit int, now time.Time, goodOnly bool) []Contact {
	if limit <= 0 {
		return nil
	}
	table.mu.RLock()
	contacts := make([]Contact, 0, table.total)
	for _, bucket := range table.buckets {
		for _, contact := range bucket.entries {
			status := contact.Liveness(now, table.goodFor)
			if status == Bad || (goodOnly && status != Good) {
				continue
			}
			contacts = append(contacts, contact)
		}
	}
	table.mu.RUnlock()
	sort.Slice(contacts, func(i, j int) bool {
		if comparison := compareDistance(target, contacts[i].ID, contacts[j].ID); comparison != 0 {
			return comparison < 0
		}
		return contacts[i].Addr.String() < contacts[j].Addr.String()
	})
	if len(contacts) > limit {
		contacts = contacts[:limit]
	}
	return contacts
}

// Contacts returns a stable copy of all non-bad contacts.
func (table *RoutingTable) Contacts(now time.Time) []Contact {
	table.mu.RLock()
	contacts := make([]Contact, 0, table.total)
	for _, bucket := range table.buckets {
		for _, contact := range bucket.entries {
			if contact.Liveness(now, table.goodFor) != Bad {
				contacts = append(contacts, contact)
			}
		}
	}
	table.mu.RUnlock()
	sort.Slice(contacts, func(i, j int) bool {
		if comparison := bytes.Compare(contacts[i].ID[:], contacts[j].ID[:]); comparison != 0 {
			return comparison < 0
		}
		return contacts[i].Addr.String() < contacts[j].Addr.String()
	})
	return contacts
}

// Len returns the number of contacts, including bad contacts awaiting
// replacement.
func (table *RoutingTable) Len() int {
	table.mu.RLock()
	defer table.mu.RUnlock()
	return table.total
}

// BucketCount returns the current number of routing buckets.
func (table *RoutingTable) BucketCount() int {
	table.mu.RLock()
	defer table.mu.RUnlock()
	return len(table.buckets)
}

func (table *RoutingTable) removeLocked(remove func(Contact) bool) {
	for bucketIndex := range table.buckets {
		entries := table.buckets[bucketIndex].entries
		kept := entries[:0]
		for _, contact := range entries {
			if remove(contact) {
				table.total--
				continue
			}
			kept = append(kept, contact)
		}
		table.buckets[bucketIndex].entries = kept
	}
}

func (table *RoutingTable) findBucketLocked(id ID) int {
	for index, bucket := range table.buckets {
		if bucketMatches(bucket, id) {
			return index
		}
	}
	panic("dht: routing table has no bucket for ID")
}

func (table *RoutingTable) splitLocked(index int, now time.Time) {
	old := table.buckets[index]
	left := routingBucket{prefix: old.prefix, bits: old.bits + 1, changed: now}
	right := routingBucket{prefix: old.prefix, bits: old.bits + 1, changed: now}
	setIDBit(&left.prefix, old.bits, 0)
	setIDBit(&right.prefix, old.bits, 1)
	for _, contact := range old.entries {
		if idBit(contact.ID, old.bits) == 0 {
			left.entries = append(left.entries, contact)
		} else {
			right.entries = append(right.entries, contact)
		}
	}
	table.buckets[index] = left
	table.buckets = append(table.buckets, routingBucket{})
	copy(table.buckets[index+2:], table.buckets[index+1:])
	table.buckets[index+1] = right
}

func bucketMatches(bucket routingBucket, id ID) bool {
	for bit := 0; bit < bucket.bits; bit++ {
		if idBit(bucket.prefix, bit) != idBit(id, bit) {
			return false
		}
	}
	return true
}

func idBit(id ID, bit int) byte {
	return id[bit/8] >> (7 - bit%8) & 1
}

func setIDBit(id *ID, bit int, value byte) {
	mask := byte(1 << (7 - bit%8))
	if value == 0 {
		id[bit/8] &^= mask
	} else {
		id[bit/8] |= mask
	}
}
