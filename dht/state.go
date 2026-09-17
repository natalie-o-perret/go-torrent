package dht

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"sort"
	"sync"
	"time"
)

const tokenSize = 16

type tokenManager struct {
	root   [32]byte
	period time.Duration
}

func newTokenManager(secret []byte, period time.Duration) tokenManager {
	var manager tokenManager
	copy(manager.root[:], secret)
	manager.period = period
	return manager
}

func (manager tokenManager) token(ip netip.Addr, now time.Time) []byte {
	secret := manager.secret(manager.epoch(now))
	return sourceToken(secret[:], ip)
}

func (manager tokenManager) valid(token []byte, ip netip.Addr, now time.Time) bool {
	if len(token) != tokenSize {
		return false
	}
	epoch := manager.epoch(now)
	current := manager.secret(epoch)
	if hmac.Equal(token, sourceToken(current[:], ip)) {
		return true
	}
	previous := manager.secret(epoch - 1)
	return hmac.Equal(token, sourceToken(previous[:], ip))
}

func (manager tokenManager) epoch(now time.Time) int64 {
	return now.UnixNano() / manager.period.Nanoseconds()
}

func (manager tokenManager) secret(epoch int64) [32]byte {
	mac := hmac.New(sha256.New, manager.root[:])
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(epoch))
	_, _ = mac.Write(encoded[:])
	var secret [32]byte
	copy(secret[:], mac.Sum(nil))
	return secret
}

func sourceToken(secret []byte, ip netip.Addr) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(ip.Unmap().AsSlice())
	return append([]byte(nil), mac.Sum(nil)[:tokenSize]...)
}

type peerRecord struct {
	expires time.Time
}

type peerBucket struct {
	peers map[netip.AddrPort]peerRecord
	last  time.Time
}

type peerStore struct {
	mu              sync.Mutex
	buckets         map[ID]*peerBucket
	ttl             time.Duration
	maxInfoHashes   int
	maxPeersPerHash int
}

func newPeerStore(ttl time.Duration, maxInfoHashes, maxPeersPerHash int) *peerStore {
	return &peerStore{
		buckets:         make(map[ID]*peerBucket),
		ttl:             ttl,
		maxInfoHashes:   maxInfoHashes,
		maxPeersPerHash: maxPeersPerHash,
	}
}

func (store *peerStore) put(infoHash ID, endpoint netip.AddrPort, now time.Time) {
	endpoint = normalizeEndpoint(endpoint)
	if !validEndpoint(endpoint) {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	bucket := store.expireBucketLocked(infoHash, now)
	if bucket == nil {
		if len(store.buckets) >= store.maxInfoHashes {
			store.evictBucketLocked()
		}
		bucket = &peerBucket{peers: make(map[netip.AddrPort]peerRecord)}
		store.buckets[infoHash] = bucket
	}
	if _, exists := bucket.peers[endpoint]; !exists && len(bucket.peers) >= store.maxPeersPerHash {
		store.evictPeerLocked(bucket)
	}
	bucket.peers[endpoint] = peerRecord{expires: now.Add(store.ttl)}
	bucket.last = now
}

func (store *peerStore) get(infoHash ID, family Family, now time.Time) []netip.AddrPort {
	store.mu.Lock()
	defer store.mu.Unlock()
	bucket := store.expireBucketLocked(infoHash, now)
	if bucket == nil {
		return nil
	}
	peers := make([]netip.AddrPort, 0, len(bucket.peers))
	for endpoint := range bucket.peers {
		if familyOf(endpoint.Addr()) == family {
			peers = append(peers, endpoint)
		}
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].String() < peers[j].String() })
	if len(peers) > K {
		peers = peers[:K]
	}
	return peers
}

func (store *peerStore) expireBucketLocked(infoHash ID, now time.Time) *peerBucket {
	bucket := store.buckets[infoHash]
	if bucket == nil {
		return nil
	}
	for endpoint, record := range bucket.peers {
		if !record.expires.After(now) {
			delete(bucket.peers, endpoint)
		}
	}
	if len(bucket.peers) == 0 {
		delete(store.buckets, infoHash)
		return nil
	}
	return bucket
}

func (store *peerStore) evictBucketLocked() {
	var oldestID ID
	var oldest time.Time
	first := true
	for infoHash, bucket := range store.buckets {
		if first || bucket.last.Before(oldest) || (bucket.last.Equal(oldest) && infoHash.String() < oldestID.String()) {
			oldestID, oldest, first = infoHash, bucket.last, false
		}
	}
	if !first {
		delete(store.buckets, oldestID)
	}
}

func (store *peerStore) evictPeerLocked(bucket *peerBucket) {
	var oldest netip.AddrPort
	var expiry time.Time
	first := true
	for endpoint, record := range bucket.peers {
		if first || record.expires.Before(expiry) || (record.expires.Equal(expiry) && endpoint.String() < oldest.String()) {
			oldest, expiry, first = endpoint, record.expires, false
		}
	}
	if !first {
		delete(bucket.peers, oldest)
	}
}

type rateEntry struct {
	window int64
	count  int
	seen   time.Time
}

type rateLimiter struct {
	mu         sync.Mutex
	sources    map[netip.Addr]rateEntry
	maxSources int
	perSecond  int
}

func newRateLimiter(maxSources, perSecond int) *rateLimiter {
	return &rateLimiter{sources: make(map[netip.Addr]rateEntry), maxSources: maxSources, perSecond: perSecond}
}

func (limiter *rateLimiter) allow(ip netip.Addr, now time.Time) bool {
	ip = ip.Unmap()
	window := now.Unix()
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	entry, exists := limiter.sources[ip]
	if !exists && len(limiter.sources) >= limiter.maxSources {
		var oldestIP netip.Addr
		var oldest time.Time
		first := true
		for candidate, current := range limiter.sources {
			if first || current.seen.Before(oldest) {
				oldestIP, oldest, first = candidate, current.seen, false
			}
		}
		delete(limiter.sources, oldestIP)
	}
	if !exists || entry.window != window {
		entry = rateEntry{window: window}
	}
	entry.seen = now
	if entry.count >= limiter.perSecond {
		limiter.sources[ip] = entry
		return false
	}
	entry.count++
	limiter.sources[ip] = entry
	return true
}
