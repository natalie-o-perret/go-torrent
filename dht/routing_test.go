package dht

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

func TestRoutingBucketsAndLiveness(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	table := NewRoutingTable(ID{}, 32, 15*time.Minute)
	contacts := make([]Contact, K)
	for index := range K {
		var id ID
		id[0] = 0x80 | byte(index)
		endpoint := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(10000+index))
		if !table.AddVerified(id, endpoint, now) {
			t.Fatalf("contact %d was rejected", index)
		}
		contacts[index] = Contact{ID: id, Addr: endpoint}
	}
	low := testID(1)
	if !table.AddVerified(low, netip.MustParseAddrPort("127.0.0.1:11000"), now) {
		t.Fatal("contact in local half was rejected")
	}
	if table.BucketCount() != 2 || table.Len() != K+1 {
		t.Fatalf("buckets=%d contacts=%d", table.BucketCount(), table.Len())
	}
	var anotherHigh ID
	anotherHigh[0] = 0x90
	if table.AddVerified(anotherHigh, netip.MustParseAddrPort("127.0.0.1:11001"), now) {
		t.Fatal("full non-local bucket accepted a ninth good contact")
	}

	first := contacts[0]
	if !table.ObserveFailure(first.ID, first.Addr) {
		t.Fatal("first failure was not recorded")
	}
	status := table.Closest(first.ID, 1, now, false)[0].Liveness(now, 15*time.Minute)
	if status != Questionable {
		t.Fatalf("one failure status = %v", status)
	}
	table.ObserveFailure(first.ID, first.Addr)
	if !table.AddVerified(anotherHigh, netip.MustParseAddrPort("127.0.0.1:11001"), now) {
		t.Fatal("bad contact was not replaced")
	}
	if table.Len() != K+1 {
		t.Fatalf("contacts after replacement = %d", table.Len())
	}
	if got := table.Closest(low, K, now.Add(16*time.Minute), true); len(got) != 0 {
		t.Fatalf("stale contacts returned as good: %#v", got)
	}
	if !table.ObserveQuery(low, netip.MustParseAddrPort("127.0.0.1:11000"), now.Add(16*time.Minute)) {
		t.Fatal("known query source was not refreshed")
	}
	if got := table.Closest(low, 1, now.Add(16*time.Minute), true); len(got) != 1 || got[0].ID != low {
		t.Fatalf("recent querying contact not good: %#v", got)
	}
}

func TestTokenRotationPeerExpiryAndRateBounds(t *testing.T) {
	period := 5 * time.Minute
	manager := newTokenManager(bytes.Repeat([]byte{0x42}, 32), period)
	ip := netip.MustParseAddr("198.51.100.20")
	start := time.Unix(300, 1)
	token := manager.token(ip, start)
	if !manager.valid(token, ip, start.Add(period)) {
		t.Fatal("previous rotating secret did not validate")
	}
	if manager.valid(token, ip, start.Add(2*period)) {
		t.Fatal("token survived beyond current and previous secrets")
	}
	if manager.valid(token, netip.MustParseAddr("198.51.100.21"), start) {
		t.Fatal("token validated for another source IP")
	}

	store := newPeerStore(time.Minute, 1, 2)
	hash := testID(1)
	store.put(hash, netip.MustParseAddrPort("192.0.2.1:1"), start)
	store.put(hash, netip.MustParseAddrPort("192.0.2.2:2"), start)
	store.put(hash, netip.MustParseAddrPort("192.0.2.3:3"), start)
	if peers := store.get(hash, IPv4, start); len(peers) != 2 {
		t.Fatalf("bounded peers = %#v", peers)
	}
	if peers := store.get(hash, IPv4, start.Add(time.Minute)); len(peers) != 0 {
		t.Fatalf("expired peers = %#v", peers)
	}
	store.put(hash, netip.MustParseAddrPort("192.0.2.4:4"), start)
	otherHash := testID(2)
	store.put(otherHash, netip.MustParseAddrPort("192.0.2.5:5"), start.Add(time.Second))
	if peers := store.get(hash, IPv4, start.Add(time.Second)); len(peers) != 0 {
		t.Fatalf("old info-hash bucket was not evicted: %#v", peers)
	}

	limiter := newRateLimiter(2, 2)
	if !limiter.allow(ip, start) || !limiter.allow(ip, start) || limiter.allow(ip, start) {
		t.Fatal("per-source packet limit was not enforced")
	}
	if !limiter.allow(ip, start.Add(time.Second)) {
		t.Fatal("packet limit did not reset")
	}
	limiter.allow(netip.MustParseAddr("192.0.2.1"), start)
	limiter.allow(netip.MustParseAddr("192.0.2.2"), start)
	if len(limiter.sources) != 2 {
		t.Fatalf("rate source map has %d entries", len(limiter.sources))
	}
}

func TestBoundedCandidateSetKeepsCloserNodes(t *testing.T) {
	target := ID{}
	candidates := make(map[candidateKey]*lookupCandidate)
	for value := byte(100); value < 100+K; value++ {
		contact := Contact{ID: testID(value), Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(12000+int(value)))}
		addCandidate(candidates, contact, testID(250), target, K)
	}
	closer := Contact{ID: testID(1), Addr: netip.MustParseAddrPort("127.0.0.1:13001")}
	addCandidate(candidates, closer, testID(250), target, K)
	if len(candidates) != K {
		t.Fatalf("candidate count = %d", len(candidates))
	}
	if _, exists := candidates[candidateKey{id: closer.ID, endpoint: closer.Addr}]; !exists {
		t.Fatal("closer discovered candidate was dropped")
	}
}

func TestRoutingContactLimitStillAllowsBadReplacement(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	table := NewRoutingTable(ID{}, K, time.Minute)
	var firstID ID
	for index := range K {
		id := testID(byte(index + 1))
		if index == 0 {
			firstID = id
		}
		if !table.AddVerified(id, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(14000+index)), now) {
			t.Fatalf("contact %d was rejected", index)
		}
	}
	firstAddr := netip.MustParseAddrPort("127.0.0.1:14000")
	table.ObserveFailure(firstID, firstAddr)
	table.ObserveFailure(firstID, firstAddr)
	if !table.AddVerified(testID(99), netip.MustParseAddrPort("127.0.0.1:15000"), now) {
		t.Fatal("contact cap blocked replacement of a bad contact")
	}
	if table.Len() != K {
		t.Fatalf("contact count = %d", table.Len())
	}
}
