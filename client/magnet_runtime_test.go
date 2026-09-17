package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/natalie-o-perret/go-torrent/bencode"
	"github.com/natalie-o-perret/go-torrent/dht"
	"github.com/natalie-o-perret/go-torrent/magnet"
	"github.com/natalie-o-perret/go-torrent/metainfo"
	"github.com/natalie-o-perret/go-torrent/peer"
	"github.com/natalie-o-perret/go-torrent/tracker"
)

func TestResolveMagnetV1Direct(t *testing.T) {
	meta := testV1Meta(t, []byte("metadata payload"), 16<<10, "", false)
	harness := newMagnetPeerHarness(t, map[string]*magnetPeerBehavior{
		"127.0.0.1:51001": {meta: meta},
	})
	v1 := meta.InfoHash
	result, err := ResolveMagnet(context.Background(), magnet.URI{
		Hashes: metainfo.Hashes{V1: &v1},
		Peers:  []magnet.Peer{{Host: "127.0.0.1", Port: 51001}},
	}, testMagnetConfig(harness.dial))
	if err != nil {
		t.Fatal(err)
	}
	harness.wait()
	if result.MetaInfo == nil || result.MetaInfo.InfoHash != meta.InfoHash || result.MetaInfo.Info.Name != meta.Info.Name {
		t.Fatalf("resolved metainfo = %#v", result.MetaInfo)
	}
	if result.PeerID != testPeerID(90) || len(result.Candidates) != 1 {
		t.Fatalf("result peer ID/candidates = %x/%+v", result.PeerID, result.Candidates)
	}
	candidate := result.Candidates[0]
	if candidate.Address != "127.0.0.1:51001" || candidate.Source != SourceDirect || candidate.Protocol != peer.ProtocolV1 {
		t.Fatalf("candidate = %+v", candidate)
	}
}

func TestResolveMagnetAnnouncesEveryTrackerAndHash(t *testing.T) {
	meta := testHybridMeta(t)
	const endpoint = "127.0.0.1:51002"
	harness := newMagnetPeerHarness(t, map[string]*magnetPeerBehavior{endpoint: {meta: meta}})
	first := newMagnetTrackerServer(t, endpoint)
	second := newMagnetTrackerServer(t, endpoint)
	v1, v2 := meta.InfoHash, meta.InfoHashV2
	result, err := ResolveMagnet(context.Background(), magnet.URI{
		Hashes:   metainfo.Hashes{V1: &v1, V2: &v2},
		Trackers: []string{first.server.URL + "/announce", second.server.URL + "/announce"},
	}, MagnetConfig{
		TrackerClient:    tracker.NewClient(&http.Client{Timeout: time.Second}),
		PeerID:           testPeerID(90),
		Port:             49000,
		DialContext:      harness.dial,
		DiscoveryTimeout: time.Second,
		DialTimeout:      time.Second,
		HandshakeTimeout: time.Second,
		RequestTimeout:   time.Second,
		WriteTimeout:     time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	harness.wait()
	for _, observed := range []*magnetTrackerServer{first, second} {
		requests := observed.snapshot()
		if len(requests) != 4 {
			t.Fatalf("tracker requests = %+v, want started and stopped per hash", requests)
		}
		started := make(map[string]magnetTrackerRequest)
		stopped := make(map[string]magnetTrackerRequest)
		for _, request := range requests {
			if request.left != 1 || request.port != 49000 || request.peerID != testPeerID(90) {
				t.Fatalf("tracker request = %+v", request)
			}
			switch request.event {
			case tracker.EventStarted:
				started[string(request.infoHash[:])] = request
			case tracker.EventStopped:
				stopped[string(request.infoHash[:])] = request
			default:
				t.Fatalf("tracker event = %q", request.event)
			}
		}
		var truncated metainfo.Hash
		copy(truncated[:], v2[:])
		for _, hash := range []metainfo.Hash{v1, truncated} {
			start, startOK := started[string(hash[:])]
			stop, stopOK := stopped[string(hash[:])]
			if !startOK || !stopOK || start.key == 0 || stop.key != start.key || stop.trackerID != "magnet-id" {
				t.Fatalf("tracker lifecycle for %x: start=%+v stop=%+v", hash, start, stop)
			}
		}
	}
	if got := result.MetaInfo.Trackers(); len(got) != 2 || got[0] != first.server.URL+"/announce" || got[1] != second.server.URL+"/announce" {
		t.Fatalf("grafted trackers = %v", got)
	}
	if len(result.Candidates) != 4 {
		t.Fatalf("candidate routes = %+v, want both trackers and protocols", result.Candidates)
	}
	for _, candidate := range result.Candidates {
		if candidate.Address != endpoint || candidate.Source != SourceTracker || candidate.Tracker == "" {
			t.Fatalf("tracker candidate = %+v", candidate)
		}
	}
}

func TestResolveMagnetStopsTrackerAfterMalformedStartResponse(t *testing.T) {
	meta := testV1Meta(t, []byte("metadata payload"), 16<<10, "", false)
	harness := newMagnetPeerHarness(t, map[string]*magnetPeerBehavior{
		"127.0.0.1:51020": {meta: meta},
	})
	var mu sync.Mutex
	var requests []magnetTrackerRequest
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		key, _ := strconv.ParseUint(query.Get("key"), 10, 32)
		mu.Lock()
		requests = append(requests, magnetTrackerRequest{event: tracker.Event(query.Get("event")), key: uint32(key)})
		mu.Unlock()
		if query.Get("event") == string(tracker.EventStarted) {
			_, _ = response.Write([]byte("not bencode"))
			return
		}
		_ = bencode.Encode(response, map[string]any{"interval": int64(60), "peers": ""})
	}))
	defer server.Close()
	v1 := meta.InfoHash
	config := testMagnetConfig(harness.dial)
	config.Port = 49020
	config.TrackerClient = tracker.NewClient(server.Client())
	if _, err := ResolveMagnet(context.Background(), magnet.URI{
		Hashes:   metainfo.Hashes{V1: &v1},
		Trackers: []string{server.URL + "/announce"},
		Peers:    []magnet.Peer{{Host: "127.0.0.1", Port: 51020}},
	}, config); err != nil {
		t.Fatal(err)
	}
	harness.wait()
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 || requests[0].event != tracker.EventStarted || requests[1].event != tracker.EventStopped || requests[0].key == 0 || requests[1].key != requests[0].key {
		t.Fatalf("tracker lifecycle = %+v", requests)
	}
}

func TestPrivateMagnetTrackerTransitionStopsBeforeStart(t *testing.T) {
	var mu sync.Mutex
	var sequence []string
	server := func(name string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			mu.Lock()
			sequence = append(sequence, name+":"+request.URL.Query().Get("event"))
			mu.Unlock()
			_ = bencode.Encode(response, map[string]any{"interval": int64(60), "peers": ""})
		}))
	}
	first := server("first")
	defer first.Close()
	second := server("second")
	defer second.Close()
	lifecycle := &magnetTrackerLifecycle{}
	request := tracker.AnnounceRequest{
		Event: tracker.EventStarted, Left: 1, NumWant: 1, Port: 49030,
		InfoHash: metainfo.Hash{1}, PeerID: testPeerID(90), Key: 1,
	}
	lifecycle.add(tracker.NewClient(first.Client()), first.URL+"/announce", request)
	lifecycle.add(tracker.NewClient(second.Client()), second.URL+"/announce", request)
	if err := lifecycle.activate(context.Background(), first.URL+"/announce", time.Second); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	sequence = nil
	mu.Unlock()
	if err := lifecycle.activate(context.Background(), second.URL+"/announce", time.Second); err != nil {
		t.Fatal(err)
	}
	lifecycle.stopAll()
	mu.Lock()
	defer mu.Unlock()
	if len(sequence) < 2 || sequence[0] != "first:stopped" || sequence[1] != "second:started" {
		t.Fatalf("tracker transition = %v", sequence)
	}
}

func TestPrivateMagnetTrackerTransitionRequiresSuccessfulStop(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		http.Error(response, "unavailable", http.StatusServiceUnavailable)
	}))
	defer first.Close()
	var secondRequests atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		secondRequests.Add(1)
		_ = bencode.Encode(response, map[string]any{"interval": int64(60), "peers": ""})
	}))
	defer second.Close()
	request := tracker.AnnounceRequest{
		Event: tracker.EventStarted, Left: 1, NumWant: 1, Port: 49031,
		InfoHash: metainfo.Hash{1}, PeerID: testPeerID(90), Key: 1,
	}
	lifecycle := &magnetTrackerLifecycle{}
	old := lifecycle.add(tracker.NewClient(first.Client()), first.URL+"/announce", request)
	replacement := lifecycle.add(tracker.NewClient(second.Client()), second.URL+"/announce", request)
	replacement.active = false
	if err := lifecycle.activate(context.Background(), second.URL+"/announce", time.Second); err == nil {
		t.Fatal("tracker transition succeeded despite failed stop")
	}
	if !old.active || replacement.active || secondRequests.Load() != 0 {
		t.Fatalf("transition state old=%t replacement=%t requests=%d", old.active, replacement.active, secondRequests.Load())
	}
}

func TestResolveMagnetDHTV2LookupOnly(t *testing.T) {
	meta := testHybridMeta(t)
	v2 := meta.InfoHashV2
	var target dht.ID
	copy(target[:], v2[:20])

	server, err := dht.Listen("udp4", "127.0.0.1:0", dht.Config{ID: dht.ID{1}, QueryTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	announcer, err := dht.Listen("udp4", "127.0.0.1:0", dht.Config{ID: dht.ID{2}, QueryTimeout: 200 * time.Millisecond})
	if err != nil {
		_ = server.Close()
		t.Fatal(err)
	}
	seeker, err := dht.Listen("udp4", "127.0.0.1:0", dht.Config{ID: dht.ID{3}, QueryTimeout: 200 * time.Millisecond})
	if err != nil {
		_ = announcer.Close()
		_ = server.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = seeker.Close()
		_ = announcer.Close()
		_ = server.Close()
	})
	if err := announcer.Bootstrap(context.Background(), []netip.AddrPort{server.Addr()}); err != nil {
		t.Fatal(err)
	}
	lookup, err := announcer.GetPeers(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if stored, err := announcer.Announce(context.Background(), target, 51010, false, lookup.Tokens); err != nil || stored != 1 {
		t.Fatalf("seed DHT peer = %d, %v", stored, err)
	}
	if err := seeker.Bootstrap(context.Background(), []netip.AddrPort{server.Addr()}); err != nil {
		t.Fatal(err)
	}

	harness := newMagnetPeerHarness(t, map[string]*magnetPeerBehavior{"127.0.0.1:51010": {meta: meta}})
	config := testMagnetConfig(harness.dial)
	config.DHTNode = seeker
	if _, err := ResolveMagnet(context.Background(), magnet.URI{Hashes: metainfo.Hashes{V2: &v2}}, config); err == nil {
		t.Fatal("ResolveMagnet used DHT without explicit public-swarm opt-in")
	}
	config.UsePublicDHT = true
	result, err := ResolveMagnet(context.Background(), magnet.URI{Hashes: metainfo.Hashes{V2: &v2}}, config)
	if err != nil {
		t.Fatal(err)
	}
	harness.wait()
	if len(result.Candidates) != 1 || result.Candidates[0].Source != SourceDHT || result.Candidates[0].Protocol != peer.ProtocolV2 {
		t.Fatalf("DHT candidates = %+v", result.Candidates)
	}
	remaining, err := seeker.GetPeers(context.Background(), target)
	if err != nil || len(remaining.Peers) != 1 {
		t.Fatalf("caller-owned DHT node after resolution = %+v, %v", remaining, err)
	}
}

func TestResolveMagnetV2PieceLayers(t *testing.T) {
	fixture := newV2HashSourceFixture(t)
	var requestMu sync.Mutex
	var requests []peer.HashRequest
	harness := newMagnetPeerHarness(t, map[string]*magnetPeerBehavior{
		"127.0.0.1:51003": {
			meta: fixture.meta,
			hashes: func(request peer.HashRequest) (peer.Hashes, bool) {
				requestMu.Lock()
				requests = append(requests, request)
				requestMu.Unlock()
				return fixture.source.Respond(request, []bool{true, true, true, true})
			},
		},
	})
	v2 := fixture.meta.InfoHashV2
	result, err := ResolveMagnet(context.Background(), magnet.URI{
		Hashes: metainfo.Hashes{V2: &v2},
		Peers:  []magnet.Peer{{Host: "127.0.0.1", Port: 51003}},
	}, testMagnetConfig(harness.dial))
	if err != nil {
		t.Fatal(err)
	}
	harness.wait()
	got := result.MetaInfo.PieceLayers[fixture.largeRoot]
	want := fixture.meta.PieceLayers[fixture.largeRoot]
	if len(got) != len(want) {
		t.Fatalf("piece layer has %d hashes, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("piece layer hash %d differs", index)
		}
	}
	requestMu.Lock()
	defer requestMu.Unlock()
	if len(requests) != 1 || requests[0].PiecesRoot != fixture.largeRoot || requests[0].BaseLayer != 2 || requests[0].Index != 0 || requests[0].Length != 4 || requests[0].ProofLayers != 0 {
		t.Fatalf("hash requests = %+v", requests)
	}
}

func TestResolveMagnetV2PieceLayerPeerFailover(t *testing.T) {
	fixture := newV2HashSourceFixture(t)
	harness := newMagnetPeerHarness(t, map[string]*magnetPeerBehavior{
		"127.0.0.1:51011": {meta: fixture.meta},
		"127.0.0.1:51012": {
			meta:          fixture.meta,
			stallMetadata: true,
			hashes: func(request peer.HashRequest) (peer.Hashes, bool) {
				return fixture.source.Respond(request, []bool{true, true, true, true})
			},
		},
	})
	v2 := fixture.meta.InfoHashV2
	result, err := ResolveMagnet(context.Background(), magnet.URI{
		Hashes: metainfo.Hashes{V2: &v2},
		Peers: []magnet.Peer{
			{Host: "127.0.0.1", Port: 51011},
			{Host: "127.0.0.1", Port: 51012},
		},
	}, testMagnetConfig(harness.dial))
	if err != nil {
		t.Fatal(err)
	}
	harness.wait()
	got := result.MetaInfo.PieceLayers[fixture.largeRoot]
	want := fixture.meta.PieceLayers[fixture.largeRoot]
	if len(got) != len(want) || harness.dials.Load() < 2 {
		t.Fatalf("piece layer/dials = %d/%d, want %d/at least 2", len(got), harness.dials.Load(), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("piece layer hash %d differs", index)
		}
	}
}

func TestResolveMagnetWrongHash(t *testing.T) {
	meta := testV1Meta(t, []byte("wrong hash"), 16<<10, "", false)
	wrong := meta.InfoHash
	wrong[0] ^= 0xff
	harness := newMagnetPeerHarness(t, map[string]*magnetPeerBehavior{
		"127.0.0.1:51004": {meta: meta, handshakeHashes: metainfo.Hashes{V1: &wrong}},
	})
	_, err := ResolveMagnet(context.Background(), magnet.URI{
		Hashes: metainfo.Hashes{V1: &wrong},
		Peers:  []magnet.Peer{{Host: "127.0.0.1", Port: 51004}},
	}, testMagnetConfig(harness.dial))
	harness.wait()
	if !errors.Is(err, peer.ErrMetadataHashMismatch) {
		t.Fatalf("ResolveMagnet error = %v, want metadata hash mismatch", err)
	}
}

func TestResolveMagnetRejectFailover(t *testing.T) {
	meta := testV1Meta(t, []byte("failover"), 16<<10, "", false)
	harness := newMagnetPeerHarness(t, map[string]*magnetPeerBehavior{
		"127.0.0.1:51005": {meta: meta, rejectMetadata: true},
		"127.0.0.1:51006": {meta: meta},
	})
	v1 := meta.InfoHash
	result, err := ResolveMagnet(context.Background(), magnet.URI{
		Hashes: metainfo.Hashes{V1: &v1},
		Peers: []magnet.Peer{
			{Host: "127.0.0.1", Port: 51005},
			{Host: "127.0.0.1", Port: 51006},
		},
	}, testMagnetConfig(harness.dial))
	if err != nil {
		t.Fatal(err)
	}
	harness.wait()
	if result.MetaInfo.InfoHash != meta.InfoHash || harness.dials.Load() != 2 {
		t.Fatalf("failover result/dials = %s/%d", result.MetaInfo.InfoHash, harness.dials.Load())
	}
}

func TestResolveMagnetPrivateFiltersNonTrackerCandidates(t *testing.T) {
	meta := testV1Meta(t, []byte("private"), 16<<10, "", true)
	trackerServer := newMagnetTrackerServer(t, "127.0.0.1:51008")
	harness := newMagnetPeerHarness(t, map[string]*magnetPeerBehavior{
		"127.0.0.1:51007": {meta: meta},
	})
	v1 := meta.InfoHash
	result, err := ResolveMagnet(context.Background(), magnet.URI{
		Hashes:      metainfo.Hashes{V1: &v1},
		DisplayName: "not-the-info-name",
		Trackers:    []string{trackerServer.server.URL + "/announce"},
		Peers:       []magnet.Peer{{Host: "127.0.0.1", Port: 51007}},
	}, MagnetConfig{
		TrackerClient:    tracker.NewClient(trackerServer.server.Client()),
		PeerID:           testPeerID(90),
		Port:             49001,
		DialContext:      harness.dial,
		DiscoveryTimeout: time.Second,
		DialTimeout:      time.Second,
		HandshakeTimeout: time.Second,
		RequestTimeout:   time.Second,
		WriteTimeout:     time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	harness.wait()
	if !result.MetaInfo.Info.Private || result.MetaInfo.Info.Name == "not-the-info-name" {
		t.Fatalf("private/name metadata = %+v", result.MetaInfo.Info)
	}
	if len(result.Candidates) != 1 || result.Candidates[0].Source != SourceTracker || result.Candidates[0].Address != "127.0.0.1:51008" {
		t.Fatalf("private candidates = %+v", result.Candidates)
	}
}

func TestResolveMagnetCancellation(t *testing.T) {
	meta := testV1Meta(t, []byte("cancel"), 16<<10, "", false)
	requested := make(chan struct{})
	harness := newMagnetPeerHarness(t, map[string]*magnetPeerBehavior{
		"127.0.0.1:51009": {meta: meta, stallMetadata: true, metadataRequested: requested},
	})
	v1 := meta.InfoHash
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := ResolveMagnet(ctx, magnet.URI{
			Hashes: metainfo.Hashes{V1: &v1},
			Peers:  []magnet.Peer{{Host: "127.0.0.1", Port: 51009}},
		}, testMagnetConfig(harness.dial))
		result <- err
	}()
	select {
	case <-requested:
	case <-time.After(2 * time.Second):
		t.Fatal("metadata request was not sent")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ResolveMagnet error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ResolveMagnet did not stop after cancellation")
	}
	harness.wait()
}

func TestResolveMagnetBounds(t *testing.T) {
	t.Run("candidates", func(t *testing.T) {
		meta := testV1Meta(t, []byte("bounds"), 16<<10, "", false)
		v1 := meta.InfoHash
		var dials atomic.Int32
		_, err := ResolveMagnet(context.Background(), magnet.URI{
			Hashes: metainfo.Hashes{V1: &v1},
			Peers: []magnet.Peer{
				{Host: "127.0.0.1", Port: 51100},
				{Host: "127.0.0.1", Port: 51101},
				{Host: "127.0.0.1", Port: 51102},
			},
		}, MagnetConfig{
			PeerID:        testPeerID(90),
			MaxCandidates: 2,
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("unreachable")
			},
			DialTimeout:      time.Second,
			HandshakeTimeout: time.Second,
			RequestTimeout:   time.Second,
			WriteTimeout:     time.Second,
		})
		if err == nil || dials.Load() != 2 {
			t.Fatalf("ResolveMagnet error/dials = %v/%d", err, dials.Load())
		}
	})

	t.Run("metadata", func(t *testing.T) {
		meta := testV1Meta(t, []byte("metadata bound"), 16<<10, "", false)
		harness := newMagnetPeerHarness(t, map[string]*magnetPeerBehavior{"127.0.0.1:51103": {meta: meta}})
		v1 := meta.InfoHash
		config := testMagnetConfig(harness.dial)
		config.MaxMetadataSize = uint32(len(meta.RawInfo) - 1)
		_, err := ResolveMagnet(context.Background(), magnet.URI{
			Hashes: metainfo.Hashes{V1: &v1},
			Peers:  []magnet.Peer{{Host: "127.0.0.1", Port: 51103}},
		}, config)
		harness.wait()
		if err == nil {
			t.Fatal("ResolveMagnet accepted metadata above MaxMetadataSize")
		}
	})

	t.Run("piece layers", func(t *testing.T) {
		fixture := newV2HashSourceFixture(t)
		harness := newMagnetPeerHarness(t, map[string]*magnetPeerBehavior{"127.0.0.1:51104": {meta: fixture.meta}})
		v2 := fixture.meta.InfoHashV2
		config := testMagnetConfig(harness.dial)
		config.MaxPieceLayerHashes = 2
		_, err := ResolveMagnet(context.Background(), magnet.URI{
			Hashes: metainfo.Hashes{V2: &v2},
			Peers:  []magnet.Peer{{Host: "127.0.0.1", Port: 51104}},
		}, config)
		harness.wait()
		if err == nil {
			t.Fatal("ResolveMagnet accepted piece layers above MaxPieceLayerHashes")
		}
	})
}

type magnetPeerBehavior struct {
	meta              *metainfo.MetaInfo
	handshakeHashes   metainfo.Hashes
	rejectMetadata    bool
	stallMetadata     bool
	metadataRequested chan struct{}
	hashes            func(peer.HashRequest) (peer.Hashes, bool)
}

type magnetPeerHarness struct {
	t         *testing.T
	ctx       context.Context
	cancel    context.CancelFunc
	behaviors map[string]*magnetPeerBehavior
	dials     atomic.Int32
	mu        sync.Mutex
	sessions  []*peer.Session
	wg        sync.WaitGroup
}

func newMagnetPeerHarness(t *testing.T, behaviors map[string]*magnetPeerBehavior) *magnetPeerHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	harness := &magnetPeerHarness{t: t, ctx: ctx, cancel: cancel, behaviors: behaviors}
	t.Cleanup(func() {
		cancel()
		harness.mu.Lock()
		for _, session := range harness.sessions {
			_ = session.Close()
		}
		harness.mu.Unlock()
		harness.wg.Wait()
	})
	return harness
}

func (harness *magnetPeerHarness) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network != "tcp" {
		return nil, fmt.Errorf("unexpected network %q", network)
	}
	behavior := harness.behaviors[address]
	if behavior == nil {
		return nil, fmt.Errorf("unexpected address %q", address)
	}
	harness.dials.Add(1)
	source, err := peer.NewMetadataSource(behavior.meta, 0)
	if err != nil {
		return nil, err
	}
	hashes := behavior.handshakeHashes
	if hashes.V1 == nil && hashes.V2 == nil {
		hashes = behavior.meta.Hashes()
	}
	local, remote := net.Pipe()
	size := source.Size()
	var session *peer.Session
	requestedOnce := sync.Once{}
	session, err = peer.NewSession(remote, peer.SessionConfig{
		PeerID:       testPeerID(byte(100 + harness.dials.Load()%100)),
		Hashes:       hashes,
		MetadataOnly: true,
		ExtensionHandshake: peer.ExtensionHandshake{
			Extensions:   map[string]uint8{peer.ExtensionMetadata: 7},
			MetadataSize: &size,
		},
		Callbacks: peer.SessionCallbacks{
			OnMetadata: func(message peer.MetadataMessage) {
				if message.Type != peer.MetadataRequest {
					return
				}
				if behavior.metadataRequested != nil {
					requestedOnce.Do(func() { close(behavior.metadataRequested) })
				}
				if behavior.stallMetadata {
					return
				}
				if behavior.rejectMetadata {
					_ = session.SendMetadata(peer.MetadataMessage{Type: peer.MetadataReject, Piece: message.Piece})
					return
				}
				response, responseErr := source.Respond(message)
				if responseErr == nil {
					_ = session.SendMetadata(response)
				}
			},
			OnHashRequest: func(request peer.HashRequest) {
				if behavior.hashes == nil {
					_ = session.SendHashReject(request)
					return
				}
				response, ok := behavior.hashes(request)
				if ok {
					_ = session.SendHashes(response)
				} else {
					_ = session.SendHashReject(request)
				}
			},
		},
		HandshakeTimeout: time.Second,
		RequestTimeout:   time.Second,
		WriteTimeout:     time.Second,
	})
	if err != nil {
		_ = local.Close()
		_ = remote.Close()
		return nil, err
	}
	harness.mu.Lock()
	harness.sessions = append(harness.sessions, session)
	harness.mu.Unlock()
	harness.wg.Add(1)
	go func() {
		defer harness.wg.Done()
		_ = session.Run(harness.ctx)
	}()
	return local, nil
}

func (harness *magnetPeerHarness) wait() {
	harness.t.Helper()
	done := make(chan struct{})
	go func() {
		harness.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		harness.t.Fatal("bootstrap peer sessions did not stop")
	}
}

func testMagnetConfig(dial func(context.Context, string, string) (net.Conn, error)) MagnetConfig {
	return MagnetConfig{
		PeerID:           testPeerID(90),
		DialContext:      dial,
		DiscoveryTimeout: time.Second,
		DialTimeout:      time.Second,
		HandshakeTimeout: time.Second,
		RequestTimeout:   time.Second,
		WriteTimeout:     time.Second,
	}
}

type magnetTrackerRequest struct {
	event     tracker.Event
	left      int64
	port      uint16
	key       uint32
	trackerID string
	infoHash  metainfo.Hash
	peerID    [20]byte
}

type magnetTrackerServer struct {
	server   *httptest.Server
	endpoint string
	mu       sync.Mutex
	requests []magnetTrackerRequest
}

func newMagnetTrackerServer(t *testing.T, endpoint string) *magnetTrackerServer {
	t.Helper()
	observed := &magnetTrackerServer{endpoint: endpoint}
	observed.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		entry := magnetTrackerRequest{event: tracker.Event(query.Get("event"))}
		entry.left, _ = strconv.ParseInt(query.Get("left"), 10, 64)
		port, _ := strconv.ParseUint(query.Get("port"), 10, 16)
		entry.port = uint16(port)
		key, _ := strconv.ParseUint(query.Get("key"), 10, 32)
		entry.key = uint32(key)
		entry.trackerID = query.Get("trackerid")
		copy(entry.infoHash[:], query.Get("info_hash"))
		copy(entry.peerID[:], query.Get("peer_id"))
		observed.mu.Lock()
		observed.requests = append(observed.requests, entry)
		observed.mu.Unlock()

		host, portText, _ := net.SplitHostPort(endpoint)
		ip := net.ParseIP(host).To4()
		peerPort, _ := strconv.ParseUint(portText, 10, 16)
		compact := append([]byte(nil), ip...)
		var encodedPort [2]byte
		binary.BigEndian.PutUint16(encodedPort[:], uint16(peerPort))
		compact = append(compact, encodedPort[:]...)
		if err := bencode.Encode(response, map[string]any{"interval": int64(60), "peers": string(compact), "tracker id": "magnet-id"}); err != nil {
			http.Error(response, err.Error(), http.StatusInternalServerError)
		}
	}))
	t.Cleanup(observed.server.Close)
	return observed
}

func (server *magnetTrackerServer) snapshot() []magnetTrackerRequest {
	server.mu.Lock()
	defer server.mu.Unlock()
	return append([]magnetTrackerRequest(nil), server.requests...)
}
