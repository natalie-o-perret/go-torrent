package client

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anacrolix/go-utp/purego"
	"github.com/natalie-o-perret/go-torrent/bencode"
	"github.com/natalie-o-perret/go-torrent/metainfo"
	"github.com/natalie-o-perret/go-torrent/peer"
	"github.com/natalie-o-perret/go-torrent/storage"
	"github.com/natalie-o-perret/go-torrent/tracker"
)

func TestTrackerTCPDownloadCompletionSeedingAndShutdown(t *testing.T) {
	data := bytes.Repeat([]byte("torrent-data-"), 1700)
	fake := &fakeTracker{}
	server := httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	defer server.Close()
	meta := testV1Meta(t, data, len(data), server.URL+"/announce", false)

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fake.setPeer(listener.Addr().String())
	seedMeta := *meta
	seedMeta.Announce = ""
	seedMeta.AnnounceList = nil
	seedStore := testStorage(t, &seedMeta)
	if err := seedStore.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := seedStore.WritePiece(storage.V1, 0, data); err != nil {
		t.Fatal(err)
	}
	seed, err := New(Config{
		Meta:             &seedMeta,
		Storage:          seedStore.Storage,
		Listener:         listener,
		PeerID:           testPeerID(1),
		ScheduleInterval: 5 * time.Millisecond,
		RandIntN:         zeroRandom,
	})
	if err != nil {
		t.Fatal(err)
	}
	seedRun := runAsync(seed)
	waitClosed(t, seed.Completed(), "seed resume verification")
	if got := seed.Progress().CompletedPieces; got != 1 {
		t.Fatalf("seed resumed %d pieces, want 1", got)
	}

	downloadStore := testStorage(t, meta)
	downloader, err := New(Config{
		Meta:             meta,
		Storage:          downloadStore.Storage,
		TrackerClient:    trackerClient(server.Client()),
		PeerID:           testPeerID(2),
		Port:             49001,
		ScheduleInterval: 5 * time.Millisecond,
		RequestTimeout:   time.Second,
		RandIntN:         zeroRandom,
	})
	if err != nil {
		t.Fatal(err)
	}
	downloadRun := runAsync(downloader)
	waitClosed(t, downloader.Completed(), "download completion")
	waitFor(t, "tracker completed announce", func() bool {
		return fake.countEvent("completed") == 1 && downloader.Completion().CompletionAnnounced[peer.ProtocolV1]
	})
	regularAtCompletion := fake.countEvent("")
	waitFor(t, "regular announce while seeding", func() bool { return fake.countEvent("") > regularAtCompletion })
	waitFor(t, "seed upload accounting", func() bool { return seed.Progress().UploadedBytes >= int64(len(data)) })

	if completion := downloader.Completion(); !completion.Complete || !completion.Seeding || completion.CompletedAt.IsZero() {
		t.Fatalf("completion snapshot = %+v", completion)
	}
	select {
	case err := <-downloadRun:
		t.Fatalf("Run returned before cancellation: %v", err)
	default:
	}
	got, err := os.ReadFile(filepath.Join(downloadStore.rootForTest(), "payload"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("downloaded file = %d bytes, %v", len(got), err)
	}

	if err := downloader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-downloadRun; !errors.Is(err, ErrClosed) {
		t.Fatalf("download Run error = %v, want ErrClosed", err)
	}
	waitFor(t, "tracker stopped announce", func() bool { return fake.countEvent("stopped") == 1 })
	if fake.countEvent("started") != 1 || fake.countEvent("completed") != 1 {
		t.Fatalf("tracker events = %v", fake.eventsSnapshot())
	}
	events := fake.eventsSnapshot()
	if events[0].event != "started" || events[0].left != int64(len(data)) {
		t.Fatalf("first tracker event = %+v", events[0])
	}
	for _, event := range events {
		if event.event == "completed" && event.left != 0 {
			t.Fatalf("completed tracker event has left=%d", event.left)
		}
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-seedRun; !errors.Is(err, ErrClosed) {
		t.Fatalf("seed Run error = %v, want ErrClosed", err)
	}
}

func TestUTPDownload(t *testing.T) {
	data := bytes.Repeat([]byte("utp-data-"), 2048)
	meta := testV1Meta(t, data, len(data), "", false)
	seedSocket, err := purego.NewSocket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seedStore := testStorage(t, meta)
	if err := seedStore.Prepare(); err != nil {
		_ = seedSocket.Close()
		t.Fatal(err)
	}
	if err := seedStore.WritePiece(storage.V1, 0, data); err != nil {
		_ = seedSocket.Close()
		t.Fatal(err)
	}
	seed, err := New(Config{
		Meta:             meta,
		Storage:          seedStore.Storage,
		UTP:              seedSocket,
		PeerID:           testPeerID(21),
		ScheduleInterval: 5 * time.Millisecond,
		RandIntN:         zeroRandom,
	})
	if err != nil {
		_ = seedSocket.Close()
		t.Fatal(err)
	}
	seedRun := runAsync(seed)
	waitClosed(t, seed.Completed(), "uTP seed resume verification")

	downloadSocket, err := purego.NewSocket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = seed.Close()
		<-seedRun
		t.Fatal(err)
	}
	downloadStore := testStorage(t, meta)
	downloader, err := New(Config{
		Meta:             meta,
		Storage:          downloadStore.Storage,
		UTP:              downloadSocket,
		PeerID:           testPeerID(22),
		ScheduleInterval: 5 * time.Millisecond,
		RequestTimeout:   time.Second,
		RetryInterval:    10 * time.Millisecond,
		RandIntN:         zeroRandom,
	})
	if err != nil {
		_ = downloadSocket.Close()
		_ = seed.Close()
		<-seedRun
		t.Fatal(err)
	}
	if err := downloader.AddPeer(Candidate{Address: seedSocket.Addr().String(), Source: SourceDirect, Transport: TransportUTP}); err != nil {
		t.Fatal(err)
	}
	downloadRun := runAsync(downloader)
	waitClosed(t, downloader.Completed(), "uTP download completion")
	waitFor(t, "uTP upload accounting", func() bool { return seed.Progress().UploadedBytes >= int64(len(data)) })
	if err := downloader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-downloadRun; !errors.Is(err, ErrClosed) {
		t.Fatalf("download Run error = %v, want ErrClosed", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-seedRun; !errors.Is(err, ErrClosed) {
		t.Fatalf("seed Run error = %v, want ErrClosed", err)
	}
}

func TestAutoCandidateRouteOrder(t *testing.T) {
	socket, err := purego.NewSocket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = socket.Close() }()
	torrent := &Client{
		utp: socket,
		layouts: map[peer.ProtocolVersion]*wireLayout{
			peer.ProtocolV1: {},
			peer.ProtocolV2: {},
		},
	}
	routes := torrent.candidateRoutes(Candidate{})
	want := []candidateRoute{
		{protocol: peer.ProtocolV2, transport: TransportUTP},
		{protocol: peer.ProtocolV2, transport: TransportTCP},
		{protocol: peer.ProtocolV1, transport: TransportUTP},
		{protocol: peer.ProtocolV1, transport: TransportTCP},
	}
	if len(routes) != len(want) {
		t.Fatalf("routes = %+v", routes)
	}
	for index := range want {
		if routes[index].protocol != want[index].protocol || routes[index].transport != want[index].transport {
			t.Fatalf("routes = %+v, want %+v", routes, want)
		}
	}
}

func TestResumeAndRejectRetryOverNetPipe(t *testing.T) {
	data := []byte("abcdefgh")
	meta := testV1Meta(t, data, 4, "", false)
	store := testStorage(t, meta)
	if err := store.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := store.WritePiece(storage.V1, 0, data[:4]); err != nil {
		t.Fatal(err)
	}

	remoteID := testPeerID(8)
	var attempts atomic.Int32
	var requestedMu sync.Mutex
	var requested []uint32
	remoteCancel := func() {}
	dialed := atomic.Bool{}
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "127.0.0.1:51413" {
			return nil, errors.New("unexpected dial")
		}
		if !dialed.CompareAndSwap(false, true) {
			return nil, errors.New("duplicate dial")
		}
		local, remote := net.Pipe()
		remoteCtx, cancel := context.WithCancel(context.Background())
		remoteCancel = cancel
		var fast peer.Reserved
		fast.Set(peer.CapabilityFast, true)
		hash := meta.InfoHash
		session, err := peer.NewSession(remote, peer.SessionConfig{
			PeerID:         remoteID,
			Hashes:         metainfo.Hashes{V1: &hash},
			Reserved:       fast,
			PieceCount:     2,
			PieceLengths:   []uint32{4, 4},
			LocalPieces:    []bool{true, true},
			RequestTimeout: time.Second,
			WriteTimeout:   time.Second,
			Callbacks: peer.SessionCallbacks{OnUploadRequest: func(_ context.Context, request peer.BlockRequest) ([]byte, error) {
				requestedMu.Lock()
				requested = append(requested, request.Index)
				requestedMu.Unlock()
				if attempts.Add(1) == 1 {
					return nil, errors.New("reject once")
				}
				start := int(request.Index)*4 + int(request.Begin)
				return append([]byte(nil), data[start:start+int(request.Length)]...), nil
			}},
		})
		if err != nil {
			cancel()
			_ = local.Close()
			_ = remote.Close()
			return nil, err
		}
		go func() {
			_ = session.Run(remoteCtx)
		}()
		go func() {
			select {
			case <-session.Ready():
				_ = session.SetChoking(false)
			case <-session.Done():
			}
		}()
		return local, nil
	}

	coordinator, err := New(Config{
		Meta:             meta,
		Storage:          store.Storage,
		PeerID:           testPeerID(7),
		DialContext:      dial,
		ScheduleInterval: 5 * time.Millisecond,
		RequestTimeout:   100 * time.Millisecond,
		RetryInterval:    10 * time.Millisecond,
		RandIntN:         zeroRandom,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remoteCancel()
	if err := coordinator.AddPeer(Candidate{Address: "127.0.0.1:51413", Protocol: peer.ProtocolV1, PeerID: remoteID}); err != nil {
		t.Fatal(err)
	}
	runResult := runAsync(coordinator)
	waitClosed(t, coordinator.Completed(), "resumed download completion")
	progress := coordinator.Progress()
	if progress.CompletedPieces != 2 || progress.CompletedBytes != int64(len(data)) {
		t.Fatalf("progress = %+v", progress)
	}
	requestedMu.Lock()
	gotRequests := append([]uint32(nil), requested...)
	requestedMu.Unlock()
	if len(gotRequests) < 2 {
		t.Fatalf("requests = %v, want a rejected request and retry", gotRequests)
	}
	for _, index := range gotRequests {
		if index != 1 {
			t.Fatalf("requested resumed piece %d, want only piece 1", index)
		}
	}
	verified, err := store.VerifyAll()
	if err != nil || len(verified) != 2 || !verified[0] || !verified[1] {
		t.Fatalf("VerifyAll = %v, %v", verified, err)
	}
	if err := coordinator.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-runResult; !errors.Is(err, ErrClosed) {
		t.Fatalf("Run error = %v, want ErrClosed", err)
	}
}

func TestPrivateProvenanceAndTrackerSwitchDrop(t *testing.T) {
	const trackerURL = "http://tracker.example/announce"
	meta := testV1Meta(t, []byte("data"), 4, trackerURL, true)
	store := testStorage(t, meta)
	torrentClient, err := New(Config{Meta: meta, Storage: store.Storage, PeerID: testPeerID(3), Port: 6881, MaxCandidates: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := torrentClient.AddPeer(Candidate{Address: "127.0.0.1:1", Source: SourceDirect}); !errors.Is(err, ErrPrivatePeerSource) {
		t.Fatalf("direct private AddPeer error = %v", err)
	}
	if err := torrentClient.AddPeer(Candidate{Address: "127.0.0.1:1", Source: SourcePEX, Introducer: testPeerID(9)}); !errors.Is(err, ErrPrivatePeerSource) {
		t.Fatalf("PEX private AddPeer error = %v", err)
	}
	if err := torrentClient.AddPeer(Candidate{Address: "127.0.0.1:1", Source: SourceTracker, Tracker: "http://other.example/announce"}); !errors.Is(err, ErrPrivatePeerSource) {
		t.Fatalf("foreign tracker AddPeer error = %v", err)
	}
	tracked := Candidate{Address: "127.0.0.1:2", Source: SourceTracker, Tracker: trackerURL, Protocol: peer.ProtocolV1}
	if err := torrentClient.AddPeer(tracked); err != nil {
		t.Fatalf("private tracker AddPeer: %v", err)
	}

	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()
	hash := meta.InfoHash
	session, err := peer.NewSession(local, peer.SessionConfig{
		PeerID:       torrentClient.peerID,
		Hashes:       metainfo.Hashes{V1: &hash},
		PieceCount:   1,
		PieceLengths: []uint32{4},
		LocalPieces:  []bool{false},
		Private:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate := torrentClient.pending[tracked.Address]
	candidate.connected = true
	managed := &peerState{
		id:        1,
		session:   session,
		endpoint:  tracked.Address,
		protocol:  peer.ProtocolV1,
		origin:    candidate.routes[0],
		routes:    append([]candidateRoute(nil), candidate.routes...),
		candidate: candidate,
		outgoing:  true,
		retry:     true,
	}
	state := &coordinator{
		client:     torrentClient,
		candidates: torrentClient.pending,
		peers:      map[uint64]*peerState{1: managed},
	}
	state.switchPrivateTracker("http://new.example/announce")
	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("private tracker switch did not close old peer")
	}
	if managed.retry || len(managed.routes) != 0 {
		t.Fatalf("old tracker peer retained retry=%t routes=%v", managed.retry, managed.routes)
	}
	if err := torrentClient.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-torrentClient.Done():
	default:
		t.Fatal("Close before Run did not finish shutdown")
	}
}

func TestPrivateClientRejectsIncomingPeer(t *testing.T) {
	meta := testV1Meta(t, []byte("data"), 4, "http://tracker.example/announce", true)
	store := testStorage(t, meta)
	torrentClient, err := New(Config{Meta: meta, Storage: store.Storage, PeerID: testPeerID(3), Port: 6881})
	if err != nil {
		t.Fatal(err)
	}
	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()
	state := &coordinator{
		client:     torrentClient,
		incoming:   1,
		candidates: make(map[string]*candidateState),
		peers:      make(map[uint64]*peerState),
		endpoints:  make(map[string]uint64),
		peerIDs:    make(map[[20]byte]uint64),
	}
	state.handleInbound(inboundEvent{
		conn:     local,
		endpoint: "127.0.0.1:51413",
		protocol: peer.ProtocolV1,
		remoteID: testPeerID(9),
	})
	if state.incoming != 0 || len(state.peers) != 0 {
		t.Fatalf("private incoming connection retained: incoming=%d peers=%d", state.incoming, len(state.peers))
	}
	_ = remote.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := remote.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("private incoming connection read error = %v, want EOF", err)
	}
}

func TestPrivateDialRouteRequiresActiveTracker(t *testing.T) {
	state := &coordinator{client: &Client{meta: &metainfo.MetaInfo{Info: metainfo.Info{Private: true}}}}
	candidate := &candidateState{routes: []candidateRoute{
		{source: SourceTracker, tracker: "http://first.example/announce", protocol: peer.ProtocolV1},
		{source: SourceTracker, tracker: "http://second.example/announce", protocol: peer.ProtocolV2},
	}}
	if _, ok := state.dialRoute(candidate); ok {
		t.Fatal("private candidate was dialable before tracker selection")
	}
	state.privateTracker = "http://second.example/announce"
	route, ok := state.dialRoute(candidate)
	if !ok || route.tracker != state.privateTracker || route.protocol != peer.ProtocolV2 {
		t.Fatalf("dialRoute = %+v, %t", route, ok)
	}
}

func TestFailedPEXRouteIsNotRetried(t *testing.T) {
	pexRoute := candidateRoute{protocol: peer.ProtocolV1, transport: TransportUTP, source: SourcePEX, introducer: testPeerID(8)}
	directRoute := candidateRoute{protocol: peer.ProtocolV1, transport: TransportTCP, source: SourceDirect}
	candidate := &candidateState{address: "127.0.0.1:49000", routes: []candidateRoute{pexRoute, directRoute}}
	state := &coordinator{
		client:     &Client{retryInterval: time.Millisecond, now: time.Now},
		candidates: map[string]*candidateState{candidate.address: candidate},
		order:      []string{candidate.address},
	}
	state.failCandidateRoute(candidate, pexRoute)
	if len(candidate.routes) != 1 || candidate.routes[0] != directRoute {
		t.Fatalf("routes after PEX failure = %+v", candidate.routes)
	}
	candidate.routes = []candidateRoute{pexRoute}
	state.failCandidateRoute(candidate, pexRoute)
	if state.candidates[candidate.address] != nil || len(state.order) != 0 {
		t.Fatal("failed PEX-only candidate was retained")
	}
}

func TestFailedPEXRouteCannotBeReaddedByIntroducer(t *testing.T) {
	meta := testV1Meta(t, []byte("data"), 4, "", false)
	torrent := &Client{meta: meta, layouts: map[peer.ProtocolVersion]*wireLayout{peer.ProtocolV1: {}}, maxCandidates: 10}
	introducer := &peerState{
		id:        1,
		ready:     true,
		protocol:  peer.ProtocolV1,
		remoteID:  testPeerID(8),
		pexFailed: make(map[pexFailure]struct{}),
	}
	state := &coordinator{
		client:     torrent,
		candidates: make(map[string]*candidateState),
		peers:      map[uint64]*peerState{introducer.id: introducer},
		peerIDs:    map[[20]byte]uint64{introducer.remoteID: introducer.id},
	}
	contact := peer.PEXContact{AddrPort: netip.MustParseAddrPort("127.0.0.1:49001")}
	event := peerPEXEvent{id: introducer.id, message: peer.PEXMessage{Added: []peer.PEXContact{contact}}}
	state.handlePEX(event)
	candidate := state.candidates[contact.AddrPort.String()]
	if candidate == nil || len(candidate.routes) != 1 {
		t.Fatalf("initial PEX candidate = %+v", candidate)
	}
	state.failCandidateRoute(candidate, candidate.routes[0])
	state.handlePEX(event)
	if state.candidates[contact.AddrPort.String()] != nil {
		t.Fatal("introducer re-added a failed PEX route")
	}
}

func TestPrivateHybridTrackerFailoverMovesBothHashes(t *testing.T) {
	first := &fakeTracker{}
	firstServer := httptest.NewServer(http.HandlerFunc(first.serveHTTP))
	defer firstServer.Close()
	second := &fakeTracker{}
	secondServer := httptest.NewServer(http.HandlerFunc(second.serveHTTP))
	defer secondServer.Close()
	meta := testHybridMeta(t)
	meta.Info.Private = true
	meta.AnnounceList = [][]string{{firstServer.URL + "/announce", secondServer.URL + "/announce"}}
	store := testStorage(t, meta)
	torrent, err := New(Config{
		Meta:             meta,
		Storage:          store.Storage,
		TrackerClient:    tracker.NewClient(http.DefaultClient),
		PeerID:           testPeerID(33),
		Port:             49033,
		ScheduleInterval: 5 * time.Millisecond,
		RetryInterval:    10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	runResult := runAsync(torrent)
	waitFor(t, "private hybrid tracker start", func() bool {
		return first.countEvent("started") == 2 || second.countEvent("started") == 2
	})
	active, replacement := first, second
	if second.countEvent("started") == 2 {
		active, replacement = second, first
	}
	if replacement.countEvent("started") != 0 {
		t.Fatal("private hybrid hashes started on different trackers")
	}
	active.setFail(true)
	waitFor(t, "private hybrid tracker failover", func() bool { return replacement.countEvent("started") == 2 })
	hashes := make(map[metainfo.Hash]struct{})
	for _, event := range replacement.eventsSnapshot() {
		if event.event == "started" {
			hashes[event.infoHash] = struct{}{}
		}
	}
	var truncatedV2 metainfo.Hash
	copy(truncatedV2[:], meta.InfoHashV2[:])
	if _, ok := hashes[meta.InfoHash]; !ok {
		t.Fatalf("replacement tracker missed v1 hash: %+v", hashes)
	}
	if _, ok := hashes[truncatedV2]; !ok {
		t.Fatalf("replacement tracker missed v2 hash: %+v", hashes)
	}
	if err := torrent.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-runResult; !errors.Is(err, ErrClosed) {
		t.Fatalf("Run error = %v, want ErrClosed", err)
	}
}

func TestHybridClientUpgradesAndServesExtensions(t *testing.T) {
	meta := testHybridMeta(t)
	store := testStorage(t, meta)
	torrentClient, err := New(Config{Meta: meta, Storage: store.Storage, PeerID: testPeerID(4), WriteTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := &coordinator{
		client:     torrentClient,
		ctx:        ctx,
		candidates: make(map[string]*candidateState),
		peers:      make(map[uint64]*peerState),
		endpoints:  make(map[string]uint64),
		peerIDs:    make(map[[20]byte]uint64),
		active:     make(map[pieceKey]*downloadPiece),
	}
	local, remoteConn := net.Pipe()
	v1 := meta.InfoHash
	v2 := meta.InfoHashV2
	metadataResult := make(chan peer.MetadataMessage, 1)
	hashReject := make(chan peer.HashRequest, 1)
	remote, err := peer.NewSession(remoteConn, peer.SessionConfig{
		PeerID:         testPeerID(5),
		Hashes:         metainfo.Hashes{V1: &v1, V2: &v2},
		PieceCount:     2,
		V1PieceLengths: []uint32{16 << 10, 5},
		V2PieceLengths: []uint32{3, 5},
		LocalPieces:    []bool{false, false},
		ExtensionHandshake: peer.ExtensionHandshake{Extensions: map[string]uint8{
			peer.ExtensionMetadata: 7,
		}},
		Callbacks: peer.SessionCallbacks{
			OnMetadata:   func(message peer.MetadataMessage) { metadataResult <- message },
			OnHashReject: func(request peer.HashRequest) { hashReject <- request },
		},
		WriteTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	remoteResult := make(chan error, 1)
	go func() { remoteResult <- remote.Run(ctx) }()
	managed, err := state.startPeer(local, "127.0.0.1:51413", peer.ProtocolV1, true, [20]byte{}, candidateRoute{protocol: peer.ProtocolV1}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	waitClosed(t, managed.session.Ready(), "client peer readiness")
	waitClosed(t, remote.Ready(), "remote peer readiness")
	waitFor(t, "metadata negotiation", func() bool {
		return managed.session.Snapshot().OutgoingExtensions[peer.ExtensionMetadata] != 0 &&
			remote.Snapshot().OutgoingExtensions[peer.ExtensionMetadata] != 0
	})
	state.handlePeerReady(managed.id)
	if managed.protocol != peer.ProtocolV2 || managed.session.Snapshot().Version != peer.ProtocolV2 {
		t.Fatalf("hybrid connection versions = %d/%d, want v2", managed.protocol, managed.session.Snapshot().Version)
	}
	if err := managed.session.Request(peer.BlockRequest{Index: 0, Length: 4}); err == nil {
		t.Fatal("upgraded client accepted a request beyond the v2 piece length")
	}

	state.handleMetadata(peerMetadataEvent{id: managed.id, message: peer.MetadataMessage{Type: peer.MetadataRequest, Piece: 0}})
	select {
	case message := <-metadataResult:
		if message.Type != peer.MetadataData || !bytes.Equal(message.Data, meta.RawInfo) {
			t.Fatalf("served metadata = type %d, %d bytes", message.Type, len(message.Data))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for served metadata")
	}

	request := peer.HashRequest{PiecesRoot: *meta.Info.V2Files[0].PiecesRoot, Length: 2}
	state.handleHashRequest(peerHashRequestEvent{id: managed.id, request: request})
	select {
	case got := <-hashReject:
		if got != request {
			t.Fatalf("hash reject = %+v, want %+v", got, request)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for hash reject")
	}

	cancel()
	_ = managed.session.Close()
	_ = remote.Close()
	state.workers.Wait()
	select {
	case <-remoteResult:
	case <-time.After(2 * time.Second):
		t.Fatal("remote session did not stop")
	}
}

func TestHybridWireLayoutsKeepDifferentPieceLengths(t *testing.T) {
	meta := testHybridMeta(t)
	store := testStorage(t, meta)
	coordinator, err := New(Config{Meta: meta, Storage: store.Storage, PeerID: testPeerID(4)})
	if err != nil {
		t.Fatal(err)
	}
	v1 := coordinator.layouts[peer.ProtocolV1]
	v2 := coordinator.layouts[peer.ProtocolV2]
	if v1.pieces[0].length != 16<<10 || v2.pieces[0].length != 3 {
		t.Fatalf("hybrid first piece lengths v1=%d v2=%d", v1.pieces[0].length, v2.pieces[0].length)
	}
	v1State, err := v1.newPiece(0)
	if err != nil {
		t.Fatal(err)
	}
	v2State, err := v2.newPiece(0)
	if err != nil {
		t.Fatal(err)
	}
	if v1State.Length() == v2State.Length() {
		t.Fatal("hybrid protocol states share an incompatible piece length")
	}
	if coordinator.PeerID() != testPeerID(4) {
		t.Fatal("configured peer ID changed")
	}
}

type fakeTrackerEvent struct {
	event    string
	left     int64
	infoHash metainfo.Hash
}

type fakeTracker struct {
	mu     sync.Mutex
	peer   string
	fail   bool
	events []fakeTrackerEvent
}

func (fake *fakeTracker) setPeer(address string) {
	fake.mu.Lock()
	fake.peer = address
	fake.mu.Unlock()
}

func (fake *fakeTracker) setFail(fail bool) {
	fake.mu.Lock()
	fake.fail = fail
	fake.mu.Unlock()
}

func (fake *fakeTracker) serveHTTP(w http.ResponseWriter, request *http.Request) {
	left, _ := strconv.ParseInt(request.URL.Query().Get("left"), 10, 64)
	var infoHash metainfo.Hash
	copy(infoHash[:], request.URL.Query().Get("info_hash"))
	fake.mu.Lock()
	fake.events = append(fake.events, fakeTrackerEvent{event: request.URL.Query().Get("event"), left: left, infoHash: infoHash})
	address := fake.peer
	fail := fake.fail
	fake.mu.Unlock()
	if fail {
		http.Error(w, "tracker unavailable", http.StatusServiceUnavailable)
		return
	}
	peers := ""
	if host, portText, err := net.SplitHostPort(address); err == nil {
		if ip := net.ParseIP(host).To4(); ip != nil {
			port, _ := strconv.ParseUint(portText, 10, 16)
			compact := append([]byte(nil), ip...)
			compact = append(compact, byte(port>>8), byte(port))
			peers = string(compact)
		}
	}
	if err := bencode.Encode(w, map[string]any{"interval": int64(1), "peers": peers}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (fake *fakeTracker) countEvent(event string) int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	count := 0
	for _, observed := range fake.events {
		if observed.event == event {
			count++
		}
	}
	return count
}

func (fake *fakeTracker) eventsSnapshot() []fakeTrackerEvent {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]fakeTrackerEvent(nil), fake.events...)
}

func trackerClient(httpClient *http.Client) *tracker.Client {
	return tracker.NewClient(httpClient)
}

func testV1Meta(t *testing.T, data []byte, pieceLength int, announce string, private bool) *metainfo.MetaInfo {
	t.Helper()
	var hashes []byte
	for offset := 0; offset < len(data); offset += pieceLength {
		end := min(offset+pieceLength, len(data))
		hash := sha1.Sum(data[offset:end])
		hashes = append(hashes, hash[:]...)
	}
	info := map[string]any{
		"length":       int64(len(data)),
		"name":         "payload",
		"piece length": int64(pieceLength),
		"pieces":       string(hashes),
	}
	if private {
		info["private"] = int64(1)
	}
	top := map[string]any{"info": info}
	if announce != "" {
		top["announce"] = announce
	}
	var encoded bytes.Buffer
	if err := bencode.Encode(&encoded, top); err != nil {
		t.Fatal(err)
	}
	meta, err := metainfo.Decode(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return meta
}

func testHybridMeta(t *testing.T) *metainfo.MetaInfo {
	t.Helper()
	const pieceLength = 16 << 10
	a := []byte("abc")
	b := []byte("12345")
	first := make([]byte, pieceLength)
	copy(first, a)
	logical := first
	logical = append(logical, b...)
	var v1Hashes []byte
	for offset := 0; offset < len(logical); offset += pieceLength {
		end := min(offset+pieceLength, len(logical))
		hash := sha1.Sum(logical[offset:end])
		v1Hashes = append(v1Hashes, hash[:]...)
	}
	rootA := sha256.Sum256(a)
	rootB := sha256.Sum256(b)
	info := map[string]any{
		"file tree": map[string]any{
			"a": map[string]any{"": map[string]any{"length": int64(len(a)), "pieces root": string(rootA[:])}},
			"b": map[string]any{"": map[string]any{"length": int64(len(b)), "pieces root": string(rootB[:])}},
		},
		"files": []any{
			map[string]any{"length": int64(len(a)), "path": []any{"a"}},
			map[string]any{"attr": "p", "length": int64(pieceLength - len(a)), "path": []any{".pad", "gap"}},
			map[string]any{"length": int64(len(b)), "path": []any{"b"}},
		},
		"meta version": int64(2),
		"name":         "bundle",
		"piece length": int64(pieceLength),
		"pieces":       string(v1Hashes),
	}
	var encoded bytes.Buffer
	if err := bencode.Encode(&encoded, map[string]any{"info": info, "piece layers": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	meta, err := metainfo.Decode(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return meta
}

type testStore struct {
	*storage.Storage
	root string
}

func testStorage(t *testing.T, meta *metainfo.MetaInfo) *testStore {
	t.Helper()
	root := t.TempDir()
	store, err := storage.New(root, meta)
	if err != nil {
		t.Fatal(err)
	}
	return &testStore{Storage: store, root: root}
}

func (store *testStore) rootForTest() string { return store.root }

func testPeerID(value byte) [20]byte {
	var id [20]byte
	for index := range id {
		id[index] = value
	}
	return id
}

func zeroRandom(int) int { return 0 }

func runAsync(client *Client) <-chan error {
	result := make(chan error, 1)
	go func() { result <- client.Run(context.Background()) }()
	return result
}

func waitClosed(t *testing.T, channel <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-channel:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func waitFor(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestGeneratedPeerIDIsStable(t *testing.T) {
	meta := testV1Meta(t, []byte("x"), 1, "", false)
	store := testStorage(t, meta)
	coordinator, err := New(Config{Meta: meta, Storage: store.Storage})
	if err != nil {
		t.Fatal(err)
	}
	first := coordinator.PeerID()
	if first == ([20]byte{}) || first != coordinator.PeerID() {
		t.Fatal("generated peer ID is zero or unstable")
	}
	_ = coordinator.Close()
}
