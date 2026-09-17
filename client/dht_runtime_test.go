package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/natalie-o-perret/go-torrent/dht"
	"github.com/natalie-o-perret/go-torrent/metainfo"
	"github.com/natalie-o-perret/go-torrent/peer"
)

func TestDHTRuntimeLooksUpAnnouncesAndReannouncesBothSwarms(t *testing.T) {
	server := listenClientTestDHT(t, 1, 500*time.Millisecond)
	publisher := listenClientTestDHT(t, 2, 500*time.Millisecond)
	node := listenClientTestDHT(t, 3, 500*time.Millisecond)
	meta := testHybridMeta(t)
	v1 := dht.ID(meta.InfoHash)
	var v2 dht.ID
	copy(v2[:], meta.InfoHashV2[:dht.IDLength])
	publishClientTestPeer(t, publisher, server.Addr(), v1, 45101)
	publishClientTestPeer(t, publisher, server.Addr(), v2, 45102)
	pingClientTestDHT(t, node, server.Addr())

	dialed := make(chan string, 32)
	torrentClient, err := New(Config{
		Meta:                  meta,
		Storage:               testStorage(t, meta).Storage,
		DHTNode:               node,
		DHTReannounceInterval: 30 * time.Millisecond,
		Port:                  45100,
		PeerID:                testPeerID(20),
		ScheduleInterval:      5 * time.Millisecond,
		RetryInterval:         time.Hour,
		DialContext: func(_ context.Context, _ string, address string) (net.Conn, error) {
			dialed <- address
			return nil, errors.New("test dial refused")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := torrentClient.dhtInfoHash(peer.ProtocolV1); got != v1 {
		t.Fatalf("v1 DHT hash = %s, want %s", got, v1)
	}
	if got := torrentClient.dhtInfoHash(peer.ProtocolV2); got != v2 {
		t.Fatalf("v2 DHT hash = %s, want truncated %s", got, v2)
	}

	runResult := runAsync(torrentClient)
	waitForClientTestDials(t, dialed, "127.0.0.1:45101", "127.0.0.1:45102")
	waitForClientTestDHTPeer(t, publisher, server.Addr(), v1, 45100)
	waitForClientTestDHTPeer(t, publisher, server.Addr(), v2, 45100)

	publishClientTestPeer(t, publisher, server.Addr(), v1, 45103)
	waitForClientTestDials(t, dialed, "127.0.0.1:45103")

	if err := torrentClient.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-runResult; !errors.Is(err, ErrClosed) {
		t.Fatalf("Run error = %v, want ErrClosed", err)
	}
	pingClientTestDHT(t, node, server.Addr())
}

func TestDHTCandidateAdmissionBoundsAndPrivateSuppression(t *testing.T) {
	publicMeta := testHybridMeta(t)
	publicClient, err := New(Config{
		Meta:          publicMeta,
		Storage:       testStorage(t, publicMeta).Storage,
		PeerID:        testPeerID(21),
		MaxCandidates: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = publicClient.Close() }()
	for _, protocol := range []peer.ProtocolVersion{peer.ProtocolV1, peer.ProtocolV2} {
		if err := publicClient.AddPeer(Candidate{Address: "127.0.0.1:45201", Source: SourceDHT, Protocol: protocol}); err != nil {
			t.Fatalf("AddPeer(%s): %v", protocolName(protocol), err)
		}
	}
	routes := publicClient.pending["127.0.0.1:45201"].routes
	if len(routes) != 2 || routes[0].source != SourceDHT || routes[0].protocol != peer.ProtocolV1 || routes[1].protocol != peer.ProtocolV2 {
		t.Fatalf("DHT routes = %#v", routes)
	}
	if err := publicClient.AddPeer(Candidate{Address: "127.0.0.1:45202", Source: SourceDHT, Protocol: peer.ProtocolV1}); !errors.Is(err, ErrCandidateLimit) {
		t.Fatalf("bounded DHT AddPeer error = %v", err)
	}

	server := listenClientTestDHT(t, 4, 500*time.Millisecond)
	publisher := listenClientTestDHT(t, 5, 500*time.Millisecond)
	node := listenClientTestDHT(t, 6, 500*time.Millisecond)
	privateMeta := testV1Meta(t, []byte("data"), 4, "", true)
	privateHash := dht.ID(privateMeta.InfoHash)
	publishClientTestPeer(t, publisher, server.Addr(), privateHash, 45203)
	pingClientTestDHT(t, node, server.Addr())
	var dials atomic.Int32
	privateClient, err := New(Config{
		Meta:                  privateMeta,
		Storage:               testStorage(t, privateMeta).Storage,
		DHTNode:               node,
		DHTReannounceInterval: 20 * time.Millisecond,
		Port:                  45200,
		PeerID:                testPeerID(22),
		ScheduleInterval:      5 * time.Millisecond,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("private DHT dial")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if privateClient.dhtPort() != 0 {
		t.Fatal("private client exposed a DHT port")
	}
	if err := privateClient.AddPeer(Candidate{Address: "127.0.0.1:45203", Source: SourceDHT, Protocol: peer.ProtocolV1}); !errors.Is(err, ErrPrivatePeerSource) {
		t.Fatalf("private DHT AddPeer error = %v", err)
	}

	privateRun := runAsync(privateClient)
	time.Sleep(100 * time.Millisecond)
	if dials.Load() != 0 || privateClient.Progress().Candidates != 0 {
		t.Fatalf("private DHT activity: dials=%d candidates=%d", dials.Load(), privateClient.Progress().Candidates)
	}
	if peers := clientTestDHTPeers(t, publisher, server.Addr(), privateHash); hasClientTestPort(peers, 45200) {
		t.Fatalf("private client announced through DHT: %v", peers)
	}
	select {
	case err := <-privateRun:
		t.Fatalf("DHT suppression terminated private client: %v", err)
	default:
	}
	if err := privateClient.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-privateRun; !errors.Is(err, ErrClosed) {
		t.Fatalf("private Run error = %v, want ErrClosed", err)
	}
}

func TestDHTPORTAdvertisesBoundPortAndPingsConnectionIP(t *testing.T) {
	node := listenClientTestDHT(t, 7, 500*time.Millisecond)
	remoteDHT := listenClientTestDHT(t, 8, 500*time.Millisecond)
	meta := testV1Meta(t, []byte("data"), 4, "", false)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	remoteCtx, cancelRemote := context.WithCancel(context.Background())
	defer cancelRemote()
	remoteSession := make(chan *peer.Session, 1)
	remoteResult := make(chan error, 1)
	seenPort := make(chan uint16, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			remoteResult <- acceptErr
			return
		}
		hash := meta.InfoHash
		session, sessionErr := peer.NewSession(conn, peer.SessionConfig{
			PeerID:       testPeerID(24),
			Hashes:       metainfo.Hashes{V1: &hash},
			PieceCount:   1,
			PieceLengths: []uint32{4},
			LocalPieces:  []bool{false},
			DHTPort:      remoteDHT.Addr().Port(),
			WriteTimeout: time.Second,
			Callbacks:    peer.SessionCallbacks{OnPort: func(port uint16) { seenPort <- port }},
		})
		if sessionErr != nil {
			_ = conn.Close()
			remoteResult <- sessionErr
			return
		}
		remoteSession <- session
		remoteResult <- session.Run(remoteCtx)
	}()

	torrentClient, err := New(Config{
		Meta:             meta,
		Storage:          testStorage(t, meta).Storage,
		DHTNode:          node,
		PeerID:           testPeerID(23),
		ScheduleInterval: 5 * time.Millisecond,
		RetryInterval:    time.Hour,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", listener.Addr().String())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := torrentClient.AddPeer(Candidate{Address: "peer.invalid:45210", Source: SourceDirect, Protocol: peer.ProtocolV1}); err != nil {
		t.Fatal(err)
	}
	runResult := runAsync(torrentClient)

	var remote *peer.Session
	select {
	case remote = <-remoteSession:
	case err := <-remoteResult:
		t.Fatalf("remote session setup: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for remote session")
	}
	waitClosed(t, remote.Ready(), "DHT peer readiness")
	if !remote.Snapshot().RemoteReserved.Has(peer.CapabilityDHT) {
		t.Fatal("public client did not advertise DHT capability")
	}
	select {
	case port := <-seenPort:
		if port != node.Addr().Port() {
			t.Fatalf("advertised DHT port = %d, want %d", port, node.Addr().Port())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for DHT PORT")
	}
	waitFor(t, "PORT ping to remote connection IP", func() bool {
		for _, contact := range node.RoutingContacts() {
			if contact.ID == remoteDHT.ID() && contact.Addr == remoteDHT.Addr() {
				return true
			}
		}
		return false
	})

	if err := torrentClient.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-runResult; !errors.Is(err, ErrClosed) {
		t.Fatalf("Run error = %v, want ErrClosed", err)
	}
	cancelRemote()
	select {
	case <-remoteResult:
	case <-time.After(3 * time.Second):
		t.Fatal("remote peer did not stop")
	}
}

func TestDHTRuntimeCancellationWaitsAndLeavesNodeOpen(t *testing.T) {
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	serverID := clientTestDHTID(9)
	node := listenClientTestDHT(t, 10, 5*time.Second)
	respondToClientTestPing(t, raw, serverID)
	pingClientTestDHT(t, node, raw.LocalAddr().(*net.UDPAddr).AddrPort())

	meta := testV1Meta(t, []byte("data"), 4, "", false)
	torrentClient, err := New(Config{
		Meta:                  meta,
		Storage:               testStorage(t, meta).Storage,
		DHTNode:               node,
		DHTReannounceInterval: time.Hour,
		PeerID:                testPeerID(25),
	})
	if err != nil {
		t.Fatal(err)
	}
	runResult := runAsync(torrentClient)
	message, _, err := readClientTestDHTMessage(raw, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if message.Type != dht.QueryMessage || message.Query != "get_peers" {
		t.Fatalf("in-flight DHT message = type %q query %q", message.Type, message.Query)
	}

	closed := make(chan error, 1)
	go func() { closed <- torrentClient.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("client shutdown did not cancel its DHT lookup")
	}
	if err := <-runResult; !errors.Is(err, ErrClosed) {
		t.Fatalf("Run error = %v, want ErrClosed", err)
	}

	respondToClientTestPing(t, raw, serverID)
	pingClientTestDHT(t, node, raw.LocalAddr().(*net.UDPAddr).AddrPort())
}

func listenClientTestDHT(t *testing.T, idByte byte, queryTimeout time.Duration) *dht.Node {
	t.Helper()
	node, err := dht.Listen("udp4", "127.0.0.1:0", dht.Config{ID: clientTestDHTID(idByte), QueryTimeout: queryTimeout})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := node.Close(); err != nil {
			t.Errorf("close DHT node: %v", err)
		}
	})
	return node
}

func clientTestDHTID(value byte) dht.ID {
	var id dht.ID
	for index := range id {
		id[index] = value
	}
	return id
}

func pingClientTestDHT(t *testing.T, node *dht.Node, endpoint netip.AddrPort) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := node.Ping(ctx, endpoint); err != nil {
		t.Fatalf("Ping(%v): %v", endpoint, err)
	}
}

func publishClientTestPeer(t *testing.T, publisher *dht.Node, server netip.AddrPort, hash dht.ID, port uint16) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	response, err := publisher.GetPeersFrom(ctx, server, hash)
	if err != nil {
		t.Fatal(err)
	}
	token := dht.AnnounceToken{Contact: response.From, Token: response.Token}
	if err := publisher.AnnouncePeer(ctx, token, hash, port, false); err != nil {
		t.Fatal(err)
	}
}

func clientTestDHTPeers(t *testing.T, seeker *dht.Node, server netip.AddrPort, hash dht.ID) []netip.AddrPort {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	response, err := seeker.GetPeersFrom(ctx, server, hash)
	if err != nil {
		t.Fatal(err)
	}
	return response.Peers
}

func waitForClientTestDHTPeer(t *testing.T, seeker *dht.Node, server netip.AddrPort, hash dht.ID, port uint16) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if hasClientTestPort(clientTestDHTPeers(t, seeker, server, hash), port) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for DHT peer port %d", port)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func hasClientTestPort(peers []netip.AddrPort, port uint16) bool {
	for _, endpoint := range peers {
		if endpoint.Port() == port {
			return true
		}
	}
	return false
}

func waitForClientTestDials(t *testing.T, dialed <-chan string, addresses ...string) {
	t.Helper()
	wanted := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		wanted[address] = struct{}{}
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for len(wanted) != 0 {
		select {
		case address := <-dialed:
			delete(wanted, address)
		case <-timer.C:
			t.Fatalf("timed out waiting for DHT dials: %v", wanted)
		}
	}
}

func respondToClientTestPing(t *testing.T, conn net.PacketConn, id dht.ID) {
	t.Helper()
	result := make(chan error, 1)
	go func() {
		message, source, err := readClientTestDHTMessage(conn, 2*time.Second)
		if err != nil {
			result <- err
			return
		}
		if message.Type != dht.QueryMessage || message.Query != "ping" {
			result <- fmt.Errorf("got type %q query %q, want ping", message.Type, message.Query)
			return
		}
		packet, err := dht.MarshalMessage(dht.Message{
			Transaction: message.Transaction,
			Type:        dht.ResponseMessage,
			Response:    map[string]any{"id": id[:]},
		})
		if err == nil {
			_, err = conn.WriteTo(packet, source)
		}
		result <- err
	}()
	t.Cleanup(func() {
		select {
		case err := <-result:
			if err != nil {
				t.Errorf("serve DHT ping: %v", err)
			}
		default:
		}
	})
}

func readClientTestDHTMessage(conn net.PacketConn, timeout time.Duration) (dht.Message, net.Addr, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return dht.Message{}, nil, err
	}
	buffer := make([]byte, dht.MaxPacketSize+1)
	count, source, err := conn.ReadFrom(buffer)
	if err != nil {
		return dht.Message{}, nil, err
	}
	message, err := dht.UnmarshalMessage(buffer[:count])
	return message, source, err
}
