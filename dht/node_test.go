package dht

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func testConfig(id ID) Config {
	fill := id[IDLength-1] + 1
	return Config{
		ID:                  id,
		QueryTimeout:        300 * time.Millisecond,
		MaxContacts:         64,
		MaxTransactions:     64,
		MaxCandidates:       64,
		MaxInfoHashes:       16,
		MaxPeersPerInfoHash: 16,
		MaxRateSources:      32,
		MaxPacketsPerSecond: 128,
		Random:              bytes.NewReader(bytes.Repeat([]byte{fill}, 64)),
	}
}

func listenTestNode(t *testing.T, network, address string, id ID, change func(*Config)) *Node {
	t.Helper()
	config := testConfig(id)
	if change != nil {
		change(&config)
	}
	node, err := Listen(network, address, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := node.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return node
}

func readRawMessage(conn net.PacketConn, timeout time.Duration) (Message, net.Addr, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return Message{}, nil, err
	}
	buffer := make([]byte, MaxPacketSize+1)
	count, source, err := conn.ReadFrom(buffer)
	if err != nil {
		return Message{}, nil, err
	}
	message, err := UnmarshalMessage(buffer[:count])
	return message, source, err
}

func writeRawMessage(conn net.PacketConn, destination netip.AddrPort, message Message) error {
	packet, err := MarshalMessage(message)
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(packet, net.UDPAddrFromAddrPort(destination))
	return err
}

func TestServerErrorsMalformedPacketsAndVerifiedUpdates(t *testing.T) {
	server := listenTestNode(t, "udp4", "127.0.0.1:0", testID(10), nil)
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })

	badID := Message{
		Transaction: []byte("a1"),
		Type:        QueryMessage,
		Query:       "ping",
		Arguments:   map[string]any{"id": []byte("short")},
	}
	if err := writeRawMessage(raw, server.Addr(), badID); err != nil {
		t.Fatal(err)
	}
	response, _, err := readRawMessage(raw, time.Second)
	if err != nil || response.Error == nil || response.Error.Code != 203 {
		t.Fatalf("malformed query response = %#v, %v", response, err)
	}

	unknownID := testID(11)
	unknown := Message{
		Transaction: []byte("a2"),
		Type:        QueryMessage,
		Query:       "unknown",
		Arguments:   map[string]any{"id": unknownID[:]},
	}
	if err := writeRawMessage(raw, server.Addr(), unknown); err != nil {
		t.Fatal(err)
	}
	response, _, err = readRawMessage(raw, time.Second)
	if err != nil || response.Error == nil || response.Error.Code != 204 {
		t.Fatalf("unknown query response = %#v, %v", response, err)
	}
	if contacts := server.RoutingContacts(); len(contacts) != 0 {
		t.Fatalf("unverified query source entered routing table: %#v", contacts)
	}

	for _, packet := range [][]byte{[]byte("not-bencode"), bytes.Repeat([]byte{'x'}, MaxPacketSize+1)} {
		if _, err := raw.WriteTo(packet, net.UDPAddrFromAddrPort(server.Addr())); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readRawMessage(raw, 80*time.Millisecond); err == nil {
			t.Fatalf("server responded to malformed packet of %d bytes", len(packet))
		}
	}
}

func TestTransactionMatchesEndpointAndSnapshotRestore(t *testing.T) {
	serverID, attackerID := testID(20), testID(21)
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	attacker, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = attacker.Close() }()
	client := listenTestNode(t, "udp4", "127.0.0.1:0", testID(22), nil)

	serveErr := make(chan error, 1)
	go func() {
		query, source, err := readRawMessage(server, time.Second)
		if err != nil {
			serveErr <- err
			return
		}
		wrongID := append([]byte(nil), query.Transaction...)
		wrongID[0] ^= 0xff
		if err := writeRawMessage(server, normalizeEndpoint(source.(*net.UDPAddr).AddrPort()), Message{Transaction: wrongID, Type: ResponseMessage, Response: map[string]any{"id": serverID[:]}}); err != nil {
			serveErr <- err
			return
		}
		if err := writeRawMessage(attacker, normalizeEndpoint(source.(*net.UDPAddr).AddrPort()), Message{Transaction: query.Transaction, Type: ResponseMessage, Response: map[string]any{"id": attackerID[:]}}); err != nil {
			serveErr <- err
			return
		}
		time.Sleep(10 * time.Millisecond)
		serveErr <- writeRawMessage(server, normalizeEndpoint(source.(*net.UDPAddr).AddrPort()), Message{Transaction: query.Transaction, Type: ResponseMessage, Response: map[string]any{"id": serverID[:]}})
	}()

	serverEndpoint, err := endpointFromNetAddr(server.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	contact, err := client.Ping(context.Background(), serverEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serveErr; err != nil {
		t.Fatal(err)
	}
	if contact.ID != serverID || contact.Addr != serverEndpoint {
		t.Fatalf("matched contact = %#v", contact)
	}

	snapshot := client.SnapshotContacts()
	if len(snapshot) != 1 || snapshot[0].ID != serverID {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	restored := listenTestNode(t, "udp4", "127.0.0.1:0", testID(23), nil)
	accepted, err := restored.RestoreContacts(snapshot)
	if err != nil || accepted != 1 {
		t.Fatalf("RestoreContacts = %d, %v", accepted, err)
	}
	if _, err := restored.RestoreContacts([]ContactSnapshot{{ID: serverID, Addr: serverEndpoint}}); err == nil {
		t.Fatal("unverified zero-time snapshot was accepted")
	}
}

func TestTransactionLimitAndCancelledContext(t *testing.T) {
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	rawEndpoint, _ := endpointFromNetAddr(raw.LocalAddr())
	client := listenTestNode(t, "udp4", "127.0.0.1:0", testID(24), func(config *Config) {
		config.MaxTransactions = 1
		config.QueryTimeout = time.Second
	})

	ctx, cancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, err := client.Ping(ctx, rawEndpoint)
		firstDone <- err
	}()
	if _, _, err := readRawMessage(raw, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Ping(context.Background(), rawEndpoint); !errors.Is(err, ErrTransactionLimit) {
		t.Fatalf("second Ping error = %v", err)
	}
	cancel()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Ping error = %v", err)
	}

	cancelled, cancelImmediately := context.WithCancel(context.Background())
	cancelImmediately()
	if _, err := client.Ping(cancelled, rawEndpoint); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled Ping error = %v", err)
	}
	if _, _, err := readRawMessage(raw, 80*time.Millisecond); err == nil {
		t.Fatal("pre-cancelled Ping sent a packet")
	}
}

func TestReadOnlyMode(t *testing.T) {
	readOnly := listenTestNode(t, "udp4", "127.0.0.1:0", testID(30), func(config *Config) {
		config.ReadOnly = true
	})
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	rawEndpoint, _ := endpointFromNetAddr(raw.LocalAddr())
	remoteID := testID(31)

	observed := make(chan error, 1)
	go func() {
		query, source, err := readRawMessage(raw, time.Second)
		if err != nil {
			observed <- err
			return
		}
		if !query.ReadOnly {
			observed <- fmt.Errorf("outgoing query omitted ro=1")
			return
		}
		observed <- writeRawMessage(raw, normalizeEndpoint(source.(*net.UDPAddr).AddrPort()), Message{
			Transaction: query.Transaction,
			Type:        ResponseMessage,
			Response:    map[string]any{"id": remoteID[:]},
		})
	}()
	if _, err := readOnly.Ping(context.Background(), rawEndpoint); err != nil {
		t.Fatal(err)
	}
	if err := <-observed; err != nil {
		t.Fatal(err)
	}

	query := Message{Transaction: []byte("ro"), Type: QueryMessage, Query: "ping", Arguments: map[string]any{"id": remoteID[:]}}
	if err := writeRawMessage(raw, readOnly.Addr(), query); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readRawMessage(raw, 100*time.Millisecond); err == nil {
		t.Fatal("read-only node responded to an incoming query")
	}
}

func TestIterativeLookupConverges(t *testing.T) {
	a := listenTestNode(t, "udp4", "127.0.0.1:0", testID(40), nil)
	b := listenTestNode(t, "udp4", "127.0.0.1:0", testID(41), nil)
	c := listenTestNode(t, "udp4", "127.0.0.1:0", testID(42), nil)
	client := listenTestNode(t, "udp4", "127.0.0.1:0", testID(43), nil)

	if _, err := a.Ping(context.Background(), b.Addr()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Ping(context.Background(), c.Addr()); err != nil {
		t.Fatal(err)
	}
	if err := client.Bootstrap(context.Background(), []netip.AddrPort{a.Addr()}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, contact := range client.RoutingContacts() {
		found = found || contact.ID == c.ID()
	}
	if !found {
		t.Fatalf("bootstrap did not converge through A and B: %#v", client.RoutingContacts())
	}
	closest, err := client.Lookup(context.Background(), c.ID())
	if err != nil {
		t.Fatal(err)
	}
	if len(closest) == 0 || closest[0].ID != c.ID() {
		t.Fatalf("closest = %#v", closest)
	}
}

func TestNonCompliantResponderIsNotRouted(t *testing.T) {
	node := listenTestNode(t, "udp4", "127.0.0.1:0", testID(43), nil)
	endpoint := netip.MustParseAddrPort("212.129.33.59:6881")
	id := ID{0x79, 0x62, 0xb6, 0x58, 0x13, 0xb6, 0x97, 0xb1, 0x2d, 0x1d, 0x3a, 0xa5, 0xcd, 0x01, 0xe1, 0xda, 0x24, 0x02, 0xc0, 0xe9}
	if ValidNodeID(id, endpoint.Addr()) {
		t.Fatal("test node ID unexpectedly complies with BEP 42")
	}
	contact, err := node.validateResponder(endpoint, nil, map[string]any{"id": string(id[:])})
	if err != nil {
		t.Fatal(err)
	}
	if contact.ID != id || contact.Addr != endpoint {
		t.Fatalf("contact = %#v", contact)
	}
	if contacts := node.RoutingContacts(); len(contacts) != 0 {
		t.Fatalf("non-compliant responder entered routing table: %#v", contacts)
	}
}

func TestGetPeersAndAnnounce(t *testing.T) {
	server := listenTestNode(t, "udp4", "127.0.0.1:0", testID(50), nil)
	announcer := listenTestNode(t, "udp4", "127.0.0.1:0", testID(51), nil)
	seeker := listenTestNode(t, "udp4", "127.0.0.1:0", testID(52), nil)
	infoHash := testID(99)

	if err := announcer.Bootstrap(context.Background(), []netip.AddrPort{server.Addr()}); err != nil {
		t.Fatal(err)
	}
	lookup, err := announcer.GetPeers(context.Background(), infoHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(lookup.Tokens) != 1 || len(lookup.Peers) != 0 {
		t.Fatalf("initial lookup = %#v", lookup)
	}
	stored, err := announcer.Announce(context.Background(), infoHash, 6881, false, lookup.Tokens)
	if err != nil || stored != 1 {
		t.Fatalf("Announce = %d, %v", stored, err)
	}
	if contacts := server.RoutingContacts(); len(contacts) != 0 {
		t.Fatalf("server promoted query-only contacts: %#v", contacts)
	}

	if err := seeker.Bootstrap(context.Background(), []netip.AddrPort{server.Addr()}); err != nil {
		t.Fatal(err)
	}
	result, err := seeker.GetPeers(context.Background(), infoHash)
	if err != nil {
		t.Fatal(err)
	}
	wantPeer := netip.AddrPortFrom(announcer.Addr().Addr(), 6881)
	if len(result.Peers) != 1 || result.Peers[0] != wantPeer {
		t.Fatalf("peers = %v, want %v", result.Peers, wantPeer)
	}

	bad := lookup.Tokens[0]
	bad.Token[0] ^= 0xff
	err = announcer.AnnouncePeer(context.Background(), bad, infoHash, 6881, false)
	var protocolError *KRPCError
	if !errors.As(err, &protocolError) || protocolError.Code != 203 {
		t.Fatalf("bad token error = %v", err)
	}

	impliedHash := testID(98)
	direct, err := announcer.GetPeersFrom(context.Background(), server.Addr(), impliedHash)
	if err != nil {
		t.Fatal(err)
	}
	if err := announcer.AnnouncePeer(context.Background(), AnnounceToken{Contact: direct.From, Token: direct.Token}, impliedHash, 0, true); err != nil {
		t.Fatal(err)
	}
	direct, err = seeker.GetPeersFrom(context.Background(), server.Addr(), impliedHash)
	if err != nil || len(direct.Peers) != 1 || direct.Peers[0] != announcer.Addr() {
		t.Fatalf("implied-port peers = %v, %v; want %v", direct.Peers, err, announcer.Addr())
	}
}

func TestIPv6PingAnnounceAndGetPeers(t *testing.T) {
	probe, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	_ = probe.Close()
	server := listenTestNode(t, "udp6", "[::1]:0", testID(60), nil)
	client := listenTestNode(t, "udp6", "[::1]:0", testID(61), nil)
	infoHash := testID(100)

	if _, err := client.Ping(context.Background(), server.Addr()); err != nil {
		t.Fatal(err)
	}
	response, err := client.GetPeersFrom(context.Background(), server.Addr(), infoHash, IPv6)
	if err != nil || len(response.Token) == 0 {
		t.Fatalf("GetPeersFrom = %#v, %v", response, err)
	}
	token := AnnounceToken{Contact: response.From, Token: response.Token}
	if err := client.AnnouncePeer(context.Background(), token, infoHash, 6882, false); err != nil {
		t.Fatal(err)
	}
	response, err = client.GetPeersFrom(context.Background(), server.Addr(), infoHash, IPv6)
	want := netip.AddrPortFrom(netip.IPv6Loopback(), 6882)
	if err != nil || len(response.Peers) != 1 || response.Peers[0] != want {
		t.Fatalf("IPv6 peers = %v, %v; want %v", response.Peers, err, want)
	}
}

func TestGetPeersParsesHybridValues(t *testing.T) {
	raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	rawEndpoint, _ := endpointFromNetAddr(raw.LocalAddr())
	client := listenTestNode(t, "udp4", "127.0.0.1:0", testID(62), nil)
	peer4 := netip.MustParseAddrPort("192.0.2.4:6881")
	peer6 := netip.MustParseAddrPort("[2001:db8::4]:6882")
	compact4, _ := EncodeCompactPeer(peer4)
	compact6, _ := EncodeCompactPeer(peer6)
	remoteID := testID(63)

	serveErr := make(chan error, 1)
	go func() {
		query, source, err := readRawMessage(raw, time.Second)
		if err != nil {
			serveErr <- err
			return
		}
		serveErr <- writeRawMessage(raw, normalizeEndpoint(source.(*net.UDPAddr).AddrPort()), Message{
			Transaction: query.Transaction,
			Type:        ResponseMessage,
			Response: map[string]any{
				"id":     remoteID[:],
				"token":  []byte("token"),
				"values": []any{compact4, compact6},
			},
		})
	}()
	response, err := client.GetPeersFrom(context.Background(), rawEndpoint, testID(101))
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serveErr; err != nil {
		t.Fatal(err)
	}
	if len(response.Peers) != 2 || response.Peers[0] != peer4 || response.Peers[1] != peer6 {
		t.Fatalf("hybrid peers = %v", response.Peers)
	}
}

func TestRaceSafeShutdownKeepsCallerPacketConnOpen(t *testing.T) {
	server := listenTestNode(t, "udp4", "127.0.0.1:0", testID(70), nil)
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	config := testConfig(testID(71))
	client, err := NewNode(conn, config)
	if err != nil {
		t.Fatal(err)
	}

	var calls sync.WaitGroup
	for range 24 {
		calls.Add(1)
		go func() {
			defer calls.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, _ = client.Ping(ctx, server.Addr())
		}()
	}
	closeResults := make(chan error, 2)
	go func() { closeResults <- client.Close() }()
	go func() { closeResults <- client.Close() }()
	if err := <-closeResults; err != nil {
		t.Fatal(err)
	}
	if err := <-closeResults; err != nil {
		t.Fatal(err)
	}
	calls.Wait()
	if _, err := conn.WriteTo([]byte("x"), net.UDPAddrFromAddrPort(server.Addr())); err != nil {
		t.Fatalf("caller-owned PacketConn was closed: %v", err)
	}
}
