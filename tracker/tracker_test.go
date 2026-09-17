package tracker

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/natalie-o-perret/go-torrent/bencode"
	"github.com/natalie-o-perret/go-torrent/metainfo"
)

func validAnnounceRequest() AnnounceRequest {
	request := AnnounceRequest{Port: 6881, NumWant: -1, Left: 100}
	for i := range request.InfoHash {
		request.InfoHash[i] = byte(i)
		request.PeerID[i] = byte(255 - i)
	}
	return request
}

func bencoded(t *testing.T, value any) []byte {
	t.Helper()
	var buffer bytes.Buffer
	if err := bencode.Encode(&buffer, value); err != nil {
		t.Fatalf("encode bencode: %v", err)
	}
	return buffer.Bytes()
}

func TestHTTPAnnounceBinaryQueryAndCompactPeers(t *testing.T) {
	request := validAnnounceRequest()
	request.Event = EventStarted
	request.Uploaded = 11
	request.Downloaded = 22
	request.NumWant = 25
	request.Key = 0x01020304
	request.TrackerID = "tracker\x00 id&"
	ipv6 := net.ParseIP("2001:db8::5").To16()
	peers6 := append(append([]byte(nil), ipv6...), 0x1a, 0xe2)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if got := []byte(query.Get("info_hash")); !bytes.Equal(got, request.InfoHash[:]) {
			t.Errorf("info_hash = %x, want %x", got, request.InfoHash)
		}
		if got := []byte(query.Get("peer_id")); !bytes.Equal(got, request.PeerID[:]) {
			t.Errorf("peer_id = %x, want %x", got, request.PeerID)
		}
		if !strings.Contains(r.URL.RawQuery, "info_hash="+escapeBinary(request.InfoHash[:])) {
			t.Errorf("raw query does not contain exact escaped info hash: %s", r.URL.RawQuery)
		}
		if !strings.Contains(r.URL.RawQuery, "peer_id="+escapeBinary(request.PeerID[:])) {
			t.Errorf("raw query does not contain exact escaped peer ID: %s", r.URL.RawQuery)
		}
		for key, want := range map[string]string{
			"compact":    "1",
			"downloaded": "22",
			"event":      "started",
			"key":        "16909060",
			"left":       "100",
			"numwant":    "25",
			"port":       "6881",
			"trackerid":  request.TrackerID,
			"uploaded":   "11",
		} {
			if got := query.Get(key); got != want {
				t.Errorf("query %s = %q, want %q", key, got, want)
			}
		}
		_, _ = w.Write(bencoded(t, map[string]any{
			"complete":        int64(7),
			"incomplete":      int64(3),
			"interval":        int64(120),
			"min interval":    int64(180),
			"peers":           string([]byte{1, 2, 3, 4, 0x1a, 0xe1}),
			"peers6":          string(peers6),
			"tracker id":      "next-id",
			"warning message": "slow down",
		}))
	}))
	defer server.Close()

	response, err := NewClient(server.Client()).Announce(context.Background(), server.URL+"/announce?passkey=ok", request)
	if err != nil {
		t.Fatalf("Announce: %v", err)
	}
	if response.Key != request.Key || response.TrackerID != "next-id" {
		t.Fatalf("roundtrip fields = key %d tracker ID %q", response.Key, response.TrackerID)
	}
	if response.Interval != 120 || response.MinInterval != 180 || response.Complete != 7 || response.Incomplete != 3 {
		t.Fatalf("announce metadata = %+v", response)
	}
	if response.Warning != "slow down" || len(response.Peers) != 2 {
		t.Fatalf("announce response = %+v", response)
	}
	if !response.Peers[0].IP.Equal(net.IPv4(1, 2, 3, 4)) || response.Peers[0].Port != 6881 {
		t.Errorf("IPv4 peer = %+v", response.Peers[0])
	}
	if !response.Peers[1].IP.Equal(ipv6) || response.Peers[1].Port != 6882 {
		t.Errorf("IPv6 peer = %+v", response.Peers[1])
	}
}

func TestHTTPAnnounceNoncompactPeerPreservesHostAndID(t *testing.T) {
	peerID := "-GT0001-abcdefghijkl"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bencoded(t, map[string]any{
			"interval": int64(60),
			"peers": []any{
				map[string]any{"ip": "peer.example.test", "peer id": peerID, "port": int64(51413)},
			},
		}))
	}))
	defer server.Close()

	response, err := NewClient(server.Client()).Announce(context.Background(), server.URL+"/announce", validAnnounceRequest())
	if err != nil {
		t.Fatalf("Announce: %v", err)
	}
	if len(response.Peers) != 1 {
		t.Fatalf("len(Peers) = %d, want 1", len(response.Peers))
	}
	peer := response.Peers[0]
	if peer.Host != "peer.example.test" || peer.IP != nil || peer.String() != "peer.example.test:51413" {
		t.Errorf("peer endpoint = %+v (%s)", peer, peer.String())
	}
	if string(peer.PeerID[:]) != peerID {
		t.Errorf("peer ID = %q, want %q", peer.PeerID, peerID)
	}
}

func TestHTTPAnnounceRejectsMalformedAndUnboundedResponses(t *testing.T) {
	request := validAnnounceRequest()
	malformed := []struct {
		name string
		body []byte
	}{
		{"not dictionary", []byte("4:nope")},
		{"missing interval", bencoded(t, map[string]any{"peers": ""})},
		{"zero interval", bencoded(t, map[string]any{"interval": int64(0), "peers": ""})},
		{"missing peers", bencoded(t, map[string]any{"interval": int64(1)})},
		{"bad compact stride", bencoded(t, map[string]any{"interval": int64(1), "peers": "abcde"})},
		{"zero compact port", bencoded(t, map[string]any{"interval": int64(1), "peers": string([]byte{1, 2, 3, 4, 0, 0})})},
		{"bad peers6 stride", bencoded(t, map[string]any{"interval": int64(1), "peers": "", "peers6": "short"})},
		{"bad noncompact port", bencoded(t, map[string]any{"interval": int64(1), "peers": []any{map[string]any{"ip": "host", "peer id": strings.Repeat("x", 20), "port": int64(65536)}}})},
		{"missing noncompact peer ID", bencoded(t, map[string]any{"interval": int64(1), "peers": []any{map[string]any{"ip": "host", "port": int64(1)}}})},
	}
	for _, test := range malformed {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(test.body)
			}))
			defer server.Close()
			if _, err := NewClient(server.Client()).Announce(context.Background(), server.URL+"/announce", request); err == nil {
				t.Fatal("Announce returned nil error")
			}
		})
	}

	t.Run("status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "no", http.StatusServiceUnavailable)
		}))
		defer server.Close()
		_, err := NewClient(server.Client()).Announce(context.Background(), server.URL+"/announce", request)
		if err == nil || !strings.Contains(err.Error(), "503") {
			t.Fatalf("Announce error = %v, want HTTP 503", err)
		}
	})

	t.Run("chunked body limit", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, strings.Repeat("x", 128))
		}))
		defer server.Close()
		client := NewClient(server.Client())
		client.MaxResponseBody = 32
		_, err := client.Announce(context.Background(), server.URL+"/announce", request)
		if err == nil || !strings.Contains(err.Error(), "32-byte limit") {
			t.Fatalf("Announce error = %v, want body limit", err)
		}
	})
}

func TestAnnounceRequestValidation(t *testing.T) {
	valid := validAnnounceRequest()
	tests := []struct {
		name   string
		mutate func(*AnnounceRequest)
	}{
		{"event", func(request *AnnounceRequest) { request.Event = "paused" }},
		{"uploaded", func(request *AnnounceRequest) { request.Uploaded = -1 }},
		{"downloaded", func(request *AnnounceRequest) { request.Downloaded = -1 }},
		{"left", func(request *AnnounceRequest) { request.Left = -1 }},
		{"numwant", func(request *AnnounceRequest) { request.NumWant = -2 }},
		{"port", func(request *AnnounceRequest) { request.Port = 0 }},
		{"peer ID", func(request *AnnounceRequest) { request.PeerID = [20]byte{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.mutate(&request)
			if _, err := NewClient(nil).Announce(context.Background(), "http://tracker.invalid/announce", request); err == nil {
				t.Fatal("Announce returned nil error")
			}
		})
	}
}

func TestHTTPScrape(t *testing.T) {
	request := validAnnounceRequest()
	hash1 := request.InfoHash
	hash2 := hash1
	hash2[0]++
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/scrape.php" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		values := r.URL.Query()["info_hash"]
		if len(values) != 2 || !bytes.Equal([]byte(values[0]), hash1[:]) || !bytes.Equal([]byte(values[1]), hash2[:]) {
			http.Error(w, "wrong hashes", http.StatusBadRequest)
			return
		}
		_, _ = w.Write(bencoded(t, map[string]any{
			"files": map[string]any{
				string(hash1[:]): map[string]any{"complete": int64(1), "downloaded": int64(2), "incomplete": int64(3)},
				string(hash2[:]): map[string]any{"complete": int64(4), "downloaded": int64(5), "incomplete": int64(6)},
			},
		}))
	}))
	defer server.Close()

	response, err := NewClient(server.Client()).Scrape(context.Background(), server.URL+"/announce.php?passkey=x", []metainfo.Hash{hash1, hash2})
	if err != nil {
		t.Fatalf("Scrape: %v", err)
	}
	if got := response.Files[hash1]; got != (ScrapeStats{Complete: 1, Downloaded: 2, Incomplete: 3}) {
		t.Errorf("hash1 stats = %+v", got)
	}
	if got := response.Files[hash2]; got != (ScrapeStats{Complete: 4, Downloaded: 5, Incomplete: 6}) {
		t.Errorf("hash2 stats = %+v", got)
	}
}

func TestUDPAnnounce(t *testing.T) {
	request := validAnnounceRequest()
	request.Event = EventStarted
	request.Downloaded = 12
	request.Uploaded = 34
	request.NumWant = 8
	const connectionID = uint64(0x1020304050607080)
	var observedKey atomic.Uint32

	trackerURL, done := startUDPFake(t, "udp4", net.IPv4(127, 0, 0, 1), func(conn *net.UDPConn) error {
		packet, address, err := readUDP(conn)
		if err != nil {
			return err
		}
		if err := replyUDPConnect(conn, address, packet, connectionID); err != nil {
			return err
		}
		packet, address, err = readUDP(conn)
		if err != nil {
			return err
		}
		if len(packet) != 98 || binary.BigEndian.Uint64(packet[:8]) != connectionID || binary.BigEndian.Uint32(packet[8:12]) != udpActionAnnounce {
			return fmt.Errorf("invalid announce packet: %x", packet)
		}
		if !bytes.Equal(packet[16:36], request.InfoHash[:]) || !bytes.Equal(packet[36:56], request.PeerID[:]) {
			return fmt.Errorf("announce hash or peer ID mismatch")
		}
		if binary.BigEndian.Uint64(packet[56:64]) != 12 || binary.BigEndian.Uint64(packet[64:72]) != 100 || binary.BigEndian.Uint64(packet[72:80]) != 34 {
			return fmt.Errorf("announce counters mismatch")
		}
		if binary.BigEndian.Uint32(packet[80:84]) != 2 || int32(binary.BigEndian.Uint32(packet[92:96])) != 8 || binary.BigEndian.Uint16(packet[96:98]) != 6881 {
			return fmt.Errorf("announce fields mismatch")
		}
		observedKey.Store(binary.BigEndian.Uint32(packet[88:92]))
		response := make([]byte, 26)
		binary.BigEndian.PutUint32(response[0:4], udpActionAnnounce)
		copy(response[4:8], packet[12:16])
		binary.BigEndian.PutUint32(response[8:12], 90)
		binary.BigEndian.PutUint32(response[12:16], 2)
		binary.BigEndian.PutUint32(response[16:20], 5)
		copy(response[20:24], net.IPv4(9, 8, 7, 6).To4())
		binary.BigEndian.PutUint16(response[24:26], 51413)
		_, err = conn.WriteToUDP(response, address)
		return err
	})

	client := NewClient(nil)
	client.UDPInitialTimeout = 100 * time.Millisecond
	client.UDPMaxRetries = 1
	response, err := client.Announce(context.Background(), trackerURL, request)
	if err != nil {
		t.Fatalf("Announce: %v", err)
	}
	waitUDPFake(t, done)
	if observedKey.Load() == 0 || response.Key != observedKey.Load() {
		t.Errorf("random key packet=%d response=%d", observedKey.Load(), response.Key)
	}
	if response.Interval != 90 || response.Complete != 5 || response.Incomplete != 2 || len(response.Peers) != 1 {
		t.Fatalf("UDP response = %+v", response)
	}
	if !response.Peers[0].IP.Equal(net.IPv4(9, 8, 7, 6)) || response.Peers[0].Port != 51413 {
		t.Errorf("UDP peer = %+v", response.Peers[0])
	}
}

func TestUDPScrape(t *testing.T) {
	request := validAnnounceRequest()
	hash1 := request.InfoHash
	hash2 := hash1
	hash2[19]++
	trackerURL, done := startUDPFake(t, "udp4", net.IPv4(127, 0, 0, 1), func(conn *net.UDPConn) error {
		packet, address, err := readUDP(conn)
		if err != nil {
			return err
		}
		if err := replyUDPConnect(conn, address, packet, 7); err != nil {
			return err
		}
		packet, address, err = readUDP(conn)
		if err != nil {
			return err
		}
		if len(packet) != 56 || binary.BigEndian.Uint32(packet[8:12]) != udpActionScrape || !bytes.Equal(packet[16:36], hash1[:]) || !bytes.Equal(packet[36:56], hash2[:]) {
			return fmt.Errorf("invalid scrape packet: %x", packet)
		}
		response := make([]byte, 32)
		binary.BigEndian.PutUint32(response[0:4], udpActionScrape)
		copy(response[4:8], packet[12:16])
		for i, value := range []uint32{1, 2, 3, 4, 5, 6} {
			binary.BigEndian.PutUint32(response[8+i*4:12+i*4], value)
		}
		_, err = conn.WriteToUDP(response, address)
		return err
	})
	client := NewClient(nil)
	client.UDPInitialTimeout = 100 * time.Millisecond
	client.UDPMaxRetries = 1
	response, err := client.Scrape(context.Background(), trackerURL, []metainfo.Hash{hash1, hash2})
	if err != nil {
		t.Fatalf("Scrape: %v", err)
	}
	waitUDPFake(t, done)
	if response.Files[hash1] != (ScrapeStats{Complete: 1, Downloaded: 2, Incomplete: 3}) || response.Files[hash2] != (ScrapeStats{Complete: 4, Downloaded: 5, Incomplete: 6}) {
		t.Errorf("UDP scrape = %+v", response.Files)
	}
}

func TestUDPTransactionMismatchAndError(t *testing.T) {
	request := validAnnounceRequest()
	t.Run("short packet", func(t *testing.T) {
		trackerURL, done := startUDPFake(t, "udp4", net.IPv4(127, 0, 0, 1), func(conn *net.UDPConn) error {
			_, address, err := readUDP(conn)
			if err != nil {
				return err
			}
			_, err = conn.WriteToUDP([]byte{0, 0, 0, 0}, address)
			return err
		})
		client := NewClient(nil)
		client.UDPInitialTimeout = 100 * time.Millisecond
		client.UDPMaxRetries = 1
		_, err := client.Announce(context.Background(), trackerURL, request)
		waitUDPFake(t, done)
		if err == nil || !strings.Contains(err.Error(), "want at least 8") {
			t.Fatalf("Announce error = %v", err)
		}
	})

	t.Run("transaction mismatch", func(t *testing.T) {
		trackerURL, done := startUDPFake(t, "udp4", net.IPv4(127, 0, 0, 1), func(conn *net.UDPConn) error {
			packet, address, err := readUDP(conn)
			if err != nil {
				return err
			}
			response := make([]byte, 16)
			binary.BigEndian.PutUint32(response[0:4], udpActionConnect)
			binary.BigEndian.PutUint32(response[4:8], binary.BigEndian.Uint32(packet[12:16])+1)
			_, err = conn.WriteToUDP(response, address)
			return err
		})
		client := NewClient(nil)
		client.UDPInitialTimeout = 100 * time.Millisecond
		client.UDPMaxRetries = 1
		_, err := client.Announce(context.Background(), trackerURL, request)
		waitUDPFake(t, done)
		if err == nil || !strings.Contains(err.Error(), "transaction ID mismatch") {
			t.Fatalf("Announce error = %v", err)
		}
	})

	t.Run("tracker error", func(t *testing.T) {
		trackerURL, done := startUDPFake(t, "udp4", net.IPv4(127, 0, 0, 1), func(conn *net.UDPConn) error {
			packet, address, err := readUDP(conn)
			if err != nil {
				return err
			}
			if err := replyUDPConnect(conn, address, packet, 8); err != nil {
				return err
			}
			packet, address, err = readUDP(conn)
			if err != nil {
				return err
			}
			response := make([]byte, 8+len("denied"))
			binary.BigEndian.PutUint32(response[0:4], udpActionError)
			copy(response[4:8], packet[12:16])
			copy(response[8:], "denied")
			_, err = conn.WriteToUDP(response, address)
			return err
		})
		client := NewClient(nil)
		client.UDPInitialTimeout = 100 * time.Millisecond
		client.UDPMaxRetries = 1
		_, err := client.Announce(context.Background(), trackerURL, request)
		waitUDPFake(t, done)
		if err == nil || !strings.Contains(err.Error(), "UDP error: denied") {
			t.Fatalf("Announce error = %v", err)
		}
	})
}

func TestUDPTimeoutRetryAndContext(t *testing.T) {
	request := validAnnounceRequest()
	trackerURL, done := startUDPFake(t, "udp4", net.IPv4(127, 0, 0, 1), func(conn *net.UDPConn) error {
		first, _, err := readUDP(conn)
		if err != nil {
			return err
		}
		second, address, err := readUDP(conn)
		if err != nil {
			return err
		}
		if !bytes.Equal(first, second) {
			return fmt.Errorf("retransmission changed packet")
		}
		if err := replyUDPConnect(conn, address, second, 9); err != nil {
			return err
		}
		packet, address, err := readUDP(conn)
		if err != nil {
			return err
		}
		response := make([]byte, 20)
		binary.BigEndian.PutUint32(response[0:4], udpActionAnnounce)
		copy(response[4:8], packet[12:16])
		binary.BigEndian.PutUint32(response[8:12], 30)
		_, err = conn.WriteToUDP(response, address)
		return err
	})
	client := NewClient(nil)
	client.UDPInitialTimeout = 10 * time.Millisecond
	client.UDPMaxRetries = 1
	if _, err := client.Announce(context.Background(), trackerURL, request); err != nil {
		t.Fatalf("Announce after retry: %v", err)
	}
	waitUDPFake(t, done)

	t.Run("context cancellation interrupts read", func(t *testing.T) {
		trackerURL, done := startUDPFake(t, "udp4", net.IPv4(127, 0, 0, 1), func(conn *net.UDPConn) error {
			_, _, err := readUDP(conn)
			return err
		})
		client := NewClient(nil)
		client.UDPInitialTimeout = time.Second
		client.UDPMaxRetries = 1
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err := client.Announce(ctx, trackerURL, request)
		waitUDPFake(t, done)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Announce error = %v, want context deadline", err)
		}
	})
}

func TestUDPIPv6PeerStride(t *testing.T) {
	request := validAnnounceRequest()
	peerIP := net.ParseIP("2001:db8::9").To16()
	trackerURL, done := startUDPFake(t, "udp6", net.ParseIP("::1"), func(conn *net.UDPConn) error {
		packet, address, err := readUDP(conn)
		if err != nil {
			return err
		}
		if err := replyUDPConnect(conn, address, packet, 10); err != nil {
			return err
		}
		packet, address, err = readUDP(conn)
		if err != nil {
			return err
		}
		response := make([]byte, 38)
		binary.BigEndian.PutUint32(response[0:4], udpActionAnnounce)
		copy(response[4:8], packet[12:16])
		binary.BigEndian.PutUint32(response[8:12], 30)
		copy(response[20:36], peerIP)
		binary.BigEndian.PutUint16(response[36:38], 6889)
		_, err = conn.WriteToUDP(response, address)
		return err
	})
	client := NewClient(nil)
	client.UDPInitialTimeout = 100 * time.Millisecond
	client.UDPMaxRetries = 1
	response, err := client.Announce(context.Background(), trackerURL, request)
	if err != nil {
		t.Fatalf("Announce: %v", err)
	}
	waitUDPFake(t, done)
	if len(response.Peers) != 1 || !response.Peers[0].IP.Equal(peerIP) || response.Peers[0].Port != 6889 {
		t.Fatalf("IPv6 peers = %+v", response.Peers)
	}
}

type sessionRequest struct {
	event     string
	key       string
	trackerID string
}

type sessionTracker struct {
	mu       sync.Mutex
	fail     bool
	id       string
	requests []sessionRequest
}

func (tracker *sessionTracker) handler(w http.ResponseWriter, r *http.Request) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if tracker.fail {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	tracker.requests = append(tracker.requests, sessionRequest{
		event:     r.URL.Query().Get("event"),
		key:       r.URL.Query().Get("key"),
		trackerID: r.URL.Query().Get("trackerid"),
	})
	_ = bencode.Encode(w, map[string]any{
		"interval":     int64(2),
		"min interval": int64(5),
		"peers":        "",
		"tracker id":   tracker.id,
	})
}

func (tracker *sessionTracker) setFail(fail bool) {
	tracker.mu.Lock()
	tracker.fail = fail
	tracker.mu.Unlock()
}

func (tracker *sessionTracker) seen() []sessionRequest {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return append([]sessionRequest(nil), tracker.requests...)
}

func TestSessionLifecycleTierPromotionAndSwitch(t *testing.T) {
	firstState := &sessionTracker{id: "first-id"}
	firstServer := httptest.NewServer(http.HandlerFunc(firstState.handler))
	defer firstServer.Close()
	secondState := &sessionTracker{id: "second-id"}
	secondServer := httptest.NewServer(http.HandlerFunc(secondState.handler))
	defer secondServer.Close()

	session, err := NewSession(NewClient(firstServer.Client()), "http://127.0.0.1:1/ignored", [][]string{
		{firstServer.URL + "/announce", secondServer.URL + "/announce"},
		{"http://127.0.0.1:1/backup"},
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	initialTiers := session.Tiers()
	if len(initialTiers) != 2 || len(initialTiers[0]) != 2 || len(initialTiers[1]) != 1 {
		t.Fatalf("tiers = %#v", initialTiers)
	}

	states := map[string]*sessionTracker{
		firstServer.URL + "/announce":  firstState,
		secondServer.URL + "/announce": secondState,
	}
	initialFirst := initialTiers[0][0]
	winner := initialTiers[0][1]
	states[initialFirst].setFail(true)
	states[winner].setFail(false)
	request := validAnnounceRequest()
	beforeStart := time.Now()
	started, err := session.Start(context.Background(), request)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if started.Tracker != winner || started.Switched || session.CurrentTracker() != winner {
		t.Fatalf("started result = %+v", started)
	}
	if got := session.Tiers()[0][0]; got != winner {
		t.Errorf("successful tracker was not promoted: %s", got)
	}
	if delay := started.NextAnnounce.Sub(beforeStart); delay < 4*time.Second || delay > 6*time.Second {
		t.Errorf("next announce delay = %s, want about 5s", delay)
	}
	if session.Due(time.Now().Add(4*time.Second)) || !session.Due(time.Now().Add(6*time.Second)) {
		t.Errorf("Due does not honour min interval")
	}
	if _, err := session.Announce(context.Background(), request); !errors.Is(err, ErrNotDue) {
		t.Fatalf("early Announce error = %v, want ErrNotDue", err)
	}

	session.next = time.Now().Add(-time.Second)
	changedIdentity := request
	changedIdentity.InfoHash[0]++
	if _, err := session.Announce(context.Background(), changedIdentity); err == nil {
		t.Fatal("Announce with changed info hash returned nil error")
	}
	regular, err := session.Announce(context.Background(), request)
	if err != nil {
		t.Fatalf("regular Announce: %v", err)
	}
	if regular.Tracker != winner || regular.Switched {
		t.Fatalf("regular result = %+v", regular)
	}

	states[winner].setFail(true)
	states[initialFirst].setFail(false)
	session.next = time.Now().Add(-time.Second)
	switched, err := session.Announce(context.Background(), request)
	if err != nil {
		t.Fatalf("switch Announce: %v", err)
	}
	if !switched.Switched || switched.PreviousTracker != winner || switched.Tracker != initialFirst {
		t.Fatalf("switch result = %+v", switched)
	}
	if got := session.Tiers()[0][0]; got != initialFirst {
		t.Errorf("replacement tracker was not promoted: %s", got)
	}

	request.Left = 0
	if _, err := session.Complete(context.Background(), request); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if _, err := session.Complete(context.Background(), request); err == nil {
		t.Fatal("second Complete returned nil error")
	}
	if _, err := session.Stop(context.Background(), request); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !session.NextAnnounce().IsZero() || session.Due(time.Now().Add(time.Hour)) {
		t.Errorf("stopped session remains scheduled")
	}
	if _, err := session.Announce(context.Background(), request); err == nil {
		t.Fatal("Announce after Stop returned nil error")
	}

	winnerRequests := states[winner].seen()
	if len(winnerRequests) != 2 || winnerRequests[0].event != "started" || winnerRequests[1].event != "" {
		t.Fatalf("winner requests = %+v", winnerRequests)
	}
	if winnerRequests[0].trackerID != "" || winnerRequests[1].trackerID != states[winner].id {
		t.Errorf("winner tracker ID roundtrip = %+v", winnerRequests)
	}
	replacementRequests := states[initialFirst].seen()
	if len(replacementRequests) != 3 || replacementRequests[0].event != "" || replacementRequests[1].event != "completed" || replacementRequests[2].event != "stopped" {
		t.Fatalf("replacement requests = %+v", replacementRequests)
	}
	if replacementRequests[0].trackerID != "" || replacementRequests[1].trackerID != states[initialFirst].id || replacementRequests[2].trackerID != states[initialFirst].id {
		t.Errorf("replacement tracker ID roundtrip = %+v", replacementRequests)
	}
	key := winnerRequests[0].key
	if key == "" || winnerRequests[1].key != key || replacementRequests[0].key != key || replacementRequests[1].key != key || replacementRequests[2].key != key {
		t.Errorf("session key was not stable: winner=%+v replacement=%+v", winnerRequests, replacementRequests)
	}
}

func startUDPFake(t *testing.T, network string, ip net.IP, handler func(*net.UDPConn) error) (string, <-chan error) {
	t.Helper()
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil {
		if network == "udp6" {
			t.Skipf("IPv6 loopback unavailable: %v", err)
		}
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	done := make(chan error, 1)
	go func() {
		done <- handler(conn)
	}()
	return "udp://" + conn.LocalAddr().String() + "/announce", done
}

func readUDP(conn *net.UDPConn) ([]byte, *net.UDPAddr, error) {
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, nil, err
	}
	buffer := make([]byte, 2048)
	n, address, err := conn.ReadFromUDP(buffer)
	return append([]byte(nil), buffer[:n]...), address, err
}

func replyUDPConnect(conn *net.UDPConn, address *net.UDPAddr, request []byte, connectionID uint64) error {
	if len(request) != 16 || binary.BigEndian.Uint64(request[0:8]) != udpProtocolID || binary.BigEndian.Uint32(request[8:12]) != udpActionConnect {
		return fmt.Errorf("invalid connect request: %x", request)
	}
	response := make([]byte, 16)
	binary.BigEndian.PutUint32(response[0:4], udpActionConnect)
	copy(response[4:8], request[12:16])
	binary.BigEndian.PutUint64(response[8:16], connectionID)
	_, err := conn.WriteToUDP(response, address)
	return err
}

func waitUDPFake(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("UDP fake: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("UDP fake did not finish")
	}
}
