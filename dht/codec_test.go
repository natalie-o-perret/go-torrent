package dht

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
)

func testID(value byte) ID {
	var id ID
	id[IDLength-1] = value
	return id
}

func TestMessageCodecAndBounds(t *testing.T) {
	id := testID(1)
	target := testID(2)
	wantIP := netip.MustParseAddrPort("[2001:db8::1]:49001")
	packet, err := MarshalMessage(Message{
		Transaction: []byte{0, 7},
		Type:        QueryMessage,
		Query:       "find_node",
		Arguments: map[string]any{
			"id":     id[:],
			"target": target[:],
			"want":   []any{"n4", "n6"},
		},
		Version:  "GT01",
		IP:       wantIP,
		ReadOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) > MaxPacketSize {
		t.Fatalf("packet has %d bytes", len(packet))
	}
	message, err := UnmarshalMessage(packet)
	if err != nil {
		t.Fatal(err)
	}
	if message.Type != QueryMessage || message.Query != "find_node" || !message.ReadOnly || message.IP != wantIP || !bytes.Equal(message.Transaction, []byte{0, 7}) {
		t.Fatalf("unexpected round trip: %#v", message)
	}
	if got, err := idField(message.Arguments, "id"); err != nil || got != id {
		t.Fatalf("id = %v, %v", got, err)
	}

	errorPacket, err := MarshalMessage(Message{Transaction: []byte("aa"), Type: ErrorMessage, Error: &KRPCError{Code: 203, Message: "bad token"}})
	if err != nil {
		t.Fatal(err)
	}
	errorMessage, err := UnmarshalMessage(errorPacket)
	if err != nil || errorMessage.Error == nil || errorMessage.Error.Code != 203 {
		t.Fatalf("error round trip = %#v, %v", errorMessage, err)
	}
	if got := errorMessage.Error.Error(); got != "dht: KRPC error 203: bad token" {
		t.Fatalf("error text = %q", got)
	}
	if got := (*KRPCError)(nil).Error(); got != "<nil>" {
		t.Fatalf("nil error text = %q", got)
	}

	_, err = MarshalMessage(Message{
		Transaction: []byte("aa"),
		Type:        ResponseMessage,
		Response:    map[string]any{"id": id[:], "padding": bytes.Repeat([]byte{'x'}, MaxPacketSize)},
	})
	if err == nil {
		t.Fatal("oversized encoded packet was accepted")
	}
	if _, err := UnmarshalMessage(make([]byte, MaxPacketSize+1)); err == nil {
		t.Fatal("oversized input was accepted")
	}
	for _, malformed := range [][]byte{
		[]byte("not bencode"),
		[]byte("d1:t2:aa1:y1:qe"),
		[]byte("d1:t9:toolongid1:y1:re"),
		[]byte("d1:eli203e3:bade1:t2:aa1:y1:eejunk"),
	} {
		if _, err := UnmarshalMessage(malformed); err == nil {
			t.Fatalf("malformed packet %q was accepted", malformed)
		}
	}
}

func TestCompactIPv4IPv6AndHybridPeers(t *testing.T) {
	contacts4 := []Contact{{ID: testID(1), Addr: netip.MustParseAddrPort("192.0.2.1:6881")}}
	encoded4, err := EncodeCompactNodes(contacts4, IPv4)
	if err != nil {
		t.Fatal(err)
	}
	decoded4, err := DecodeCompactNodes(encoded4, IPv4, K)
	if err != nil || len(decoded4) != 1 || decoded4[0].ID != contacts4[0].ID || decoded4[0].Addr != contacts4[0].Addr {
		t.Fatalf("IPv4 nodes = %#v, %v", decoded4, err)
	}

	contacts6 := []Contact{{ID: testID(2), Addr: netip.MustParseAddrPort("[2001:db8::2]:6882")}}
	encoded6, err := EncodeCompactNodes(contacts6, IPv6)
	if err != nil {
		t.Fatal(err)
	}
	decoded6, err := DecodeCompactNodes(encoded6, IPv6, K)
	if err != nil || len(decoded6) != 1 || decoded6[0].Addr != contacts6[0].Addr {
		t.Fatalf("IPv6 nodes = %#v, %v", decoded6, err)
	}

	for _, peer := range []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.9:51413"),
		netip.MustParseAddrPort("[2001:db8::9]:51413"),
	} {
		compact, err := EncodeCompactPeer(peer)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeCompactPeer(compact)
		if err != nil || decoded != peer {
			t.Fatalf("peer round trip = %v, %v; want %v", decoded, err, peer)
		}
	}
	if _, err := DecodeCompactNodes(append(encoded4, 0), IPv4, K); err == nil {
		t.Fatal("misaligned compact nodes were accepted")
	}
	if _, err := EncodeCompactNodes(contacts6, IPv4); err == nil {
		t.Fatal("IPv6 contact encoded as IPv4")
	}
}

func TestLargestServerResponseFitsPacketLimit(t *testing.T) {
	nodes4 := make([]Contact, K)
	nodes6 := make([]Contact, K)
	values := make([]any, K)
	for index := range K {
		nodes4[index] = Contact{ID: testID(byte(index + 1)), Addr: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(20000+index))}
		nodes6[index] = Contact{ID: testID(byte(index + 21)), Addr: netip.AddrPortFrom(netip.MustParseAddr("2001:db8::1"), uint16(21000+index))}
		peer, err := EncodeCompactPeer(netip.AddrPortFrom(netip.MustParseAddr("2001:db8::2"), uint16(22000+index)))
		if err != nil {
			t.Fatal(err)
		}
		values[index] = peer
	}
	compact4, err := EncodeCompactNodes(nodes4, IPv4)
	if err != nil {
		t.Fatal(err)
	}
	compact6, err := EncodeCompactNodes(nodes6, IPv6)
	if err != nil {
		t.Fatal(err)
	}
	id := testID(100)
	packet, err := MarshalMessage(Message{
		Transaction: []byte("aa"),
		Type:        ResponseMessage,
		Response: map[string]any{
			"id":     id[:],
			"nodes":  compact4,
			"nodes6": compact6,
			"token":  bytes.Repeat([]byte{1}, tokenSize),
			"values": values,
		},
		IP: netip.MustParseAddrPort("[2001:db8::3]:23000"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) > MaxPacketSize {
		t.Fatalf("largest response has %d bytes", len(packet))
	}
}

func TestBEP42VectorsAndDistance(t *testing.T) {
	vectors := []struct {
		ip string
		id string
	}{
		{"124.31.75.21", "5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401"},
		{"21.75.31.124", "5a3ce9c14e7a08645677bbd1cfe7d8f956d53256"},
		{"65.23.51.170", "a5d43220bc8f112a3d426c84764f8c2a1150e616"},
		{"84.124.73.14", "1b0321dd1bb1fe518101ceef99462b947a01ff41"},
		{"43.213.53.83", "e56f6cbf5b7c4be0237986d5243b87aa6d51305a"},
	}
	for _, vector := range vectors {
		raw, err := hex.DecodeString(strings.TrimSpace(vector.id))
		if err != nil {
			t.Fatal(err)
		}
		id, err := IDFromBytes(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !ValidNodeID(id, netip.MustParseAddr(vector.ip)) {
			t.Errorf("official vector for %s failed", vector.ip)
		}
		id[0] ^= 0x80
		if ValidNodeID(id, netip.MustParseAddr(vector.ip)) {
			t.Errorf("corrupt vector for %s passed", vector.ip)
		}
	}

	generated, err := SecureNodeID(netip.MustParseAddr("2001:4860:4860::8888"), bytes.NewReader(bytes.Repeat([]byte{0x5a}, IDLength)))
	if err != nil || !ValidNodeID(generated, netip.MustParseAddr("2001:4860:4860::8888")) {
		t.Fatalf("generated IPv6 ID = %s, %v", generated, err)
	}
	if got := generated.Bytes(); len(got) != IDLength || !bytes.Equal(got, generated[:]) {
		t.Fatalf("ID bytes = %x", got)
	}
	if got := generated.String(); len(got) != 2*IDLength {
		t.Fatalf("ID string = %q", got)
	}
	a, b := testID(0x0f), testID(0xf0)
	if got := Distance(a, b); got[IDLength-1] != 0xff {
		t.Fatalf("distance = %x", got)
	}
}
