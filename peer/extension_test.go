package peer_test

import (
	"bytes"
	"net/netip"
	"reflect"
	"testing"

	"github.com/natalie-o-perret/go-torrent/bencode"
	"github.com/natalie-o-perret/go-torrent/peer"
)

func TestExtensionHandshakeRoundTripAndUnknownFields(t *testing.T) {
	port := uint16(6881)
	queue := uint32(250)
	metadataSize := uint32(12345)
	want := peer.ExtensionHandshake{
		Extensions: map[string]uint8{
			peer.ExtensionMetadata: 3,
			peer.ExtensionPEX:      7,
		},
		Port:         &port,
		Client:       "go-torrent test",
		YourIP:       netip.MustParseAddr("203.0.113.4"),
		IPv4:         netip.MustParseAddr("192.0.2.2"),
		IPv6:         netip.MustParseAddr("2001:db8::2"),
		RequestQueue: &queue,
		MetadataSize: &metadataSize,
		Unknown: map[string]any{
			"x_blob": "opaque",
			"x_list": []any{int64(1), "two"},
		},
	}
	payload, err := want.Encode()
	if err != nil {
		t.Fatalf("ExtensionHandshake.Encode: %v", err)
	}
	got, err := peer.DecodeExtensionHandshake(payload)
	if err != nil {
		t.Fatalf("DecodeExtensionHandshake: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("extension handshake = %#v, want %#v", got, want)
	}

	envelope, err := peer.FormatExtended(peer.ExtendedHandshakeID, payload)
	if err != nil {
		t.Fatalf("FormatExtended: %v", err)
	}
	extended, err := peer.ParseExtended(envelope)
	if err != nil {
		t.Fatalf("ParseExtended: %v", err)
	}
	if extended.ID != 0 || !bytes.Equal(extended.Payload, payload) {
		t.Fatalf("extended envelope = %#v", extended)
	}
}

func TestExtensionHandshakeRejectsMalformedKnownShapes(t *testing.T) {
	tests := map[string]map[string]any{
		"m not dictionary": {"m": "bad"},
		"duplicate IDs": {
			"m": map[string]any{"a_ext": int64(1), "b_ext": int64(1)},
		},
		"negative ID": {
			"m": map[string]any{"a_ext": int64(-1)},
		},
		"large ID": {
			"m": map[string]any{"a_ext": int64(256)},
		},
		"bad port": {"p": int64(0)},
		"bad ipv4": {"ipv4": "abc"},
		"bad ipv6": {"ipv6": string(make([]byte, 4))},
		"bad reqq": {"reqq": "many"},
	}
	for name, dictionary := range tests {
		t.Run(name, func(t *testing.T) {
			payload := encodeBencode(t, dictionary)
			if _, err := peer.DecodeExtensionHandshake(payload); err == nil {
				t.Fatal("malformed extension handshake accepted")
			}
		})
	}
	if _, err := peer.DecodeExtensionHandshake([]byte("degarbage")); err == nil {
		t.Fatal("extension handshake with trailing data accepted")
	}
	if _, err := peer.ParseExtended([]byte{0}); err == nil {
		t.Fatal("empty extension handshake envelope accepted")
	}
	if got, err := peer.ParseExtended([]byte{99}); err != nil || got.ID != 99 {
		t.Fatalf("unknown extension envelope = (%#v, %v)", got, err)
	}
}

func TestExtensionMapsApplyRepeatedUpdatesByDirection(t *testing.T) {
	var maps peer.ExtensionMaps
	initial := peer.ExtensionHandshake{Extensions: map[string]uint8{
		peer.ExtensionMetadata: 1,
		peer.ExtensionPEX:      2,
	}}
	if err := maps.ApplyRemote(initial); err != nil {
		t.Fatalf("ApplyRemote initial: %v", err)
	}
	update := peer.ExtensionHandshake{Extensions: map[string]uint8{
		peer.ExtensionMetadata: 3,
		peer.ExtensionPEX:      0,
		"x_new":                2,
	}}
	if err := maps.ApplyRemote(update); err != nil {
		t.Fatalf("ApplyRemote update: %v", err)
	}
	if id, ok := maps.Outgoing.ID(peer.ExtensionMetadata); !ok || id != 3 {
		t.Fatalf("outgoing metadata ID = (%d, %v), want 3", id, ok)
	}
	if _, ok := maps.Outgoing.ID(peer.ExtensionPEX); ok {
		t.Fatal("disabled outgoing PEX ID remains present")
	}
	if name, ok := maps.Outgoing.Name(2); !ok || name != "x_new" {
		t.Fatalf("outgoing ID 2 = (%q, %v)", name, ok)
	}

	before := maps.Outgoing.Snapshot()
	if err := maps.ApplyRemote(peer.ExtensionHandshake{Extensions: map[string]uint8{"collision": 3}}); err == nil {
		t.Fatal("colliding repeated update succeeded")
	}
	if !reflect.DeepEqual(maps.Outgoing.Snapshot(), before) {
		t.Fatal("failed update changed the outgoing map")
	}
	if err := maps.ApplyLocal(peer.ExtensionHandshake{Extensions: map[string]uint8{peer.ExtensionMetadata: 9}}); err != nil {
		t.Fatalf("ApplyLocal: %v", err)
	}
	if id, ok := maps.Incoming.ID(peer.ExtensionMetadata); !ok || id != 9 {
		t.Fatalf("incoming metadata ID = (%d, %v), want 9", id, ok)
	}
	if id, _ := maps.Outgoing.ID(peer.ExtensionMetadata); id != 3 {
		t.Fatalf("local update changed outgoing ID to %d", id)
	}
}

func encodeBencode(t *testing.T, value any) []byte {
	t.Helper()
	var buffer bytes.Buffer
	if err := bencode.Encode(&buffer, value); err != nil {
		t.Fatalf("bencode.Encode: %v", err)
	}
	return buffer.Bytes()
}
