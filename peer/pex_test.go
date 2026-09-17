package peer_test

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"github.com/natalie-o-perret/go-torrent/peer"
)

func TestPEXIPv4IPv6RoundTrip(t *testing.T) {
	want := peer.PEXMessage{
		Added: []peer.PEXContact{
			{
				AddrPort: netip.MustParseAddrPort("192.0.2.1:51413"),
				Flags:    peer.PEXPrefersEncryption | peer.PEXSupportsUTP,
			},
			{
				AddrPort: netip.MustParseAddrPort("[2001:db8::1]:6881"),
				Flags:    peer.PEXSeed | peer.PEXOutgoing | 0x80,
			},
		},
		Dropped: []netip.AddrPort{
			netip.MustParseAddrPort("198.51.100.9:80"),
			netip.MustParseAddrPort("[2001:db8::9]:443"),
		},
		Unknown: map[string]any{"x_future": int64(7)},
	}
	payload, err := peer.EncodePEXMessage(want)
	if err != nil {
		t.Fatalf("EncodePEXMessage: %v", err)
	}
	got, err := peer.DecodePEX(payload)
	if err != nil {
		t.Fatalf("DecodePEX: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PEX = %#v, want %#v", got, want)
	}
}

func TestPEXOptionalFlagsDefaultToZero(t *testing.T) {
	compact := compactTestEndpoint(netip.MustParseAddrPort("192.0.2.3:6881"))
	payload := encodeBencode(t, map[string]any{"added": compact})
	message, err := peer.DecodePEX(payload)
	if err != nil {
		t.Fatalf("DecodePEX: %v", err)
	}
	if len(message.Added) != 1 || message.Added[0].Flags != 0 {
		t.Fatalf("added contacts = %#v", message.Added)
	}
}

func TestPEXRejectsMalformedContactsAndDuplicates(t *testing.T) {
	endpoint := netip.MustParseAddrPort("192.0.2.1:6881")
	duplicateIP := peer.PEXMessage{Added: []peer.PEXContact{
		{AddrPort: endpoint},
		{AddrPort: netip.MustParseAddrPort("192.0.2.1:6882")},
	}}
	if _, err := peer.EncodePEXMessage(duplicateIP); err == nil {
		t.Fatal("duplicate PEX IP accepted")
	}
	addedAndDropped := peer.PEXMessage{
		Added:   []peer.PEXContact{{AddrPort: endpoint}},
		Dropped: []netip.AddrPort{endpoint},
	}
	if _, err := peer.EncodePEXMessage(addedAndDropped); err == nil {
		t.Fatal("contact added and dropped in one PEX message")
	}

	tests := []map[string]any{
		{"added": "short"},
		{"added": ""},
		{"added.f": "\x01"},
		{"added": compactTestEndpoint(endpoint), "added.f": ""},
		{"x_only": int64(1)},
	}
	for i, dictionary := range tests {
		if _, err := peer.DecodePEX(encodeBencode(t, dictionary)); err == nil {
			t.Errorf("malformed PEX case %d accepted", i)
		}
	}

	duplicates := compactTestEndpoint(endpoint) + compactTestEndpoint(endpoint)
	if _, err := peer.DecodePEX(encodeBencode(t, map[string]any{"added": duplicates})); err == nil {
		t.Fatal("wire duplicate PEX contacts accepted")
	}
}

func TestPEXContactLimitsAreConfigurableForInitialMessage(t *testing.T) {
	message := peer.PEXMessage{Added: make([]peer.PEXContact, 51)}
	for i := range message.Added {
		message.Added[i].AddrPort = netip.MustParseAddrPort(fmt.Sprintf("10.0.0.%d:6881", i+1))
	}
	if _, err := peer.EncodePEXMessage(message); err == nil {
		t.Fatal("standard PEX limit accepted 51 contacts")
	}
	initialLimits := peer.PEXLimits{MaxAdded: 100, MaxDropped: 100}
	payload, err := message.Encode(initialLimits)
	if err != nil {
		t.Fatalf("initial PEX encode: %v", err)
	}
	if _, err := peer.DecodePEX(payload); err == nil {
		t.Fatal("standard PEX decoder accepted 51 contacts")
	}
	got, err := peer.DecodePEXMessage(payload, initialLimits)
	if err != nil || len(got.Added) != len(message.Added) {
		t.Fatalf("initial PEX decode = (%d contacts, %v)", len(got.Added), err)
	}
}

func compactTestEndpoint(endpoint netip.AddrPort) string {
	address := endpoint.Addr().Unmap()
	var result []byte
	if address.Is4() {
		bytes := address.As4()
		result = append(result, bytes[:]...)
	} else {
		bytes := address.As16()
		result = append(result, bytes[:]...)
	}
	result = binary.BigEndian.AppendUint16(result, endpoint.Port())
	return string(result)
}
