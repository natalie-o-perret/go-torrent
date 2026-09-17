package magnet_test

import (
	"encoding/hex"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/natalie-o-perret/go-torrent/magnet"
	"github.com/natalie-o-perret/go-torrent/metainfo"
)

const (
	emptySHA1   = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

func TestParseCommonHashVectors(t *testing.T) {
	hybrid := "magnet:?xt=urn:btih:" + emptySHA1 + "&xt=urn:btmh:1220" + emptySHA256
	parsed, err := magnet.Parse(hybrid)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Hashes.V1 == nil || parsed.Hashes.V1.String() != emptySHA1 {
		t.Fatalf("v1 hash = %v, want %s", parsed.Hashes.V1, emptySHA1)
	}
	if parsed.Hashes.V2 == nil || parsed.Hashes.V2.String() != emptySHA256 {
		t.Fatalf("v2 hash = %v, want %s", parsed.Hashes.V2, emptySHA256)
	}

	for _, base32Hash := range []string{
		"3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ",
		"3i42h3s6nnfq2msvx7xzkyayscx5qbyj",
	} {
		got, err := magnet.Parse("magnet:?xt=urn:btih:" + base32Hash)
		if err != nil {
			t.Fatalf("Parse(base32 %q): %v", base32Hash, err)
		}
		if got.Hashes.V1 == nil || got.Hashes.V1.String() != emptySHA1 {
			t.Errorf("base32 %q decoded to %v, want %s", base32Hash, got.Hashes.V1, emptySHA1)
		}
	}

	duplicate, err := magnet.Parse("magnet:?xt=URN:BTIH:" + strings.ToUpper(emptySHA1) + "&xt=urn:btih:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ")
	if err != nil {
		t.Fatalf("equal duplicate hashes: %v", err)
	}
	if duplicate.Hashes.V1 == nil || duplicate.Hashes.V1.String() != emptySHA1 {
		t.Fatalf("duplicate v1 hash = %v", duplicate.Hashes.V1)
	}

	formatted, err := magnet.Format(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if formatted != hybrid {
		t.Errorf("Format() = %q, want %q", formatted, hybrid)
	}
	roundTrip, err := magnet.Parse(formatted)
	if err != nil {
		t.Fatalf("Parse(Format()): %v", err)
	}
	if !reflect.DeepEqual(roundTrip.Hashes, parsed.Hashes) {
		t.Errorf("round-trip hashes = %#v, want %#v", roundTrip.Hashes, parsed.Hashes)
	}
}

func TestParseFieldsAndRoundTrip(t *testing.T) {
	trackers := []string{
		"https://tracker.example/announce?pass=one&mode=fast",
		"udp://tracker.example:6969/announce",
	}
	peers := []string{"seed.example:6881", "192.0.2.1:51413", "[2001:db8::1]:443"}
	raw := "MAGNET:?xt=urn:btih:" + emptySHA1 +
		"&dn=Example+File" +
		"&tr=" + url.QueryEscape(trackers[0]) +
		"&x.pe=" + url.QueryEscape(peers[0]) +
		"&x.foo=first" +
		"&tr=" + url.QueryEscape(trackers[1]) +
		"&x.pe=" + url.QueryEscape(peers[1]) +
		"&x.pe=" + url.QueryEscape(peers[2]) +
		"&xl=123&x.foo=second"

	parsed, err := magnet.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.DisplayName != "Example File" {
		t.Errorf("DisplayName = %q", parsed.DisplayName)
	}
	if !reflect.DeepEqual(parsed.Trackers, trackers) {
		t.Errorf("Trackers = %#v, want %#v", parsed.Trackers, trackers)
	}
	wantPeers := []magnet.Peer{
		{Host: "seed.example", Port: 6881},
		{Host: "192.0.2.1", Port: 51413},
		{Host: "2001:db8::1", Port: 443},
	}
	if !reflect.DeepEqual(parsed.Peers, wantPeers) {
		t.Errorf("Peers = %#v, want %#v", parsed.Peers, wantPeers)
	}
	if got := []string{parsed.Peers[0].String(), parsed.Peers[1].String(), parsed.Peers[2].String()}; !reflect.DeepEqual(got, peers) {
		t.Errorf("peer strings = %#v, want %#v", got, peers)
	}
	wantUnknown := url.Values{"x.foo": {"first", "second"}, "xl": {"123"}}
	if !reflect.DeepEqual(parsed.Unknown, wantUnknown) {
		t.Errorf("Unknown = %#v, want %#v", parsed.Unknown, wantUnknown)
	}

	formatted, err := magnet.Format(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(formatted, "&x.pe=[2001:db8::1]:443") {
		t.Errorf("Format() did not use the BEP 9 IPv6 endpoint form: %q", formatted)
	}
	roundTrip, err := magnet.Parse(formatted)
	if err != nil {
		t.Fatalf("Parse(Format()): %v", err)
	}
	if !reflect.DeepEqual(roundTrip, parsed) {
		t.Errorf("round trip = %#v, want %#v", roundTrip, parsed)
	}
}

func TestFormatDoesNotDuplicateKnownFieldsFromUnknown(t *testing.T) {
	v1 := decodeV1(t, emptySHA1)
	uri := magnet.URI{
		Hashes:      metainfo.Hashes{V1: &v1},
		DisplayName: "right name",
		Trackers:    []string{"https://tracker.example/announce"},
		Peers:       []magnet.Peer{{Host: "peer.example", Port: 80}},
		Unknown: url.Values{
			"dn":   {"wrong name"},
			"tr":   {"https://wrong.example/announce"},
			"x.pe": {"wrong.example:1"},
			"xt":   {"urn:btih:" + strings.Repeat("0", 40)},
			"xl":   {"42"},
		},
	}
	formatted, err := magnet.Format(uri)
	if err != nil {
		t.Fatal(err)
	}
	parsedURL, err := url.Parse(formatted)
	if err != nil {
		t.Fatal(err)
	}
	query, err := url.ParseQuery(parsedURL.RawQuery)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"xt", "dn", "tr", "x.pe"} {
		if len(query[key]) != 1 {
			t.Errorf("%s has %d values, want 1: %q", key, len(query[key]), query[key])
		}
	}
	if query.Get("dn") != "right name" || query.Get("xl") != "42" {
		t.Errorf("query = %#v", query)
	}
}

func TestParseRejectsMalformedURI(t *testing.T) {
	valid := "magnet:?xt=urn:btih:" + emptySHA1
	zerosV2 := strings.Repeat("0", 64)
	tests := map[string]string{
		"empty":                "",
		"wrong scheme":         "https:?xt=urn:btih:" + emptySHA1,
		"opaque path":          "magnet:file?xt=urn:btih:" + emptySHA1,
		"authority":            "magnet://host?xt=urn:btih:" + emptySHA1,
		"fragment":             valid + "#section",
		"empty fragment":       valid + "#",
		"missing xt":           "magnet:?dn=file",
		"empty xt":             "magnet:?xt=",
		"unsupported xt":       "magnet:?xt=urn:sha1:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ",
		"bad query escape":     valid + "&dn=%zz",
		"semicolon separator":  valid + ";dn=file",
		"short btih":           "magnet:?xt=urn:btih:abcd",
		"invalid hex btih":     "magnet:?xt=urn:btih:" + strings.Repeat("g", 40),
		"invalid base32 btih":  "magnet:?xt=urn:btih:" + strings.Repeat("0", 32),
		"padded base32 btih":   "magnet:?xt=urn:btih:3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ%3D",
		"short btmh":           "magnet:?xt=urn:btmh:" + zerosV2,
		"wrong btmh tag":       "magnet:?xt=urn:btmh:1120" + zerosV2,
		"invalid btmh hex":     "magnet:?xt=urn:btmh:1220" + strings.Repeat("z", 64),
		"conflicting btih":     valid + "&xt=urn:btih:" + strings.Repeat("0", 40),
		"conflicting btmh":     "magnet:?xt=urn:btmh:1220" + emptySHA256 + "&xt=urn:btmh:1220" + zerosV2,
		"conflicting name":     valid + "&dn=one&dn=two",
		"invalid display name": valid + "&dn=%ff",
		"empty tracker":        valid + "&tr=",
		"relative tracker":     valid + "&tr=tracker.example%2Fannounce",
		"tracker fragment":     valid + "&tr=https%3A%2F%2Ftracker.example%2Fa%23fragment",
		"peer missing port":    valid + "&x.pe=peer.example",
		"peer empty host":      valid + "&x.pe=%3A80",
		"peer port zero":       valid + "&x.pe=peer.example%3A0",
		"peer port high":       valid + "&x.pe=peer.example%3A65536",
		"peer service port":    valid + "&x.pe=peer.example%3Ahttp",
		"unbracketed IPv6":     valid + "&x.pe=2001%3Adb8%3A%3A1%3A80",
		"bracketed DNS":        valid + "&x.pe=%5Bpeer.example%5D%3A80",
		"bracketed IPv4":       valid + "&x.pe=%5B192.0.2.1%5D%3A80",
		"malformed IPv4":       valid + "&x.pe=192.0.2.999%3A80",
		"invalid DNS label":    valid + "&x.pe=bad_host%3A80",
		"empty DNS label":      valid + "&x.pe=bad..example%3A80",
		"scoped IPv6":          valid + "&x.pe=%5Bfe80%3A%3A1%25eth0%5D%3A80",
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if got, err := magnet.Parse(raw); err == nil {
				t.Fatalf("Parse(%q) succeeded: %#v", raw, got)
			}
		})
	}
}

func TestFormatRejectsInvalidValues(t *testing.T) {
	v1 := decodeV1(t, emptySHA1)
	valid := magnet.URI{Hashes: metainfo.Hashes{V1: &v1}}
	tests := map[string]magnet.URI{
		"missing hash": {},
		"invalid name": {
			Hashes:      valid.Hashes,
			DisplayName: string([]byte{0xff}),
		},
		"invalid tracker": {
			Hashes:   valid.Hashes,
			Trackers: []string{"tracker.example/announce"},
		},
		"invalid peer host": {
			Hashes: valid.Hashes,
			Peers:  []magnet.Peer{{Host: "bad_host", Port: 80}},
		},
		"invalid peer port": {
			Hashes: valid.Hashes,
			Peers:  []magnet.Peer{{Host: "peer.example"}},
		},
	}
	for name, uri := range tests {
		t.Run(name, func(t *testing.T) {
			if got, err := magnet.Format(uri); err == nil {
				t.Fatalf("Format() = %q, want an error", got)
			}
		})
	}
}

func decodeV1(t *testing.T, encoded string) metainfo.Hash {
	t.Helper()
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var hash metainfo.Hash
	copy(hash[:], raw)
	return hash
}
