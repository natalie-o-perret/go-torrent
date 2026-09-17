package peer_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/natalie-o-perret/go-torrent/metainfo"
	"github.com/natalie-o-perret/go-torrent/peer"
)

func TestExchangeHandshakePreservesReservedBytes(t *testing.T) {
	infoHash := metainfo.Hash{1, 2, 3}
	left := peer.HandshakeMessage{
		Reserved: peer.Reserved{0x80, 1, 2, 3, 4, 5, 6, 7},
		InfoHash: infoHash,
		PeerID:   [20]byte{'L'},
	}
	right := peer.HandshakeMessage{
		Reserved: peer.Reserved{7, 6, 5, 4, 3, 2, 1, 0x80},
		InfoHash: infoHash,
		PeerID:   [20]byte{'R'},
	}
	left.Reserved.Set(peer.CapabilityExtensionProtocol, true)
	right.Reserved.Set(peer.CapabilityFast, true)

	leftConn, rightConn := net.Pipe()
	defer func() { _ = leftConn.Close() }()
	defer func() { _ = rightConn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	type result struct {
		remote peer.HandshakeMessage
		err    error
	}
	leftResult := make(chan result, 1)
	rightResult := make(chan result, 1)
	go func() {
		remote, err := peer.ExchangeHandshake(ctx, leftConn, left)
		leftResult <- result{remote: remote, err: err}
	}()
	go func() {
		remote, err := peer.ExchangeHandshake(ctx, rightConn, right)
		rightResult <- result{remote: remote, err: err}
	}()

	if got := <-leftResult; got.err != nil || got.remote != right {
		t.Fatalf("left exchange = (%+v, %v), want right handshake", got.remote, got.err)
	}
	if got := <-rightResult; got.err != nil || got.remote != left {
		t.Fatalf("right exchange = (%+v, %v), want left handshake", got.remote, got.err)
	}
}

func TestExchangeHandshakeHonoursContext(t *testing.T) {
	left, right := net.Pipe()
	defer func() { _ = left.Close() }()
	defer func() { _ = right.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := peer.ExchangeHandshake(ctx, left, peer.HandshakeMessage{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ExchangeHandshake error = %v, want context deadline", err)
	}
}

func TestHandshakeReadWriteUsesFullIOSemantics(t *testing.T) {
	want := peer.HandshakeMessage{
		Reserved: peer.Reserved{1, 2, 3, 4, 5, 6, 7, 8},
		InfoHash: metainfo.Hash{9, 8, 7},
		PeerID:   [20]byte{'p', 'e', 'e', 'r'},
	}
	writer := &limitedWriter{limit: 3}
	if err := peer.WriteHandshake(writer, want); err != nil {
		t.Fatalf("WriteHandshake: %v", err)
	}
	got, err := peer.ReadHandshake(&oneByteReader{reader: bytes.NewReader(writer.Bytes())})
	if err != nil {
		t.Fatalf("ReadHandshake: %v", err)
	}
	if got != want {
		t.Fatalf("handshake = %+v, want %+v", got, want)
	}
}

func TestReservedCapabilitiesAndNegotiation(t *testing.T) {
	var local, remote peer.Reserved
	for _, capability := range []peer.Capability{
		peer.CapabilityDHT,
		peer.CapabilityFast,
		peer.CapabilityV2Upgrade,
		peer.CapabilityExtensionProtocol,
	} {
		local.Set(capability, true)
		if !local.Has(capability) {
			t.Fatalf("capability %d was not set", capability)
		}
	}
	if local[7] != 0x15 || local[5] != 0x10 {
		t.Fatalf("reserved bytes = %x, want BEP masks", local)
	}
	if err := peer.ValidateNegotiatedMessage(peer.MsgPort, local, remote); err == nil {
		t.Fatal("PORT accepted without remote DHT capability")
	}
	remote.Set(peer.CapabilityDHT, true)
	if err := peer.ValidateNegotiatedMessage(peer.MsgPort, local, remote); err != nil {
		t.Fatalf("PORT rejected after negotiation: %v", err)
	}
	if err := peer.ValidateNegotiatedMessage(peer.MsgAllowedFast, local, remote); err == nil {
		t.Fatal("Allowed Fast accepted without remote fast capability")
	}
	remote.Set(peer.CapabilityFast, true)
	if err := peer.ValidateNegotiatedMessage(peer.MsgAllowedFast, local, remote); err != nil {
		t.Fatalf("Allowed Fast rejected after negotiation: %v", err)
	}
	if err := peer.ValidateNegotiatedMessage(peer.MsgExtended, local, remote); err == nil {
		t.Fatal("Extended accepted without remote extension capability")
	}
	remote.Set(peer.CapabilityExtensionProtocol, true)
	if err := peer.ValidateNegotiatedMessage(peer.MsgExtended, local, remote); err != nil {
		t.Fatalf("Extended rejected after negotiation: %v", err)
	}
}

func TestCodecBoundsValidationAndKeepalive(t *testing.T) {
	var oversized [4]byte
	binary.BigEndian.PutUint32(oversized[:], 9)
	_, err := (peer.Codec{MaxFrameSize: 8}).ReadMessage(bytes.NewReader(oversized[:]))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized read error = %v", err)
	}

	codec := peer.Codec{MaxFrameSize: 8}
	if err := codec.WriteMessage(io.Discard, &peer.Message{ID: 99, Payload: make([]byte, 8)}); err == nil {
		t.Fatal("oversized write succeeded")
	}
	if err := codec.WriteMessage(io.Discard, &peer.Message{ID: peer.MsgChoke, Payload: []byte{1}}); err == nil {
		t.Fatal("malformed static payload succeeded")
	}

	var wire bytes.Buffer
	if err := codec.WriteKeepalive(&wire); err != nil {
		t.Fatalf("WriteKeepalive: %v", err)
	}
	if !bytes.Equal(wire.Bytes(), []byte{0, 0, 0, 0}) {
		t.Fatalf("keepalive = %x", wire.Bytes())
	}
	message, err := codec.ReadMessage(&wire)
	if err != nil || message != nil {
		t.Fatalf("ReadMessage keepalive = (%+v, %v)", message, err)
	}
	if err := peer.WriteKeepalive(&wire); err != nil {
		t.Fatalf("package WriteKeepalive: %v", err)
	}
}

func TestCodecCompletesShortWritesAndReads(t *testing.T) {
	want := &peer.Message{ID: peer.MsgHave, Payload: peer.FormatHave(42)}
	writer := &limitedWriter{limit: 2}
	if err := (peer.Codec{}).WriteMessage(writer, want); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	got, err := (peer.Codec{}).ReadMessage(&oneByteReader{reader: bytes.NewReader(writer.Bytes())})
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("message = %+v, want %+v", got, want)
	}
	if err := (peer.Codec{}).WriteMessage(zeroWriter{}, want); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero writer error = %v, want io.ErrShortWrite", err)
	}
}

func TestStaticPayloadCodecs(t *testing.T) {
	if err := peer.ParseHaveAll(nil); err != nil {
		t.Fatalf("ParseHaveAll: %v", err)
	}
	if err := peer.ParseHaveNone(nil); err != nil {
		t.Fatalf("ParseHaveNone: %v", err)
	}
	if got, err := peer.ParseHave(peer.FormatHave(17)); err != nil || got != 17 {
		t.Fatalf("Have round trip = (%d, %v)", got, err)
	}
	if err := peer.ValidatePieceIndex(17, 17); err == nil {
		t.Fatal("out-of-range piece index accepted")
	}
	pieces := []bool{true, false, true, false, false, false, false, true, true}
	bitfield := peer.FormatBitfield(pieces)
	if !bytes.Equal(bitfield, []byte{0xa1, 0x80}) {
		t.Fatalf("bitfield = %08b", bitfield)
	}
	if got, err := peer.ParseBitfield(bitfield, uint32(len(pieces))); err != nil || !reflect.DeepEqual(got, pieces) {
		t.Fatalf("Bitfield round trip = (%v, %v)", got, err)
	}
	if err := peer.ValidateBitfield([]byte{0xa1, 0x81}, 9); err == nil {
		t.Fatal("nonzero bitfield spare bits accepted")
	}

	wantRequest := peer.BlockRequest{Index: 5, Begin: 16 << 10, Length: 16 << 10}
	for name, test := range map[string]struct {
		payload []byte
		parse   func([]byte) (peer.BlockRequest, error)
	}{
		"request": {peer.FormatRequest(wantRequest.Index, wantRequest.Begin, wantRequest.Length), peer.ParseRequest},
		"cancel":  {peer.FormatCancel(wantRequest.Index, wantRequest.Begin, wantRequest.Length), peer.ParseCancel},
		"reject":  {peer.FormatReject(wantRequest.Index, wantRequest.Begin, wantRequest.Length), peer.ParseReject},
	} {
		got, err := test.parse(test.payload)
		if err != nil || got != wantRequest {
			t.Errorf("%s round trip = (%+v, %v)", name, got, err)
		}
	}
	if _, err := peer.ParseRequest(peer.FormatRequest(0, 0, 0)); err == nil {
		t.Error("zero-length request accepted")
	}
	if _, err := peer.ParseRequest(peer.FormatRequest(0, ^uint32(0), 1)); err == nil {
		t.Error("overflowing request accepted")
	}

	piecePayload, err := peer.FormatPiece(9, 123, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("FormatPiece: %v", err)
	}
	index, begin, data, err := peer.ParsePiece(piecePayload)
	if err != nil || index != 9 || begin != 123 || !bytes.Equal(data, []byte{1, 2, 3}) {
		t.Fatalf("Piece round trip = (%d, %d, %x, %v)", index, begin, data, err)
	}
	if _, err := peer.FormatPiece(0, ^uint32(0), []byte{1}); err == nil {
		t.Error("overflowing piece accepted")
	}

	portPayload, err := peer.FormatPort(6881)
	if err != nil {
		t.Fatalf("FormatPort: %v", err)
	}
	if got, err := peer.ParsePort(portPayload); err != nil || got != 6881 {
		t.Fatalf("Port round trip = (%d, %v)", got, err)
	}
	if _, err := peer.ParsePort([]byte{0, 0}); err == nil {
		t.Error("zero port accepted")
	}
	if got, err := peer.ParseSuggestPiece(peer.FormatSuggestPiece(3)); err != nil || got != 3 {
		t.Fatalf("Suggest Piece round trip = (%d, %v)", got, err)
	}
	if got, err := peer.ParseAllowedFast(peer.FormatAllowedFast(4)); err != nil || got != 4 {
		t.Fatalf("Allowed Fast round trip = (%d, %v)", got, err)
	}
}

func TestHashMessageCodecs(t *testing.T) {
	request := peer.HashRequest{
		PiecesRoot:  metainfo.HashV2{1, 2, 3},
		BaseLayer:   0,
		Index:       8,
		Length:      4,
		ProofLayers: 4,
	}
	payload, err := peer.FormatHashRequest(request)
	if err != nil {
		t.Fatalf("FormatHashRequest: %v", err)
	}
	if got, err := peer.ParseHashRequest(payload); err != nil || got != request {
		t.Fatalf("Hash Request round trip = (%+v, %v)", got, err)
	}
	if got, err := peer.ParseHashReject(payload); err != nil || got != request {
		t.Fatalf("Hash Reject round trip = (%+v, %v)", got, err)
	}

	values := make([]metainfo.HashV2, 7) // 4 base hashes + (4 proof layers - (log2(4) - 1)).
	for i := range values {
		values[i][0] = byte(i + 1)
	}
	hashesPayload, err := peer.FormatHashes(peer.Hashes{Request: request, Values: values})
	if err != nil {
		t.Fatalf("FormatHashes: %v", err)
	}
	got, err := peer.ParseHashes(hashesPayload)
	if err != nil || !reflect.DeepEqual(got, peer.Hashes{Request: request, Values: values}) {
		t.Fatalf("Hashes round trip = (%+v, %v)", got, err)
	}
	if _, err := peer.ParseHashes(hashesPayload[:len(hashesPayload)-32]); err == nil {
		t.Error("Hashes accepted a wrong implied count")
	}
	if err := (peer.HashRequest{Length: 1024}).Validate(); err != nil {
		t.Fatalf("protocol-valid hash count above the recommendation was rejected: %v", err)
	}

	badRequests := []peer.HashRequest{
		{Length: 1},
		{Length: 3},
		{Index: 1, Length: 2},
		{Index: ^uint32(0) - 1, Length: 2},
		{Length: 2, BaseLayer: 63, ProofLayers: 1},
	}
	for _, bad := range badRequests {
		if _, err := peer.FormatHashRequest(bad); err == nil {
			t.Errorf("invalid hash request accepted: %+v", bad)
		}
	}
}

func TestHashesProofCountBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		length      uint32
		proofLayers uint32
		wantHashes  int
	}{
		{name: "length 2 no proofs", length: 2, proofLayers: 0, wantHashes: 2},
		{name: "length 2 one proof", length: 2, proofLayers: 1, wantHashes: 3},
		{name: "length 2 many proofs", length: 2, proofLayers: 10, wantHashes: 12},
		{name: "length 512 all omitted", length: 512, proofLayers: 8, wantHashes: 512},
		{name: "length 512 one proof", length: 512, proofLayers: 9, wantHashes: 513},
		{name: "length 512 two proofs", length: 512, proofLayers: 10, wantHashes: 514},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := peer.HashRequest{Length: test.length, ProofLayers: test.proofLayers}
			values := make([]metainfo.HashV2, test.wantHashes)
			payload, err := peer.FormatHashes(peer.Hashes{Request: request, Values: values})
			if err != nil {
				t.Fatalf("FormatHashes: %v", err)
			}
			if got := len(payload); got != 48+test.wantHashes*len(metainfo.HashV2{}) {
				t.Fatalf("payload length = %d, want %d", got, 48+test.wantHashes*len(metainfo.HashV2{}))
			}
			parsed, err := peer.ParseHashes(payload)
			if err != nil || len(parsed.Values) != test.wantHashes {
				t.Fatalf("ParseHashes = (%d hashes, %v), want %d", len(parsed.Values), err, test.wantHashes)
			}
			if _, err := peer.ParseHashes(payload[:len(payload)-len(metainfo.HashV2{})]); err == nil {
				t.Fatal("payload with one missing hash was accepted")
			}
		})
	}
}

func TestHashesCodecFrameBoundAndDeclaredCountSafety(t *testing.T) {
	request := peer.HashRequest{Length: 512, ProofLayers: 10}
	payload, err := peer.FormatHashes(peer.Hashes{
		Request: request,
		Values:  make([]metainfo.HashV2, 514),
	})
	if err != nil {
		t.Fatalf("FormatHashes: %v", err)
	}
	frameSize := uint32(1 + len(payload))
	message := &peer.Message{ID: peer.MsgHashes, Payload: payload}
	if err := (peer.Codec{MaxFrameSize: frameSize - 1}).WriteMessage(io.Discard, message); err == nil {
		t.Fatal("Hashes frame above the configured maximum was accepted")
	}
	var wire bytes.Buffer
	codec := peer.Codec{MaxFrameSize: frameSize}
	if err := codec.WriteMessage(&wire, message); err != nil {
		t.Fatalf("WriteMessage at exact frame maximum: %v", err)
	}
	decoded, err := codec.ReadMessage(&wire)
	if err != nil {
		t.Fatalf("ReadMessage at exact frame maximum: %v", err)
	}
	parsed, err := peer.ParseHashes(decoded.Payload)
	if err != nil || len(parsed.Values) != 514 {
		t.Fatalf("decoded Hashes = (%d hashes, %v), want 514", len(parsed.Values), err)
	}

	declared, err := peer.FormatHashRequest(peer.HashRequest{Length: peer.MaxHashRequestLength})
	if err != nil {
		t.Fatalf("FormatHashRequest maximum length: %v", err)
	}
	wire.Reset()
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(1+len(declared)))
	wire.Write(prefix[:])
	wire.WriteByte(byte(peer.MsgHashes))
	wire.Write(declared)
	if _, err := (peer.Codec{MaxFrameSize: uint32(1 + len(declared))}).ReadMessage(&wire); err == nil {
		t.Fatal("Hashes payload with a huge declared count and no hashes was accepted")
	}
}

func TestAllowedFastOfficialVector(t *testing.T) {
	var infoHash metainfo.Hash
	for i := range infoHash {
		infoHash[i] = 0xaa
	}
	got, err := peer.GenerateAllowedFastSet(infoHash, netip.MustParseAddr("80.4.4.200"), 1313, 9)
	if err != nil {
		t.Fatalf("GenerateAllowedFastSet: %v", err)
	}
	want := []uint32{1059, 431, 808, 1217, 287, 376, 1188, 353, 508}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allowed fast set = %v, want %v", got, want)
	}
}

type limitedWriter struct {
	bytes.Buffer
	limit int
}

func (writer *limitedWriter) Write(data []byte) (int, error) {
	if len(data) > writer.limit {
		data = data[:writer.limit]
	}
	return writer.Buffer.Write(data)
}

type oneByteReader struct {
	reader io.Reader
}

func (reader *oneByteReader) Read(data []byte) (int, error) {
	if len(data) > 1 {
		data = data[:1]
	}
	return reader.reader.Read(data)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) {
	return 0, nil
}
