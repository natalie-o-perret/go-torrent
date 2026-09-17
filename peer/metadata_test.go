package peer_test

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/natalie-o-perret/go-torrent/metainfo"
	"github.com/natalie-o-perret/go-torrent/peer"
)

func TestMetadataMessageCodec(t *testing.T) {
	officialRequest := []byte("d8:msg_typei0e5:piecei0ee")
	request, err := peer.DecodeMetadataMessage(officialRequest, 0)
	if err != nil {
		t.Fatalf("DecodeMetadataMessage request: %v", err)
	}
	if request.Type != peer.MetadataRequest || request.Piece != 0 || request.TotalSize != nil || len(request.Data) != 0 {
		t.Fatalf("request = %#v", request)
	}
	encoded, err := request.Encode()
	if err != nil {
		t.Fatalf("request.Encode: %v", err)
	}
	if !bytes.Equal(encoded, officialRequest) {
		t.Fatalf("encoded request = %q, want %q", encoded, officialRequest)
	}

	total := peer.MetadataBlockSize + 3
	want := peer.MetadataMessage{
		Type:      peer.MetadataData,
		Piece:     1,
		TotalSize: &total,
		Data:      []byte{1, 2, 3},
		Unknown:   map[string]any{"x_field": "opaque"},
	}
	payload, err := want.Encode()
	if err != nil {
		t.Fatalf("data.Encode: %v", err)
	}
	got, err := peer.DecodeMetadataMessage(payload, total)
	if err != nil {
		t.Fatalf("DecodeMetadataMessage data: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata data = %#v, want %#v", got, want)
	}

	unknownPayload := append(encodeBencode(t, map[string]any{
		"msg_type": int64(99),
		"piece":    int64(7),
		"x":        int64(1),
	}), []byte("future payload")...)
	unknown, err := peer.DecodeMetadataMessage(unknownPayload, 0)
	if err != nil {
		t.Fatalf("unknown metadata type: %v", err)
	}
	if unknown.Type != 99 || string(unknown.Data) != "future payload" || unknown.Unknown["x"] != int64(1) {
		t.Fatalf("unknown metadata message = %#v", unknown)
	}
}

func TestMetadataMessageRejectsMalformedShapes(t *testing.T) {
	total := uint32(5)
	tests := []peer.MetadataMessage{
		{Type: peer.MetadataRequest, Piece: 0, Data: []byte{1}},
		{Type: peer.MetadataRequest, Piece: 0, TotalSize: &total},
		{Type: peer.MetadataData, Piece: 0, Data: []byte("12345")},
		{Type: peer.MetadataData, Piece: 0, TotalSize: &total, Data: []byte("1234")},
		{Type: peer.MetadataData, Piece: 1, TotalSize: &total, Data: []byte("12345")},
	}
	for _, message := range tests {
		if _, err := message.Encode(); err == nil {
			t.Errorf("malformed metadata message encoded: %#v", message)
		}
	}
	if _, err := peer.DecodeMetadataMessage(append([]byte("d8:msg_typei0e5:piecei0ee"), 1), 0); err == nil {
		t.Fatal("request with trailing payload accepted")
	}
	tooLarge := append(encodeBencode(t, map[string]any{
		"msg_type":   int64(1),
		"piece":      int64(0),
		"total_size": int64(6),
	}), []byte("123456")...)
	if _, err := peer.DecodeMetadataMessage(tooLarge, 5); err == nil {
		t.Fatal("metadata total_size above configured maximum accepted")
	}
}

func TestMetadataAssemblerExactBlocksAndHashes(t *testing.T) {
	raw := make([]byte, int(peer.MetadataBlockSize)+3)
	for i := range raw {
		raw[i] = byte(i * 31)
	}
	v1 := metainfo.Hash(sha1.Sum(raw))
	v2 := metainfo.HashV2(sha256.Sum256(raw))
	assembler, err := peer.NewMetadataAssembler(peer.MetadataAssemblerConfig{
		Size:    uint32(len(raw)),
		MaxSize: uint32(len(raw)),
		Hashes:  metainfo.Hashes{V1: &v1, V2: &v2},
	})
	if err != nil {
		t.Fatalf("NewMetadataAssembler: %v", err)
	}
	total := uint32(len(raw))
	last := peer.MetadataMessage{Type: peer.MetadataData, Piece: 1, TotalSize: &total, Data: raw[peer.MetadataBlockSize:]}
	complete, err := assembler.Add(last)
	if err != nil || complete {
		t.Fatalf("Add last first = (%v, %v)", complete, err)
	}
	first := peer.MetadataMessage{Type: peer.MetadataData, Piece: 0, TotalSize: &total, Data: raw[:peer.MetadataBlockSize]}
	complete, err = assembler.Add(first)
	if err != nil || !complete {
		t.Fatalf("Add first = (%v, %v)", complete, err)
	}
	complete, err = assembler.Add(last)
	if err != nil || !complete {
		t.Fatalf("duplicate block = (%v, %v)", complete, err)
	}
	got, ok := assembler.Bytes()
	if !ok || !bytes.Equal(got, raw) {
		t.Fatalf("assembled bytes = (%x, %v)", got, ok)
	}
	got[0] ^= 0xff
	again, _ := assembler.Bytes()
	if bytes.Equal(got, again) {
		t.Fatal("Bytes exposed mutable assembler storage")
	}

	wrong := v1
	wrong[0] ^= 0xff
	badAssembler, err := peer.NewMetadataAssembler(peer.MetadataAssemblerConfig{
		Size:   uint32(len(raw)),
		Hashes: metainfo.Hashes{V1: &wrong},
	})
	if err != nil {
		t.Fatalf("NewMetadataAssembler wrong hash: %v", err)
	}
	if _, err := badAssembler.Add(first); err != nil {
		t.Fatalf("bad assembler first block: %v", err)
	}
	if _, err := badAssembler.Add(last); !errors.Is(err, peer.ErrMetadataHashMismatch) {
		t.Fatalf("hash mismatch error = %v", err)
	}
	if badAssembler.Complete() {
		t.Fatal("hash-mismatched assembler reports complete")
	}
}

func TestMetadataSourceServesRawInfo(t *testing.T) {
	rawInfo := "d6:lengthi1e4:name1:x12:piece lengthi16384e6:pieces20:aaaaaaaaaaaaaaaaaaaae"
	meta, err := metainfo.Decode(strings.NewReader("d4:info" + rawInfo + "e"))
	if err != nil {
		t.Fatalf("metainfo.Decode: %v", err)
	}
	source, err := peer.NewMetadataSource(meta, 0)
	if err != nil {
		t.Fatalf("NewMetadataSource: %v", err)
	}
	if source.Size() != uint32(len(rawInfo)) {
		t.Fatalf("source size = %d, want %d", source.Size(), len(rawInfo))
	}
	message, err := source.Respond(peer.MetadataMessage{Type: peer.MetadataRequest, Piece: 0})
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if message.Type != peer.MetadataData || !bytes.Equal(message.Data, meta.RawInfo) {
		t.Fatalf("source data = %#v", message)
	}
	reject, err := source.Respond(peer.MetadataMessage{Type: peer.MetadataRequest, Piece: 1})
	if err != nil || reject.Type != peer.MetadataReject || reject.Piece != 1 {
		t.Fatalf("out-of-range response = (%#v, %v)", reject, err)
	}

	assembler, err := peer.NewMetadataAssembler(peer.MetadataAssemblerConfig{
		Size:   source.Size(),
		Hashes: meta.Hashes(),
	})
	if err != nil {
		t.Fatalf("NewMetadataAssembler: %v", err)
	}
	if complete, err := assembler.Add(message); err != nil || !complete {
		t.Fatalf("assemble served RawInfo = (%v, %v)", complete, err)
	}

	tampered := *meta
	tampered.RawInfo = append([]byte(nil), meta.RawInfo...)
	tampered.RawInfo[len(tampered.RawInfo)-2] ^= 1
	if _, err := peer.NewMetadataSource(&tampered, 0); !errors.Is(err, peer.ErrMetadataHashMismatch) {
		t.Fatalf("tampered RawInfo error = %v", err)
	}
}

func TestMetadataAssemblerBound(t *testing.T) {
	hash := metainfo.Hash{}
	if _, err := peer.NewMetadataAssembler(peer.MetadataAssemblerConfig{
		Size:    11,
		MaxSize: 10,
		Hashes:  metainfo.Hashes{V1: &hash},
	}); err == nil {
		t.Fatal("oversized metadata assembler succeeded")
	}
}
