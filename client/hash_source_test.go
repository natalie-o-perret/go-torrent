package client

import (
	"bytes"
	"crypto/sha256"
	"math"
	"math/bits"
	"reflect"
	"testing"

	"github.com/natalie-o-perret/go-torrent/bencode"
	"github.com/natalie-o-perret/go-torrent/metainfo"
	"github.com/natalie-o-perret/go-torrent/peer"
	"github.com/natalie-o-perret/go-torrent/storage"
)

type v2HashSourceFixture struct {
	meta       *metainfo.MetaInfo
	store      *storage.Storage
	source     *v2HashSource
	largeData  []byte
	largeRoot  metainfo.HashV2
	largeTree  [][]metainfo.HashV2
	singleRoot metainfo.HashV2
	singleTree [][]metainfo.HashV2
}

func TestV2HashSourceRespond(t *testing.T) {
	fixture := newV2HashSourceFixture(t)
	verified := func(indexes ...int) []bool {
		result := make([]bool, 4)
		for _, index := range indexes {
			result[index] = true
		}
		return result
	}
	tests := []struct {
		name     string
		request  peer.HashRequest
		verified []bool
		tree     [][]metainfo.HashV2
	}{
		{
			name:     "leaf",
			request:  peer.HashRequest{PiecesRoot: fixture.largeRoot, Index: 4, Length: 2},
			verified: verified(1),
			tree:     fixture.largeTree,
		},
		{
			name:     "lower layer",
			request:  peer.HashRequest{PiecesRoot: fixture.largeRoot, BaseLayer: 1, Length: 2},
			verified: verified(0),
			tree:     fixture.largeTree,
		},
		{
			name:    "piece layer without local data",
			request: peer.HashRequest{PiecesRoot: fixture.largeRoot, BaseLayer: 2, Length: 2, ProofLayers: 1},
			tree:    fixture.largeTree,
		},
		{
			name:    "higher layer without local data",
			request: peer.HashRequest{PiecesRoot: fixture.largeRoot, BaseLayer: 3, Length: 2},
			tree:    fixture.largeTree,
		},
		{
			name:     "leaf proof",
			request:  peer.HashRequest{PiecesRoot: fixture.largeRoot, Length: 2, ProofLayers: 3},
			verified: verified(0),
			tree:     fixture.largeTree,
		},
		{
			name:     "partial final piece and zero padding",
			request:  peer.HashRequest{PiecesRoot: fixture.largeRoot, Index: 8, Length: 4, ProofLayers: 2},
			verified: verified(2),
			tree:     fixture.largeTree,
		},
		{
			name:    "padded piece",
			request: peer.HashRequest{PiecesRoot: fixture.largeRoot, Index: 12, Length: 4},
			tree:    fixture.largeTree,
		},
		{
			name:     "single piece file",
			request:  peer.HashRequest{PiecesRoot: fixture.singleRoot, Length: 2},
			verified: verified(3),
			tree:     fixture.singleTree,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := fixture.source.Respond(test.request, test.verified)
			if !ok {
				t.Fatal("Respond rejected an available request")
			}
			want := v2HashSourceExpected(test.tree, test.request)
			if got.Request != test.request || !reflect.DeepEqual(got.Values, want) {
				t.Fatalf("Respond = %+v, want request %+v and hashes %x", got, test.request, want)
			}
			payload, err := peer.FormatHashes(got)
			if err != nil {
				t.Fatalf("FormatHashes: %v", err)
			}
			parsed, err := peer.ParseHashes(payload)
			if err != nil || !reflect.DeepEqual(parsed, got) {
				t.Fatalf("hashes round trip = (%+v, %v), want %+v", parsed, err, got)
			}
		})
	}
}

func TestV2HashSourceRejectsUnavailableAndInvalidRequests(t *testing.T) {
	fixture := newV2HashSourceFixture(t)
	unknown := metainfo.HashV2{0xff}
	tests := []struct {
		name     string
		request  peer.HashRequest
		verified []bool
	}{
		{
			name:     "unverified piece",
			request:  peer.HashRequest{PiecesRoot: fixture.largeRoot, Length: 2},
			verified: make([]bool, 4),
		},
		{
			name:     "short bitmap",
			request:  peer.HashRequest{PiecesRoot: fixture.largeRoot, Length: 2},
			verified: []bool{true},
		},
		{
			name:    "unknown pieces root",
			request: peer.HashRequest{PiecesRoot: unknown, Length: 2},
		},
		{
			name:    "length below minimum",
			request: peer.HashRequest{PiecesRoot: fixture.largeRoot, Length: 1},
		},
		{
			name:    "non power of two length",
			request: peer.HashRequest{PiecesRoot: fixture.largeRoot, Length: 3},
		},
		{
			name:    "unaligned index",
			request: peer.HashRequest{PiecesRoot: fixture.largeRoot, Index: 1, Length: 2},
		},
		{
			name:    "wire range overflow",
			request: peer.HashRequest{PiecesRoot: fixture.largeRoot, Index: math.MaxUint32 - 1, Length: 2},
		},
		{
			name:    "past padded tree",
			request: peer.HashRequest{PiecesRoot: fixture.largeRoot, Index: 16, Length: 2},
		},
		{
			name:    "base layer at root",
			request: peer.HashRequest{PiecesRoot: fixture.largeRoot, BaseLayer: 4, Length: 2},
		},
		{
			name:    "proof past root",
			request: peer.HashRequest{PiecesRoot: fixture.largeRoot, Length: 2, ProofLayers: 4},
		},
		{
			name:    "maximum wire request exceeds tree",
			request: peer.HashRequest{PiecesRoot: fixture.largeRoot, Length: peer.MaxHashRequestLength},
		},
		{
			name:    "above recommended request bound",
			request: peer.HashRequest{PiecesRoot: fixture.largeRoot, Length: 1024},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if response, ok := fixture.source.Respond(test.request, test.verified); ok {
				t.Fatalf("Respond accepted request with %d hashes: %+v", len(response.Values), test.request)
			}
		})
	}
}

func TestV2HashSourceRechecksVerifiedPieceRoot(t *testing.T) {
	fixture := newV2HashSourceFixture(t)
	corrupt := append([]byte(nil), fixture.largeData[:64<<10]...)
	corrupt[0] ^= 0xff
	if err := fixture.store.WritePiece(storage.V2, 0, corrupt); err != nil {
		t.Fatal(err)
	}
	request := peer.HashRequest{PiecesRoot: fixture.largeRoot, Length: 2}
	if _, ok := fixture.source.Respond(request, []bool{true, false, false, false}); ok {
		t.Fatal("Respond served hashes from data that no longer matches its verified piece root")
	}
}

func TestNewV2HashSourceValidatesPieceLayers(t *testing.T) {
	fixture := newV2HashSourceFixture(t)
	tests := []struct {
		name   string
		mutate func(*metainfo.MetaInfo)
	}{
		{
			name: "missing complete layer set",
			mutate: func(meta *metainfo.MetaInfo) {
				meta.PieceLayers = nil
			},
		},
		{
			name: "missing required layer",
			mutate: func(meta *metainfo.MetaInfo) {
				delete(meta.PieceLayers, fixture.largeRoot)
			},
		},
		{
			name: "layer does not match root",
			mutate: func(meta *metainfo.MetaInfo) {
				layer := meta.PieceLayers[fixture.largeRoot]
				layer[0][0] ^= 0xff
			},
		},
		{
			name: "unknown layer root",
			mutate: func(meta *metainfo.MetaInfo) {
				meta.PieceLayers[metainfo.HashV2{0xff}] = append([]metainfo.HashV2(nil), meta.PieceLayers[fixture.largeRoot]...)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			meta := cloneV2HashSourceMeta(fixture.meta)
			test.mutate(meta)
			if _, err := newV2HashSource(meta, fixture.store); err == nil {
				t.Fatal("newV2HashSource accepted invalid piece layers")
			}
		})
	}
	if _, err := newV2HashSource(fixture.meta, nil); err == nil {
		t.Fatal("newV2HashSource accepted nil storage")
	}
}

func newV2HashSourceFixture(t *testing.T) *v2HashSourceFixture {
	t.Helper()
	const pieceLength = 64 << 10
	largeData := make([]byte, 2*pieceLength+7)
	for index := range largeData {
		largeData[index] = byte(index*31 + 7)
	}
	singleData := make([]byte, v2HashBlockSize+3)
	for index := range singleData {
		singleData[index] = byte(index*17 + 11)
	}
	largeTree := v2HashSourceTree(largeData)
	singleTree := v2HashSourceTree(singleData)
	largeRoot := largeTree[len(largeTree)-1][0]
	singleRoot := singleTree[len(singleTree)-1][0]
	pieceLayer := bits.TrailingZeros(uint(pieceLength / v2HashBlockSize))
	pieceHashes := largeTree[pieceLayer][:3]

	var encoded bytes.Buffer
	if err := bencode.Encode(&encoded, map[string]any{
		"info": map[string]any{
			"file tree": map[string]any{
				"large": map[string]any{"": map[string]any{
					"length": int64(len(largeData)), "pieces root": string(largeRoot[:]),
				}},
				"single": map[string]any{"": map[string]any{
					"length": int64(len(singleData)), "pieces root": string(singleRoot[:]),
				}},
			},
			"meta version": int64(2),
			"name":         "hash-source",
			"piece length": int64(pieceLength),
		},
		"piece layers": map[string]any{
			string(largeRoot[:]): v2HashSourceJoin(pieceHashes),
		},
	}); err != nil {
		t.Fatal(err)
	}
	meta, err := metainfo.Decode(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.New(t.TempDir(), meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Prepare(); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		begin := index * pieceLength
		end := min(begin+pieceLength, len(largeData))
		if err := store.WritePiece(storage.V2, index, largeData[begin:end]); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.WritePiece(storage.V2, 3, singleData); err != nil {
		t.Fatal(err)
	}
	source, err := newV2HashSource(meta, store)
	if err != nil {
		t.Fatal(err)
	}
	return &v2HashSourceFixture{
		meta:       meta,
		store:      store,
		source:     source,
		largeData:  largeData,
		largeRoot:  largeRoot,
		largeTree:  largeTree,
		singleRoot: singleRoot,
		singleTree: singleTree,
	}
}

func v2HashSourceTree(data []byte) [][]metainfo.HashV2 {
	blocks := 1 + (len(data)-1)/v2HashBlockSize
	leaves := 1
	for leaves < blocks {
		leaves *= 2
	}
	tree := [][]metainfo.HashV2{make([]metainfo.HashV2, leaves)}
	for block := 0; block < blocks; block++ {
		begin := block * v2HashBlockSize
		end := min(begin+v2HashBlockSize, len(data))
		tree[0][block] = metainfo.HashV2(sha256.Sum256(data[begin:end]))
	}
	for len(tree[len(tree)-1]) > 1 {
		previous := tree[len(tree)-1]
		current := make([]metainfo.HashV2, len(previous)/2)
		for index := range current {
			var pair [sha256.Size * 2]byte
			copy(pair[:sha256.Size], previous[index*2][:])
			copy(pair[sha256.Size:], previous[index*2+1][:])
			current[index] = metainfo.HashV2(sha256.Sum256(pair[:]))
		}
		tree = append(tree, current)
	}
	return tree
}

func v2HashSourceExpected(tree [][]metainfo.HashV2, request peer.HashRequest) []metainfo.HashV2 {
	values := append([]metainfo.HashV2(nil), tree[request.BaseLayer][request.Index:request.Index+request.Length]...)
	lengthLayer := uint32(bits.TrailingZeros32(request.Length))
	omitted := lengthLayer - 1
	if request.ProofLayers <= omitted {
		return values
	}
	index := request.Index >> lengthLayer
	layer := request.BaseLayer + lengthLayer
	for count := request.ProofLayers - omitted; count > 0; count-- {
		values = append(values, tree[layer][index^1])
		index >>= 1
		layer++
	}
	return values
}

func v2HashSourceJoin(hashes []metainfo.HashV2) string {
	data := make([]byte, 0, len(hashes)*len(metainfo.HashV2{}))
	for _, hash := range hashes {
		data = append(data, hash[:]...)
	}
	return string(data)
}

func cloneV2HashSourceMeta(meta *metainfo.MetaInfo) *metainfo.MetaInfo {
	clone := *meta
	clone.PieceLayers = make(map[metainfo.HashV2][]metainfo.HashV2, len(meta.PieceLayers))
	for root, layer := range meta.PieceLayers {
		clone.PieceLayers[root] = append([]metainfo.HashV2(nil), layer...)
	}
	return &clone
}
