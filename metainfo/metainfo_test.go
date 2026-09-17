package metainfo_test

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/natalie-o-perret/go-torrent/bencode"
	"github.com/natalie-o-perret/go-torrent/metainfo"
)

func buildTorrent(t *testing.T, announce string, infoDict map[string]any) []byte {
	t.Helper()
	top := map[string]any{"info": infoDict}
	if announce != "" {
		top["announce"] = announce
	}
	s, err := bencode.EncodeToString(top)
	if err != nil {
		t.Fatalf("buildTorrent: encode: %v", err)
	}
	return []byte(s)
}

func zeroHashes(n int) string {
	return strings.Repeat(strings.Repeat("\x00", 20), n)
}

func encodeTop(t *testing.T, top map[string]any) []byte {
	t.Helper()
	s, err := bencode.EncodeToString(top)
	if err != nil {
		t.Fatalf("encode top-level dictionary: %v", err)
	}
	return []byte(s)
}

func validV1Info() map[string]any {
	return map[string]any{
		"length":       int64(1),
		"name":         "file",
		"piece length": int64(16 << 10),
		"pieces":       zeroHashes(1),
	}
}

func hashV2(fill byte) metainfo.HashV2 {
	var hash metainfo.HashV2
	for i := range hash {
		hash[i] = fill
	}
	return hash
}

func joinV2Hashes(hashes []metainfo.HashV2) string {
	var b strings.Builder
	b.Grow(len(hashes) * len(metainfo.HashV2{}))
	for _, hash := range hashes {
		_, _ = b.Write(hash[:])
	}
	return b.String()
}

func hashV2Pair(left, right metainfo.HashV2) metainfo.HashV2 {
	var pair [64]byte
	copy(pair[:32], left[:])
	copy(pair[32:], right[:])
	return sha256.Sum256(pair[:])
}

func pieceLayerRoot(hashes []metainfo.HashV2, pieceLength int64) metainfo.HashV2 {
	zeroPiece := metainfo.HashV2{}
	for size := int64(16 << 10); size < pieceLength; size *= 2 {
		zeroPiece = hashV2Pair(zeroPiece, zeroPiece)
	}
	work := append([]metainfo.HashV2(nil), hashes...)
	for size := 1; size < len(work); size *= 2 {
		if size*2 > len(work) {
			work = append(work, make([]metainfo.HashV2, size*2-len(work))...)
			for i := len(hashes); i < len(work); i++ {
				work[i] = zeroPiece
			}
		}
	}
	for len(work) > 1 {
		next := make([]metainfo.HashV2, len(work)/2)
		for i := range next {
			next[i] = hashV2Pair(work[i*2], work[i*2+1])
		}
		work = next
	}
	return work[0]
}

type v2TestFixture struct {
	top       map[string]any
	info      map[string]any
	largeRoot metainfo.HashV2
	smallRoot metainfo.HashV2
	layer     []metainfo.HashV2
}

func validV2Fixture() v2TestFixture {
	layer := []metainfo.HashV2{hashV2(1), hashV2(2), hashV2(3)}
	largeRoot := pieceLayerRoot(layer, 16<<10)
	smallRoot := hashV2(9)
	info := map[string]any{
		"file tree": map[string]any{
			"empty": map[string]any{"": map[string]any{"length": int64(0)}},
			"large.bin": map[string]any{"": map[string]any{
				"length":      int64(40_000),
				"pieces root": string(largeRoot[:]),
			}},
			"link": map[string]any{"": map[string]any{
				"attr":         "l",
				"length":       int64(0),
				"symlink path": []any{"large.bin"},
			}},
			"small.bin": map[string]any{"": map[string]any{
				"attr":        "x",
				"length":      int64(1),
				"pieces root": string(smallRoot[:]),
			}},
		},
		"meta version": int64(2),
		"name":         "bundle",
		"piece length": int64(16 << 10),
	}
	top := map[string]any{
		"info": info,
		"piece layers": map[string]any{
			string(largeRoot[:]): joinV2Hashes(layer),
		},
	}
	return v2TestFixture{top: top, info: info, largeRoot: largeRoot, smallRoot: smallRoot, layer: layer}
}

func v2Properties(info map[string]any, name string) map[string]any {
	tree := info["file tree"].(map[string]any)
	node := tree[name].(map[string]any)
	return node[""].(map[string]any)
}

type hybridTestFixture struct {
	top  map[string]any
	info map[string]any
}

func validHybridFixture() hybridTestFixture {
	rootA := hashV2(0xa1)
	rootB := hashV2(0xb2)
	info := map[string]any{
		"file tree": map[string]any{
			"a": map[string]any{"": map[string]any{
				"length":      int64(100),
				"pieces root": string(rootA[:]),
			}},
			"b": map[string]any{"": map[string]any{
				"length":      int64(200),
				"pieces root": string(rootB[:]),
			}},
		},
		"files": []any{
			map[string]any{"length": int64(100), "path": []any{"a"}},
			map[string]any{"attr": "p", "length": int64((16 << 10) - 100), "path": []any{".pad", "16284"}},
			map[string]any{"length": int64(200), "path": []any{"b"}},
		},
		"meta version": int64(2),
		"name":         "bundle",
		"piece length": int64(16 << 10),
		"pieces":       zeroHashes(2),
	}
	return hybridTestFixture{
		info: info,
		top: map[string]any{
			"info":         info,
			"piece layers": map[string]any{},
		},
	}
}

func TestDecodeSingleFile(t *testing.T) {
	infoDict := map[string]any{
		"name":         "test.iso",
		"piece length": int64(524288),
		"pieces":       zeroHashes(2),
		"length":       int64(1048576),
	}
	data := buildTorrent(t, "http://tracker.example.com/announce", infoDict)

	m, err := metainfo.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if m.Info.Name != "test.iso" {
		t.Errorf("Name = %q, want test.iso", m.Info.Name)
	}
	if m.Info.Length != 1048576 {
		t.Errorf("Length = %d, want 1048576", m.Info.Length)
	}
	if m.Info.PieceLength != 524288 {
		t.Errorf("PieceLength = %d, want 524288", m.Info.PieceLength)
	}
	if m.Info.PieceCount() != 2 {
		t.Errorf("PieceCount = %d, want 2", m.Info.PieceCount())
	}
	if m.Info.TotalLength() != 1048576 {
		t.Errorf("TotalLength = %d, want 1048576", m.Info.TotalLength())
	}
	if m.Announce != "http://tracker.example.com/announce" {
		t.Errorf("Announce = %q", m.Announce)
	}
	if len(m.Info.Files) != 0 {
		t.Errorf("Files should be nil for single-file torrent, got %d", len(m.Info.Files))
	}
}

func TestDecodeMultiFile(t *testing.T) {
	infoDict := map[string]any{
		"name":         "album",
		"piece length": int64(262144),
		"pieces":       zeroHashes(1),
		"files": []any{
			map[string]any{
				"length": int64(131072),
				"path":   []any{"track01.flac"},
			},
			map[string]any{
				"length": int64(131072),
				"path":   []any{"track02.flac"},
			},
		},
	}
	data := buildTorrent(t, "http://tracker.example.com/announce", infoDict)

	m, err := metainfo.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if m.Info.Name != "album" {
		t.Errorf("Name = %q, want album", m.Info.Name)
	}
	if len(m.Info.Files) != 2 {
		t.Fatalf("len(Files) = %d, want 2", len(m.Info.Files))
	}
	if m.Info.Files[0].Path[0] != "track01.flac" {
		t.Errorf("Files[0].Path[0] = %q", m.Info.Files[0].Path[0])
	}
	if m.Info.TotalLength() != 262144 {
		t.Errorf("TotalLength = %d, want 262144", m.Info.TotalLength())
	}
}

func TestInfoHash(t *testing.T) {
	infoDict := map[string]any{
		"name":         "test.iso",
		"piece length": int64(524288),
		"pieces":       zeroHashes(1),
		"length":       int64(524288),
	}
	data := buildTorrent(t, "http://tracker.example.com/announce", infoDict)

	m, err := metainfo.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	infoEncoded, err := bencode.EncodeToString(infoDict)
	if err != nil {
		t.Fatalf("encode info: %v", err)
	}
	want := sha1.Sum([]byte(infoEncoded))

	if m.InfoHash != want {
		t.Errorf("InfoHash = %s, want %x", m.InfoHash, want)
	}
}

func TestTrackers(t *testing.T) {
	infoDict := map[string]any{
		"name":         "test.iso",
		"piece length": int64(524288),
		"pieces":       zeroHashes(1),
		"length":       int64(524288),
	}
	top := map[string]any{
		"info":     infoDict,
		"announce": "http://ignored.example.com/announce",
		"announce-list": []any{
			[]any{"http://primary.example.com/announce"},
			[]any{"http://secondary.example.com/announce", "http://tertiary.example.com/announce"},
		},
	}
	s, err := bencode.EncodeToString(top)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	m, err := metainfo.Decode(strings.NewReader(s))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	trackers := m.Trackers()
	if trackers[0] != "http://primary.example.com/announce" {
		t.Errorf("trackers[0] = %q, want primary", trackers[0])
	}
	found := make(map[string]int)
	for _, u := range trackers {
		found[u]++
	}
	if found["http://primary.example.com/announce"] != 1 {
		t.Errorf("primary appeared %d times, want 1 (dedup)", found["http://primary.example.com/announce"])
	}
	if len(trackers) != 3 {
		t.Errorf("len(trackers) = %d, want 3", len(trackers))
	}
	if found["http://ignored.example.com/announce"] != 0 {
		t.Error("announce was retained despite announce-list precedence")
	}
}

func TestDecodeMissingInfo(t *testing.T) {
	s, err := bencode.EncodeToString(map[string]any{"announce": "http://x.example.com"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	_, err = metainfo.Decode(strings.NewReader(s))
	if err == nil {
		t.Error("want error for missing 'info' key, got nil")
	}
}

func TestDecodeMissingPieces(t *testing.T) {
	infoDict := map[string]any{
		"name":         "test.iso",
		"piece length": int64(524288),
		"length":       int64(524288),
	}
	data := buildTorrent(t, "", infoDict)
	_, err := metainfo.Decode(bytes.NewReader(data))
	if err == nil {
		t.Error("want error for missing 'pieces' key, got nil")
	}
}

func TestDecodeInvalidPiecesLength(t *testing.T) {
	infoDict := map[string]any{
		"name":         "test.iso",
		"piece length": int64(524288),
		"pieces":       "abc",
		"length":       int64(524288),
	}
	data := buildTorrent(t, "", infoDict)
	_, err := metainfo.Decode(bytes.NewReader(data))
	if err == nil {
		t.Error("want error for pieces length not multiple of 20, got nil")
	}
}

func TestHashString(t *testing.T) {
	var h metainfo.Hash
	h[0] = 0xde
	h[1] = 0xad
	s := h.String()
	if !strings.HasPrefix(s, "dead") {
		t.Errorf("Hash.String() = %q, want prefix dead", s)
	}
	if len(s) != 40 {
		t.Errorf("Hash.String() len = %d, want 40", len(s))
	}
}

func TestInfoHashVectorsAndRawInfo(t *testing.T) {
	t.Run("v1", func(t *testing.T) {
		info := map[string]any{
			"length":       int64(3),
			"name":         "a",
			"piece length": int64(4),
			"pieces":       zeroHashes(1),
		}
		rawInfo, err := bencode.EncodeToString(info)
		if err != nil {
			t.Fatal(err)
		}
		data := encodeTop(t, map[string]any{"info": info})
		m, err := metainfo.Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if string(m.RawInfo) != rawInfo {
			t.Fatalf("RawInfo = %q, want %q", m.RawInfo, rawInfo)
		}
		if got, want := m.InfoHash.String(), "6e3b0f4aaa0f5dfa01fa6884691c10cae0881c85"; got != want {
			t.Errorf("v1 info hash = %s, want %s", got, want)
		}
		hashes := m.Hashes()
		if hashes.V1 == nil || hashes.V2 != nil || *hashes.V1 != m.InfoHash {
			t.Fatalf("Hashes() = %#v, want only v1", hashes)
		}
	})

	t.Run("v2", func(t *testing.T) {
		info := map[string]any{
			"file tree": map[string]any{
				"empty": map[string]any{"": map[string]any{"length": int64(0)}},
			},
			"meta version": int64(2),
			"name":         "x",
			"piece length": int64(16 << 10),
		}
		rawInfo, err := bencode.EncodeToString(info)
		if err != nil {
			t.Fatal(err)
		}
		m, err := metainfo.Decode(bytes.NewReader(encodeTop(t, map[string]any{
			"info":         info,
			"piece layers": map[string]any{},
		})))
		if err != nil {
			t.Fatal(err)
		}
		if string(m.RawInfo) != rawInfo {
			t.Fatalf("RawInfo = %q, want %q", m.RawInfo, rawInfo)
		}
		if got, want := m.InfoHashV2.String(), "cd77dbf100d42b1a2b3682896b55b101fc63d12f6ca034ce026ce370c82b8e87"; got != want {
			t.Errorf("v2 info hash = %s, want %s", got, want)
		}
		hashes := m.Hashes()
		if hashes.V1 != nil || hashes.V2 == nil || *hashes.V2 != m.InfoHashV2 {
			t.Fatalf("Hashes() = %#v, want only v2", hashes)
		}
	})

	t.Run("hybrid", func(t *testing.T) {
		root := hashV2('r')
		info := map[string]any{
			"file tree": map[string]any{
				"a": map[string]any{"": map[string]any{
					"length":      int64(1),
					"pieces root": string(root[:]),
				}},
			},
			"length":       int64(1),
			"meta version": int64(2),
			"name":         "a",
			"piece length": int64(16 << 10),
			"pieces":       strings.Repeat("p", 20),
		}
		rawInfo, err := bencode.EncodeToString(info)
		if err != nil {
			t.Fatal(err)
		}
		m, err := metainfo.Decode(bytes.NewReader(encodeTop(t, map[string]any{
			"info":         info,
			"piece layers": map[string]any{},
		})))
		if err != nil {
			t.Fatal(err)
		}
		if string(m.RawInfo) != rawInfo {
			t.Fatalf("RawInfo = %q, want %q", m.RawInfo, rawInfo)
		}
		if got, want := m.InfoHash.String(), "81ca199e3b6652cdcd542877bb8d243b0776b396"; got != want {
			t.Errorf("hybrid v1 info hash = %s, want %s", got, want)
		}
		if got, want := m.InfoHashV2.String(), "4d0e2e7fb511ce92e2f21eb307dff56cda66e02c2c14d6cda02d97b3a8aea6e6"; got != want {
			t.Errorf("hybrid v2 info hash = %s, want %s", got, want)
		}
		hashes := m.Hashes()
		if hashes.V1 == nil || hashes.V2 == nil || *hashes.V1 != m.InfoHash || *hashes.V2 != m.InfoHashV2 {
			t.Fatalf("Hashes() = %#v, want v1 and v2", hashes)
		}
	})
}

func TestDecodeInfoV1(t *testing.T) {
	raw, err := bencode.EncodeToString(validV1Info())
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(raw)
	m, err := metainfo.DecodeInfo(input)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := sha1.Sum([]byte(raw))
	input[0] = 'x'
	if !bytes.Equal(m.RawInfo, []byte(raw)) {
		t.Fatal("RawInfo aliases the input")
	}
	if m.InfoHash != wantHash || !m.Info.HasV1() || m.Info.HasV2() {
		t.Fatalf("decoded v1 info or hash differs: %#v", m)
	}
	if err := m.SetPieceLayers(nil); err == nil {
		t.Fatal("SetPieceLayers accepted v1 metadata")
	}

	for _, invalid := range [][]byte{
		append([]byte(raw), 'x'),
		[]byte("d4:name4:file6:lengthi1e12:piece lengthi16384e6:pieces20:" + zeroHashes(1) + "e"),
	} {
		if got, err := metainfo.DecodeInfo(invalid); err == nil {
			t.Fatalf("DecodeInfo(%q) succeeded: %#v", invalid, got)
		}
	}
}

func TestDecodeInfoV2PieceLayers(t *testing.T) {
	fixture := validV2Fixture()
	raw, err := bencode.EncodeToString(fixture.info)
	if err != nil {
		t.Fatal(err)
	}
	decode := func(t *testing.T) *metainfo.MetaInfo {
		t.Helper()
		m, err := metainfo.DecodeInfo([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if !m.Info.HasV2() || m.PieceLayers != nil {
			t.Fatalf("decoded v2 metadata is not pending piece layers: %#v", m)
		}
		if got, want := m.InfoHashV2, metainfo.HashV2(sha256.Sum256([]byte(raw))); got != want {
			t.Fatalf("InfoHashV2 = %s, want %s", got, want)
		}
		return m
	}

	t.Run("success copies input and preserves hashes", func(t *testing.T) {
		m := decode(t)
		beforeRaw := append([]byte(nil), m.RawInfo...)
		beforeHash := m.InfoHashV2
		layer := append([]metainfo.HashV2(nil), fixture.layer...)
		layers := map[metainfo.HashV2][]metainfo.HashV2{fixture.largeRoot: layer}
		if err := m.SetPieceLayers(layers); err != nil {
			t.Fatal(err)
		}
		layer[0][0] ^= 0xff
		delete(layers, fixture.largeRoot)
		if got := m.PieceLayers[fixture.largeRoot]; len(got) != len(fixture.layer) || got[0] != fixture.layer[0] {
			t.Fatalf("PieceLayers aliases input: %#v", got)
		}
		if !bytes.Equal(m.RawInfo, beforeRaw) || m.InfoHashV2 != beforeHash {
			t.Fatal("setting piece layers changed RawInfo or its hash")
		}

		beforeLayer := append([]metainfo.HashV2(nil), m.PieceLayers[fixture.largeRoot]...)
		if err := m.SetPieceLayers(nil); err == nil {
			t.Fatal("SetPieceLayers accepted a missing layer")
		}
		if got := m.PieceLayers[fixture.largeRoot]; len(got) != len(beforeLayer) || got[0] != beforeLayer[0] {
			t.Fatal("failed SetPieceLayers modified the existing layer")
		}
	})

	tampered := append([]metainfo.HashV2(nil), fixture.layer...)
	tampered[0][0] ^= 0xff
	extraRoot := hashV2(0xee)
	for _, test := range []struct {
		name   string
		layers map[metainfo.HashV2][]metainfo.HashV2
	}{
		{name: "missing", layers: map[metainfo.HashV2][]metainfo.HashV2{}},
		{name: "extra", layers: map[metainfo.HashV2][]metainfo.HashV2{
			fixture.largeRoot: fixture.layer,
			extraRoot:         fixture.layer,
		}},
		{name: "wrong count", layers: map[metainfo.HashV2][]metainfo.HashV2{
			fixture.largeRoot: fixture.layer[:2],
		}},
		{name: "tampered", layers: map[metainfo.HashV2][]metainfo.HashV2{
			fixture.largeRoot: tampered,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := decode(t)
			beforeRaw := append([]byte(nil), m.RawInfo...)
			beforeHash := m.InfoHashV2
			if err := m.SetPieceLayers(test.layers); err == nil {
				t.Fatal("SetPieceLayers succeeded")
			}
			if m.PieceLayers != nil || !bytes.Equal(m.RawInfo, beforeRaw) || m.InfoHashV2 != beforeHash {
				t.Fatal("failed SetPieceLayers modified metadata")
			}
		})
	}
}

func TestDecodeRejectsMalformedV1(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"missing name", func(info map[string]any) { delete(info, "name") }},
		{"name type", func(info map[string]any) { info["name"] = int64(1) }},
		{"empty name", func(info map[string]any) { info["name"] = "" }},
		{"name UTF-8", func(info map[string]any) { info["name"] = "\xff" }},
		{"missing piece length", func(info map[string]any) { delete(info, "piece length") }},
		{"piece length type", func(info map[string]any) { info["piece length"] = "16384" }},
		{"zero piece length", func(info map[string]any) { info["piece length"] = int64(0) }},
		{"negative piece length", func(info map[string]any) { info["piece length"] = int64(-1) }},
		{"piece length overflow", func(info map[string]any) {
			info["piece length"] = new(big.Int).Add(big.NewInt(math.MaxInt64), big.NewInt(1))
		}},
		{"missing pieces", func(info map[string]any) { delete(info, "pieces") }},
		{"pieces type", func(info map[string]any) { info["pieces"] = []any{} }},
		{"pieces shape", func(info map[string]any) { info["pieces"] = "short" }},
		{"piece count short", func(info map[string]any) { info["pieces"] = "" }},
		{"piece count long", func(info map[string]any) { info["pieces"] = zeroHashes(2) }},
		{"both length and files", func(info map[string]any) { info["files"] = []any{} }},
		{"neither length nor files", func(info map[string]any) { delete(info, "length") }},
		{"negative length", func(info map[string]any) { info["length"] = int64(-1) }},
		{"length overflow", func(info map[string]any) {
			info["length"] = new(big.Int).Add(big.NewInt(math.MaxInt64), big.NewInt(1))
		}},
		{"files type", func(info map[string]any) {
			delete(info, "length")
			info["files"] = "files"
		}},
		{"empty files", func(info map[string]any) {
			delete(info, "length")
			info["pieces"] = ""
			info["files"] = []any{}
		}},
		{"file entry type", func(info map[string]any) {
			delete(info, "length")
			info["files"] = []any{"file"}
		}},
		{"file missing length", func(info map[string]any) {
			delete(info, "length")
			info["files"] = []any{map[string]any{"path": []any{"a"}}}
		}},
		{"file negative length", func(info map[string]any) {
			delete(info, "length")
			info["files"] = []any{map[string]any{"length": int64(-1), "path": []any{"a"}}}
		}},
		{"file missing path", func(info map[string]any) {
			delete(info, "length")
			info["files"] = []any{map[string]any{"length": int64(1)}}
		}},
		{"file path type", func(info map[string]any) {
			delete(info, "length")
			info["files"] = []any{map[string]any{"length": int64(1), "path": "a"}}
		}},
		{"empty file path", func(info map[string]any) {
			delete(info, "length")
			info["files"] = []any{map[string]any{"length": int64(1), "path": []any{}}}
		}},
		{"empty path component", func(info map[string]any) {
			delete(info, "length")
			info["files"] = []any{map[string]any{"length": int64(1), "path": []any{""}}}
		}},
		{"path component type", func(info map[string]any) {
			delete(info, "length")
			info["files"] = []any{map[string]any{"length": int64(1), "path": []any{int64(1)}}}
		}},
		{"path component UTF-8", func(info map[string]any) {
			delete(info, "length")
			info["files"] = []any{map[string]any{"length": int64(1), "path": []any{"\xff"}}}
		}},
		{"file attr type", func(info map[string]any) {
			delete(info, "length")
			info["files"] = []any{map[string]any{"attr": int64(1), "length": int64(1), "path": []any{"a"}}}
		}},
		{"symlink without attr", func(info map[string]any) {
			delete(info, "length")
			info["pieces"] = ""
			info["files"] = []any{map[string]any{"length": int64(0), "path": []any{"a"}, "symlink path": []any{"b"}}}
		}},
		{"symlink nonzero length", func(info map[string]any) {
			delete(info, "length")
			info["files"] = []any{map[string]any{"attr": "l", "length": int64(1), "path": []any{"a"}, "symlink path": []any{"b"}}}
		}},
		{"symlink missing target", func(info map[string]any) {
			delete(info, "length")
			info["pieces"] = ""
			info["files"] = []any{map[string]any{"attr": "l", "length": int64(0), "path": []any{"a"}}}
		}},
		{"empty padding", func(info map[string]any) {
			delete(info, "length")
			info["pieces"] = ""
			info["files"] = []any{map[string]any{"attr": "p", "length": int64(0), "path": []any{"a"}}}
		}},
		{"file sha1 shape", func(info map[string]any) {
			delete(info, "length")
			info["files"] = []any{map[string]any{"length": int64(1), "path": []any{"a"}, "sha1": "short"}}
		}},
		{"total length overflow", func(info map[string]any) {
			delete(info, "length")
			info["files"] = []any{
				map[string]any{"length": int64(math.MaxInt64), "path": []any{"a"}},
				map[string]any{"length": int64(1), "path": []any{"b"}},
			}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := validV1Info()
			test.mutate(info)
			if got, err := metainfo.Decode(bytes.NewReader(encodeTop(t, map[string]any{"info": info}))); err == nil {
				t.Fatalf("Decode() succeeded: %#v", got)
			}
		})
	}
}

func TestDecodeRejectsNoncanonicalMetainfo(t *testing.T) {
	info, err := bencode.EncodeToString(validV1Info())
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{
		"d4:info" + info + "8:announce1:xe",
		"d4:info" + info + "4:info" + info + "e",
		"d4:info" + info + "eignored",
	} {
		if got, err := metainfo.Decode(strings.NewReader(data)); err == nil {
			t.Fatalf("Decode(%q) succeeded: %#v", data, got)
		}
	}
}

func TestDecodeExtensions(t *testing.T) {
	for _, urlList := range []any{
		"https://seed.example/file",
		[]any{"https://seed-1.example/file", "ftp://seed-2.example/file"},
	} {
		info := validV1Info()
		info["private"] = int64(1)
		top := map[string]any{
			"announce": "https://primary.example/announce",
			"announce-list": []any{
				[]any{"https://primary.example/announce"},
				[]any{"udp://backup.example:80/announce", "https://last.example/announce"},
			},
			"comment":       "comment",
			"created by":    "creator",
			"creation date": int64(1234),
			"encoding":      "UTF-8",
			"info":          info,
			"nodes": []any{
				[]any{"router.example", int64(6881)},
			},
			"url-list": urlList,
		}
		m, err := metainfo.Decode(bytes.NewReader(encodeTop(t, top)))
		if err != nil {
			t.Fatal(err)
		}
		if !m.Info.Private || m.Comment != "comment" || m.CreatedBy != "creator" || m.CreationDate != 1234 || m.Encoding != "UTF-8" {
			t.Errorf("metadata not preserved: %#v", m)
		}
		if len(m.AnnounceList) != 2 || len(m.AnnounceList[1]) != 2 || m.AnnounceList[1][0] != "udp://backup.example:80/announce" {
			t.Errorf("AnnounceList = %#v", m.AnnounceList)
		}
		if len(m.Trackers()) != 3 {
			t.Errorf("Trackers() = %#v", m.Trackers())
		}
		if len(m.Nodes) != 1 || m.Nodes[0] != (metainfo.Node{Host: "router.example", Port: 6881}) {
			t.Errorf("Nodes = %#v", m.Nodes)
		}
		wantURLs := 1
		if _, ok := urlList.([]any); ok {
			wantURLs = 2
		}
		if len(m.URLList) != wantURLs {
			t.Errorf("URLList = %#v, want %d entries", m.URLList, wantURLs)
		}
	}
}

func TestDecodePrivateValues(t *testing.T) {
	for _, test := range []struct {
		value int64
		want  bool
	}{
		{value: 0, want: false},
		{value: 1, want: true},
	} {
		info := validV1Info()
		info["private"] = test.value
		m, err := metainfo.Decode(bytes.NewReader(encodeTop(t, map[string]any{"info": info})))
		if err != nil {
			t.Fatalf("private=%d: %v", test.value, err)
		}
		if m.Info.Private != test.want {
			t.Errorf("private=%d: Private = %v, want %v", test.value, m.Info.Private, test.want)
		}
	}
}

func TestDecodeV1FileAttributes(t *testing.T) {
	fileSHA1 := strings.Repeat("s", 20)
	info := map[string]any{
		"files": []any{
			map[string]any{
				"attr":   "xh",
				"length": int64(1),
				"path":   []any{"target"},
				"sha1":   fileSHA1,
			},
			map[string]any{
				"attr":         "l",
				"length":       int64(0),
				"path":         []any{"link"},
				"symlink path": []any{"target"},
			},
		},
		"name":         "bundle",
		"piece length": int64(16 << 10),
		"pieces":       zeroHashes(1),
	}
	m, err := metainfo.Decode(bytes.NewReader(encodeTop(t, map[string]any{"info": info})))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Info.Files) != 2 || m.Info.Files[0].Attr != "xh" || m.Info.Files[0].SHA1 == nil || string(m.Info.Files[0].SHA1[:]) != fileSHA1 {
		t.Fatalf("regular file attributes = %#v", m.Info.Files)
	}
	link := m.Info.Files[1]
	if !link.IsSymlink() || link.Offset != 1 || len(link.SymlinkPath) != 1 || link.SymlinkPath[0] != "target" {
		t.Errorf("symlink = %#v", link)
	}
}

func TestDecodeRejectsMalformedExtensions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any, map[string]any)
	}{
		{"announce type", func(top, _ map[string]any) { top["announce"] = int64(1) }},
		{"announce UTF-8", func(top, _ map[string]any) { top["announce"] = "\xff" }},
		{"comment type", func(top, _ map[string]any) { top["comment"] = int64(1) }},
		{"created by UTF-8", func(top, _ map[string]any) { top["created by"] = "\xff" }},
		{"creation date type", func(top, _ map[string]any) { top["creation date"] = "now" }},
		{"creation date overflow", func(top, _ map[string]any) {
			top["creation date"] = new(big.Int).Add(big.NewInt(math.MaxInt64), big.NewInt(1))
		}},
		{"announce-list type", func(top, _ map[string]any) { top["announce-list"] = "tracker" }},
		{"announce tier type", func(top, _ map[string]any) { top["announce-list"] = []any{"tracker"} }},
		{"announce entry type", func(top, _ map[string]any) { top["announce-list"] = []any{[]any{int64(1)}} }},
		{"url-list type", func(top, _ map[string]any) { top["url-list"] = int64(1) }},
		{"url-list entry type", func(top, _ map[string]any) { top["url-list"] = []any{int64(1)} }},
		{"nodes type", func(top, _ map[string]any) { top["nodes"] = "node" }},
		{"node shape", func(top, _ map[string]any) { top["nodes"] = []any{[]any{"host"}} }},
		{"node host type", func(top, _ map[string]any) { top["nodes"] = []any{[]any{int64(1), int64(80)}} }},
		{"node empty host", func(top, _ map[string]any) { top["nodes"] = []any{[]any{"", int64(80)}} }},
		{"node port type", func(top, _ map[string]any) { top["nodes"] = []any{[]any{"host", "80"}} }},
		{"node port low", func(top, _ map[string]any) { top["nodes"] = []any{[]any{"host", int64(0)}} }},
		{"node port high", func(top, _ map[string]any) { top["nodes"] = []any{[]any{"host", int64(65536)}} }},
		{"private type", func(_, info map[string]any) { info["private"] = "1" }},
		{"private negative", func(_, info map[string]any) { info["private"] = int64(-1) }},
		{"private high", func(_, info map[string]any) { info["private"] = int64(2) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := validV1Info()
			top := map[string]any{"info": info}
			test.mutate(top, info)
			if got, err := metainfo.Decode(bytes.NewReader(encodeTop(t, top))); err == nil {
				t.Fatalf("Decode() succeeded: %#v", got)
			}
		})
	}
}

func TestDecodeV2Only(t *testing.T) {
	fixture := validV2Fixture()
	rawInfo, err := bencode.EncodeToString(fixture.info)
	if err != nil {
		t.Fatal(err)
	}
	m, err := metainfo.Decode(bytes.NewReader(encodeTop(t, fixture.top)))
	if err != nil {
		t.Fatal(err)
	}
	if string(m.RawInfo) != rawInfo {
		t.Errorf("RawInfo differs from exact encoded info")
	}
	if m.Info.HasV1() || !m.Info.HasV2() || m.Info.IsHybrid() {
		t.Errorf("versions: v1=%v v2=%v hybrid=%v", m.Info.HasV1(), m.Info.HasV2(), m.Info.IsHybrid())
	}
	if m.Info.MetaVersion != 2 || m.Info.PieceLength != 16<<10 {
		t.Errorf("Info version fields = %#v", m.Info)
	}
	if got, want := m.Info.PieceCount(), 4; got != want {
		t.Errorf("PieceCount() = %d, want %d", got, want)
	}
	if got, want := m.Info.TotalLength(), int64(40_001); got != want {
		t.Errorf("TotalLength() = %d, want %d", got, want)
	}
	if len(m.Info.Files) != 4 || len(m.Info.V2Files) != 4 {
		t.Fatalf("file counts = %d/%d, want 4/4", len(m.Info.Files), len(m.Info.V2Files))
	}
	wantPaths := []string{"empty", "large.bin", "link", "small.bin"}
	wantOffsets := []int64{0, 0, 40_000, 3 * (16 << 10)}
	for i, file := range m.Info.V2Files {
		if len(file.Path) != 1 || file.Path[0] != wantPaths[i] || file.Offset != wantOffsets[i] {
			t.Errorf("V2Files[%d] = %#v, want path %q offset %d", i, file, wantPaths[i], wantOffsets[i])
		}
	}
	if !m.Info.V2Files[2].IsSymlink() || len(m.Info.V2Files[2].SymlinkPath) != 1 || m.Info.V2Files[2].SymlinkPath[0] != "large.bin" {
		t.Errorf("symlink = %#v", m.Info.V2Files[2])
	}
	if m.Info.V2Files[3].Attr != "x" || m.Info.V2Files[3].PiecesRoot == nil || *m.Info.V2Files[3].PiecesRoot != fixture.smallRoot {
		t.Errorf("small file = %#v", m.Info.V2Files[3])
	}
	layer, ok := m.PieceLayers[fixture.largeRoot]
	if !ok || len(layer) != len(fixture.layer) {
		t.Fatalf("PieceLayers = %#v", m.PieceLayers)
	}
	for i := range layer {
		if layer[i] != fixture.layer[i] {
			t.Errorf("piece layer hash %d differs", i)
		}
	}
	if m.InfoHash != (metainfo.Hash{}) || m.Hashes().V1 != nil || m.Hashes().V2 == nil {
		t.Errorf("v2-only hashes are ambiguous: %#v", m.Hashes())
	}
	if err := m.Info.ValidatePaths(); err != nil {
		t.Errorf("ValidatePaths: %v", err)
	}
}

func TestDecodeV2NestedFileTree(t *testing.T) {
	info := map[string]any{
		"file tree": map[string]any{
			"dir": map[string]any{
				"sub": map[string]any{
					"file": map[string]any{"": map[string]any{"length": int64(0)}},
				},
			},
		},
		"meta version": int64(2),
		"name":         "bundle",
		"piece length": int64(16 << 10),
	}
	m, err := metainfo.Decode(bytes.NewReader(encodeTop(t, map[string]any{
		"info":         info,
		"piece layers": map[string]any{},
	})))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Info.V2Files) != 1 || strings.Join(m.Info.V2Files[0].Path, "/") != "dir/sub/file" {
		t.Fatalf("V2Files = %#v", m.Info.V2Files)
	}
}

func TestDecodeV2PreservesByteStringPath(t *testing.T) {
	component := string([]byte{0xff, 'x'})
	info := map[string]any{
		"file tree": map[string]any{
			component: map[string]any{"": map[string]any{"length": int64(0)}},
		},
		"meta version": int64(2),
		"name":         "bundle",
		"piece length": int64(16 << 10),
	}
	m, err := metainfo.Decode(bytes.NewReader(encodeTop(t, map[string]any{
		"info":         info,
		"piece layers": map[string]any{},
	})))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Info.V2Files) != 1 || len(m.Info.V2Files[0].Path) != 1 || !bytes.Equal([]byte(m.Info.V2Files[0].Path[0]), []byte(component)) {
		t.Fatalf("V2Files = %#v", m.Info.V2Files)
	}
	if err := m.Info.ValidatePaths(); err == nil {
		t.Fatal("ValidatePaths accepted a non-UTF-8 v2 path")
	}
}

func TestDecodeV2AcceptsUnverifiableSinglePieceRoot(t *testing.T) {
	root := hashV2(0xff)
	info := map[string]any{
		"file tree": map[string]any{
			"file": map[string]any{"": map[string]any{
				"length":      int64(1),
				"pieces root": string(root[:]),
			}},
		},
		"meta version": int64(2),
		"name":         "file",
		"piece length": int64(16 << 10),
	}
	m, err := metainfo.Decode(bytes.NewReader(encodeTop(t, map[string]any{
		"info":         info,
		"piece layers": map[string]any{},
	})))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Info.V2Files[0].PiecesRoot; got == nil || *got != root {
		t.Fatalf("PiecesRoot = %v, want %s", got, root)
	}
}

func TestDecodeRejectsMalformedV2(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(v2TestFixture)
	}{
		{"meta version type", func(f v2TestFixture) { f.info["meta version"] = "2" }},
		{"unsupported meta version", func(f v2TestFixture) { f.info["meta version"] = int64(3) }},
		{"small piece length", func(f v2TestFixture) { f.info["piece length"] = int64(8192) }},
		{"non-power-of-two piece length", func(f v2TestFixture) { f.info["piece length"] = int64(24 << 10) }},
		{"name UTF-8", func(f v2TestFixture) { f.info["name"] = "\xff" }},
		{"missing file tree", func(f v2TestFixture) { delete(f.info, "file tree") }},
		{"file tree type", func(f v2TestFixture) { f.info["file tree"] = "tree" }},
		{"empty file tree", func(f v2TestFixture) { f.info["file tree"] = map[string]any{} }},
		{"root is file", func(f v2TestFixture) {
			f.info["file tree"] = map[string]any{"": map[string]any{"length": int64(0)}}
		}},
		{"empty directory", func(f v2TestFixture) {
			f.info["file tree"].(map[string]any)["directory"] = map[string]any{}
		}},
		{"file properties type", func(f v2TestFixture) {
			f.info["file tree"].(map[string]any)["empty"] = map[string]any{"": "properties"}
		}},
		{"file and directory collision", func(f v2TestFixture) {
			f.info["file tree"].(map[string]any)["empty"].(map[string]any)["child"] = map[string]any{"": map[string]any{"length": int64(0)}}
		}},
		{"negative length", func(f v2TestFixture) { v2Properties(f.info, "empty")["length"] = int64(-1) }},
		{"length overflow", func(f v2TestFixture) {
			v2Properties(f.info, "empty")["length"] = new(big.Int).Add(big.NewInt(math.MaxInt64), big.NewInt(1))
		}},
		{"missing pieces root", func(f v2TestFixture) { delete(v2Properties(f.info, "large.bin"), "pieces root") }},
		{"pieces root type", func(f v2TestFixture) { v2Properties(f.info, "large.bin")["pieces root"] = int64(1) }},
		{"pieces root shape", func(f v2TestFixture) { v2Properties(f.info, "large.bin")["pieces root"] = "short" }},
		{"empty file pieces root", func(f v2TestFixture) { v2Properties(f.info, "empty")["pieces root"] = strings.Repeat("r", 32) }},
		{"symlink length", func(f v2TestFixture) { v2Properties(f.info, "link")["length"] = int64(1) }},
		{"symlink target missing", func(f v2TestFixture) { delete(v2Properties(f.info, "link"), "symlink path") }},
		{"symlink attr missing", func(f v2TestFixture) { delete(v2Properties(f.info, "link"), "attr") }},
		{"symlink target UTF-8", func(f v2TestFixture) { v2Properties(f.info, "link")["symlink path"] = []any{"\xff"} }},
		{"v2 padding file", func(f v2TestFixture) { v2Properties(f.info, "empty")["attr"] = "p" }},
		{"piece layers missing", func(f v2TestFixture) { delete(f.top, "piece layers") }},
		{"piece layers type", func(f v2TestFixture) { f.top["piece layers"] = "layers" }},
		{"required layer missing", func(f v2TestFixture) { f.top["piece layers"] = map[string]any{} }},
		{"layer root shape", func(f v2TestFixture) { f.top["piece layers"] = map[string]any{"short": ""} }},
		{"unknown layer root", func(f v2TestFixture) {
			root := hashV2(0xee)
			f.top["piece layers"] = map[string]any{string(root[:]): joinV2Hashes(f.layer)}
		}},
		{"single-piece layer", func(f v2TestFixture) {
			layers := f.top["piece layers"].(map[string]any)
			layers[string(f.smallRoot[:])] = string(f.smallRoot[:])
		}},
		{"layer value type", func(f v2TestFixture) {
			f.top["piece layers"].(map[string]any)[string(f.largeRoot[:])] = int64(1)
		}},
		{"layer value shape", func(f v2TestFixture) {
			f.top["piece layers"].(map[string]any)[string(f.largeRoot[:])] = joinV2Hashes(f.layer) + "x"
		}},
		{"layer hash count", func(f v2TestFixture) {
			f.top["piece layers"].(map[string]any)[string(f.largeRoot[:])] = joinV2Hashes(f.layer[:2])
		}},
		{"layer root mismatch", func(f v2TestFixture) {
			bad := append([]metainfo.HashV2(nil), f.layer...)
			bad[0][0] ^= 0xff
			f.top["piece layers"].(map[string]any)[string(f.largeRoot[:])] = joinV2Hashes(bad)
		}},
		{"offset overflow", func(f v2TestFixture) {
			rootA := hashV2(0xa0)
			rootB := hashV2(0xb0)
			f.info["file tree"] = map[string]any{
				"a": map[string]any{"": map[string]any{"length": int64(math.MaxInt64 - 100), "pieces root": string(rootA[:])}},
				"b": map[string]any{"": map[string]any{"length": int64(200), "pieces root": string(rootB[:])}},
			}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := validV2Fixture()
			test.mutate(fixture)
			if got, err := metainfo.Decode(bytes.NewReader(encodeTop(t, fixture.top))); err == nil {
				t.Fatalf("Decode() succeeded: %#v", got)
			}
		})
	}
}

func TestDecodeHybrid(t *testing.T) {
	fixture := validHybridFixture()
	m, err := metainfo.Decode(bytes.NewReader(encodeTop(t, fixture.top)))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Info.IsHybrid() || !m.Info.HasV1() || !m.Info.HasV2() {
		t.Fatalf("hybrid version flags are false")
	}
	if len(m.Info.Files) != 3 || len(m.Info.V2Files) != 2 {
		t.Fatalf("file counts = %d/%d, want 3/2", len(m.Info.Files), len(m.Info.V2Files))
	}
	if !m.Info.Files[1].IsPadding() || m.Info.Files[2].Offset != 16<<10 {
		t.Errorf("v1 padding/alignment = %#v", m.Info.Files)
	}
	if m.Info.Files[0].PiecesRoot == nil || m.Info.Files[2].PiecesRoot == nil {
		t.Errorf("v2 roots were not attached to matching v1 files")
	}
	if got, want := m.Info.PieceCount(), 2; got != want {
		t.Errorf("PieceCount() = %d, want %d", got, want)
	}
	if hashes := m.Hashes(); hashes.V1 == nil || hashes.V2 == nil {
		t.Errorf("Hashes() = %#v, want both", hashes)
	}
}

func TestDecodeHybridOptionalFinalTailPadding(t *testing.T) {
	fixture := validHybridFixture()
	fixture.info["files"] = append(fixture.info["files"].([]any), map[string]any{
		"attr":   "p",
		"length": int64((16 << 10) - 200),
		"path":   []any{".pad", "16184"},
	})
	m, err := metainfo.Decode(bytes.NewReader(encodeTop(t, fixture.top)))
	if err != nil {
		t.Fatal(err)
	}
	if files := m.Info.Files; len(files) != 4 || !files[3].IsPadding() || files[3].Offset+files[3].Length != 2*(16<<10) {
		t.Fatalf("final padding = %#v", m.Info.Files)
	}
}

func TestDecodeHybridPaddingAroundEmptyFiles(t *testing.T) {
	for _, paddingBeforeEmpty := range []bool{false, true} {
		fixture := validHybridFixture()
		fixture.info["file tree"].(map[string]any)["a-empty"] = map[string]any{"": map[string]any{"length": int64(0)}}
		files := fixture.info["files"].([]any)
		empty := map[string]any{"length": int64(0), "path": []any{"a-empty"}}
		if paddingBeforeEmpty {
			fixture.info["files"] = []any{files[0], files[1], empty, files[2]}
		} else {
			fixture.info["files"] = []any{files[0], empty, files[1], files[2]}
		}
		if _, err := metainfo.Decode(bytes.NewReader(encodeTop(t, fixture.top))); err != nil {
			t.Errorf("paddingBeforeEmpty=%v: %v", paddingBeforeEmpty, err)
		}
	}
}

func TestDecodeRejectsInconsistentHybrid(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(hybridTestFixture)
	}{
		{"path", func(f hybridTestFixture) {
			f.info["files"].([]any)[0].(map[string]any)["path"] = []any{"different"}
		}},
		{"length", func(f hybridTestFixture) {
			v2Properties(f.info, "a")["length"] = int64(101)
		}},
		{"alignment", func(f hybridTestFixture) {
			f.info["files"].([]any)[1].(map[string]any)["length"] = int64((16 << 10) - 101)
		}},
		{"overfilled alignment", func(f hybridTestFixture) {
			f.info["files"].([]any)[1].(map[string]any)["length"] = int64((16 << 10) - 99)
		}},
		{"leading padding", func(f hybridTestFixture) {
			f.info["files"] = append([]any{
				map[string]any{"attr": "p", "length": int64(1), "path": []any{".pad", "leading"}},
			}, f.info["files"].([]any)...)
		}},
		{"partial final padding", func(f hybridTestFixture) {
			f.info["files"] = append(f.info["files"].([]any), map[string]any{
				"attr": "p", "length": int64(1), "path": []any{".pad", "partial-tail"},
			})
		}},
		{"v1 file missing", func(f hybridTestFixture) {
			f.info["files"] = f.info["files"].([]any)[:2]
			f.info["pieces"] = zeroHashes(1)
		}},
		{"v1 extra piece", func(f hybridTestFixture) {
			f.info["files"] = append(f.info["files"].([]any), map[string]any{
				"attr": "p", "length": int64(16 << 10), "path": []any{".pad", "extra"},
			})
			f.info["pieces"] = zeroHashes(3)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := validHybridFixture()
			test.mutate(fixture)
			if got, err := metainfo.Decode(bytes.NewReader(encodeTop(t, fixture.top))); err == nil {
				t.Fatalf("Decode() succeeded: %#v", got)
			}
		})
	}

	t.Run("single-file name", func(t *testing.T) {
		root := hashV2(1)
		info := map[string]any{
			"file tree": map[string]any{
				"different": map[string]any{"": map[string]any{"length": int64(1), "pieces root": string(root[:])}},
			},
			"length":       int64(1),
			"meta version": int64(2),
			"name":         "name",
			"piece length": int64(16 << 10),
			"pieces":       zeroHashes(1),
		}
		if got, err := metainfo.Decode(bytes.NewReader(encodeTop(t, map[string]any{
			"info":         info,
			"piece layers": map[string]any{},
		}))); err == nil {
			t.Fatalf("Decode() succeeded: %#v", got)
		}
	})
}

func TestPathValidationIsSeparate(t *testing.T) {
	info := map[string]any{
		"files": []any{
			map[string]any{"length": int64(1), "path": []any{"..", "file"}},
		},
		"name":         "bundle",
		"piece length": int64(16 << 10),
		"pieces":       zeroHashes(1),
	}
	m, err := metainfo.Decode(bytes.NewReader(encodeTop(t, map[string]any{"info": info})))
	if err != nil {
		t.Fatalf("Decode rejected a syntactically valid path before sanitisation: %v", err)
	}
	if err := m.Info.ValidatePaths(); err == nil {
		t.Fatal("ValidatePaths accepted traversal")
	}
	if err := metainfo.ValidatePath([]string{"safe", "file"}); err != nil {
		t.Fatalf("ValidatePath(safe): %v", err)
	}
	for _, path := range [][]string{
		nil,
		{""},
		{"."},
		{".."},
		{"dir/file"},
		{"dir\\file"},
		{"nul\x00file"},
	} {
		if err := metainfo.ValidatePath(path); err == nil {
			t.Errorf("ValidatePath(%q) succeeded", path)
		}
	}
}

func TestHashV2String(t *testing.T) {
	hash := hashV2(0xab)
	if got, want := hash.String(), strings.Repeat("ab", 32); got != want {
		t.Errorf("HashV2.String() = %q, want %q", got, want)
	}
	decoded, err := hex.DecodeString(hash.String())
	if err != nil || !bytes.Equal(decoded, hash[:]) {
		t.Errorf("HashV2.String() is not round-trippable hex")
	}
}
