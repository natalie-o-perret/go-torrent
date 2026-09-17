package storage

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/natalie-o-perret/go-torrent/bencode"
	"github.com/natalie-o-perret/go-torrent/metainfo"
)

func decodeMeta(t *testing.T, info, layers map[string]any) *metainfo.MetaInfo {
	t.Helper()
	top := map[string]any{"info": info}
	if _, ok := info["meta version"]; ok {
		if layers == nil {
			layers = map[string]any{}
		}
		top["piece layers"] = layers
	}
	encoded, err := bencode.EncodeToString(top)
	if err != nil {
		t.Fatalf("encode metainfo: %v", err)
	}
	meta, err := metainfo.Decode(strings.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode metainfo: %v", err)
	}
	return meta
}

func v1Hashes(data []byte, pieceLength int) string {
	var hashes []byte
	for len(data) > 0 {
		length := min(pieceLength, len(data))
		hash := sha1.Sum(data[:length])
		hashes = append(hashes, hash[:]...)
		data = data[length:]
	}
	return string(hashes)
}

func hashPair(left, right metainfo.HashV2) metainfo.HashV2 {
	var pair [64]byte
	copy(pair[:32], left[:])
	copy(pair[32:], right[:])
	return sha256.Sum256(pair[:])
}

func joinedHashes(hashes ...metainfo.HashV2) string {
	var joined []byte
	for _, hash := range hashes {
		joined = append(joined, hash[:]...)
	}
	return string(joined)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func TestV1CrossFileAndFinalPieces(t *testing.T) {
	const pieceLength = 4
	data := []byte("abcdefg")
	meta := decodeMeta(t, map[string]any{
		"files": []any{
			map[string]any{"length": int64(3), "path": []any{"a"}},
			map[string]any{"length": int64(4), "path": []any{"b"}},
		},
		"name":         "bundle",
		"piece length": int64(pieceLength),
		"pieces":       v1Hashes(data, pieceLength),
	}, nil)

	root := t.TempDir()
	store, err := New(root, meta)
	if err != nil {
		t.Fatal(err)
	}
	layout := store.Layout()
	if count, err := layout.PieceCount(V1); err != nil || count != 2 {
		t.Fatalf("PieceCount(V1) = %d, %v; want 2, nil", count, err)
	}
	if length, err := layout.PieceLength(V1, 1); err != nil || length != 3 {
		t.Fatalf("PieceLength(V1, 1) = %d, %v; want 3, nil", length, err)
	}
	if pieceRange, err := layout.PieceRange(V1, 1); err != nil || pieceRange != (ByteRange{Offset: 4, Length: 3}) {
		t.Fatalf("PieceRange(V1, 1) = %#v, %v", pieceRange, err)
	}
	spans, err := layout.PieceSpans(V1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 2 || spans[0].Path != "a" || spans[0].Length != 3 || spans[1].Path != "b" || spans[1].Length != 1 {
		t.Fatalf("PieceSpans(V1, 0) = %#v", spans)
	}
	spans, err = layout.Spans(V1, 0, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 2 || spans[0].FileOffset != 2 || spans[0].PieceOffset != 2 || spans[1].FileOffset != 0 || spans[1].PieceOffset != 3 {
		t.Fatalf("Spans(V1, 0, 2, 2) = %#v", spans)
	}
	for _, test := range []struct {
		begin  int64
		length int64
	}{{-1, 1}, {0, -1}, {3, 2}, {5, 0}} {
		if _, err := layout.Range(V1, 0, test.begin, test.length); err == nil {
			t.Errorf("Range(V1, 0, %d, %d) succeeded", test.begin, test.length)
		}
	}
	if _, err := layout.PieceLength(V1, 2); err == nil {
		t.Error("PieceLength accepted an out-of-range index")
	}
	if _, err := layout.PieceCount(V2); err == nil {
		t.Error("PieceCount accepted an absent v2 layout")
	}

	if err := store.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := store.WritePiece(V1, 0, data[:4]); err != nil {
		t.Fatal(err)
	}
	if err := store.WritePiece(V1, 1, data[4:]); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(root, "a")); !bytes.Equal(got, []byte("abc")) {
		t.Errorf("a = %q, want abc", got)
	}
	if got := readFile(t, filepath.Join(root, "b")); !bytes.Equal(got, []byte("defg")) {
		t.Errorf("b = %q, want defg", got)
	}
	if got, err := store.ReadPiece(V1, 0); err != nil || !bytes.Equal(got, data[:4]) {
		t.Fatalf("ReadPiece(V1, 0) = %q, %v", got, err)
	}
	verified, err := store.VerifyAll()
	if err != nil || !bytes.Equal(boolBytes(verified), []byte{1, 1}) {
		t.Fatalf("VerifyAll() = %v, %v", verified, err)
	}
}

func TestPaddingReadsZerosAndDiscardsWrites(t *testing.T) {
	logical := []byte{'a', 'b', 0, 0, 'c', 'd'}
	meta := decodeMeta(t, map[string]any{
		"files": []any{
			map[string]any{"length": int64(2), "path": []any{"a"}},
			map[string]any{"attr": "p", "length": int64(2), "path": []any{".pad", "2"}},
			map[string]any{"length": int64(2), "path": []any{"b"}},
		},
		"name":         "bundle",
		"piece length": int64(4),
		"pieces":       v1Hashes(logical, 4),
	}, nil)
	root := t.TempDir()
	store, err := New(root, meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := store.WritePiece(V1, 0, []byte("abXY")); err != nil {
		t.Fatal(err)
	}
	if err := store.WritePiece(V1, 1, []byte("cd")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ".pad")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("padding directory exists or Stat failed unexpectedly: %v", err)
	}
	got, err := store.ReadPiece(V1, 0)
	if err != nil || !bytes.Equal(got, []byte{'a', 'b', 0, 0}) {
		t.Fatalf("ReadPiece(V1, 0) = %q, %v", got, err)
	}
	spans, err := store.Layout().PieceSpans(V1, 0)
	if err != nil || len(spans) != 2 || !spans[1].Padding {
		t.Fatalf("padding spans = %#v, %v", spans, err)
	}
	verified, err := store.VerifyAll()
	if err != nil || !verified[0] || !verified[1] {
		t.Fatalf("VerifyAll() = %v, %v", verified, err)
	}
}

func TestV2AlignmentAndTruncatedPieces(t *testing.T) {
	const pieceLength = 16 << 10
	a := []byte("alpha")
	b := []byte("bee")
	rootA := metainfo.HashV2(sha256.Sum256(a))
	rootB := metainfo.HashV2(sha256.Sum256(b))
	meta := decodeMeta(t, map[string]any{
		"file tree": map[string]any{
			"a": map[string]any{"": map[string]any{"length": int64(len(a)), "pieces root": string(rootA[:])}},
			"b": map[string]any{"": map[string]any{"length": int64(len(b)), "pieces root": string(rootB[:])}},
		},
		"meta version": int64(2),
		"name":         "bundle",
		"piece length": int64(pieceLength),
	}, nil)

	root := t.TempDir()
	store, err := New(root, meta)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Layout().PieceRange(V2, 0)
	if err != nil || first != (ByteRange{Offset: 0, Length: int64(len(a))}) {
		t.Fatalf("first v2 range = %#v, %v", first, err)
	}
	second, err := store.Layout().PieceRange(V2, 1)
	if err != nil || second != (ByteRange{Offset: pieceLength, Length: int64(len(b))}) {
		t.Fatalf("second v2 range = %#v, %v", second, err)
	}
	if err := store.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := store.WritePiece(V2, 0, a); err != nil {
		t.Fatal(err)
	}
	if err := store.WritePiece(V2, 1, b); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(root, "a")); !bytes.Equal(got, a) {
		t.Errorf("a = %q", got)
	}
	if got := readFile(t, filepath.Join(root, "b")); !bytes.Equal(got, b) {
		t.Errorf("b = %q", got)
	}
	verified, err := store.VerifyAll()
	if err != nil || !verified[0] || !verified[1] {
		t.Fatalf("VerifyAll() = %v, %v", verified, err)
	}
}

func TestHybridUsesBothLayouts(t *testing.T) {
	const pieceLength = 16 << 10
	a := []byte("abc")
	b := []byte("12345")
	firstV1Piece := make([]byte, pieceLength)
	copy(firstV1Piece, a)
	logical := append(bytes.Clone(firstV1Piece), b...)
	rootA := metainfo.HashV2(sha256.Sum256(a))
	rootB := metainfo.HashV2(sha256.Sum256(b))
	meta := decodeMeta(t, map[string]any{
		"file tree": map[string]any{
			"a": map[string]any{"": map[string]any{"length": int64(len(a)), "pieces root": string(rootA[:])}},
			"b": map[string]any{"": map[string]any{"length": int64(len(b)), "pieces root": string(rootB[:])}},
		},
		"files": []any{
			map[string]any{"length": int64(len(a)), "path": []any{"a"}},
			map[string]any{"attr": "p", "length": int64(pieceLength - len(a)), "path": []any{".pad", "gap"}},
			map[string]any{"length": int64(len(b)), "path": []any{"b"}},
		},
		"meta version": int64(2),
		"name":         "bundle",
		"piece length": int64(pieceLength),
		"pieces":       v1Hashes(logical, pieceLength),
	}, nil)
	root := t.TempDir()
	store, err := New(root, meta)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := store.Layout().PieceLength(V1, 0); err != nil || got != pieceLength {
		t.Fatalf("v1 piece length = %d, %v", got, err)
	}
	if got, err := store.Layout().PieceLength(V2, 0); err != nil || got != int64(len(a)) {
		t.Fatalf("v2 piece length = %d, %v", got, err)
	}
	if err := store.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := store.WritePiece(V1, 0, firstV1Piece); err != nil {
		t.Fatal(err)
	}
	if err := store.WritePiece(V2, 1, b); err != nil {
		t.Fatal(err)
	}
	if got, err := store.ReadPiece(V2, 0); err != nil || !bytes.Equal(got, a) {
		t.Fatalf("ReadPiece(V2, 0) = %q, %v", got, err)
	}
	if got, err := store.ReadPiece(V1, 0); err != nil || !bytes.Equal(got, firstV1Piece) {
		t.Fatalf("ReadPiece(V1, 0) mismatch: %v", err)
	}
	verified, err := store.VerifyAll()
	if err != nil || !verified[0] || !verified[1] {
		t.Fatalf("VerifyAll() = %v, %v", verified, err)
	}
}

func TestRejectsTraversalCollisionsAndOverlaps(t *testing.T) {
	t.Run("traversal", func(t *testing.T) {
		meta := decodeMeta(t, map[string]any{
			"files": []any{map[string]any{"length": int64(1), "path": []any{"..", "escape"}}},
			"name":  "bundle", "piece length": int64(4), "pieces": v1Hashes([]byte("x"), 4),
		}, nil)
		if _, err := New(t.TempDir(), meta); err == nil {
			t.Fatal("New accepted a traversing path")
		}
	})

	t.Run("duplicate path", func(t *testing.T) {
		meta := decodeMeta(t, map[string]any{
			"files": []any{
				map[string]any{"length": int64(1), "path": []any{"same"}},
				map[string]any{"length": int64(1), "path": []any{"same"}},
			},
			"name": "bundle", "piece length": int64(4), "pieces": v1Hashes([]byte("xy"), 4),
		}, nil)
		if _, err := NewLayout(meta); err == nil {
			t.Fatal("NewLayout accepted duplicate paths")
		}
	})

	t.Run("file directory collision", func(t *testing.T) {
		meta := decodeMeta(t, map[string]any{
			"files": []any{
				map[string]any{"length": int64(1), "path": []any{"a"}},
				map[string]any{"length": int64(1), "path": []any{"a", "b"}},
			},
			"name": "bundle", "piece length": int64(4), "pieces": v1Hashes([]byte("xy"), 4),
		}, nil)
		if _, err := NewLayout(meta); err == nil {
			t.Fatal("NewLayout accepted a file/directory collision")
		}
	})

	t.Run("overlap", func(t *testing.T) {
		meta := decodeMeta(t, map[string]any{
			"files": []any{
				map[string]any{"length": int64(1), "path": []any{"a"}},
				map[string]any{"length": int64(1), "path": []any{"b"}},
			},
			"name": "bundle", "piece length": int64(4), "pieces": v1Hashes([]byte("xy"), 4),
		}, nil)
		meta.Info.Files[1].Offset = 0
		if _, err := NewLayout(meta); err == nil {
			t.Fatal("NewLayout accepted overlapping files")
		}
	})
}

func TestDeclaredAndExistingSymlinks(t *testing.T) {
	t.Run("declared", func(t *testing.T) {
		meta := decodeMeta(t, map[string]any{
			"files": []any{
				map[string]any{"length": int64(1), "path": []any{"target"}},
				map[string]any{"attr": "l", "length": int64(0), "path": []any{"dir", "link"}, "symlink path": []any{"target"}},
			},
			"name": "bundle", "piece length": int64(4), "pieces": v1Hashes([]byte("x"), 4),
		}, nil)
		root := t.TempDir()
		store, err := New(root, meta)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Prepare(); err != nil {
			t.Fatal(err)
		}
		target, err := os.Readlink(filepath.Join(root, "dir", "link"))
		if err != nil || target != filepath.Join("..", "target") {
			t.Fatalf("declared symlink target = %q, %v", target, err)
		}
		if err := store.WritePiece(V1, 0, []byte("x")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("declared traversal", func(t *testing.T) {
		meta := decodeMeta(t, map[string]any{
			"files": []any{
				map[string]any{"length": int64(1), "path": []any{"target"}},
				map[string]any{"attr": "l", "length": int64(0), "path": []any{"link"}, "symlink path": []any{"..", "outside"}},
			},
			"name": "bundle", "piece length": int64(4), "pieces": v1Hashes([]byte("x"), 4),
		}, nil)
		if _, err := New(t.TempDir(), meta); err == nil {
			t.Fatal("New accepted a traversing symlink target")
		}
	})

	t.Run("existing escape", func(t *testing.T) {
		meta := decodeMeta(t, map[string]any{
			"length": int64(4), "name": "file", "piece length": int64(4), "pieces": v1Hashes([]byte("data"), 4),
		}, nil)
		root := t.TempDir()
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("safe"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "file")); err != nil {
			t.Fatal(err)
		}
		store, err := New(root, meta)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Prepare(); err == nil {
			t.Fatal("Prepare followed an existing symlink")
		}
		if _, err := store.ReadPiece(V1, 0); err == nil {
			t.Fatal("ReadPiece followed a symlink outside the root")
		}
		if got := readFile(t, outside); !bytes.Equal(got, []byte("safe")) {
			t.Fatalf("outside file changed to %q", got)
		}
	})
}

func TestShortIO(t *testing.T) {
	meta := decodeMeta(t, map[string]any{
		"length": int64(4), "name": "file", "piece length": int64(4), "pieces": v1Hashes([]byte("data"), 4),
	}, nil)
	root := t.TempDir()
	store, err := New(root, meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := store.WritePiece(V1, 0, []byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(filepath.Join(root, "file"), 2); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadPiece(V1, 0); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ReadPiece short read error = %v, want io.ErrUnexpectedEOF", err)
	}
	if err := readAtFull(shortReaderAt{}, make([]byte, 4), 0); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("readAtFull short read = %v", err)
	}
	if err := writeAtFull(shortWriterAt{}, make([]byte, 4), 0); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("writeAtFull short write = %v", err)
	}
}

type shortReaderAt struct{}

func (shortReaderAt) ReadAt(data []byte, _ int64) (int, error) {
	data[0] = 1
	return 1, nil
}

type shortWriterAt struct{}

func (shortWriterAt) WriteAt(_ []byte, _ int64) (int, error) {
	return 1, nil
}

func TestResumeVerificationV2PieceLayer(t *testing.T) {
	const pieceLength = 32 << 10
	data := make([]byte, pieceLength+3)
	for i := range data {
		data[i] = byte(i % 251)
	}
	leaf0 := metainfo.HashV2(sha256.Sum256(data[:16<<10]))
	leaf1 := metainfo.HashV2(sha256.Sum256(data[16<<10 : pieceLength]))
	leaf2 := metainfo.HashV2(sha256.Sum256(data[pieceLength:]))
	piece0 := hashPair(leaf0, leaf1)
	piece1 := hashPair(leaf2, metainfo.HashV2{})
	rootHash := hashPair(piece0, piece1)
	meta := decodeMeta(t, map[string]any{
		"file tree": map[string]any{
			"file": map[string]any{"": map[string]any{
				"length": int64(len(data)), "pieces root": string(rootHash[:]),
			}},
		},
		"meta version": int64(2),
		"name":         "file",
		"piece length": int64(pieceLength),
	}, map[string]any{string(rootHash[:]): joinedHashes(piece0, piece1)})

	root := t.TempDir()
	store, err := New(root, meta)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.VerifyPiece(0); err != nil || ok {
		t.Fatalf("VerifyPiece before Prepare = %v, %v; want false, nil", ok, err)
	}
	if err := store.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := store.WritePiece(V2, 0, data[:pieceLength]); err != nil {
		t.Fatal(err)
	}
	if err := store.WritePiece(V2, 1, data[pieceLength:]); err != nil {
		t.Fatal(err)
	}
	verified, err := store.VerifyAll()
	if err != nil || !verified[0] || !verified[1] {
		t.Fatalf("VerifyAll() = %v, %v", verified, err)
	}
	handle, err := os.OpenFile(filepath.Join(root, "file"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := handle.WriteAt([]byte{data[pieceLength] ^ 0xff}, pieceLength)
	closeErr := handle.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("corrupt file: write=%v close=%v", writeErr, closeErr)
	}
	if ok, err := store.VerifyPiece(0); err != nil || !ok {
		t.Fatalf("VerifyPiece(0) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := store.VerifyPiece(1); err != nil || ok {
		t.Fatalf("VerifyPiece(1) = %v, %v; want false, nil", ok, err)
	}
}

func boolBytes(values []bool) []byte {
	result := make([]byte, len(values))
	for i, value := range values {
		if value {
			result[i] = 1
		}
	}
	return result
}
