package piece_test

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"testing"

	"github.com/natalie-o-perret/go-torrent/metainfo"
	"github.com/natalie-o-perret/go-torrent/piece"
)

func makeHash(data []byte) metainfo.Hash {
	return sha1.Sum(data)
}

func newV1(t *testing.T, index int, hash metainfo.Hash, length int) *piece.State {
	t.Helper()
	s, err := piece.New(index, hash, length)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func makeHashV2(t *testing.T, value string) metainfo.HashV2 {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != len(metainfo.HashV2{}) {
		t.Fatalf("invalid test SHA-256 hash %q", value)
	}
	var hash metainfo.HashV2
	copy(hash[:], raw)
	return hash
}

func storeAll(t *testing.T, s *piece.State, data []byte) {
	t.Helper()
	for {
		begin, blockLen, ok := s.NextRequest()
		if !ok {
			return
		}
		if err := s.Store(begin, data[begin:begin+blockLen]); err != nil {
			t.Fatalf("Store at %d: %v", begin, err)
		}
	}
}

func TestNewState(t *testing.T) {
	h := metainfo.Hash{}
	s := newV1(t, 0, h, 100)
	if s.Index() != 0 {
		t.Errorf("Index = %d, want 0", s.Index())
	}
	if s.Length() != 100 {
		t.Errorf("Length = %d, want 100", s.Length())
	}
	if s.Complete() {
		t.Error("Complete() = true on fresh state, want false")
	}
}

func TestConstructorsRejectMalformedState(t *testing.T) {
	v1 := metainfo.Hash{}
	v2 := metainfo.HashV2{}
	tests := []struct {
		name string
		new  func() (*piece.State, error)
	}{
		{"v1 negative index", func() (*piece.State, error) { return piece.New(-1, v1, 1) }},
		{"v1 zero length", func() (*piece.State, error) { return piece.New(0, v1, 0) }},
		{"v1 negative length", func() (*piece.State, error) { return piece.New(0, v1, -1) }},
		{"v2 zero length", func() (*piece.State, error) { return piece.NewV2(0, v2, 0, piece.BlockSize) }},
		{"v2 zero span", func() (*piece.State, error) { return piece.NewV2(0, v2, 1, 0) }},
		{"v2 span below one leaf", func() (*piece.State, error) { return piece.NewV2(0, v2, 1, piece.BlockSize/2) }},
		{"v2 non-power-of-two span", func() (*piece.State, error) { return piece.NewV2(0, v2, 1, piece.BlockSize*3) }},
		{"v2 length exceeds span", func() (*piece.State, error) { return piece.NewV2(0, v2, piece.BlockSize+1, piece.BlockSize) }},
		{"hybrid negative index", func() (*piece.State, error) { return piece.NewHybrid(-1, v1, v2, 1, piece.BlockSize) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := tt.new()
			if err == nil {
				t.Fatal("constructor: want error, got nil")
			}
			if s != nil {
				t.Errorf("constructor returned state %v on error", s)
			}
		})
	}
}

func TestNextRequest(t *testing.T) {
	s := newV1(t, 0, metainfo.Hash{}, 100)
	begin, blockLen, ok := s.NextRequest()
	if !ok {
		t.Fatal("NextRequest: ok = false on first call")
	}
	if begin != 0 {
		t.Errorf("begin = %d, want 0", begin)
	}
	if blockLen != 100 {
		t.Errorf("blockLen = %d, want 100", blockLen)
	}
	_, _, ok = s.NextRequest()
	if ok {
		t.Error("NextRequest: ok = true after all blocks requested")
	}
}

func TestNextRequestMultipleBlocks(t *testing.T) {
	total := piece.BlockSize*3 + 500
	s := newV1(t, 1, metainfo.Hash{}, total)

	expected := []struct {
		begin    int
		blockLen int
	}{
		{0, piece.BlockSize},
		{piece.BlockSize, piece.BlockSize},
		{piece.BlockSize * 2, piece.BlockSize},
		{piece.BlockSize * 3, 500},
	}

	for i, want := range expected {
		begin, blockLen, ok := s.NextRequest()
		if !ok {
			t.Fatalf("call %d: ok = false", i)
		}
		if begin != want.begin || blockLen != want.blockLen {
			t.Errorf("call %d: got (%d, %d), want (%d, %d)", i, begin, blockLen, want.begin, want.blockLen)
		}
	}
	_, _, ok := s.NextRequest()
	if ok {
		t.Error("NextRequest returned ok=true after all blocks requested")
	}
}

func TestRetry(t *testing.T) {
	s := newV1(t, 0, metainfo.Hash{}, piece.BlockSize+1)
	status, err := s.BlockStatus(0)
	if err != nil || status != piece.BlockMissing {
		t.Fatalf("BlockStatus before request = (%v, %v), want (%v, nil)", status, err, piece.BlockMissing)
	}
	begin, blockLen, ok := s.NextRequest()
	if !ok {
		t.Fatal("NextRequest: ok = false")
	}
	status, err = s.BlockStatus(begin)
	if err != nil || status != piece.BlockRequested {
		t.Fatalf("BlockStatus after request = (%v, %v), want (%v, nil)", status, err, piece.BlockRequested)
	}
	if err := s.Retry(begin); err != nil {
		t.Fatalf("Retry: %v", err)
	}
	status, err = s.BlockStatus(begin)
	if err != nil || status != piece.BlockMissing {
		t.Fatalf("BlockStatus after Retry = (%v, %v), want (%v, nil)", status, err, piece.BlockMissing)
	}

	retryBegin, retryLen, ok := s.NextRequest()
	if !ok || retryBegin != begin || retryLen != blockLen {
		t.Fatalf("NextRequest after Retry = (%d, %d, %t), want (%d, %d, true)", retryBegin, retryLen, ok, begin, blockLen)
	}
	if err := s.Store(begin, make([]byte, blockLen)); err != nil {
		t.Fatalf("Store: %v", err)
	}
	status, err = s.BlockStatus(begin)
	if err != nil || status != piece.BlockReceived {
		t.Fatalf("BlockStatus after Store = (%v, %v), want (%v, nil)", status, err, piece.BlockReceived)
	}
	if err := s.Retry(begin); err != nil {
		t.Fatalf("Retry received block: %v", err)
	}
	status, err = s.BlockStatus(begin)
	if err != nil || status != piece.BlockReceived {
		t.Fatalf("BlockStatus after retrying received block = (%v, %v), want (%v, nil)", status, err, piece.BlockReceived)
	}
	nextBegin, nextLen, ok := s.NextRequest()
	if !ok || nextBegin != piece.BlockSize || nextLen != 1 {
		t.Fatalf("NextRequest after retrying received block = (%d, %d, %t), want (%d, 1, true)", nextBegin, nextLen, ok, piece.BlockSize)
	}
}

func TestRetryAll(t *testing.T) {
	s := newV1(t, 0, metainfo.Hash{}, piece.BlockSize*2+1)
	for range 3 {
		if _, _, ok := s.NextRequest(); !ok {
			t.Fatal("NextRequest: ok = false")
		}
	}
	if err := s.Store(piece.BlockSize, make([]byte, piece.BlockSize)); err != nil {
		t.Fatalf("Store: %v", err)
	}

	s.RetryAll()
	wants := []struct {
		begin int
		len   int
	}{{0, piece.BlockSize}, {piece.BlockSize * 2, 1}}
	for _, want := range wants {
		begin, blockLen, ok := s.NextRequest()
		if !ok || begin != want.begin || blockLen != want.len {
			t.Fatalf("NextRequest after RetryAll = (%d, %d, %t), want (%d, %d, true)", begin, blockLen, ok, want.begin, want.len)
		}
	}
}

func TestStoreAndComplete(t *testing.T) {
	data := []byte("hello, torrent!")
	hash := makeHash(data)
	s := newV1(t, 0, hash, len(data))

	if _, _, ok := s.NextRequest(); !ok {
		t.Fatal("NextRequest: ok = false")
	}
	if err := s.Store(0, data); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if !s.Complete() {
		t.Error("Complete() = false after full store")
	}
}

func TestStoreRejectsInvalidBlocks(t *testing.T) {
	tests := []struct {
		name  string
		begin int
		data  []byte
	}{
		{"negative offset", -1, []byte{1}},
		{"out of bounds", piece.BlockSize * 2, []byte{1}},
		{"misaligned", 1, []byte{1}},
		{"unsolicited", piece.BlockSize, []byte{1}},
		{"wrong full block length", 0, make([]byte, piece.BlockSize-1)},
		{"wrong final block length", piece.BlockSize, []byte{1, 2}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newV1(t, 0, metainfo.Hash{}, piece.BlockSize+1)
			if tt.begin == 0 {
				s.NextRequest()
			} else if tt.name == "wrong final block length" {
				s.NextRequest()
				s.NextRequest()
			}
			if err := s.Store(tt.begin, tt.data); err == nil {
				t.Fatal("Store: want error, got nil")
			}
			if s.Complete() {
				t.Error("Complete() = true after rejected block")
			}
		})
	}
}

func TestStoreDuplicate(t *testing.T) {
	data := make([]byte, piece.BlockSize+1)
	data[piece.BlockSize] = 1
	s := newV1(t, 0, makeHash(data), len(data))
	s.NextRequest()
	s.NextRequest()
	if err := s.Store(0, data[:piece.BlockSize]); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := s.Store(0, append([]byte(nil), data[:piece.BlockSize]...)); err != nil {
		t.Fatalf("Store duplicate: %v", err)
	}
	if s.Complete() {
		t.Error("Complete() = true after duplicate first block")
	}
	conflict := append([]byte(nil), data[:piece.BlockSize]...)
	conflict[0]++
	if err := s.Store(0, conflict); err == nil {
		t.Fatal("Store conflicting duplicate: want error, got nil")
	}
	if err := s.Store(piece.BlockSize, data[piece.BlockSize:]); err != nil {
		t.Fatalf("Store final block: %v", err)
	}
	if !s.Complete() {
		t.Error("Complete() = false after final block")
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("Verify after duplicate: %v", err)
	}
}

func TestVerify(t *testing.T) {
	data := []byte("some piece data here, four score and seven bytes ago")
	hash := makeHash(data)
	s := newV1(t, 2, hash, len(data))
	s.NextRequest()
	if err := s.Store(0, data); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := s.Verify(); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerifyV2Vectors(t *testing.T) {
	// These roots match FileHasher in the BEP 52 reference torrent creator.
	tests := []struct {
		name string
		data []byte
		span int
		root string
	}{
		{
			name: "short leaf",
			data: []byte("abc"),
			span: piece.BlockSize,
			root: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
		{
			name: "short final leaf and zero-hash padding",
			data: append(bytes.Repeat([]byte{'a'}, piece.BlockSize), 'b'),
			span: piece.BlockSize * 4,
			root: "da2c713a4cfb83900c4866aefcbc2a6ff72957aba8cb09b42a0b6c869f4bade0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := piece.NewV2(3, makeHashV2(t, tt.root), len(tt.data), tt.span)
			if err != nil {
				t.Fatalf("NewV2: %v", err)
			}
			storeAll(t, s, tt.data)
			if err := s.Verify(); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got := s.Data(); !bytes.Equal(got, tt.data) {
				t.Errorf("Data() differs after v2 verification")
			}
		})
	}
}

func TestVerifyHybridRequiresBothHashes(t *testing.T) {
	data := []byte("abc")
	v1 := makeHash(data)
	v2 := makeHashV2(t, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	tests := []struct {
		name    string
		v1      metainfo.Hash
		v2      metainfo.HashV2
		wantErr bool
	}{
		{"both match", v1, v2, false},
		{"v1 mismatch", metainfo.Hash{}, v2, true},
		{"v2 mismatch", v1, metainfo.HashV2{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := piece.NewHybrid(0, tt.v1, tt.v2, len(data), piece.BlockSize)
			if err != nil {
				t.Fatalf("NewHybrid: %v", err)
			}
			storeAll(t, s, data)
			err = s.Verify()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Verify error = %v, wantErr %t", err, tt.wantErr)
			}
			if tt.wantErr && s.Complete() {
				t.Error("Complete() = true after hybrid hash mismatch")
			}
		})
	}
}

func TestVerifyIncomplete(t *testing.T) {
	s := newV1(t, 0, metainfo.Hash{}, 1)
	if err := s.Verify(); err == nil {
		t.Fatal("Verify: want error for incomplete piece, got nil")
	}
}

func TestVerifyMismatchResetsPiece(t *testing.T) {
	data := make([]byte, piece.BlockSize+1)
	data[piece.BlockSize] = 1
	s := newV1(t, 0, makeHash(data), len(data))
	for range 2 {
		s.NextRequest()
	}
	if err := s.Store(0, make([]byte, piece.BlockSize)); err != nil {
		t.Fatalf("Store first block: %v", err)
	}
	if err := s.Store(piece.BlockSize, []byte{2}); err != nil {
		t.Fatalf("Store final block: %v", err)
	}
	if err := s.Verify(); err == nil {
		t.Error("Verify: want error for hash mismatch, got nil")
	}
	if s.Complete() {
		t.Error("Complete() = true after hash mismatch")
	}
	if got := s.Data(); got != nil {
		t.Errorf("Data() after hash mismatch = %v, want nil", got)
	}

	for _, want := range []struct {
		begin int
		len   int
	}{{0, piece.BlockSize}, {piece.BlockSize, 1}} {
		begin, blockLen, ok := s.NextRequest()
		if !ok || begin != want.begin || blockLen != want.len {
			t.Fatalf("NextRequest after hash mismatch = (%d, %d, %t), want (%d, %d, true)", begin, blockLen, ok, want.begin, want.len)
		}
		if err := s.Store(begin, data[begin:begin+blockLen]); err != nil {
			t.Fatalf("Store retry at %d: %v", begin, err)
		}
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("Verify retry: %v", err)
	}
}

func TestDataRequiresVerificationAndReturnsCopy(t *testing.T) {
	data := []byte("piece payload")
	hash := makeHash(data)
	s := newV1(t, 0, hash, len(data))
	if got := s.Data(); got != nil {
		t.Errorf("Data() before download = %v, want nil", got)
	}
	s.NextRequest()
	if err := s.Store(0, data); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if got := s.Data(); got != nil {
		t.Errorf("Data() before verification = %v, want nil", got)
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	got := s.Data()
	if !bytes.Equal(got, data) {
		t.Errorf("Data() = %q, want %q", got, data)
	}
	got[0]++
	if bytes.Equal(got, s.Data()) {
		t.Error("mutating Data() result changed stored piece data")
	}
}

func TestBlockSize(t *testing.T) {
	if piece.BlockSize != 16384 {
		t.Errorf("BlockSize = %d, want 16384", piece.BlockSize)
	}
}
