// Package piece manages per-piece download state for a BitTorrent client.
//
// Each piece is divided into fixed-size blocks (see [BlockSize]). A [State]
// tracks which blocks have been requested and received, accumulates the
// downloaded data, and verifies BitTorrent v1 and v2 piece hashes.
package piece

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"

	"github.com/natalie-o-perret/go-torrent/metainfo"
)

// BlockSize is both the standard peer request size and the BEP 52 leaf size.
const BlockSize = 1 << 14 // 16384 bytes

// BlockStatus is the download state of one block.
type BlockStatus uint8

const (
	// BlockMissing is available for a new request.
	BlockMissing BlockStatus = iota
	// BlockRequested is currently in flight.
	BlockRequested
	// BlockReceived has been stored successfully.
	BlockReceived
)

// State tracks the download progress of a single piece.
type State struct {
	data       []byte
	blocks     []BlockStatus
	index      int
	length     int
	span       int
	expectedV1 metainfo.Hash
	expectedV2 metainfo.HashV2
	hasV1      bool
	hasV2      bool
	verified   bool
}

// New creates a v1 State with an expected SHA-1 hash.
func New(index int, hash metainfo.Hash, length int) (*State, error) {
	return newState(index, length, 0, &hash, nil)
}

// NewV2 creates a v2 State with an expected BEP 52 piece root. Span is the
// power-of-two byte span covered by the Merkle root and may exceed length for a
// final piece.
func NewV2(index int, hash metainfo.HashV2, length, span int) (*State, error) {
	return newState(index, length, span, nil, &hash)
}

// NewHybrid creates a State that must match both v1 and v2 expected hashes.
func NewHybrid(index int, v1 metainfo.Hash, v2 metainfo.HashV2, length, span int) (*State, error) {
	return newState(index, length, span, &v1, &v2)
}

// Index returns the piece index.
func (s *State) Index() int { return s.index }

// Length returns the piece length in bytes.
func (s *State) Length() int { return s.length }

// BlockStatus reports the state of the block at begin without exposing the
// mutable state table.
func (s *State) BlockStatus(begin int) (BlockStatus, error) {
	i, _, err := s.block(begin)
	if err != nil {
		return 0, err
	}
	return s.blocks[i], nil
}

// Complete reports whether every block of the piece has been received.
func (s *State) Complete() bool {
	for _, state := range s.blocks {
		if state != BlockReceived {
			return false
		}
	}
	return true
}

// NextRequest returns the offset and block length of the next block to
// request, and whether there are still blocks left to request.
//
// Calling NextRequest marks the returned block as requested. Pairs with
// [State.Store] to fill the piece buffer and [State.Retry] on request failure.
func (s *State) NextRequest() (begin, blockLen int, ok bool) {
	for i, state := range s.blocks {
		if state != BlockMissing {
			continue
		}
		s.blocks[i] = BlockRequested
		begin = i * BlockSize
		return begin, min(BlockSize, s.length-begin), true
	}
	return 0, 0, false
}

// Retry makes an outstanding block available to request again after a request
// failure or timeout. Calls for blocks already missing or received are harmless.
func (s *State) Retry(begin int) error {
	i, _, err := s.block(begin)
	if err != nil {
		return err
	}
	if s.blocks[i] == BlockRequested {
		s.blocks[i] = BlockMissing
	}
	return nil
}

// RetryAll makes every outstanding block available to request again after a
// peer choke or disconnect.
func (s *State) RetryAll() {
	for i, state := range s.blocks {
		if state == BlockRequested {
			s.blocks[i] = BlockMissing
		}
	}
}

// Store writes data into the piece buffer at the given byte offset.
// Only requested, correctly aligned, full blocks are accepted.
func (s *State) Store(begin int, data []byte) error {
	i, blockLen, err := s.block(begin)
	if err != nil {
		return err
	}
	if len(data) != blockLen {
		return fmt.Errorf("piece %d: block at offset %d has length %d, want %d", s.index, begin, len(data), blockLen)
	}

	switch s.blocks[i] {
	case BlockMissing:
		return fmt.Errorf("piece %d: unsolicited block at offset %d", s.index, begin)
	case BlockReceived:
		if bytes.Equal(s.data[begin:begin+blockLen], data) {
			return nil
		}
		return fmt.Errorf("piece %d: conflicting duplicate block at offset %d", s.index, begin)
	}

	copy(s.data[begin:], data)
	s.blocks[i] = BlockReceived
	return nil
}

// Verify checks the downloaded data against every expected hash.
func (s *State) Verify() error {
	if !s.Complete() {
		return fmt.Errorf("piece %d: cannot verify incomplete piece", s.index)
	}
	if s.hasV1 {
		got := sha1.Sum(s.data)
		if got != s.expectedV1 {
			s.reset()
			return fmt.Errorf("piece %d: SHA-1 mismatch: got %x, want %x", s.index, got, s.expectedV1)
		}
	}
	if s.hasV2 {
		got := merkleRoot(s.data, s.span)
		if got != s.expectedV2 {
			s.reset()
			return fmt.Errorf("piece %d: SHA-256 Merkle root mismatch: got %x, want %x", s.index, got, s.expectedV2)
		}
	}
	s.verified = true
	return nil
}

// Data returns the fully downloaded and verified piece data.
// It returns nil before successful verification and never exposes the internal
// mutable buffer.
func (s *State) Data() []byte {
	if !s.verified {
		return nil
	}
	return bytes.Clone(s.data)
}

func newState(index, length, span int, v1 *metainfo.Hash, v2 *metainfo.HashV2) (*State, error) {
	if index < 0 {
		return nil, fmt.Errorf("piece: index must be nonnegative, got %d", index)
	}
	if length <= 0 {
		return nil, fmt.Errorf("piece %d: length must be positive, got %d", index, length)
	}
	if v2 != nil {
		if span < BlockSize || span&(span-1) != 0 {
			return nil, fmt.Errorf("piece %d: v2 span must be a power of two and at least %d, got %d", index, BlockSize, span)
		}
		if length > span {
			return nil, fmt.Errorf("piece %d: length %d exceeds v2 span %d", index, length, span)
		}
	}

	s := &State{
		index:  index,
		length: length,
		span:   span,
		data:   make([]byte, length),
		blocks: make([]BlockStatus, 1+(length-1)/BlockSize),
	}
	if v1 != nil {
		s.expectedV1 = *v1
		s.hasV1 = true
	}
	if v2 != nil {
		s.expectedV2 = *v2
		s.hasV2 = true
	}
	return s, nil
}

func (s *State) reset() {
	clear(s.data)
	clear(s.blocks)
	s.verified = false
}

func merkleRoot(data []byte, span int) metainfo.HashV2 {
	hashes := make([]metainfo.HashV2, span/BlockSize)
	for begin := 0; begin < len(data); begin += BlockSize {
		end := min(begin+BlockSize, len(data))
		hashes[begin/BlockSize] = metainfo.HashV2(sha256.Sum256(data[begin:end]))
	}
	for width := len(hashes); width > 1; width /= 2 {
		for i := 0; i < width; i += 2 {
			hashes[i/2] = hashPair(hashes[i], hashes[i+1])
		}
	}
	return hashes[0]
}

func hashPair(left, right metainfo.HashV2) metainfo.HashV2 {
	var pair [sha256.Size * 2]byte
	copy(pair[:sha256.Size], left[:])
	copy(pair[sha256.Size:], right[:])
	return metainfo.HashV2(sha256.Sum256(pair[:]))
}

func (s *State) block(begin int) (index, length int, err error) {
	if begin < 0 {
		return 0, 0, fmt.Errorf("piece %d: negative block offset %d", s.index, begin)
	}
	if begin >= s.length {
		return 0, 0, fmt.Errorf("piece %d: block offset %d outside piece length %d", s.index, begin, s.length)
	}
	if begin%BlockSize != 0 {
		return 0, 0, fmt.Errorf("piece %d: block offset %d is not aligned to %d bytes", s.index, begin, BlockSize)
	}
	return begin / BlockSize, min(BlockSize, s.length-begin), nil
}
