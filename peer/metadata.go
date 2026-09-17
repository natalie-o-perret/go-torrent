package peer

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"

	"github.com/natalie-o-perret/go-torrent/metainfo"
)

const (
	// MetadataBlockSize is the BEP 9 transfer block size.
	MetadataBlockSize uint32 = 16 << 10
	// DefaultMaxMetadataSize bounds metadata allocation when no limit is given.
	DefaultMaxMetadataSize uint32 = 4 << 20
)

// MetadataMessageType is a BEP 9 msg_type. Unknown nonnegative values are
// retained so callers can ignore future message types.
type MetadataMessageType int64

const (
	// MetadataRequest requests one metadata block.
	MetadataRequest MetadataMessageType = 0
	// MetadataData carries one metadata block.
	MetadataData MetadataMessageType = 1
	// MetadataReject rejects one metadata request.
	MetadataReject MetadataMessageType = 2
)

// ErrMetadataHashMismatch reports a complete assembly that did not match its
// advertised info hash.
var ErrMetadataHashMismatch = errors.New("peer: assembled metadata hash mismatch")

// MetadataMessage is a BEP 9 dictionary and its optional trailing data. Unknown
// dictionary fields are retained in Unknown.
type MetadataMessage struct {
	Type      MetadataMessageType
	Piece     uint32
	TotalSize *uint32
	Data      []byte
	Unknown   map[string]any
}

// Encode serialises a BEP 9 message.
func (message MetadataMessage) Encode() ([]byte, error) {
	if err := validateMetadataMessage(message, math.MaxUint32); err != nil {
		return nil, err
	}
	dict := copyDictionary(message.Unknown)
	if dict == nil {
		dict = make(map[string]any)
	}
	delete(dict, "msg_type")
	delete(dict, "piece")
	delete(dict, "total_size")
	dict["msg_type"] = int64(message.Type)
	dict["piece"] = int64(message.Piece)
	if message.TotalSize != nil {
		dict["total_size"] = int64(*message.TotalSize)
	}
	header, err := encodeDictionary(dict, "metadata message")
	if err != nil {
		return nil, err
	}
	result := make([]byte, len(header)+len(message.Data))
	copy(result, header)
	copy(result[len(header):], message.Data)
	return result, nil
}

// EncodeMetadataMessage serialises a BEP 9 message.
func EncodeMetadataMessage(message MetadataMessage) ([]byte, error) {
	return message.Encode()
}

// DecodeMetadataMessage decodes a BEP 9 dictionary with bencode.DecodePrefix
// and validates the exact trailing block length. A zero maxSize selects
// DefaultMaxMetadataSize.
func DecodeMetadataMessage(payload []byte, maxSize uint32) (MetadataMessage, error) {
	if maxSize == 0 {
		maxSize = DefaultMaxMetadataSize
	}
	dict, consumed, err := decodeDictionaryPrefix(payload, "metadata message")
	if err != nil {
		return MetadataMessage{}, err
	}

	rawType, ok := dict["msg_type"]
	if !ok {
		return MetadataMessage{}, fmt.Errorf("peer: metadata message is missing msg_type")
	}
	messageType, err := integerField(rawType, "metadata msg_type")
	if err != nil {
		return MetadataMessage{}, err
	}
	if messageType < 0 {
		return MetadataMessage{}, fmt.Errorf("peer: metadata msg_type %d is negative", messageType)
	}
	rawPiece, ok := dict["piece"]
	if !ok {
		return MetadataMessage{}, fmt.Errorf("peer: metadata message is missing piece")
	}
	piece, err := uintField(rawPiece, "metadata piece", 0, math.MaxUint32)
	if err != nil {
		return MetadataMessage{}, err
	}

	message := MetadataMessage{
		Type:    MetadataMessageType(messageType),
		Piece:   uint32(piece),
		Data:    append([]byte(nil), payload[consumed:]...),
		Unknown: copyDictionary(dict),
	}
	delete(message.Unknown, "msg_type")
	delete(message.Unknown, "piece")
	delete(message.Unknown, "total_size")
	if raw, ok := dict["total_size"]; ok {
		total, err := uintField(raw, "metadata total_size", 1, math.MaxUint32)
		if err != nil {
			return MetadataMessage{}, err
		}
		size := uint32(total)
		message.TotalSize = &size
	}
	if err := validateMetadataMessage(message, maxSize); err != nil {
		return MetadataMessage{}, err
	}
	return message, nil
}

// MetadataAssemblerConfig configures a bounded metadata assembly.
type MetadataAssemblerConfig struct {
	Size    uint32
	MaxSize uint32
	Hashes  metainfo.Hashes
}

// MetadataAssembler collects exact BEP 9 blocks and only exposes bytes after
// all advertised hashes pass.
type MetadataAssembler struct {
	v1        *metainfo.Hash
	v2        *metainfo.HashV2
	data      []byte
	received  []bool
	remaining int
	verified  bool
	maxSize   uint32
}

// NewMetadataAssembler allocates a bounded assembler.
func NewMetadataAssembler(config MetadataAssemblerConfig) (*MetadataAssembler, error) {
	if config.MaxSize == 0 {
		config.MaxSize = DefaultMaxMetadataSize
	}
	if config.Size == 0 || config.Size > config.MaxSize {
		return nil, fmt.Errorf("peer: metadata size %d is outside 1..%d", config.Size, config.MaxSize)
	}
	if uint64(config.Size) > uint64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("peer: metadata size %d overflows int", config.Size)
	}
	if config.Hashes.V1 == nil && config.Hashes.V2 == nil {
		return nil, fmt.Errorf("peer: metadata assembler requires an info hash")
	}
	assembler := &MetadataAssembler{
		data:      make([]byte, int(config.Size)),
		received:  make([]bool, metadataBlockCount(config.Size)),
		remaining: metadataBlockCount(config.Size),
		maxSize:   config.MaxSize,
	}
	if config.Hashes.V1 != nil {
		hash := *config.Hashes.V1
		assembler.v1 = &hash
	}
	if config.Hashes.V2 != nil {
		hash := *config.Hashes.V2
		assembler.v2 = &hash
	}
	return assembler, nil
}

// Add stores one MetadataData message. Duplicate identical blocks are
// idempotent. A completed hash mismatch clears all blocks for a clean retry.
func (assembler *MetadataAssembler) Add(message MetadataMessage) (bool, error) {
	if assembler == nil {
		return false, fmt.Errorf("peer: nil metadata assembler")
	}
	if message.Type != MetadataData {
		return false, fmt.Errorf("peer: metadata assembler requires a data message")
	}
	if err := validateMetadataMessage(message, assembler.maxSize); err != nil {
		return false, err
	}
	if message.TotalSize == nil || int(*message.TotalSize) != len(assembler.data) {
		var got uint32
		if message.TotalSize != nil {
			got = *message.TotalSize
		}
		return false, fmt.Errorf("peer: metadata total_size %d does not match assembly size %d", got, len(assembler.data))
	}
	offset := int(uint64(message.Piece) * uint64(MetadataBlockSize))
	end := offset + len(message.Data)
	if assembler.received[message.Piece] {
		if !bytes.Equal(assembler.data[offset:end], message.Data) {
			return false, fmt.Errorf("peer: metadata piece %d conflicts with an earlier block", message.Piece)
		}
		return assembler.verified, nil
	}
	copy(assembler.data[offset:end], message.Data)
	assembler.received[message.Piece] = true
	assembler.remaining--
	if assembler.remaining != 0 {
		return false, nil
	}
	if !metadataHashesMatch(assembler.data, assembler.v1, assembler.v2) {
		clear(assembler.data)
		clear(assembler.received)
		assembler.remaining = len(assembler.received)
		return false, ErrMetadataHashMismatch
	}
	assembler.verified = true
	return true, nil
}

// Complete reports whether every block and advertised hash has passed.
func (assembler *MetadataAssembler) Complete() bool {
	return assembler != nil && assembler.verified
}

// Bytes returns a copy of verified raw info bytes.
func (assembler *MetadataAssembler) Bytes() ([]byte, bool) {
	if assembler == nil || !assembler.verified {
		return nil, false
	}
	return append([]byte(nil), assembler.data...), true
}

// MetadataSource serves BEP 9 blocks from a MetaInfo's exact RawInfo bytes.
type MetadataSource struct {
	rawInfo []byte
}

// NewMetadataSource validates and copies meta.RawInfo for serving.
func NewMetadataSource(meta *metainfo.MetaInfo, maxSize uint32) (*MetadataSource, error) {
	if meta == nil {
		return nil, fmt.Errorf("peer: nil metainfo")
	}
	if maxSize == 0 {
		maxSize = DefaultMaxMetadataSize
	}
	if len(meta.RawInfo) == 0 || uint64(len(meta.RawInfo)) > uint64(maxSize) {
		return nil, fmt.Errorf("peer: RawInfo size %d is outside 1..%d", len(meta.RawInfo), maxSize)
	}
	_, consumed, err := decodeDictionaryPrefix(meta.RawInfo, "RawInfo")
	if err != nil {
		return nil, err
	}
	if consumed != len(meta.RawInfo) {
		return nil, fmt.Errorf("peer: RawInfo has %d trailing bytes", len(meta.RawInfo)-consumed)
	}
	hashes := meta.Hashes()
	if hashes.V1 == nil && hashes.V2 == nil {
		return nil, fmt.Errorf("peer: RawInfo has no advertised info hash")
	}
	if !metadataHashesMatch(meta.RawInfo, hashes.V1, hashes.V2) {
		return nil, ErrMetadataHashMismatch
	}
	return &MetadataSource{rawInfo: append([]byte(nil), meta.RawInfo...)}, nil
}

// Size returns the advertised metadata_size.
func (source *MetadataSource) Size() uint32 {
	if source == nil {
		return 0
	}
	return uint32(len(source.rawInfo))
}

// Message returns one exact MetadataData block.
func (source *MetadataSource) Message(piece uint32) (MetadataMessage, error) {
	if source == nil || len(source.rawInfo) == 0 {
		return MetadataMessage{}, fmt.Errorf("peer: empty metadata source")
	}
	if uint64(piece)*uint64(MetadataBlockSize) >= uint64(len(source.rawInfo)) {
		return MetadataMessage{}, fmt.Errorf("peer: metadata piece %d is out of range", piece)
	}
	offset := int(uint64(piece) * uint64(MetadataBlockSize))
	end := min(offset+int(MetadataBlockSize), len(source.rawInfo))
	total := uint32(len(source.rawInfo))
	return MetadataMessage{
		Type:      MetadataData,
		Piece:     piece,
		TotalSize: &total,
		Data:      append([]byte(nil), source.rawInfo[offset:end]...),
	}, nil
}

// Respond returns data for a valid request, or a BEP 9 reject when the piece
// does not exist.
func (source *MetadataSource) Respond(request MetadataMessage) (MetadataMessage, error) {
	if request.Type != MetadataRequest || request.TotalSize != nil || len(request.Data) != 0 {
		return MetadataMessage{}, fmt.Errorf("peer: invalid metadata request")
	}
	message, err := source.Message(request.Piece)
	if err != nil {
		return MetadataMessage{Type: MetadataReject, Piece: request.Piece}, nil //nolint:nilerr // BEP 9 uses a reject message for an unavailable piece.
	}
	return message, nil
}

func validateMetadataMessage(message MetadataMessage, maxSize uint32) error {
	if message.Type < 0 {
		return fmt.Errorf("peer: metadata msg_type %d is negative", message.Type)
	}
	switch message.Type {
	case MetadataRequest, MetadataReject:
		if message.TotalSize != nil {
			return fmt.Errorf("peer: metadata message type %d must not contain total_size", message.Type)
		}
		if len(message.Data) != 0 {
			return fmt.Errorf("peer: metadata message type %d has %d trailing bytes", message.Type, len(message.Data))
		}
	case MetadataData:
		if message.TotalSize == nil {
			return fmt.Errorf("peer: metadata data message is missing total_size")
		}
		if *message.TotalSize == 0 || *message.TotalSize > maxSize {
			return fmt.Errorf("peer: metadata total_size %d is outside 1..%d", *message.TotalSize, maxSize)
		}
		blocks := uint64(metadataBlockCount(*message.TotalSize))
		if uint64(message.Piece) >= blocks {
			return fmt.Errorf("peer: metadata piece %d is outside %d blocks", message.Piece, blocks)
		}
		offset := uint64(message.Piece) * uint64(MetadataBlockSize)
		remaining := uint64(*message.TotalSize) - offset
		expected := min(remaining, uint64(MetadataBlockSize))
		if uint64(len(message.Data)) != expected {
			return fmt.Errorf("peer: metadata piece %d is %d bytes, want %d", message.Piece, len(message.Data), expected)
		}
	default:
		if message.TotalSize != nil && (*message.TotalSize == 0 || *message.TotalSize > maxSize) {
			return fmt.Errorf("peer: metadata total_size %d is outside 1..%d", *message.TotalSize, maxSize)
		}
	}
	return nil
}

func metadataBlockCount(size uint32) int {
	return int((uint64(size) + uint64(MetadataBlockSize) - 1) / uint64(MetadataBlockSize))
}

func metadataHashesMatch(data []byte, v1 *metainfo.Hash, v2 *metainfo.HashV2) bool {
	if v1 != nil && metainfo.Hash(sha1.Sum(data)) != *v1 {
		return false
	}
	if v2 != nil && metainfo.HashV2(sha256.Sum256(data)) != *v2 {
		return false
	}
	return true
}
