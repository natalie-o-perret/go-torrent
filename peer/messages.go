package peer

import (
	"encoding/binary"
	"fmt"
	"math/bits"

	"github.com/natalie-o-perret/go-torrent/metainfo"
)

const (
	// MaxBlockLength is the BEP 3 request and piece block limit.
	MaxBlockLength uint32 = 16 << 10
	// RecommendedMaxHashRequestLength is the BEP 52 recommended request count.
	RecommendedMaxHashRequestLength uint32 = 512
	// MaxHashRequestLength is the largest power of two representable without
	// overflowing the uint32 index space. The frame limit bounds responses.
	MaxHashRequestLength uint32 = 1 << 31
	// MaxHashTreeLayers bounds nonsensical or malicious proof counts.
	MaxHashTreeLayers uint32 = 63
)

// BlockRequest is the common payload carried by Request, Cancel, and Reject.
type BlockRequest struct {
	Index  uint32
	Begin  uint32
	Length uint32
}

// Validate checks the context-independent BEP 3 block bounds.
func (r BlockRequest) Validate() error {
	if r.Length == 0 || r.Length > MaxBlockLength {
		return fmt.Errorf("peer: block length %d is outside 1..%d", r.Length, MaxBlockLength)
	}
	if uint64(r.Begin)+uint64(r.Length) > uint64(^uint32(0)) {
		return fmt.Errorf("peer: block range %d+%d overflows uint32", r.Begin, r.Length)
	}
	return nil
}

// MarshalBinary returns the common 12-byte payload after validating it.
func (r BlockRequest) MarshalBinary() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return formatBlockRequest(r), nil
}

// FormatHave builds a Have payload.
func FormatHave(index uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, index)
	return buf
}

// ParseHave parses an exact Have payload.
func ParseHave(payload []byte) (uint32, error) {
	return parseIndexPayload("have", payload)
}

// ValidatePieceIndex checks a Have, Suggest Piece, or Allowed Fast index once
// the session knows the torrent piece count.
func ValidatePieceIndex(index, pieceCount uint32) error {
	if index >= pieceCount {
		return fmt.Errorf("peer: piece index %d is outside %d pieces", index, pieceCount)
	}
	return nil
}

// FormatBitfield packs piece availability from most-significant to
// least-significant bit as specified by BEP 3.
func FormatBitfield(pieces []bool) []byte {
	payload := make([]byte, int((uint64(len(pieces))+7)/8))
	for index, present := range pieces {
		if present {
			payload[index/8] |= 1 << (7 - uint(index%8))
		}
	}
	return payload
}

// ValidateBitfield checks its exact torrent-dependent length and zero spare
// bits.
func ValidateBitfield(payload []byte, pieceCount uint32) error {
	expected := (uint64(pieceCount) + 7) / 8
	if uint64(len(payload)) != expected {
		return fmt.Errorf("peer: bitfield is %d bytes, want %d for %d pieces", len(payload), expected, pieceCount)
	}
	if remainder := pieceCount % 8; remainder != 0 && len(payload) != 0 {
		spareMask := byte(1<<(8-remainder)) - 1
		if payload[len(payload)-1]&spareMask != 0 {
			return fmt.Errorf("peer: bitfield has nonzero spare bits")
		}
	}
	return nil
}

// ParseBitfield validates and expands a torrent-dependent bitfield.
func ParseBitfield(payload []byte, pieceCount uint32) ([]bool, error) {
	if err := ValidateBitfield(payload, pieceCount); err != nil {
		return nil, err
	}
	if uint64(pieceCount) > uint64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("peer: piece count %d overflows int", pieceCount)
	}
	pieces := make([]bool, int(pieceCount))
	for index := range pieces {
		pieces[index] = payload[index/8]&(1<<(7-uint(index%8))) != 0
	}
	return pieces, nil
}

// FormatRequest builds the 12-byte Request payload. Use BlockRequest.Validate
// when values did not already come from a valid piece layout.
func FormatRequest(index, begin, length uint32) []byte {
	return formatBlockRequest(BlockRequest{Index: index, Begin: begin, Length: length})
}

// ParseRequest parses and validates a Request payload.
func ParseRequest(payload []byte) (BlockRequest, error) {
	return parseBlockRequest("request", payload)
}

// FormatCancel builds the 12-byte Cancel payload.
func FormatCancel(index, begin, length uint32) []byte {
	return formatBlockRequest(BlockRequest{Index: index, Begin: begin, Length: length})
}

// ParseCancel parses and validates a Cancel payload.
func ParseCancel(payload []byte) (BlockRequest, error) {
	return parseBlockRequest("cancel", payload)
}

// FormatReject builds the 12-byte Reject payload.
func FormatReject(index, begin, length uint32) []byte {
	return formatBlockRequest(BlockRequest{Index: index, Begin: begin, Length: length})
}

// ParseReject parses and validates a Reject payload.
func ParseReject(payload []byte) (BlockRequest, error) {
	return parseBlockRequest("reject", payload)
}

// FormatPiece builds a Piece payload and copies data into it.
func FormatPiece(index, begin uint32, data []byte) ([]byte, error) {
	if len(data) == 0 || uint64(len(data)) > uint64(MaxBlockLength) {
		return nil, fmt.Errorf("peer: piece block length %d is outside 1..%d", len(data), MaxBlockLength)
	}
	if uint64(begin)+uint64(len(data)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("peer: piece range %d+%d overflows uint32", begin, len(data))
	}
	buf := make([]byte, 8+len(data))
	binary.BigEndian.PutUint32(buf[0:4], index)
	binary.BigEndian.PutUint32(buf[4:8], begin)
	copy(buf[8:], data)
	return buf, nil
}

// ParsePiece parses and validates a Piece payload. The returned data aliases
// payload.
func ParsePiece(payload []byte) (index, begin uint32, data []byte, err error) {
	if len(payload) < 9 {
		return 0, 0, nil, fmt.Errorf("peer: piece payload must contain an 8-byte header and data, got %d bytes", len(payload))
	}
	if len(payload)-8 > int(MaxBlockLength) {
		return 0, 0, nil, fmt.Errorf("peer: piece block length %d exceeds %d", len(payload)-8, MaxBlockLength)
	}
	index = binary.BigEndian.Uint32(payload[0:4])
	begin = binary.BigEndian.Uint32(payload[4:8])
	data = payload[8:]
	if uint64(begin)+uint64(len(data)) > uint64(^uint32(0)) {
		return 0, 0, nil, fmt.Errorf("peer: piece range %d+%d overflows uint32", begin, len(data))
	}
	return index, begin, data, nil
}

// FormatPort builds a BEP 5 PORT payload.
func FormatPort(port uint16) ([]byte, error) {
	if port == 0 {
		return nil, fmt.Errorf("peer: DHT port must be nonzero")
	}
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, port)
	return buf, nil
}

// ParsePort parses an exact BEP 5 PORT payload.
func ParsePort(payload []byte) (uint16, error) {
	if len(payload) != 2 {
		return 0, fmt.Errorf("peer: port payload must be 2 bytes, got %d", len(payload))
	}
	port := binary.BigEndian.Uint16(payload)
	if port == 0 {
		return 0, fmt.Errorf("peer: DHT port must be nonzero")
	}
	return port, nil
}

// FormatSuggestPiece builds a BEP 6 Suggest Piece payload.
func FormatSuggestPiece(index uint32) []byte {
	return FormatHave(index)
}

// ParseSuggestPiece parses an exact BEP 6 Suggest Piece payload.
func ParseSuggestPiece(payload []byte) (uint32, error) {
	return parseIndexPayload("suggest piece", payload)
}

// FormatAllowedFast builds a BEP 6 Allowed Fast payload.
func FormatAllowedFast(index uint32) []byte {
	return FormatHave(index)
}

// ParseAllowedFast parses an exact BEP 6 Allowed Fast payload.
func ParseAllowedFast(payload []byte) (uint32, error) {
	return parseIndexPayload("allowed fast", payload)
}

// ParseHaveAll validates the empty BEP 6 Have All payload.
func ParseHaveAll(payload []byte) error {
	return parseEmptyPayload("have all", payload)
}

// ParseHaveNone validates the empty BEP 6 Have None payload.
func ParseHaveNone(payload []byte) error {
	return parseEmptyPayload("have none", payload)
}

// HashRequest is the common BEP 52 Hash Request and Hash Reject payload.
type HashRequest struct {
	PiecesRoot  metainfo.HashV2
	BaseLayer   uint32
	Index       uint32
	Length      uint32
	ProofLayers uint32
}

// Validate checks the context-independent BEP 52 request constraints.
func (r HashRequest) Validate() error {
	if r.Length < 2 || r.Length > MaxHashRequestLength || r.Length&(r.Length-1) != 0 {
		return fmt.Errorf("peer: hash request length %d must be a power of two in 2..%d", r.Length, MaxHashRequestLength)
	}
	if r.Index%r.Length != 0 {
		return fmt.Errorf("peer: hash request index %d is not a multiple of length %d", r.Index, r.Length)
	}
	if uint64(r.Index)+uint64(r.Length) > uint64(^uint32(0)) {
		return fmt.Errorf("peer: hash request range %d+%d overflows uint32", r.Index, r.Length)
	}
	if r.BaseLayer > MaxHashTreeLayers || r.ProofLayers > MaxHashTreeLayers || uint64(r.BaseLayer)+uint64(r.ProofLayers) > uint64(MaxHashTreeLayers) {
		return fmt.Errorf("peer: hash layer range %d+%d exceeds %d", r.BaseLayer, r.ProofLayers, MaxHashTreeLayers)
	}
	return nil
}

// MarshalBinary returns the 48-byte common hash-message payload.
func (r HashRequest) MarshalBinary() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return formatHashRequest(r), nil
}

// Hashes is a BEP 52 Hashes payload.
type Hashes struct {
	Request HashRequest
	Values  []metainfo.HashV2
}

// FormatHashRequest formats a validated Hash Request payload.
func FormatHashRequest(request HashRequest) ([]byte, error) {
	return request.MarshalBinary()
}

// ParseHashRequest parses and validates an exact Hash Request payload.
func ParseHashRequest(payload []byte) (HashRequest, error) {
	return parseHashRequest("hash request", payload)
}

// FormatHashReject formats a validated Hash Reject payload.
func FormatHashReject(request HashRequest) ([]byte, error) {
	return request.MarshalBinary()
}

// ParseHashReject parses and validates an exact Hash Reject payload.
func ParseHashReject(payload []byte) (HashRequest, error) {
	return parseHashRequest("hash reject", payload)
}

// FormatHashes formats a Hashes payload with the exact hash count implied by
// its request fields.
func FormatHashes(message Hashes) ([]byte, error) {
	if err := message.Request.Validate(); err != nil {
		return nil, err
	}
	want := expectedHashCount(message.Request)
	if uint64(len(message.Values)) != want {
		return nil, fmt.Errorf("peer: hashes payload has %d hashes, want %d", len(message.Values), want)
	}
	hashSize := uint64(len(metainfo.HashV2{}))
	if uint64(len(message.Values)) > (uint64(int(^uint(0)>>1))-48)/hashSize {
		return nil, fmt.Errorf("peer: hashes payload size overflows int")
	}
	buf := make([]byte, 48+len(message.Values)*len(metainfo.HashV2{}))
	copy(buf, formatHashRequest(message.Request))
	for i := range message.Values {
		copy(buf[48+i*len(metainfo.HashV2{}):], message.Values[i][:])
	}
	return buf, nil
}

// ParseHashes parses a Hashes payload and enforces its implied hash count.
func ParseHashes(payload []byte) (Hashes, error) {
	if len(payload) < 48 {
		return Hashes{}, fmt.Errorf("peer: hashes payload is %d bytes, want at least 48", len(payload))
	}
	if (len(payload)-48)%len(metainfo.HashV2{}) != 0 {
		return Hashes{}, fmt.Errorf("peer: hashes data length %d is not a multiple of %d", len(payload)-48, len(metainfo.HashV2{}))
	}
	request, err := parseHashRequest("hashes", payload[:48])
	if err != nil {
		return Hashes{}, err
	}
	count := (len(payload) - 48) / len(metainfo.HashV2{})
	want := expectedHashCount(request)
	if uint64(count) != want {
		return Hashes{}, fmt.Errorf("peer: hashes payload has %d hashes, want %d", count, want)
	}
	// Validate the untrusted header count before allocating its hash slice.
	message := Hashes{Request: request, Values: make([]metainfo.HashV2, count)}
	for i := range message.Values {
		copy(message.Values[i][:], payload[48+i*len(metainfo.HashV2{}):])
	}
	return message, nil
}

// ValidateMessage checks every context-independent static payload shape.
// Unknown IDs are retained for forward compatibility.
func ValidateMessage(message *Message) error {
	if message == nil {
		return fmt.Errorf("peer: nil message")
	}
	var err error
	switch message.ID {
	case MsgChoke, MsgUnchoke, MsgInterested, MsgNotInterested, MsgHaveAll, MsgHaveNone:
		err = parseEmptyPayload("static message", message.Payload)
	case MsgHave:
		_, err = ParseHave(message.Payload)
	case MsgBitfield:
		// Its exact size and spare bits require the torrent piece count.
	case MsgRequest:
		_, err = ParseRequest(message.Payload)
	case MsgPiece:
		_, _, _, err = ParsePiece(message.Payload)
	case MsgCancel:
		_, err = ParseCancel(message.Payload)
	case MsgPort:
		_, err = ParsePort(message.Payload)
	case MsgSuggestPiece:
		_, err = ParseSuggestPiece(message.Payload)
	case MsgReject:
		_, err = ParseReject(message.Payload)
	case MsgAllowedFast:
		_, err = ParseAllowedFast(message.Payload)
	case MsgExtended:
		_, err = ParseExtended(message.Payload)
	case MsgHashRequest:
		_, err = ParseHashRequest(message.Payload)
	case MsgHashes:
		_, err = ParseHashes(message.Payload)
	case MsgHashReject:
		_, err = ParseHashReject(message.Payload)
	}
	if err != nil {
		return fmt.Errorf("peer: invalid message %d: %w", message.ID, err)
	}
	return nil
}

func parseIndexPayload(name string, payload []byte) (uint32, error) {
	if len(payload) != 4 {
		return 0, fmt.Errorf("peer: %s payload must be 4 bytes, got %d", name, len(payload))
	}
	return binary.BigEndian.Uint32(payload), nil
}

func parseEmptyPayload(name string, payload []byte) error {
	if len(payload) != 0 {
		return fmt.Errorf("peer: %s payload must be empty, got %d bytes", name, len(payload))
	}
	return nil
}

func formatBlockRequest(request BlockRequest) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint32(buf[0:4], request.Index)
	binary.BigEndian.PutUint32(buf[4:8], request.Begin)
	binary.BigEndian.PutUint32(buf[8:12], request.Length)
	return buf
}

func parseBlockRequest(name string, payload []byte) (BlockRequest, error) {
	if len(payload) != 12 {
		return BlockRequest{}, fmt.Errorf("peer: %s payload must be 12 bytes, got %d", name, len(payload))
	}
	request := BlockRequest{
		Index:  binary.BigEndian.Uint32(payload[0:4]),
		Begin:  binary.BigEndian.Uint32(payload[4:8]),
		Length: binary.BigEndian.Uint32(payload[8:12]),
	}
	if err := request.Validate(); err != nil {
		return BlockRequest{}, fmt.Errorf("peer: %s: %w", name, err)
	}
	return request, nil
}

func formatHashRequest(request HashRequest) []byte {
	buf := make([]byte, 48)
	copy(buf[:32], request.PiecesRoot[:])
	binary.BigEndian.PutUint32(buf[32:36], request.BaseLayer)
	binary.BigEndian.PutUint32(buf[36:40], request.Index)
	binary.BigEndian.PutUint32(buf[40:44], request.Length)
	binary.BigEndian.PutUint32(buf[44:48], request.ProofLayers)
	return buf
}

func parseHashRequest(name string, payload []byte) (HashRequest, error) {
	if len(payload) != 48 {
		return HashRequest{}, fmt.Errorf("peer: %s payload must be 48 bytes, got %d", name, len(payload))
	}
	var request HashRequest
	copy(request.PiecesRoot[:], payload[:32])
	request.BaseLayer = binary.BigEndian.Uint32(payload[32:36])
	request.Index = binary.BigEndian.Uint32(payload[36:40])
	request.Length = binary.BigEndian.Uint32(payload[40:44])
	request.ProofLayers = binary.BigEndian.Uint32(payload[44:48])
	if err := request.Validate(); err != nil {
		return HashRequest{}, fmt.Errorf("peer: %s: %w", name, err)
	}
	return request, nil
}

func expectedHashCount(request HashRequest) uint64 {
	// A two-hash base omits no proof layer. Larger bases omit log2(length)-1.
	omittedProofs := uint32(bits.TrailingZeros32(request.Length) - 1)
	proofHashes := uint32(0)
	if request.ProofLayers > omittedProofs {
		proofHashes = request.ProofLayers - omittedProofs
	}
	return uint64(request.Length) + uint64(proofHashes)
}
