// Package peer implements bounded codecs for the BitTorrent peer wire
// protocol and its standard extensions.
package peer

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/natalie-o-perret/go-torrent/metainfo"
)

const (
	protocolString = "BitTorrent protocol"
	handshakeSize  = 68

	// DefaultMaxFrameSize is the largest peer-wire frame accepted by the
	// package-level ReadMessage and WriteMessage helpers.
	DefaultMaxFrameSize uint32 = 4 << 20
	// DefaultHandshakeTimeout bounds the convenience Handshake exchange.
	DefaultHandshakeTimeout = 3 * time.Second
)

// Capability is a bit number counted from the right of the eight reserved
// handshake bytes, as used by the BEPs.
type Capability uint8

const (
	// CapabilityDHT enables the BEP 5 PORT message.
	CapabilityDHT Capability = 0
	// CapabilityFast enables the BEP 6 fast-extension messages.
	CapabilityFast Capability = 2
	// CapabilityV2Upgrade permits a BEP 52 hybrid connection upgrade.
	CapabilityV2Upgrade Capability = 4
	// CapabilityExtensionProtocol enables BEP 10 extended messages.
	CapabilityExtensionProtocol Capability = 20
)

// Reserved is the eight-byte capability field in a peer handshake. Unknown
// bits are retained verbatim.
type Reserved [8]byte

// Has reports whether capability is set.
func (r Reserved) Has(capability Capability) bool {
	if capability >= 64 {
		return false
	}
	return r[7-capability/8]&(1<<(capability%8)) != 0
}

// Set enables or disables capability while preserving every other bit.
func (r *Reserved) Set(capability Capability, enabled bool) {
	if r == nil || capability >= 64 {
		return
	}
	mask := byte(1 << (capability % 8))
	index := 7 - capability/8
	if enabled {
		r[index] |= mask
	} else {
		r[index] &^= mask
	}
}

// HandshakeMessage is the complete BEP 3 handshake body.
type HandshakeMessage struct {
	Reserved Reserved
	InfoHash metainfo.Hash
	PeerID   [20]byte
}

// MarshalBinary returns the 68-byte wire representation of h.
func (h HandshakeMessage) MarshalBinary() ([]byte, error) {
	buf := make([]byte, handshakeSize)
	buf[0] = byte(len(protocolString))
	copy(buf[1:20], protocolString)
	copy(buf[20:28], h.Reserved[:])
	copy(buf[28:48], h.InfoHash[:])
	copy(buf[48:68], h.PeerID[:])
	return buf, nil
}

// ParseHandshake parses one complete BEP 3 handshake.
func ParseHandshake(data []byte) (HandshakeMessage, error) {
	if len(data) != handshakeSize {
		return HandshakeMessage{}, fmt.Errorf("peer: handshake must be %d bytes, got %d", handshakeSize, len(data))
	}
	if data[0] != byte(len(protocolString)) {
		return HandshakeMessage{}, fmt.Errorf("peer: unexpected protocol name length %d", data[0])
	}
	if string(data[1:20]) != protocolString {
		return HandshakeMessage{}, fmt.Errorf("peer: unexpected protocol %q", data[1:20])
	}

	var h HandshakeMessage
	copy(h.Reserved[:], data[20:28])
	copy(h.InfoHash[:], data[28:48])
	copy(h.PeerID[:], data[48:68])
	return h, nil
}

// ReadHandshake reads and validates one complete BEP 3 handshake.
func ReadHandshake(r io.Reader) (HandshakeMessage, error) {
	var data [handshakeSize]byte
	if _, err := io.ReadFull(r, data[:20]); err != nil {
		return HandshakeMessage{}, fmt.Errorf("peer: read handshake protocol: %w", err)
	}
	if data[0] != byte(len(protocolString)) || string(data[1:20]) != protocolString {
		return HandshakeMessage{}, fmt.Errorf("peer: invalid handshake protocol prefix")
	}
	if _, err := io.ReadFull(r, data[20:]); err != nil {
		return HandshakeMessage{}, fmt.Errorf("peer: read handshake body: %w", err)
	}
	return ParseHandshake(data[:])
}

// WriteHandshake writes every byte of one BEP 3 handshake.
func WriteHandshake(w io.Writer, h HandshakeMessage) error {
	data, err := h.MarshalBinary()
	if err != nil {
		return fmt.Errorf("peer: marshal handshake: %w", err)
	}
	if err := writeFull(w, data); err != nil {
		return fmt.Errorf("peer: write handshake: %w", err)
	}
	return nil
}

// ExchangeHandshake concurrently writes local and reads the remote handshake.
// Cancellation interrupts a net.Conn by installing an expired deadline. The
// deadline is cleared only when this operation installed it. net.Conn does not
// expose an earlier caller-owned deadline, so callers should not concurrently
// change deadlines during the exchange.
func ExchangeHandshake(ctx context.Context, conn net.Conn, local HandshakeMessage) (HandshakeMessage, error) {
	if ctx == nil {
		return HandshakeMessage{}, fmt.Errorf("peer: nil handshake context")
	}
	if conn == nil {
		return HandshakeMessage{}, fmt.Errorf("peer: nil handshake connection")
	}

	opCtx, cancel := context.WithCancel(ctx)
	deadlineDone := make(chan struct{})
	stopDeadline := context.AfterFunc(opCtx, func() {
		_ = conn.SetDeadline(time.Now())
		close(deadlineDone)
	})
	defer func() {
		if stopDeadline() {
			cancel()
			return
		}
		<-deadlineDone
		_ = conn.SetDeadline(time.Time{})
		cancel()
	}()

	type result struct {
		handshake HandshakeMessage
		operation string
		err       error
	}
	results := make(chan result, 2)
	go func() {
		results <- result{operation: "send", err: WriteHandshake(conn, local)}
	}()
	go func() {
		remote, err := ReadHandshake(conn)
		results <- result{handshake: remote, operation: "receive", err: err}
	}()

	var remote HandshakeMessage
	var exchangeErr error
	for range 2 {
		res := <-results
		if res.operation == "receive" && res.err == nil {
			remote = res.handshake
			if remote.InfoHash != local.InfoHash {
				res.err = fmt.Errorf("info hash mismatch: got %s, want %s", remote.InfoHash, local.InfoHash)
			}
		}
		if res.err != nil && exchangeErr == nil {
			exchangeErr = fmt.Errorf("peer: %s handshake: %w", res.operation, res.err)
			cancel()
		}
	}
	if err := ctx.Err(); err != nil {
		return HandshakeMessage{}, fmt.Errorf("peer: handshake: %w", err)
	}
	if exchangeErr != nil {
		return HandshakeMessage{}, exchangeErr
	}
	return remote, nil
}

// Handshake performs a bounded BEP 3 handshake with zero reserved bytes and
// returns the remote peer ID. Use ExchangeHandshake when capabilities or the
// remote reserved bytes are needed.
func Handshake(conn net.Conn, infoHash metainfo.Hash, peerID [20]byte) ([20]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultHandshakeTimeout)
	defer cancel()
	remote, err := ExchangeHandshake(ctx, conn, HandshakeMessage{InfoHash: infoHash, PeerID: peerID})
	if err != nil {
		return [20]byte{}, err
	}
	return remote.PeerID, nil
}

// MessageID identifies a peer-wire message type.
type MessageID uint8

const (
	// BEP 3 messages.
	MsgChoke         MessageID = 0
	MsgUnchoke       MessageID = 1
	MsgInterested    MessageID = 2
	MsgNotInterested MessageID = 3
	MsgHave          MessageID = 4
	MsgBitfield      MessageID = 5
	MsgRequest       MessageID = 6
	MsgPiece         MessageID = 7
	MsgCancel        MessageID = 8

	// MsgPort is the BEP 5 DHT port message.
	MsgPort MessageID = 9

	// BEP 6 fast-extension messages.
	MsgSuggestPiece MessageID = 13
	MsgHaveAll      MessageID = 14
	MsgHaveNone     MessageID = 15
	MsgReject       MessageID = 16
	MsgAllowedFast  MessageID = 17

	// MsgExtended is the BEP 10 extension envelope.
	MsgExtended MessageID = 20

	// BEP 52 hash messages.
	MsgHashRequest MessageID = 21
	MsgHashes      MessageID = 22
	MsgHashReject  MessageID = 23
)

// Message is a decoded length-prefixed peer-wire frame. A nil *Message denotes
// a keepalive when returned by a reader.
type Message struct {
	Payload []byte
	ID      MessageID
}

// Codec reads and writes peer-wire frames with a hard allocation bound. A zero
// MaxFrameSize selects DefaultMaxFrameSize.
type Codec struct {
	MaxFrameSize uint32
}

func (c Codec) maxFrameSize() uint32 {
	if c.MaxFrameSize == 0 {
		return DefaultMaxFrameSize
	}
	return c.MaxFrameSize
}

// ReadMessage reads and validates the next frame. It returns nil for a
// keepalive and rejects an oversized length before allocating its payload.
func (c Codec) ReadMessage(r io.Reader) (*Message, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, fmt.Errorf("peer: read message length: %w", err)
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length == 0 {
		return nil, nil
	}
	if length > c.maxFrameSize() {
		return nil, fmt.Errorf("peer: frame length %d exceeds maximum %d", length, c.maxFrameSize())
	}
	if uint64(length) > uint64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("peer: frame length %d overflows int", length)
	}

	raw := make([]byte, int(length))
	if _, err := io.ReadFull(r, raw); err != nil {
		return nil, fmt.Errorf("peer: read message payload: %w", err)
	}
	msg := &Message{ID: MessageID(raw[0]), Payload: raw[1:]}
	if err := ValidateMessage(msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// WriteMessage validates and writes one complete frame.
func (c Codec) WriteMessage(w io.Writer, msg *Message) error {
	if msg == nil {
		return fmt.Errorf("peer: nil message, use WriteKeepalive for a keepalive")
	}
	length := uint64(len(msg.Payload)) + 1
	if length > uint64(^uint32(0)) {
		return fmt.Errorf("peer: frame length %d overflows uint32", length)
	}
	if length > uint64(c.maxFrameSize()) {
		return fmt.Errorf("peer: frame length %d exceeds maximum %d", length, c.maxFrameSize())
	}
	if err := ValidateMessage(msg); err != nil {
		return err
	}

	var header [5]byte
	binary.BigEndian.PutUint32(header[:4], uint32(length))
	header[4] = byte(msg.ID)
	if err := writeFull(w, header[:]); err != nil {
		return fmt.Errorf("peer: write message header: %w", err)
	}
	if err := writeFull(w, msg.Payload); err != nil {
		return fmt.Errorf("peer: write message payload: %w", err)
	}
	return nil
}

// WriteKeepalive writes a zero-length peer-wire frame.
func (c Codec) WriteKeepalive(w io.Writer) error {
	if err := writeFull(w, []byte{0, 0, 0, 0}); err != nil {
		return fmt.Errorf("peer: write keepalive: %w", err)
	}
	return nil
}

// ReadMessage uses DefaultMaxFrameSize.
func ReadMessage(r io.Reader) (*Message, error) {
	return (Codec{}).ReadMessage(r)
}

// WriteMessage uses DefaultMaxFrameSize.
func WriteMessage(w io.Writer, msg *Message) error {
	return (Codec{}).WriteMessage(w, msg)
}

// WriteKeepalive writes a zero-length peer-wire frame.
func WriteKeepalive(w io.Writer) error {
	return (Codec{}).WriteKeepalive(w)
}

// ValidateNegotiatedMessage checks the wire IDs whose legality is determined
// solely by both handshakes. Stateful v2 upgrade and extension-ID checks belong
// to the session layer.
func ValidateNegotiatedMessage(id MessageID, local, remote Reserved) error {
	switch {
	case id == MsgPort:
		if !local.Has(CapabilityDHT) || !remote.Has(CapabilityDHT) {
			return fmt.Errorf("peer: message %d requires negotiated DHT support", id)
		}
	case id >= MsgSuggestPiece && id <= MsgAllowedFast:
		if !local.Has(CapabilityFast) || !remote.Has(CapabilityFast) {
			return fmt.Errorf("peer: message %d requires negotiated fast extension", id)
		}
	case id == MsgExtended:
		if !local.Has(CapabilityExtensionProtocol) || !remote.Has(CapabilityExtensionProtocol) {
			return fmt.Errorf("peer: message %d requires negotiated extension protocol", id)
		}
	}
	return nil
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return fmt.Errorf("invalid write count %d", n)
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
