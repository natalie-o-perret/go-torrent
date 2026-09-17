package dht

import (
	"bytes"
	"fmt"
	"math/big"
	"net/netip"

	"github.com/natalie-o-perret/go-torrent/bencode"
)

const (
	maxTransactionIDSize = 8
	maxVersionSize       = 16
	maxMethodSize        = 32
)

type packetBuffer struct {
	bytes.Buffer
}

func (buffer *packetBuffer) Write(data []byte) (int, error) {
	if len(data) > MaxPacketSize-buffer.Len() {
		return 0, fmt.Errorf("KRPC packet exceeds %d bytes", MaxPacketSize)
	}
	return buffer.Buffer.Write(data)
}

// MessageType identifies a KRPC envelope.
type MessageType byte

const (
	QueryMessage    MessageType = 'q'
	ResponseMessage MessageType = 'r'
	ErrorMessage    MessageType = 'e'
)

// KRPCError is a remote or locally generated KRPC protocol error.
type KRPCError struct {
	Code    int64
	Message string
}

func (e *KRPCError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("dht: KRPC error %d: %s", e.Code, e.Message)
}

// Message is a bounded KRPC query, response, or error envelope. Arguments and
// Response contain values accepted by the repository's bencode package.
type Message struct {
	Transaction []byte
	Type        MessageType
	Query       string
	Arguments   map[string]any
	Response    map[string]any
	Error       *KRPCError
	Version     string
	IP          netip.AddrPort
	ReadOnly    bool
}

// MarshalMessage bencodes msg and rejects packets larger than 1024 bytes.
func MarshalMessage(msg Message) ([]byte, error) {
	if len(msg.Transaction) == 0 || len(msg.Transaction) > maxTransactionIDSize {
		return nil, fmt.Errorf("dht: transaction ID length %d is outside 1..%d", len(msg.Transaction), maxTransactionIDSize)
	}
	root := map[string]any{
		"t": msg.Transaction,
		"y": []byte{byte(msg.Type)},
	}
	if msg.Version != "" {
		if len(msg.Version) > maxVersionSize {
			return nil, fmt.Errorf("dht: version is longer than %d bytes", maxVersionSize)
		}
		root["v"] = msg.Version
	}
	if msg.IP.IsValid() {
		ip, err := EncodeCompactPeer(msg.IP)
		if err != nil {
			return nil, fmt.Errorf("dht: encode observed IP: %w", err)
		}
		root["ip"] = ip
	}
	if msg.ReadOnly {
		root["ro"] = int64(1)
	}
	switch msg.Type {
	case QueryMessage:
		if msg.Query == "" || len(msg.Query) > maxMethodSize {
			return nil, fmt.Errorf("dht: query method length is outside 1..%d", maxMethodSize)
		}
		if msg.Arguments == nil {
			return nil, fmt.Errorf("dht: query arguments are nil")
		}
		root["q"], root["a"] = msg.Query, msg.Arguments
	case ResponseMessage:
		if msg.Response == nil {
			return nil, fmt.Errorf("dht: response dictionary is nil")
		}
		root["r"] = msg.Response
	case ErrorMessage:
		if msg.Error == nil || len(msg.Error.Message) > 128 {
			return nil, fmt.Errorf("dht: invalid KRPC error")
		}
		root["e"] = []any{msg.Error.Code, msg.Error.Message}
	default:
		return nil, fmt.Errorf("dht: unknown message type %q", msg.Type)
	}

	var buffer packetBuffer
	if err := bencode.Encode(&buffer, root); err != nil {
		return nil, fmt.Errorf("dht: encode KRPC: %w", err)
	}
	if buffer.Len() > MaxPacketSize {
		return nil, fmt.Errorf("dht: KRPC packet is %d bytes, limit is %d", buffer.Len(), MaxPacketSize)
	}
	return buffer.Bytes(), nil
}

// UnmarshalMessage decodes one bounded KRPC envelope.
func UnmarshalMessage(packet []byte) (Message, error) {
	if len(packet) == 0 || len(packet) > MaxPacketSize {
		return Message{}, fmt.Errorf("dht: KRPC packet size %d is outside 1..%d", len(packet), MaxPacketSize)
	}
	decoder := bencode.NewDecoder(bytes.NewReader(packet))
	decoder.MaxBytes = MaxPacketSize
	decoder.MaxDepth = 4
	decoder.MaxValues = 128
	value, err := decoder.Decode()
	if err != nil {
		return Message{}, fmt.Errorf("dht: decode KRPC: %w", err)
	}
	root, ok := value.(map[string]any)
	if !ok {
		return Message{}, fmt.Errorf("dht: KRPC message is not a dictionary")
	}

	transaction, err := bytesField(root, "t", 1, maxTransactionIDSize)
	if err != nil {
		return Message{}, err
	}
	typeBytes, err := bytesField(root, "y", 1, 1)
	if err != nil {
		return Message{}, err
	}
	msg := Message{Transaction: transaction, Type: MessageType(typeBytes[0])}
	if raw, exists := root["v"]; exists {
		version, ok := raw.(string)
		if !ok || len(version) > maxVersionSize {
			return Message{}, fmt.Errorf("dht: field v is not a bounded byte string")
		}
		msg.Version = version
	}
	if raw, exists := root["ip"]; exists {
		encoded, ok := raw.(string)
		if !ok {
			return Message{}, fmt.Errorf("dht: field ip is not a byte string")
		}
		msg.IP, err = DecodeCompactPeer([]byte(encoded))
		if err != nil {
			return Message{}, fmt.Errorf("dht: field ip: %w", err)
		}
	}
	if raw, exists := root["ro"]; exists {
		readOnly, err := integer(raw, "ro")
		if err != nil || (readOnly != 0 && readOnly != 1) {
			return Message{}, fmt.Errorf("dht: field ro must be 0 or 1")
		}
		msg.ReadOnly = readOnly == 1
	}

	switch msg.Type {
	case QueryMessage:
		method, err := bytesField(root, "q", 1, maxMethodSize)
		if err != nil {
			return Message{}, err
		}
		arguments, ok := root["a"].(map[string]any)
		if !ok {
			return Message{}, fmt.Errorf("dht: field a is not a dictionary")
		}
		msg.Query, msg.Arguments = string(method), arguments
	case ResponseMessage:
		response, ok := root["r"].(map[string]any)
		if !ok {
			return Message{}, fmt.Errorf("dht: field r is not a dictionary")
		}
		msg.Response = response
	case ErrorMessage:
		list, ok := root["e"].([]any)
		if !ok || len(list) != 2 {
			return Message{}, fmt.Errorf("dht: field e is not a two-item list")
		}
		code, err := integer(list[0], "e[0]")
		if err != nil {
			return Message{}, err
		}
		text, ok := list[1].(string)
		if !ok || len(text) > 128 {
			return Message{}, fmt.Errorf("dht: field e[1] is not a bounded byte string")
		}
		msg.Error = &KRPCError{Code: code, Message: text}
	default:
		return Message{}, fmt.Errorf("dht: unknown message type %q", msg.Type)
	}
	return msg, nil
}

func bytesField(dict map[string]any, key string, minimum, maximum int) ([]byte, error) {
	raw, ok := dict[key]
	if !ok {
		return nil, fmt.Errorf("dht: missing field %s", key)
	}
	value, ok := raw.(string)
	if !ok || len(value) < minimum || len(value) > maximum {
		return nil, fmt.Errorf("dht: field %s is not a byte string of length %d..%d", key, minimum, maximum)
	}
	return []byte(value), nil
}

func integer(value any, name string) (int64, error) {
	switch number := value.(type) {
	case int64:
		return number, nil
	case *big.Int:
		return 0, fmt.Errorf("dht: field %s is outside int64", name)
	default:
		return 0, fmt.Errorf("dht: field %s is not an integer", name)
	}
}

func idField(dict map[string]any, key string) (ID, error) {
	value, err := bytesField(dict, key, IDLength, IDLength)
	if err != nil {
		return ID{}, err
	}
	return IDFromBytes(value)
}
