package peer

import (
	"fmt"
	"math"
	"net/netip"
	"unicode/utf8"
)

const (
	// ExtendedHandshakeID identifies the BEP 10 extension handshake envelope.
	ExtendedHandshakeID uint8 = 0
	// ExtensionMetadata is the BEP 9 extension name.
	ExtensionMetadata = "ut_metadata"
	// ExtensionPEX is the BEP 11 extension name.
	ExtensionPEX = "ut_pex"
)

// ExtendedMessage is the payload nested inside message ID 20.
type ExtendedMessage struct {
	ID      uint8
	Payload []byte
}

// FormatExtended formats a BEP 10 extension envelope.
func FormatExtended(id uint8, payload []byte) ([]byte, error) {
	if id == ExtendedHandshakeID {
		if _, err := DecodeExtensionHandshake(payload); err != nil {
			return nil, err
		}
	}
	result := make([]byte, 1+len(payload))
	result[0] = id
	copy(result[1:], payload)
	return result, nil
}

// ParseExtended parses a BEP 10 extension envelope. Its payload aliases the
// input. Unknown nonzero extension IDs remain opaque.
func ParseExtended(payload []byte) (ExtendedMessage, error) {
	if len(payload) < 1 {
		return ExtendedMessage{}, fmt.Errorf("peer: extended payload is missing its extension ID")
	}
	message := ExtendedMessage{ID: payload[0], Payload: payload[1:]}
	if message.ID == ExtendedHandshakeID {
		if _, err := DecodeExtensionHandshake(message.Payload); err != nil {
			return ExtendedMessage{}, err
		}
	}
	return message, nil
}

// ExtensionHandshake is the BEP 10 extension handshake. Unknown top-level
// fields are retained in Unknown and emitted again by Encode.
type ExtensionHandshake struct {
	Extensions   map[string]uint8
	Port         *uint16
	Client       string
	YourIP       netip.Addr
	IPv4         netip.Addr
	IPv6         netip.Addr
	RequestQueue *uint32
	MetadataSize *uint32
	Unknown      map[string]any
}

// Encode serialises h as a canonical bencoded dictionary.
func (h ExtensionHandshake) Encode() ([]byte, error) {
	dict := copyDictionary(h.Unknown)
	if dict == nil {
		dict = make(map[string]any)
	}
	for _, key := range []string{"m", "p", "v", "yourip", "ipv4", "ipv6", "reqq", "metadata_size"} {
		delete(dict, key)
	}

	if h.Extensions != nil {
		var ids ExtensionIDs
		if err := ids.Apply(h.Extensions); err != nil {
			return nil, fmt.Errorf("peer: extension handshake m: %w", err)
		}
		m := make(map[string]any, len(h.Extensions))
		for name, id := range h.Extensions {
			m[name] = int64(id)
		}
		dict["m"] = m
	}
	if h.Port != nil {
		if *h.Port == 0 {
			return nil, fmt.Errorf("peer: extension handshake p must be nonzero")
		}
		dict["p"] = int64(*h.Port)
	}
	if h.Client != "" {
		if !utf8.ValidString(h.Client) {
			return nil, fmt.Errorf("peer: extension handshake v is not valid UTF-8")
		}
		dict["v"] = h.Client
	}
	if h.YourIP.IsValid() {
		encoded, err := compactIP(h.YourIP)
		if err != nil {
			return nil, fmt.Errorf("peer: extension handshake yourip: %w", err)
		}
		dict["yourip"] = encoded
	}
	if h.IPv4.IsValid() {
		if !h.IPv4.Is4() {
			return nil, fmt.Errorf("peer: extension handshake ipv4 is not IPv4")
		}
		bytes := h.IPv4.As4()
		dict["ipv4"] = string(bytes[:])
	}
	if h.IPv6.IsValid() {
		if !h.IPv6.Is6() || h.IPv6.Is4In6() || h.IPv6.Zone() != "" {
			return nil, fmt.Errorf("peer: extension handshake ipv6 is not IPv6")
		}
		bytes := h.IPv6.As16()
		dict["ipv6"] = string(bytes[:])
	}
	if h.RequestQueue != nil {
		dict["reqq"] = int64(*h.RequestQueue)
	}
	if h.MetadataSize != nil {
		if *h.MetadataSize == 0 {
			return nil, fmt.Errorf("peer: extension handshake metadata_size must be positive")
		}
		dict["metadata_size"] = int64(*h.MetadataSize)
	}
	return encodeDictionary(dict, "extension handshake")
}

// EncodeExtensionHandshake serialises h as a canonical bencoded dictionary.
func EncodeExtensionHandshake(h ExtensionHandshake) ([]byte, error) {
	return h.Encode()
}

// DecodeExtensionHandshake decodes one complete BEP 10 handshake.
func DecodeExtensionHandshake(payload []byte) (ExtensionHandshake, error) {
	dict, consumed, err := decodeDictionaryPrefix(payload, "extension handshake")
	if err != nil {
		return ExtensionHandshake{}, err
	}
	if consumed != len(payload) {
		return ExtensionHandshake{}, fmt.Errorf("peer: extension handshake has %d trailing bytes", len(payload)-consumed)
	}

	handshake := ExtensionHandshake{Unknown: copyDictionary(dict)}
	for _, key := range []string{"m", "p", "v", "yourip", "ipv4", "ipv6", "reqq", "metadata_size"} {
		delete(handshake.Unknown, key)
	}
	if raw, ok := dict["m"]; ok {
		rawMap, ok := raw.(map[string]any)
		if !ok {
			return ExtensionHandshake{}, fmt.Errorf("peer: extension handshake m is not a dictionary")
		}
		handshake.Extensions = make(map[string]uint8, len(rawMap))
		for name, value := range rawMap {
			if name == "" {
				return ExtensionHandshake{}, fmt.Errorf("peer: extension handshake contains an empty extension name")
			}
			id, err := integerField(value, fmt.Sprintf("extension handshake m[%q]", name))
			if err != nil {
				return ExtensionHandshake{}, err
			}
			if id < 0 || id > math.MaxUint8 {
				return ExtensionHandshake{}, fmt.Errorf("peer: extension handshake ID %d for %q is outside 0..255", id, name)
			}
			handshake.Extensions[name] = uint8(id)
		}
		var ids ExtensionIDs
		if err := ids.Apply(handshake.Extensions); err != nil {
			return ExtensionHandshake{}, fmt.Errorf("peer: extension handshake m: %w", err)
		}
	}
	if raw, ok := dict["p"]; ok {
		value, err := uintField(raw, "extension handshake p", 1, math.MaxUint16)
		if err != nil {
			return ExtensionHandshake{}, err
		}
		port := uint16(value)
		handshake.Port = &port
	}
	if raw, ok := dict["v"]; ok {
		client, ok := raw.(string)
		if !ok || !utf8.ValidString(client) {
			return ExtensionHandshake{}, fmt.Errorf("peer: extension handshake v is not a UTF-8 string")
		}
		handshake.Client = client
	}
	if raw, ok := dict["yourip"]; ok {
		handshake.YourIP, err = parseCompactIP(raw, "yourip", 0)
		if err != nil {
			return ExtensionHandshake{}, err
		}
	}
	if raw, ok := dict["ipv4"]; ok {
		handshake.IPv4, err = parseCompactIP(raw, "ipv4", 4)
		if err != nil {
			return ExtensionHandshake{}, err
		}
	}
	if raw, ok := dict["ipv6"]; ok {
		handshake.IPv6, err = parseCompactIP(raw, "ipv6", 16)
		if err != nil {
			return ExtensionHandshake{}, err
		}
		if handshake.IPv6.Is4In6() {
			return ExtensionHandshake{}, fmt.Errorf("peer: extension handshake ipv6 contains an IPv4-mapped address")
		}
	}
	if raw, ok := dict["reqq"]; ok {
		value, err := uintField(raw, "extension handshake reqq", 0, math.MaxUint32)
		if err != nil {
			return ExtensionHandshake{}, err
		}
		queue := uint32(value)
		handshake.RequestQueue = &queue
	}
	if raw, ok := dict["metadata_size"]; ok {
		value, err := uintField(raw, "extension handshake metadata_size", 1, math.MaxUint32)
		if err != nil {
			return ExtensionHandshake{}, err
		}
		size := uint32(value)
		handshake.MetadataSize = &size
	}
	return handshake, nil
}

// ExtensionIDs maintains both lookup directions of one additive BEP 10 ID map.
// Its zero value is ready for use.
type ExtensionIDs struct {
	byName map[string]uint8
	byID   map[uint8]string
}

// Apply atomically applies an additive handshake update. ID zero disables a
// name. Positive IDs must remain unique after the complete update.
func (ids *ExtensionIDs) Apply(update map[string]uint8) error {
	if ids == nil {
		return fmt.Errorf("peer: nil extension ID map")
	}
	candidate := make(map[string]uint8, len(ids.byName)+len(update))
	for name, id := range ids.byName {
		candidate[name] = id
	}
	for name, id := range update {
		if name == "" {
			return fmt.Errorf("empty extension name")
		}
		if id == 0 {
			delete(candidate, name)
		} else {
			candidate[name] = id
		}
	}
	reverse := make(map[uint8]string, len(candidate))
	for name, id := range candidate {
		if previous, exists := reverse[id]; exists {
			return fmt.Errorf("extension ID %d is shared by %q and %q", id, previous, name)
		}
		reverse[id] = name
	}
	ids.byName = candidate
	ids.byID = reverse
	return nil
}

// ID returns the current ID for name.
func (ids *ExtensionIDs) ID(name string) (uint8, bool) {
	if ids == nil {
		return 0, false
	}
	id, ok := ids.byName[name]
	return id, ok
}

// Name returns the current extension name for id.
func (ids *ExtensionIDs) Name(id uint8) (string, bool) {
	if ids == nil {
		return "", false
	}
	name, ok := ids.byID[id]
	return name, ok
}

// Snapshot returns a copy of the current name-to-ID map.
func (ids *ExtensionIDs) Snapshot() map[string]uint8 {
	if ids == nil || len(ids.byName) == 0 {
		return nil
	}
	result := make(map[string]uint8, len(ids.byName))
	for name, id := range ids.byName {
		result[name] = id
	}
	return result
}

// ExtensionMaps separates IDs accepted by this peer from IDs accepted by the
// remote peer.
type ExtensionMaps struct {
	Incoming ExtensionIDs
	Outgoing ExtensionIDs
}

// ApplyLocal applies IDs advertised locally, which identify incoming messages.
func (maps *ExtensionMaps) ApplyLocal(handshake ExtensionHandshake) error {
	if maps == nil {
		return fmt.Errorf("peer: nil extension maps")
	}
	return maps.Incoming.Apply(handshake.Extensions)
}

// ApplyRemote applies IDs advertised remotely, which identify outgoing messages.
func (maps *ExtensionMaps) ApplyRemote(handshake ExtensionHandshake) error {
	if maps == nil {
		return fmt.Errorf("peer: nil extension maps")
	}
	return maps.Outgoing.Apply(handshake.Extensions)
}

func compactIP(address netip.Addr) (string, error) {
	if address.Zone() != "" {
		return "", fmt.Errorf("scoped IP address is not compact-encodable")
	}
	address = address.Unmap()
	if address.Is4() {
		bytes := address.As4()
		return string(bytes[:]), nil
	}
	if address.Is6() {
		bytes := address.As16()
		return string(bytes[:]), nil
	}
	return "", fmt.Errorf("invalid IP address")
}

func parseCompactIP(raw any, name string, exactLength int) (netip.Addr, error) {
	value, ok := raw.(string)
	if !ok {
		return netip.Addr{}, fmt.Errorf("peer: extension handshake %s is not a string", name)
	}
	if (exactLength != 0 && len(value) != exactLength) || (exactLength == 0 && len(value) != 4 && len(value) != 16) {
		return netip.Addr{}, fmt.Errorf("peer: extension handshake %s has invalid length %d", name, len(value))
	}
	address, ok := netip.AddrFromSlice([]byte(value))
	if !ok {
		return netip.Addr{}, fmt.Errorf("peer: extension handshake %s is not an IP address", name)
	}
	return address, nil
}

func uintField(raw any, name string, minimum, maximum uint64) (uint64, error) {
	value, err := integerField(raw, name)
	if err != nil {
		return 0, err
	}
	if value < 0 || uint64(value) < minimum || uint64(value) > maximum {
		return 0, fmt.Errorf("peer: %s value %d is outside %d..%d", name, value, minimum, maximum)
	}
	return uint64(value), nil
}
