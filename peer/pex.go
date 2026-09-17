package peer

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

const (
	// DefaultPEXContactLimit is the BEP 11 non-initial per-direction limit.
	DefaultPEXContactLimit = 50
)

// PEXFlags is the BEP 11 one-byte contact flag set. Unknown bits are retained.
type PEXFlags uint8

const (
	// PEXPrefersEncryption indicates support for encrypted connections.
	PEXPrefersEncryption PEXFlags = 1 << iota
	// PEXSeed indicates a seed or upload-only peer.
	PEXSeed
	// PEXSupportsUTP indicates uTP support.
	PEXSupportsUTP
	// PEXSupportsHolepunch indicates ut_holepunch support.
	PEXSupportsHolepunch
	// PEXOutgoing indicates an outgoing, reachable connection.
	PEXOutgoing
)

// PEXContact is one added contact and its flags.
type PEXContact struct {
	AddrPort netip.AddrPort
	Flags    PEXFlags
}

// PEXMessage is a BEP 11 update. Unknown dictionary fields are retained.
type PEXMessage struct {
	Added   []PEXContact
	Dropped []netip.AddrPort
	Unknown map[string]any
}

// PEXLimits bounds contacts after combining IPv4 and IPv6 fields. The BEP 11
// non-initial limits are 50 and 50. A session may use a larger bounded value
// for its initial PEX message.
type PEXLimits struct {
	MaxAdded   int
	MaxDropped int
}

// StandardPEXLimits returns the BEP 11 non-initial limits.
func StandardPEXLimits() PEXLimits {
	return PEXLimits{MaxAdded: DefaultPEXContactLimit, MaxDropped: DefaultPEXContactLimit}
}

// Encode serialises a canonical PEX dictionary under limits.
func (message PEXMessage) Encode(limits PEXLimits) ([]byte, error) {
	limits, err := normalisePEXLimits(limits)
	if err != nil {
		return nil, err
	}
	if err := validatePEXMessage(message, limits); err != nil {
		return nil, err
	}
	dict := copyDictionary(message.Unknown)
	if dict == nil {
		dict = make(map[string]any)
	}
	for _, key := range []string{"added", "added.f", "added6", "added6.f", "dropped", "dropped6"} {
		delete(dict, key)
	}

	added4, flags4, added6, flags6 := encodeAddedContacts(message.Added)
	if len(added4) != 0 {
		dict["added"] = string(added4)
		if hasPEXFlags(flags4) {
			dict["added.f"] = string(flags4)
		}
	}
	if len(added6) != 0 {
		dict["added6"] = string(added6)
		if hasPEXFlags(flags6) {
			dict["added6.f"] = string(flags6)
		}
	}
	dropped4, dropped6 := encodeDroppedContacts(message.Dropped)
	if len(dropped4) != 0 {
		dict["dropped"] = string(dropped4)
	}
	if len(dropped6) != 0 {
		dict["dropped6"] = string(dropped6)
	}
	return encodeDictionary(dict, "PEX message")
}

// EncodePEXMessage serialises a PEX message with the standard non-initial
// limits.
func EncodePEXMessage(message PEXMessage) ([]byte, error) {
	return message.Encode(StandardPEXLimits())
}

// DecodePEXMessage decodes and validates a PEX dictionary under limits.
func DecodePEXMessage(payload []byte, limits PEXLimits) (PEXMessage, error) {
	limits, err := normalisePEXLimits(limits)
	if err != nil {
		return PEXMessage{}, err
	}
	dict, consumed, err := decodeDictionaryPrefix(payload, "PEX message")
	if err != nil {
		return PEXMessage{}, err
	}
	if consumed != len(payload) {
		return PEXMessage{}, fmt.Errorf("peer: PEX message has %d trailing bytes", len(payload)-consumed)
	}

	message := PEXMessage{Unknown: copyDictionary(dict)}
	for _, key := range []string{"added", "added.f", "added6", "added6.f", "dropped", "dropped6"} {
		delete(message.Unknown, key)
	}
	added4, present4, err := compactContactsField(dict, "added", 4, limits.MaxAdded)
	if err != nil {
		return PEXMessage{}, err
	}
	added6, present6, err := compactContactsField(dict, "added6", 16, limits.MaxAdded)
	if err != nil {
		return PEXMessage{}, err
	}
	flags4, err := pexFlagsField(dict, "added.f", len(added4), present4)
	if err != nil {
		return PEXMessage{}, err
	}
	flags6, err := pexFlagsField(dict, "added6.f", len(added6), present6)
	if err != nil {
		return PEXMessage{}, err
	}
	message.Added = make([]PEXContact, 0, len(added4)+len(added6))
	for i, endpoint := range added4 {
		message.Added = append(message.Added, PEXContact{AddrPort: endpoint, Flags: flags4[i]})
	}
	for i, endpoint := range added6 {
		message.Added = append(message.Added, PEXContact{AddrPort: endpoint, Flags: flags6[i]})
	}
	dropped4, presentDropped4, err := compactContactsField(dict, "dropped", 4, limits.MaxDropped)
	if err != nil {
		return PEXMessage{}, err
	}
	dropped6, presentDropped6, err := compactContactsField(dict, "dropped6", 16, limits.MaxDropped)
	if err != nil {
		return PEXMessage{}, err
	}
	message.Dropped = dropped4
	message.Dropped = append(message.Dropped, dropped6...)
	if !present4 && !present6 && !presentDropped4 && !presentDropped6 {
		return PEXMessage{}, fmt.Errorf("peer: PEX message contains no contact field")
	}
	if err := validatePEXMessage(message, limits); err != nil {
		return PEXMessage{}, err
	}
	return message, nil
}

// DecodePEX decodes a PEX message with the standard non-initial limits.
func DecodePEX(payload []byte) (PEXMessage, error) {
	return DecodePEXMessage(payload, StandardPEXLimits())
}

func normalisePEXLimits(limits PEXLimits) (PEXLimits, error) {
	if limits.MaxAdded == 0 && limits.MaxDropped == 0 {
		return StandardPEXLimits(), nil
	}
	if limits.MaxAdded <= 0 || limits.MaxDropped <= 0 {
		return PEXLimits{}, fmt.Errorf("peer: PEX contact limits must be positive")
	}
	return limits, nil
}

func validatePEXMessage(message PEXMessage, limits PEXLimits) error {
	if len(message.Added) == 0 && len(message.Dropped) == 0 {
		return fmt.Errorf("peer: PEX message contains no contacts")
	}
	if len(message.Added) > limits.MaxAdded {
		return fmt.Errorf("peer: PEX message has %d added contacts, limit %d", len(message.Added), limits.MaxAdded)
	}
	if len(message.Dropped) > limits.MaxDropped {
		return fmt.Errorf("peer: PEX message has %d dropped contacts, limit %d", len(message.Dropped), limits.MaxDropped)
	}
	addedAddresses := make(map[netip.Addr]netip.AddrPort, len(message.Added))
	for i, contact := range message.Added {
		endpoint, err := validPEXEndpoint(contact.AddrPort)
		if err != nil {
			return fmt.Errorf("peer: PEX added contact %d: %w", i, err)
		}
		address := endpoint.Addr()
		if previous, duplicate := addedAddresses[address]; duplicate {
			return fmt.Errorf("peer: PEX added contacts duplicate IP %s at %s and %s", address, previous, endpoint)
		}
		addedAddresses[address] = endpoint
	}
	droppedAddresses := make(map[netip.Addr]netip.AddrPort, len(message.Dropped))
	for i, rawEndpoint := range message.Dropped {
		endpoint, err := validPEXEndpoint(rawEndpoint)
		if err != nil {
			return fmt.Errorf("peer: PEX dropped contact %d: %w", i, err)
		}
		address := endpoint.Addr()
		if previous, duplicate := droppedAddresses[address]; duplicate {
			return fmt.Errorf("peer: PEX dropped contacts duplicate IP %s at %s and %s", address, previous, endpoint)
		}
		if added, exists := addedAddresses[address]; exists {
			return fmt.Errorf("peer: PEX IP %s is both added at %s and dropped at %s", address, added, endpoint)
		}
		droppedAddresses[address] = endpoint
	}
	return nil
}

func validPEXEndpoint(endpoint netip.AddrPort) (netip.AddrPort, error) {
	if !endpoint.IsValid() || endpoint.Port() == 0 || endpoint.Addr().Zone() != "" {
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint %s", endpoint)
	}
	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port()), nil
}

func compactContactsField(dict map[string]any, key string, addressLength, limit int) ([]netip.AddrPort, bool, error) {
	raw, present := dict[key]
	if !present {
		return nil, false, nil
	}
	value, ok := raw.(string)
	if !ok {
		return nil, false, fmt.Errorf("peer: PEX %s is not a string", key)
	}
	contactLength := addressLength + 2
	if value == "" || len(value)%contactLength != 0 {
		return nil, false, fmt.Errorf("peer: PEX %s length %d is not a positive multiple of %d", key, len(value), contactLength)
	}
	count := len(value) / contactLength
	if count > limit {
		return nil, false, fmt.Errorf("peer: PEX %s has %d contacts, limit %d", key, count, limit)
	}
	contacts := make([]netip.AddrPort, count)
	for i := range contacts {
		offset := i * contactLength
		address, ok := netip.AddrFromSlice([]byte(value[offset : offset+addressLength]))
		if !ok {
			return nil, false, fmt.Errorf("peer: PEX %s contact %d has an invalid address", key, i)
		}
		if addressLength == 16 && address.Is4In6() {
			return nil, false, fmt.Errorf("peer: PEX %s contact %d contains an IPv4-mapped address", key, i)
		}
		port := binary.BigEndian.Uint16([]byte(value[offset+addressLength : offset+contactLength]))
		if port == 0 {
			return nil, false, fmt.Errorf("peer: PEX %s contact %d has port zero", key, i)
		}
		contacts[i] = netip.AddrPortFrom(address, port)
	}
	return contacts, true, nil
}

func pexFlagsField(dict map[string]any, key string, count int, contactsPresent bool) ([]PEXFlags, error) {
	raw, present := dict[key]
	flags := make([]PEXFlags, count)
	if !present {
		return flags, nil
	}
	if !contactsPresent {
		return nil, fmt.Errorf("peer: PEX %s is present without its contact field", key)
	}
	value, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("peer: PEX %s is not a string", key)
	}
	if len(value) != count {
		return nil, fmt.Errorf("peer: PEX %s has %d flags, want %d", key, len(value), count)
	}
	for i := range flags {
		flags[i] = PEXFlags(value[i])
	}
	return flags, nil
}

func encodeAddedContacts(contacts []PEXContact) (ipv4, flags4, ipv6, flags6 []byte) {
	for _, contact := range contacts {
		address := contact.AddrPort.Addr().Unmap()
		port := contact.AddrPort.Port()
		if address.Is4() {
			bytes := address.As4()
			ipv4 = append(ipv4, bytes[:]...)
			ipv4 = binary.BigEndian.AppendUint16(ipv4, port)
			flags4 = append(flags4, byte(contact.Flags))
		} else {
			bytes := address.As16()
			ipv6 = append(ipv6, bytes[:]...)
			ipv6 = binary.BigEndian.AppendUint16(ipv6, port)
			flags6 = append(flags6, byte(contact.Flags))
		}
	}
	return ipv4, flags4, ipv6, flags6
}

func encodeDroppedContacts(contacts []netip.AddrPort) (ipv4, ipv6 []byte) {
	for _, contact := range contacts {
		address := contact.Addr().Unmap()
		if address.Is4() {
			bytes := address.As4()
			ipv4 = append(ipv4, bytes[:]...)
			ipv4 = binary.BigEndian.AppendUint16(ipv4, contact.Port())
		} else {
			bytes := address.As16()
			ipv6 = append(ipv6, bytes[:]...)
			ipv6 = binary.BigEndian.AppendUint16(ipv6, contact.Port())
		}
	}
	return ipv4, ipv6
}

func hasPEXFlags(flags []byte) bool {
	for _, flag := range flags {
		if flag != 0 {
			return true
		}
	}
	return false
}
