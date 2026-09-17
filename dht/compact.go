package dht

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// EncodeCompactPeer encodes an IPv4 or IPv6 peer endpoint in compact form.
func EncodeCompactPeer(peer netip.AddrPort) ([]byte, error) {
	peer = normalizeEndpoint(peer)
	if !validEndpoint(peer) {
		return nil, fmt.Errorf("dht: invalid peer endpoint %v", peer)
	}
	addr := peer.Addr()
	if addr.Is4() {
		ip := addr.As4()
		out := make([]byte, 6)
		copy(out, ip[:])
		binary.BigEndian.PutUint16(out[4:], peer.Port())
		return out, nil
	}
	ip := addr.As16()
	out := make([]byte, 18)
	copy(out, ip[:])
	binary.BigEndian.PutUint16(out[16:], peer.Port())
	return out, nil
}

// DecodeCompactPeer decodes a 6-byte IPv4 or 18-byte IPv6 peer endpoint.
func DecodeCompactPeer(data []byte) (netip.AddrPort, error) {
	var addr netip.Addr
	switch len(data) {
	case 6:
		var ip [4]byte
		copy(ip[:], data[:4])
		addr = netip.AddrFrom4(ip)
	case 18:
		var ip [16]byte
		copy(ip[:], data[:16])
		addr = netip.AddrFrom16(ip)
	default:
		return netip.AddrPort{}, fmt.Errorf("dht: compact peer is %d bytes, want 6 or 18", len(data))
	}
	peer := netip.AddrPortFrom(addr, binary.BigEndian.Uint16(data[len(data)-2:]))
	if !validEndpoint(peer) {
		return netip.AddrPort{}, fmt.Errorf("dht: invalid compact peer %v", peer)
	}
	return peer, nil
}

// EncodeCompactNodes encodes contacts as BEP 5 or BEP 32 compact nodes.
func EncodeCompactNodes(contacts []Contact, family Family) ([]byte, error) {
	entrySize, err := compactNodeSize(family)
	if err != nil {
		return nil, err
	}
	if len(contacts) > K {
		return nil, fmt.Errorf("dht: %d compact nodes exceed K=%d", len(contacts), K)
	}
	out := make([]byte, 0, len(contacts)*entrySize)
	for _, contact := range contacts {
		endpoint := normalizeEndpoint(contact.Addr)
		if !validEndpoint(endpoint) || familyOf(endpoint.Addr()) != family {
			return nil, fmt.Errorf("dht: contact %v is not valid IPv%d", endpoint, family)
		}
		peer, err := EncodeCompactPeer(endpoint)
		if err != nil {
			return nil, err
		}
		out = append(out, contact.ID[:]...)
		out = append(out, peer...)
	}
	return out, nil
}

// DecodeCompactNodes decodes up to limit compact BEP 5 or BEP 32 contacts.
func DecodeCompactNodes(data []byte, family Family, limit int) ([]Contact, error) {
	entrySize, err := compactNodeSize(family)
	if err != nil {
		return nil, err
	}
	if limit < 0 || len(data)%entrySize != 0 {
		return nil, fmt.Errorf("dht: invalid IPv%d compact nodes length %d", family, len(data))
	}
	count := len(data) / entrySize
	if count > limit {
		return nil, fmt.Errorf("dht: %d compact nodes exceed limit %d", count, limit)
	}
	contacts := make([]Contact, 0, count)
	peerSize := entrySize - IDLength
	for offset := 0; offset < len(data); offset += entrySize {
		id, err := IDFromBytes(data[offset : offset+IDLength])
		if err != nil {
			return nil, err
		}
		peer, err := DecodeCompactPeer(data[offset+IDLength : offset+IDLength+peerSize])
		if err != nil {
			return nil, err
		}
		contacts = append(contacts, Contact{ID: id, Addr: peer})
	}
	return contacts, nil
}

func compactNodeSize(family Family) (int, error) {
	switch family {
	case IPv4:
		return IDLength + 6, nil
	case IPv6:
		return IDLength + 18, nil
	default:
		return 0, fmt.Errorf("dht: unsupported address family %d", family)
	}
}
