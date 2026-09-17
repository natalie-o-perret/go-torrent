// Package dht implements the BitTorrent mainline DHT protocol (BEP 5),
// including IPv6 (BEP 32), secure node IDs (BEP 42), and read-only nodes
// (BEP 43).
package dht

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"net/netip"
	"time"
)

var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

const (
	// IDLength is the byte length of a DHT node ID or torrent info hash.
	IDLength = 20
	// K is the maximum number of contacts in a routing bucket.
	K = 8
	// MaxPacketSize is the largest KRPC datagram this package sends or accepts.
	MaxPacketSize = 1024
)

// ID is a 160-bit DHT node ID or torrent info hash.
type ID [IDLength]byte

// IDFromBytes converts exactly 20 bytes to an ID.
func IDFromBytes(data []byte) (ID, error) {
	var id ID
	if len(data) != IDLength {
		return id, fmt.Errorf("dht: ID is %d bytes, want %d", len(data), IDLength)
	}
	copy(id[:], data)
	return id, nil
}

// Bytes returns a copy of id.
func (id ID) Bytes() []byte {
	return append([]byte(nil), id[:]...)
}

// String returns the hexadecimal representation of id.
func (id ID) String() string {
	return hex.EncodeToString(id[:])
}

// Distance returns the XOR distance between a and b.
func Distance(a, b ID) ID {
	var distance ID
	for i := range distance {
		distance[i] = a[i] ^ b[i]
	}
	return distance
}

func compareDistance(target, a, b ID) int {
	da, db := Distance(target, a), Distance(target, b)
	return bytes.Compare(da[:], db[:])
}

// Family identifies an IP address family in BEP 32 requests.
type Family uint8

const (
	IPv4 Family = 4
	IPv6 Family = 6
)

func familyOf(addr netip.Addr) Family {
	if addr.Unmap().Is4() {
		return IPv4
	}
	return IPv6
}

// Liveness is a routing contact's current status.
type Liveness uint8

const (
	Good Liveness = iota
	Questionable
	Bad
)

// Contact is a DHT node and the reachability information learned for it.
type Contact struct {
	ID           ID
	Addr         netip.AddrPort
	LastResponse time.Time
	LastQuery    time.Time
	Failures     uint8
}

// Liveness reports the contact's status at now.
func (c Contact) Liveness(now time.Time, goodFor time.Duration) Liveness {
	if c.Failures >= 2 {
		return Bad
	}
	if c.LastResponse.IsZero() {
		return Questionable
	}
	if c.Failures == 0 && (now.Sub(c.LastResponse) <= goodFor || (!c.LastQuery.IsZero() && now.Sub(c.LastQuery) <= goodFor)) {
		return Good
	}
	return Questionable
}

// SecureNodeID creates a BEP 42 node ID for ip using entropy for the
// unrestricted bits.
func SecureNodeID(ip netip.Addr, entropy io.Reader) (ID, error) {
	var id ID
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return id, fmt.Errorf("dht: cannot create node ID for %v", ip)
	}
	if entropy == nil {
		return id, fmt.Errorf("dht: nil entropy reader")
	}
	if _, err := io.ReadFull(entropy, id[:]); err != nil {
		return ID{}, fmt.Errorf("dht: generate node ID: %w", err)
	}
	prefix := securePrefix(ip, id[19]&7)
	id[0], id[1] = byte(prefix>>24), byte(prefix>>16)
	id[2] = byte(prefix>>8)&0xf8 | id[2]&7
	return id, nil
}

// ValidNodeID reports whether id is valid for ip under BEP 42. Local,
// private, and link-local addresses are exempt from validation.
func ValidNodeID(id ID, ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	ip = ip.Unmap()
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	prefix := securePrefix(ip, id[19]&7)
	return id[0] == byte(prefix>>24) && id[1] == byte(prefix>>16) && id[2]&0xf8 == byte(prefix>>8)&0xf8
}

func securePrefix(ip netip.Addr, r byte) uint32 {
	if ip = ip.Unmap(); ip.Is4() {
		value := ip.As4()
		mask := [4]byte{0x03, 0x0f, 0x3f, 0xff}
		for i := range value {
			value[i] &= mask[i]
		}
		value[0] |= (r & 7) << 5
		return crc32.Checksum(value[:], crc32cTable)
	}
	value := ip.As16()
	mask := [8]byte{0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff}
	for i := range mask {
		value[i] &= mask[i]
	}
	value[0] |= (r & 7) << 5
	return crc32.Checksum(value[:8], crc32cTable)
}

func validEndpoint(endpoint netip.AddrPort) bool {
	addr := endpoint.Addr()
	return endpoint.IsValid() && endpoint.Port() != 0 && addr.Zone() == "" && !addr.IsUnspecified() && !addr.IsMulticast()
}

func normalizeEndpoint(endpoint netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
}
