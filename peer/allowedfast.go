package peer

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/natalie-o-perret/go-torrent/metainfo"
)

// GenerateAllowedFastSet implements the canonical BEP 6 IPv4 /24 algorithm.
// The result order is the order in which Allowed Fast messages are sent.
func GenerateAllowedFastSet(infoHash metainfo.Hash, address netip.Addr, pieceCount uint32, count int) ([]uint32, error) {
	address = address.Unmap()
	if !address.Is4() || address.Zone() != "" {
		return nil, fmt.Errorf("peer: allowed fast generation requires an IPv4 address")
	}
	if count < 0 || uint64(count) > uint64(pieceCount) {
		return nil, fmt.Errorf("peer: allowed fast count %d is outside 0..%d", count, pieceCount)
	}
	if count == 0 {
		return []uint32{}, nil
	}

	ip := address.As4()
	seed := make([]byte, 24)
	copy(seed[:3], ip[:3])
	copy(seed[4:], infoHash[:])
	result := make([]uint32, 0, count)
	seen := make(map[uint32]struct{}, count)
	for len(result) < count {
		digest := sha1.Sum(seed)
		seed = digest[:]
		for offset := 0; offset < len(digest) && len(result) < count; offset += 4 {
			index := binary.BigEndian.Uint32(digest[offset:offset+4]) % pieceCount
			if _, duplicate := seen[index]; duplicate {
				continue
			}
			seen[index] = struct{}{}
			result = append(result, index)
		}
	}
	return result, nil
}
