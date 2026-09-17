package client

import (
	"fmt"
	"math"

	"github.com/natalie-o-perret/go-torrent/metainfo"
	"github.com/natalie-o-perret/go-torrent/peer"
	"github.com/natalie-o-perret/go-torrent/piece"
	"github.com/natalie-o-perret/go-torrent/storage"
)

type wirePiece struct {
	v1     metainfo.Hash
	v2     metainfo.HashV2
	length uint32
	span   int
}

type wireLayout struct {
	protocol storage.Protocol
	pieces   []wirePiece
	total    int64
	infoHash metainfo.Hash
}

func buildWireLayouts(meta *metainfo.MetaInfo, layout *storage.Layout) (map[peer.ProtocolVersion]*wireLayout, peer.ProtocolVersion, int, error) {
	if layout == nil {
		return nil, 0, 0, fmt.Errorf("client: storage has no layout")
	}
	layouts := make(map[peer.ProtocolVersion]*wireLayout, 2)
	pieceCount := -1
	if meta.Info.HasV1() {
		wire, err := buildV1Layout(meta, layout)
		if err != nil {
			return nil, 0, 0, err
		}
		layouts[peer.ProtocolV1] = wire
		pieceCount = len(wire.pieces)
	}
	if meta.Info.HasV2() {
		wire, err := buildV2Layout(meta, layout)
		if err != nil {
			return nil, 0, 0, err
		}
		layouts[peer.ProtocolV2] = wire
		if pieceCount >= 0 && pieceCount != len(wire.pieces) {
			return nil, 0, 0, fmt.Errorf("client: hybrid layouts have different piece counts")
		}
		pieceCount = len(wire.pieces)
	}
	if pieceCount < 0 {
		return nil, 0, 0, fmt.Errorf("client: metainfo has no supported swarm")
	}
	primary := peer.ProtocolV1
	if layouts[primary] == nil {
		primary = peer.ProtocolV2
	}
	return layouts, primary, pieceCount, nil
}

func buildV1Layout(meta *metainfo.MetaInfo, layout *storage.Layout) (*wireLayout, error) {
	count, err := layout.PieceCount(storage.V1)
	if err != nil {
		return nil, fmt.Errorf("client: v1 layout: %w", err)
	}
	if count != len(meta.Info.Pieces) {
		return nil, fmt.Errorf("client: v1 storage has %d pieces, metainfo has %d", count, len(meta.Info.Pieces))
	}
	wire := &wireLayout{protocol: storage.V1, pieces: make([]wirePiece, count), infoHash: meta.InfoHash}
	for index := range wire.pieces {
		length, err := checkedPieceLength(layout, storage.V1, index)
		if err != nil {
			return nil, err
		}
		wire.pieces[index] = wirePiece{v1: meta.Info.Pieces[index], length: length}
		wire.total += int64(length)
	}
	return wire, nil
}

func buildV2Layout(meta *metainfo.MetaInfo, layout *storage.Layout) (*wireLayout, error) {
	count, err := layout.PieceCount(storage.V2)
	if err != nil {
		return nil, fmt.Errorf("client: v2 layout: %w", err)
	}
	wire := &wireLayout{protocol: storage.V2, pieces: make([]wirePiece, 0, count)}
	copy(wire.infoHash[:], meta.InfoHashV2[:len(wire.infoHash)])
	for _, file := range meta.Info.V2Files {
		if file.Length == 0 {
			continue
		}
		if file.PiecesRoot == nil {
			return nil, fmt.Errorf("client: v2 file has no pieces root")
		}
		filePieces := int(1 + (file.Length-1)/meta.Info.PieceLength)
		var hashes []metainfo.HashV2
		if filePieces == 1 {
			hashes = []metainfo.HashV2{*file.PiecesRoot}
		} else {
			hashes = meta.PieceLayers[*file.PiecesRoot]
			if len(hashes) != filePieces {
				return nil, fmt.Errorf("client: v2 file piece layer has %d hashes, want %d", len(hashes), filePieces)
			}
		}
		for localIndex := range filePieces {
			length := min(meta.Info.PieceLength, file.Length-int64(localIndex)*meta.Info.PieceLength)
			if length <= 0 || length > math.MaxUint32 || length > int64(math.MaxInt) {
				return nil, fmt.Errorf("client: v2 piece length %d is outside peer-wire bounds", length)
			}
			span := meta.Info.PieceLength
			if file.Length <= meta.Info.PieceLength {
				span = piece.BlockSize
				for span < length {
					span *= 2
				}
			}
			if span > int64(math.MaxInt) {
				return nil, fmt.Errorf("client: v2 piece span %d overflows int", span)
			}
			wire.pieces = append(wire.pieces, wirePiece{v2: hashes[localIndex], length: uint32(length), span: int(span)})
			wire.total += length
		}
	}
	if len(wire.pieces) != count {
		return nil, fmt.Errorf("client: v2 storage has %d pieces, metainfo maps %d", count, len(wire.pieces))
	}
	for index := range wire.pieces {
		length, err := checkedPieceLength(layout, storage.V2, index)
		if err != nil {
			return nil, err
		}
		if wire.pieces[index].length != length {
			return nil, fmt.Errorf("client: v2 piece %d length %d differs from storage length %d", index, wire.pieces[index].length, length)
		}
	}
	return wire, nil
}

func checkedPieceLength(layout *storage.Layout, protocol storage.Protocol, index int) (uint32, error) {
	length, err := layout.PieceLength(protocol, index)
	if err != nil {
		return 0, fmt.Errorf("client: %s piece %d: %w", protocol, index, err)
	}
	if length <= 0 || length > math.MaxUint32 || length > int64(math.MaxInt) {
		return 0, fmt.Errorf("client: %s piece %d length %d is outside peer-wire bounds", protocol, index, length)
	}
	return uint32(length), nil
}

func (layout *wireLayout) newPiece(index int) (*piece.State, error) {
	if layout == nil || index < 0 || index >= len(layout.pieces) {
		return nil, fmt.Errorf("client: piece index %d is out of range", index)
	}
	description := layout.pieces[index]
	if layout.protocol == storage.V1 {
		return piece.New(index, description.v1, int(description.length))
	}
	return piece.NewV2(index, description.v2, int(description.length), description.span)
}

func protocolStorage(version peer.ProtocolVersion) storage.Protocol {
	if version == peer.ProtocolV2 {
		return storage.V2
	}
	return storage.V1
}
