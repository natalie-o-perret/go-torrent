package client

import (
	"crypto/sha256"
	"fmt"
	"math/bits"

	"github.com/natalie-o-perret/go-torrent/metainfo"
	"github.com/natalie-o-perret/go-torrent/peer"
	"github.com/natalie-o-perret/go-torrent/storage"
)

const v2HashBlockSize = 16 << 10

type v2HashSource struct {
	store       *storage.Storage
	files       map[metainfo.HashV2][]*v2HashFile
	pieceLength int64
	pieceLayer  uint32
	pieceCount  int
	zero        [64]metainfo.HashV2
}

type v2HashFile struct {
	root         metainfo.HashV2
	pieces       []metainfo.HashV2
	length       int64
	paddedLeaves uint64
	height       uint32
	firstPiece   int
	pieceCount   int
}

type v2HashPiece struct {
	layers [][]metainfo.HashV2
}

func newV2HashSource(meta *metainfo.MetaInfo, store *storage.Storage) (*v2HashSource, error) {
	if meta == nil {
		return nil, fmt.Errorf("client: nil metainfo for v2 hash source")
	}
	if store == nil {
		return nil, fmt.Errorf("client: nil storage for v2 hash source")
	}
	if !meta.Info.HasV2() {
		return nil, fmt.Errorf("client: v2 hash source requires v2 metainfo")
	}
	if meta.PieceLayers == nil {
		return nil, fmt.Errorf("client: v2 hash source requires complete piece layers")
	}
	pieceLength := meta.Info.PieceLength
	if pieceLength < v2HashBlockSize || pieceLength&(pieceLength-1) != 0 {
		return nil, fmt.Errorf("client: invalid v2 piece length %d", pieceLength)
	}
	pieceCount, err := store.Layout().PieceCount(storage.V2)
	if err != nil {
		return nil, fmt.Errorf("client: v2 hash source storage: %w", err)
	}

	source := &v2HashSource{
		store:       store,
		files:       make(map[metainfo.HashV2][]*v2HashFile),
		pieceLength: pieceLength,
		pieceLayer:  uint32(bits.TrailingZeros64(uint64(pieceLength / v2HashBlockSize))),
		pieceCount:  pieceCount,
	}
	for layer := 1; layer < len(source.zero); layer++ {
		source.zero[layer] = v2HashPair(source.zero[layer-1], source.zero[layer-1])
	}

	allRoots := make(map[metainfo.HashV2]struct{})
	requiredLayers := make(map[metainfo.HashV2]int)
	for _, file := range meta.Info.V2Files {
		if file.Length < 0 {
			return nil, fmt.Errorf("client: v2 file has negative length %d", file.Length)
		}
		if file.Length == 0 {
			if file.PiecesRoot != nil {
				return nil, fmt.Errorf("client: empty v2 file has a pieces root")
			}
			continue
		}
		if file.PiecesRoot == nil {
			return nil, fmt.Errorf("client: nonempty v2 file has no pieces root")
		}
		root := *file.PiecesRoot
		allRoots[root] = struct{}{}
		count := int(1 + (file.Length-1)/pieceLength)
		if count > 1 {
			if previous, ok := requiredLayers[root]; ok && previous != count {
				return nil, fmt.Errorf("client: pieces root %s is reused with incompatible file lengths", root)
			}
			requiredLayers[root] = count
		}
	}

	layers := make(map[metainfo.HashV2][]metainfo.HashV2, len(requiredLayers))
	for root, layer := range meta.PieceLayers {
		if _, ok := allRoots[root]; !ok {
			return nil, fmt.Errorf("client: piece layer root %s is absent from the file tree", root)
		}
		count, ok := requiredLayers[root]
		if !ok {
			return nil, fmt.Errorf("client: piece layer root %s belongs only to single-piece files", root)
		}
		if len(layer) != count {
			return nil, fmt.Errorf("client: piece layer for root %s has %d hashes, want %d", root, len(layer), count)
		}
		copyLayer := append([]metainfo.HashV2(nil), layer...)
		if v2HashLayerRoot(copyLayer, source.zero[source.pieceLayer]) != root {
			return nil, fmt.Errorf("client: piece layer does not match root %s", root)
		}
		layers[root] = copyLayer
	}
	for root := range requiredLayers {
		if _, ok := layers[root]; !ok {
			return nil, fmt.Errorf("client: missing piece layer for root %s", root)
		}
	}

	firstPiece := 0
	for _, file := range meta.Info.V2Files {
		if file.Length == 0 {
			continue
		}
		count := int(1 + (file.Length-1)/pieceLength)
		if count > pieceCount-firstPiece {
			return nil, fmt.Errorf("client: v2 file pieces exceed storage layout")
		}
		actualLeaves := uint64(1 + (file.Length-1)/v2HashBlockSize)
		paddedLeaves := v2HashNextPower(actualLeaves)
		description := &v2HashFile{
			root:         *file.PiecesRoot,
			pieces:       layers[*file.PiecesRoot],
			length:       file.Length,
			paddedLeaves: paddedLeaves,
			height:       uint32(bits.TrailingZeros64(paddedLeaves)),
			firstPiece:   firstPiece,
			pieceCount:   count,
		}
		if count > 1 {
			paddedPieces := v2HashNextPower(uint64(count))
			if description.height != source.pieceLayer+uint32(bits.TrailingZeros64(paddedPieces)) {
				return nil, fmt.Errorf("client: inconsistent v2 hash tree for root %s", description.root)
			}
		}
		source.files[description.root] = append(source.files[description.root], description)
		firstPiece += count
	}
	if firstPiece != pieceCount {
		return nil, fmt.Errorf("client: v2 hash source maps %d pieces, storage has %d", firstPiece, pieceCount)
	}
	return source, nil
}

// Respond returns false when the request must be answered with Hash Reject.
func (source *v2HashSource) Respond(request peer.HashRequest, verified []bool) (peer.Hashes, bool) {
	response := peer.Hashes{Request: request}
	if source == nil || request.Validate() != nil || request.Length > peer.RecommendedMaxHashRequestLength {
		return response, false
	}
	for _, file := range source.files[request.PiecesRoot] {
		if !file.contains(request) {
			continue
		}
		values, ok := source.hashes(file, request, verified)
		if ok {
			response.Values = values
			return response, true
		}
	}
	return response, false
}

func (file *v2HashFile) contains(request peer.HashRequest) bool {
	if request.BaseLayer >= file.height {
		return false
	}
	width := file.paddedLeaves >> request.BaseLayer
	if uint64(request.Index)+uint64(request.Length) > width {
		return false
	}
	return request.ProofLayers < file.height-request.BaseLayer
}

func (source *v2HashSource) hashes(file *v2HashFile, request peer.HashRequest, verified []bool) ([]metainfo.HashV2, bool) {
	lengthLayer := uint32(bits.TrailingZeros32(request.Length))
	omittedProofs := lengthLayer - 1
	proofHashes := uint32(0)
	if request.ProofLayers > omittedProofs {
		proofHashes = request.ProofLayers - omittedProofs
	}
	count := uint64(request.Length) + uint64(proofHashes)
	if count > uint64(int(^uint(0)>>1)) {
		return nil, false
	}
	values := make([]metainfo.HashV2, 0, int(count))
	loaded := make(map[int]v2HashPiece)
	end := uint64(request.Index) + uint64(request.Length)
	for index := uint64(request.Index); index < end; index++ {
		hash, ok := source.hash(file, request.BaseLayer, index, verified, loaded)
		if !ok {
			return nil, false
		}
		values = append(values, hash)
	}

	layer := request.BaseLayer + lengthLayer
	index := uint64(request.Index) >> lengthLayer
	for range proofHashes {
		hash, ok := source.hash(file, layer, index^1, verified, loaded)
		if !ok {
			return nil, false
		}
		values = append(values, hash)
		index >>= 1
		layer++
	}
	return values, true
}

func (source *v2HashSource) hash(file *v2HashFile, layer uint32, index uint64, verified []bool, loaded map[int]v2HashPiece) (metainfo.HashV2, bool) {
	if layer > file.height || index >= file.paddedLeaves>>layer {
		return metainfo.HashV2{}, false
	}
	if file.pieceCount > 1 && layer >= source.pieceLayer {
		return source.metadataHash(file, layer, index)
	}

	startLeaf := index << layer
	localPiece := 0
	pieceHeight := file.height
	if file.pieceCount > 1 {
		localPiece = int(startLeaf >> source.pieceLayer)
		if localPiece >= file.pieceCount {
			return source.zero[layer], true
		}
		pieceHeight = source.pieceLayer
	}
	piece, ok := source.loadPiece(file, localPiece, pieceHeight, verified, loaded)
	if !ok {
		return metainfo.HashV2{}, false
	}
	pieceStart := uint64(0)
	if file.pieceCount > 1 {
		pieceStart = uint64(localPiece) << source.pieceLayer
	}
	localIndex := (startLeaf - pieceStart) >> layer
	if layer > pieceHeight || localIndex >= uint64(len(piece.layers[layer])) {
		return metainfo.HashV2{}, false
	}
	return piece.layers[layer][localIndex], true
}

func (source *v2HashSource) metadataHash(file *v2HashFile, layer uint32, index uint64) (metainfo.HashV2, bool) {
	if layer < source.pieceLayer || layer > file.height {
		return metainfo.HashV2{}, false
	}
	firstPiece := index << (layer - source.pieceLayer)
	if firstPiece >= uint64(file.pieceCount) {
		return source.zero[layer], true
	}
	if layer == source.pieceLayer {
		return file.pieces[index], true
	}
	left, ok := source.metadataHash(file, layer-1, index*2)
	if !ok {
		return metainfo.HashV2{}, false
	}
	right, ok := source.metadataHash(file, layer-1, index*2+1)
	if !ok {
		return metainfo.HashV2{}, false
	}
	return v2HashPair(left, right), true
}

func (source *v2HashSource) loadPiece(file *v2HashFile, localPiece int, height uint32, verified []bool, loaded map[int]v2HashPiece) (v2HashPiece, bool) {
	globalPiece := file.firstPiece + localPiece
	if piece, ok := loaded[globalPiece]; ok {
		return piece, true
	}
	if len(verified) != source.pieceCount || globalPiece < 0 || globalPiece >= len(verified) || !verified[globalPiece] {
		return v2HashPiece{}, false
	}
	data, err := source.store.ReadPiece(storage.V2, globalPiece)
	if err != nil {
		return v2HashPiece{}, false
	}
	offset := int64(localPiece) * source.pieceLength
	want := min(source.pieceLength, file.length-offset)
	if want <= 0 || int64(len(data)) != want {
		return v2HashPiece{}, false
	}
	leaves64 := uint64(1) << height
	if leaves64 > uint64(int(^uint(0)>>1)) {
		return v2HashPiece{}, false
	}
	leaves := int(leaves64)
	blocks := 1 + (len(data)-1)/v2HashBlockSize
	if blocks > leaves {
		return v2HashPiece{}, false
	}

	piece := v2HashPiece{layers: make([][]metainfo.HashV2, int(height)+1)}
	piece.layers[0] = make([]metainfo.HashV2, leaves)
	for block := 0; block < blocks; block++ {
		begin := block * v2HashBlockSize
		end := min(begin+v2HashBlockSize, len(data))
		piece.layers[0][block] = metainfo.HashV2(sha256.Sum256(data[begin:end]))
	}
	for layer := 1; layer <= int(height); layer++ {
		previous := piece.layers[layer-1]
		current := make([]metainfo.HashV2, len(previous)/2)
		for index := range current {
			current[index] = v2HashPair(previous[index*2], previous[index*2+1])
		}
		piece.layers[layer] = current
	}
	expected := file.root
	if file.pieceCount > 1 {
		expected = file.pieces[localPiece]
	}
	if piece.layers[height][0] != expected {
		return v2HashPiece{}, false
	}
	loaded[globalPiece] = piece
	return piece, true
}

func v2HashLayerRoot(layer []metainfo.HashV2, padding metainfo.HashV2) metainfo.HashV2 {
	target := v2HashNextPower(uint64(len(layer)))
	var stack [64]metainfo.HashV2
	var occupied uint64
	add := func(hash metainfo.HashV2) {
		for level := 0; ; level++ {
			mask := uint64(1) << level
			if occupied&mask == 0 {
				stack[level] = hash
				occupied |= mask
				return
			}
			hash = v2HashPair(stack[level], hash)
			occupied &^= mask
		}
	}
	for _, hash := range layer {
		add(hash)
	}
	for index := uint64(len(layer)); index < target; index++ {
		add(padding)
	}
	return stack[bits.TrailingZeros64(target)]
}

func v2HashNextPower(value uint64) uint64 {
	return uint64(1) << bits.Len64(value-1)
}

func v2HashPair(left, right metainfo.HashV2) metainfo.HashV2 {
	var pair [sha256.Size * 2]byte
	copy(pair[:sha256.Size], left[:])
	copy(pair[sha256.Size:], right[:])
	return metainfo.HashV2(sha256.Sum256(pair[:]))
}
