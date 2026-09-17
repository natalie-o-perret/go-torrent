// Package storage maps validated metainfo pieces to local files.
package storage

import (
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/natalie-o-perret/go-torrent/metainfo"
)

const v2BlockLength int64 = 16 << 10

// Protocol selects a metainfo piece layout.
type Protocol uint8

const (
	// V1 selects the BEP 3 concatenated-file layout.
	V1 Protocol = 1
	// V2 selects the BEP 52 piece-aligned file layout.
	V2 Protocol = 2
)

// ByteRange is a range in a protocol's logical piece address space.
type ByteRange struct {
	Offset int64
	Length int64
}

// Span maps bytes in a piece to one local file. Padding spans have no backing
// file: reads return zeros and writes are discarded.
type Span struct {
	Path        string
	FileOffset  int64
	PieceOffset int64
	Length      int64
	Padding     bool
}

// Layout is an immutable mapping from protocol piece indexes to local files.
type Layout struct {
	views map[Protocol]*protocolLayout
	files []diskFile
}

type protocolLayout struct {
	pieces []pieceLayout
}

type pieceLayout struct {
	byteRange ByteRange
	spans     []Span
	v1Hash    metainfo.Hash
	v2Hash    metainfo.HashV2
	v2Leaves  int
}

type declaration struct {
	path     string
	target   string
	length   int64
	protocol Protocol
	padding  bool
	symlink  bool
}

type mappedFile struct {
	declaration
	offset int64
}

type diskFile struct {
	path          string
	symlinkTarget string
	length        int64
	symlink       bool
}

// NewLayout validates and builds the v1 and v2 layouts present in meta.
func NewLayout(meta *metainfo.MetaInfo) (*Layout, error) {
	if meta == nil {
		return nil, fmt.Errorf("storage: nil metainfo")
	}
	if err := meta.Info.ValidatePaths(); err != nil {
		return nil, fmt.Errorf("storage: validate paths: %w", err)
	}
	if meta.Info.PieceLength <= 0 {
		return nil, fmt.Errorf("storage: piece length must be positive")
	}

	layout := &Layout{
		views: make(map[Protocol]*protocolLayout, 2),
	}
	var declarations []declaration
	if meta.Info.HasV1() {
		view, files, err := buildV1(meta)
		if err != nil {
			return nil, err
		}
		layout.views[V1] = view
		declarations = append(declarations, files...)
	}
	if meta.Info.HasV2() {
		if meta.Info.PieceLength < v2BlockLength || meta.Info.PieceLength&(meta.Info.PieceLength-1) != 0 {
			return nil, fmt.Errorf("storage: invalid v2 piece length %d", meta.Info.PieceLength)
		}
		view, files, err := buildV2(meta)
		if err != nil {
			return nil, err
		}
		layout.views[V2] = view
		declarations = append(declarations, files...)
	}
	if len(layout.views) == 0 {
		return nil, fmt.Errorf("storage: metainfo has no supported layout")
	}
	if meta.Info.IsHybrid() && len(layout.views[V1].pieces) != len(layout.views[V2].pieces) {
		return nil, fmt.Errorf("storage: hybrid layouts have different piece counts")
	}

	var err error
	layout.files, err = mergeDeclarations(declarations, meta.Info.IsHybrid())
	if err != nil {
		return nil, err
	}
	return layout, nil
}

// PieceCount returns the number of pieces in protocol's layout.
func (l *Layout) PieceCount(protocol Protocol) (int, error) {
	view, err := l.view(protocol)
	if err != nil {
		return 0, err
	}
	return len(view.pieces), nil
}

// PieceLength returns the checked wire length of a piece. Hybrid v1 and v2
// pieces can have different lengths because v1 includes explicit padding.
func (l *Layout) PieceLength(protocol Protocol, index int) (int64, error) {
	piece, err := l.piece(protocol, index)
	if err != nil {
		return 0, err
	}
	return piece.byteRange.Length, nil
}

// PieceRange returns the checked full logical range of a piece.
func (l *Layout) PieceRange(protocol Protocol, index int) (ByteRange, error) {
	piece, err := l.piece(protocol, index)
	if err != nil {
		return ByteRange{}, err
	}
	return piece.byteRange, nil
}

// Range validates a subrange of a piece and returns its logical byte range.
func (l *Layout) Range(protocol Protocol, index int, begin, length int64) (ByteRange, error) {
	piece, err := l.piece(protocol, index)
	if err != nil {
		return ByteRange{}, err
	}
	if err := checkRange(piece.byteRange.Length, begin, length); err != nil {
		return ByteRange{}, fmt.Errorf("storage: %s piece %d: %w", protocol, index, err)
	}
	return ByteRange{Offset: piece.byteRange.Offset + begin, Length: length}, nil
}

// PieceSpans returns the file spans covering a complete piece.
func (l *Layout) PieceSpans(protocol Protocol, index int) ([]Span, error) {
	piece, err := l.piece(protocol, index)
	if err != nil {
		return nil, err
	}
	return append([]Span(nil), piece.spans...), nil
}

// Spans returns the file spans intersecting a checked piece subrange. Returned
// PieceOffset values remain relative to the complete piece.
func (l *Layout) Spans(protocol Protocol, index int, begin, length int64) ([]Span, error) {
	piece, err := l.piece(protocol, index)
	if err != nil {
		return nil, err
	}
	if err := checkRange(piece.byteRange.Length, begin, length); err != nil {
		return nil, fmt.Errorf("storage: %s piece %d: %w", protocol, index, err)
	}
	if length == 0 {
		return nil, nil
	}

	end := begin + length
	spans := make([]Span, 0, len(piece.spans))
	for _, span := range piece.spans {
		start := max(begin, span.PieceOffset)
		stop := min(end, span.PieceOffset+span.Length)
		if start >= stop {
			continue
		}
		span.FileOffset += start - span.PieceOffset
		span.PieceOffset = start
		span.Length = stop - start
		spans = append(spans, span)
	}
	return spans, nil
}

func (l *Layout) view(protocol Protocol) (*protocolLayout, error) {
	if l == nil {
		return nil, fmt.Errorf("storage: nil layout")
	}
	view := l.views[protocol]
	if view == nil {
		return nil, fmt.Errorf("storage: %s layout is not present", protocol)
	}
	return view, nil
}

func (l *Layout) piece(protocol Protocol, index int) (*pieceLayout, error) {
	view, err := l.view(protocol)
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= len(view.pieces) {
		return nil, fmt.Errorf("storage: %s piece index %d outside [0,%d)", protocol, index, len(view.pieces))
	}
	return &view.pieces[index], nil
}

func (p Protocol) String() string {
	switch p {
	case V1:
		return "v1"
	case V2:
		return "v2"
	default:
		return fmt.Sprintf("protocol(%d)", p)
	}
}

func checkRange(pieceLength, begin, length int64) error {
	if begin < 0 {
		return fmt.Errorf("negative begin %d", begin)
	}
	if length < 0 {
		return fmt.Errorf("negative length %d", length)
	}
	if begin > pieceLength || length > pieceLength-begin {
		return fmt.Errorf("range beginning at %d with length %d outside piece length %d", begin, length, pieceLength)
	}
	return nil
}

func buildV1(meta *metainfo.MetaInfo) (*protocolLayout, []declaration, error) {
	info := &meta.Info
	var files []mappedFile
	var declarations []declaration
	var total int64

	if len(info.Files) == 0 {
		file, err := makeDeclaration(V1, []string{info.Name}, info.SymlinkPath, info.Length, info.Attr)
		if err != nil {
			return nil, nil, err
		}
		files = append(files, mappedFile{declaration: file})
		declarations = append(declarations, file)
		total = info.Length
	} else {
		for i, fileInfo := range info.Files {
			if fileInfo.Offset != total {
				return nil, nil, fmt.Errorf("storage: v1 file %q has offset %d, want %d; files overlap or leave a gap", strings.Join(fileInfo.Path, "/"), fileInfo.Offset, total)
			}
			file, err := makeDeclaration(V1, fileInfo.Path, fileInfo.SymlinkPath, fileInfo.Length, fileInfo.Attr)
			if err != nil {
				return nil, nil, fmt.Errorf("storage: v1 file %d: %w", i, err)
			}
			files = append(files, mappedFile{declaration: file, offset: total})
			declarations = append(declarations, file)
			total, err = add(total, fileInfo.Length)
			if err != nil {
				return nil, nil, fmt.Errorf("storage: v1 total length: %w", err)
			}
		}
	}

	count := pieceCount(total, info.PieceLength)
	if count != int64(len(info.Pieces)) {
		return nil, nil, fmt.Errorf("storage: v1 has %d piece hashes, want %d", len(info.Pieces), count)
	}
	view := &protocolLayout{pieces: make([]pieceLayout, len(info.Pieces))}
	for i, hash := range info.Pieces {
		offset := int64(i) * info.PieceLength
		view.pieces[i] = pieceLayout{
			byteRange: ByteRange{Offset: offset, Length: min(info.PieceLength, total-offset)},
			v1Hash:    hash,
		}
	}

	for _, file := range files {
		if file.length == 0 {
			continue
		}
		end := file.offset + file.length
		first := file.offset / info.PieceLength
		last := (end - 1) / info.PieceLength
		for pieceIndex := first; pieceIndex <= last; pieceIndex++ {
			pieceStart := pieceIndex * info.PieceLength
			start := max(file.offset, pieceStart)
			stop := min(end, pieceStart+info.PieceLength)
			view.pieces[int(pieceIndex)].spans = append(view.pieces[int(pieceIndex)].spans, Span{
				Path:        file.path,
				FileOffset:  start - file.offset,
				PieceOffset: start - pieceStart,
				Length:      stop - start,
				Padding:     file.padding,
			})
		}
	}
	for i, piece := range view.pieces {
		var covered int64
		for _, span := range piece.spans {
			covered += span.Length
		}
		if covered != piece.byteRange.Length {
			return nil, nil, fmt.Errorf("storage: v1 piece %d maps %d bytes, want %d", i, covered, piece.byteRange.Length)
		}
	}
	return view, declarations, nil
}

func buildV2(meta *metainfo.MetaInfo) (*protocolLayout, []declaration, error) {
	info := &meta.Info
	if len(info.V2Files) == 0 {
		return nil, nil, fmt.Errorf("storage: v2 layout has no files")
	}

	view := &protocolLayout{}
	declarations := make([]declaration, 0, len(info.V2Files))
	var cursor int64
	for i, fileInfo := range info.V2Files {
		file, err := makeDeclaration(V2, fileInfo.Path, fileInfo.SymlinkPath, fileInfo.Length, fileInfo.Attr)
		if err != nil {
			return nil, nil, fmt.Errorf("storage: v2 file %d: %w", i, err)
		}
		if file.padding {
			return nil, nil, fmt.Errorf("storage: v2 file %q is padding", file.path)
		}
		declarations = append(declarations, file)

		expectedOffset := cursor
		if file.length > 0 {
			expectedOffset, err = align(cursor, info.PieceLength)
			if err != nil {
				return nil, nil, fmt.Errorf("storage: v2 file %q offset: %w", file.path, err)
			}
		}
		if fileInfo.Offset != expectedOffset {
			return nil, nil, fmt.Errorf("storage: v2 file %q has offset %d, want %d; files overlap or are not minimally aligned", file.path, fileInfo.Offset, expectedOffset)
		}
		if file.length == 0 {
			continue
		}
		if fileInfo.PiecesRoot == nil {
			return nil, nil, fmt.Errorf("storage: v2 file %q has no pieces root", file.path)
		}
		if fileInfo.Offset/info.PieceLength != int64(len(view.pieces)) {
			return nil, nil, fmt.Errorf("storage: v2 file %q does not follow the preceding piece", file.path)
		}

		filePieces := pieceCount(file.length, info.PieceLength)
		var layer []metainfo.HashV2
		if file.length > info.PieceLength {
			var ok bool
			layer, ok = meta.PieceLayers[*fileInfo.PiecesRoot]
			if !ok || int64(len(layer)) != filePieces {
				return nil, nil, fmt.Errorf("storage: v2 file %q has no complete piece layer", file.path)
			}
		}
		for localPiece := int64(0); localPiece < filePieces; localPiece++ {
			fileOffset := localPiece * info.PieceLength
			length := min(info.PieceLength, file.length-fileOffset)
			leaves, err := v2LeafCount(file.length, info.PieceLength, length)
			if err != nil {
				return nil, nil, fmt.Errorf("storage: v2 file %q: %w", file.path, err)
			}
			expected := *fileInfo.PiecesRoot
			if layer != nil {
				expected = layer[int(localPiece)]
			}
			view.pieces = append(view.pieces, pieceLayout{
				byteRange: ByteRange{Offset: fileInfo.Offset + fileOffset, Length: length},
				spans: []Span{{
					Path:       file.path,
					FileOffset: fileOffset,
					Length:     length,
				}},
				v2Hash:   expected,
				v2Leaves: leaves,
			})
		}
		cursor, err = add(fileInfo.Offset, file.length)
		if err != nil {
			return nil, nil, fmt.Errorf("storage: v2 file %q end: %w", file.path, err)
		}
	}
	if !info.HasV1() && len(view.pieces) != info.PieceCount() {
		return nil, nil, fmt.Errorf("storage: v2 maps %d pieces, want %d", len(view.pieces), info.PieceCount())
	}
	return view, declarations, nil
}

func makeDeclaration(protocol Protocol, path, target []string, length int64, attr string) (declaration, error) {
	if length < 0 {
		return declaration{}, fmt.Errorf("negative length %d", length)
	}
	localPath, err := joinLocal(path)
	if err != nil {
		return declaration{}, err
	}
	file := declaration{
		path:     localPath,
		length:   length,
		protocol: protocol,
		padding:  strings.Contains(attr, "p"),
		symlink:  strings.Contains(attr, "l"),
	}
	if file.padding && file.symlink {
		return declaration{}, fmt.Errorf("file %q is both padding and a symlink", localPath)
	}
	if file.padding && length <= 0 {
		return declaration{}, fmt.Errorf("padding file %q is empty", localPath)
	}
	if file.symlink {
		if length != 0 {
			return declaration{}, fmt.Errorf("symlink %q has nonzero length", localPath)
		}
		file.target, err = joinLocal(target)
		if err != nil {
			return declaration{}, fmt.Errorf("symlink %q target: %w", localPath, err)
		}
	} else if len(target) != 0 {
		return declaration{}, fmt.Errorf("file %q has a symlink target without the symlink attribute", localPath)
	}
	return file, nil
}

func joinLocal(components []string) (string, error) {
	if len(components) == 0 {
		return "", fmt.Errorf("empty path")
	}
	path := filepath.Join(components...)
	if !filepath.IsLocal(path) || path == "." {
		return "", fmt.Errorf("joined path %q escapes the torrent root", path)
	}
	return path, nil
}

func mergeDeclarations(declarations []declaration, hybrid bool) ([]diskFile, error) {
	sort.Slice(declarations, func(i, j int) bool {
		if declarations[i].path != declarations[j].path {
			return declarations[i].path < declarations[j].path
		}
		return declarations[i].protocol < declarations[j].protocol
	})

	files := make([]diskFile, 0, len(declarations))
	seen := make(map[string]struct{}, len(declarations))
	for start := 0; start < len(declarations); {
		end := start + 1
		for end < len(declarations) && declarations[end].path == declarations[start].path {
			end++
		}
		group := declarations[start:end]
		file := group[0]
		if len(group) != 1 {
			if len(group) != 2 || !hybrid || group[0].protocol == group[1].protocol || !sameDeclaration(group[0], group[1]) {
				return nil, fmt.Errorf("storage: path collision at %q", file.path)
			}
		}
		for parent := filepath.Dir(file.path); parent != "."; parent = filepath.Dir(parent) {
			if _, ok := seen[parent]; ok {
				return nil, fmt.Errorf("storage: path collision between %q and %q", parent, file.path)
			}
		}
		seen[file.path] = struct{}{}
		if !file.padding {
			disk := diskFile{path: file.path, length: file.length, symlink: file.symlink}
			if file.symlink {
				disk.symlinkTarget = file.target
				target, err := filepath.Rel(filepath.Dir(file.path), file.target)
				if err != nil || filepath.IsAbs(target) {
					return nil, fmt.Errorf("storage: symlink %q target %q is not relative", file.path, file.target)
				}
				resolved := filepath.Clean(filepath.Join(filepath.Dir(file.path), target))
				if !filepath.IsLocal(resolved) || resolved != file.target {
					return nil, fmt.Errorf("storage: symlink %q target %q escapes the torrent root", file.path, file.target)
				}
				disk.symlinkTarget = target
			}
			files = append(files, disk)
		}
		start = end
	}
	return files, nil
}

func sameDeclaration(a, b declaration) bool {
	return !a.padding && !b.padding && a.length == b.length && a.symlink == b.symlink && a.target == b.target
}

func pieceCount(length, pieceLength int64) int64 {
	if length == 0 {
		return 0
	}
	return 1 + (length-1)/pieceLength
}

func add(a, b int64) (int64, error) {
	if b < 0 || a > int64(^uint64(0)>>1)-b {
		return 0, fmt.Errorf("length overflows int64")
	}
	return a + b, nil
}

func align(offset, alignment int64) (int64, error) {
	remainder := offset % alignment
	if remainder == 0 {
		return offset, nil
	}
	return add(offset, alignment-remainder)
}

func v2LeafCount(fileLength, pieceLength, dataLength int64) (int, error) {
	var leaves int64
	if fileLength > pieceLength {
		leaves = pieceLength / v2BlockLength
	} else {
		blocks := pieceCount(dataLength, v2BlockLength)
		leaves = 1
		for leaves < blocks {
			leaves *= 2
		}
	}
	if leaves <= 0 || uint64(leaves) > uint64(^uint(0)>>1) {
		return 0, fmt.Errorf("Merkle leaf count %d does not fit int", leaves)
	}
	return int(leaves), nil
}

// Storage performs synchronous piece I/O beneath one torrent root. Multi-file
// paths are relative to root; a v1 single file is stored at root/Info.Name.
type Storage struct {
	root   string
	layout *Layout
}

// New validates meta and returns storage rooted at root. It does not access the
// filesystem; call Prepare before writing pieces.
func New(root string, meta *metainfo.MetaInfo) (*Storage, error) {
	layout, err := NewLayout(meta)
	if err != nil {
		return nil, err
	}
	if root == "" {
		return nil, fmt.Errorf("storage: empty root")
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("storage: resolve root: %w", err)
	}
	return &Storage{root: absoluteRoot, layout: layout}, nil
}

// Layout returns the immutable layout used by s.
func (s *Storage) Layout() *Layout {
	if s == nil {
		return nil
	}
	return s.layout
}

// Prepare creates parent directories, sizes regular files, and creates declared
// symlinks. Padding files and v2 alignment gaps are not created.
func (s *Storage) Prepare() error {
	if s == nil || s.layout == nil {
		return fmt.Errorf("storage: nil storage")
	}
	if err := os.MkdirAll(s.root, 0o777); err != nil {
		return fmt.Errorf("storage: create root: %w", err)
	}
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return fmt.Errorf("storage: open root: %w", err)
	}
	err = s.prepare(root)
	closeErr := root.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return fmt.Errorf("storage: close root: %w", closeErr)
	}
	return nil
}

func (s *Storage) prepare(root *os.Root) error {
	for _, file := range s.layout.files {
		if file.symlink {
			continue
		}
		if err := makeParent(root, file.path); err != nil {
			return err
		}
		info, err := root.Lstat(file.path)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("storage: regular file %q is an existing symlink", file.path)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("storage: inspect %q: %w", file.path, err)
		}
		handle, err := root.OpenFile(file.path, os.O_CREATE|os.O_RDWR, 0o666)
		if err != nil {
			return fmt.Errorf("storage: open %q: %w", file.path, err)
		}
		truncateErr := handle.Truncate(file.length)
		closeErr := handle.Close()
		if truncateErr != nil {
			return fmt.Errorf("storage: size %q: %w", file.path, truncateErr)
		}
		if closeErr != nil {
			return fmt.Errorf("storage: close %q: %w", file.path, closeErr)
		}
	}

	for _, file := range s.layout.files {
		if !file.symlink {
			continue
		}
		if err := makeParent(root, file.path); err != nil {
			return err
		}
		info, err := root.Lstat(file.path)
		switch {
		case err == nil:
			if info.Mode()&os.ModeSymlink == 0 {
				return fmt.Errorf("storage: declared symlink %q already exists and is not a symlink", file.path)
			}
			target, readErr := root.Readlink(file.path)
			if readErr != nil {
				return fmt.Errorf("storage: read symlink %q: %w", file.path, readErr)
			}
			if target != file.symlinkTarget {
				return fmt.Errorf("storage: symlink %q targets %q, want %q", file.path, target, file.symlinkTarget)
			}
		case errors.Is(err, os.ErrNotExist):
			if err := root.Symlink(file.symlinkTarget, file.path); err != nil {
				return fmt.Errorf("storage: create symlink %q: %w", file.path, err)
			}
		default:
			return fmt.Errorf("storage: inspect symlink %q: %w", file.path, err)
		}
	}
	return nil
}

func makeParent(root *os.Root, path string) error {
	parent := filepath.Dir(path)
	if parent == "." {
		return nil
	}
	if err := root.MkdirAll(parent, 0o777); err != nil {
		return fmt.Errorf("storage: create parent for %q: %w", path, err)
	}
	return nil
}

// ReadPiece reads one complete piece. Padding bytes are returned as zeros.
func (s *Storage) ReadPiece(protocol Protocol, index int) ([]byte, error) {
	if s == nil || s.layout == nil {
		return nil, fmt.Errorf("storage: nil storage")
	}
	piece, err := s.layout.piece(protocol, index)
	if err != nil {
		return nil, err
	}
	length, err := intLength(piece.byteRange.Length)
	if err != nil {
		return nil, fmt.Errorf("storage: %s piece %d: %w", protocol, index, err)
	}
	data := make([]byte, length)
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return nil, fmt.Errorf("storage: open root: %w", err)
	}
	err = readSpans(root, piece.spans, data)
	closeErr := root.Close()
	if err != nil {
		return nil, fmt.Errorf("storage: read %s piece %d: %w", protocol, index, err)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("storage: close root: %w", closeErr)
	}
	return data, nil
}

func readSpans(root *os.Root, spans []Span, data []byte) error {
	for _, span := range spans {
		if span.Padding {
			continue
		}
		handle, err := root.Open(span.Path)
		if err != nil {
			return fmt.Errorf("open %q: %w", span.Path, err)
		}
		start := int(span.PieceOffset)
		stop := int(span.PieceOffset + span.Length)
		readErr := readAtFull(handle, data[start:stop], span.FileOffset)
		closeErr := handle.Close()
		if readErr != nil {
			return fmt.Errorf("read %q at %d: %w", span.Path, span.FileOffset, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close %q: %w", span.Path, closeErr)
		}
	}
	return nil
}

// WritePiece writes one complete piece. Padding bytes are discarded.
func (s *Storage) WritePiece(protocol Protocol, index int, data []byte) error {
	if s == nil || s.layout == nil {
		return fmt.Errorf("storage: nil storage")
	}
	piece, err := s.layout.piece(protocol, index)
	if err != nil {
		return err
	}
	if int64(len(data)) != piece.byteRange.Length {
		return fmt.Errorf("storage: %s piece %d has %d bytes, want %d", protocol, index, len(data), piece.byteRange.Length)
	}
	root, err := os.OpenRoot(s.root)
	if err != nil {
		return fmt.Errorf("storage: open root: %w", err)
	}
	err = writeSpans(root, piece.spans, data)
	closeErr := root.Close()
	if err != nil {
		return fmt.Errorf("storage: write %s piece %d: %w", protocol, index, err)
	}
	if closeErr != nil {
		return fmt.Errorf("storage: close root: %w", closeErr)
	}
	return nil
}

func writeSpans(root *os.Root, spans []Span, data []byte) error {
	for _, span := range spans {
		if span.Padding {
			continue
		}
		handle, err := root.OpenFile(span.Path, os.O_WRONLY, 0)
		if err != nil {
			return fmt.Errorf("open %q: %w", span.Path, err)
		}
		start := int(span.PieceOffset)
		stop := int(span.PieceOffset + span.Length)
		writeErr := writeAtFull(handle, data[start:stop], span.FileOffset)
		closeErr := handle.Close()
		if writeErr != nil {
			return fmt.Errorf("write %q at %d: %w", span.Path, span.FileOffset, writeErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close %q: %w", span.Path, closeErr)
		}
	}
	return nil
}

func readAtFull(reader io.ReaderAt, data []byte, offset int64) error {
	n, err := reader.ReadAt(data, offset)
	if n == len(data) {
		return nil
	}
	if err == nil || errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

func writeAtFull(writer io.WriterAt, data []byte, offset int64) error {
	n, err := writer.WriteAt(data, offset)
	if n == len(data) {
		return nil
	}
	if err == nil {
		return io.ErrShortWrite
	}
	return err
}

func intLength(length int64) (int, error) {
	if length < 0 || uint64(length) > uint64(^uint(0)>>1) {
		return 0, fmt.Errorf("length %d does not fit int", length)
	}
	return int(length), nil
}

// VerifyPiece reports whether every hash format available for index matches
// the local data. Missing and short files report false without an error.
func (s *Storage) VerifyPiece(index int) (bool, error) {
	if s == nil || s.layout == nil {
		return false, fmt.Errorf("storage: nil storage")
	}
	verified := false
	if view := s.layout.views[V1]; view != nil {
		if index < 0 || index >= len(view.pieces) {
			return false, fmt.Errorf("storage: v1 piece index %d outside [0,%d)", index, len(view.pieces))
		}
		data, err := s.ReadPiece(V1, index)
		if err != nil {
			if incomplete(err) {
				return false, nil
			}
			return false, err
		}
		if sha1.Sum(data) != view.pieces[index].v1Hash {
			return false, nil
		}
		verified = true
	}
	if view := s.layout.views[V2]; view != nil {
		if index < 0 || index >= len(view.pieces) {
			return false, fmt.Errorf("storage: v2 piece index %d outside [0,%d)", index, len(view.pieces))
		}
		data, err := s.ReadPiece(V2, index)
		if err != nil {
			if incomplete(err) {
				return false, nil
			}
			return false, err
		}
		hash, err := merkleRoot(data, view.pieces[index].v2Leaves)
		if err != nil {
			return false, fmt.Errorf("storage: hash v2 piece %d: %w", index, err)
		}
		if hash != view.pieces[index].v2Hash {
			return false, nil
		}
		verified = true
	}
	return verified, nil
}

// VerifyAll verifies every piece synchronously and returns a resume bitmap.
func (s *Storage) VerifyAll() ([]bool, error) {
	if s == nil || s.layout == nil {
		return nil, fmt.Errorf("storage: nil storage")
	}
	view := s.layout.views[V1]
	if view == nil {
		view = s.layout.views[V2]
	}
	verified := make([]bool, len(view.pieces))
	for i := range verified {
		ok, err := s.VerifyPiece(i)
		if err != nil {
			return nil, err
		}
		verified[i] = ok
	}
	return verified, nil
}

func incomplete(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func merkleRoot(data []byte, leaves int) (metainfo.HashV2, error) {
	blocks := 0
	if len(data) > 0 {
		blocks = 1 + (len(data)-1)/int(v2BlockLength)
	}
	if leaves <= 0 || leaves&(leaves-1) != 0 || blocks == 0 || blocks > leaves {
		return metainfo.HashV2{}, fmt.Errorf("%d data blocks do not fit %d leaves", blocks, leaves)
	}
	hashes := make([]metainfo.HashV2, leaves)
	for i := 0; i < blocks; i++ {
		start := i * int(v2BlockLength)
		stop := min(len(data), start+int(v2BlockLength))
		hashes[i] = sha256.Sum256(data[start:stop])
	}
	for width := leaves; width > 1; width /= 2 {
		for i := 0; i < width; i += 2 {
			var pair [64]byte
			copy(pair[:32], hashes[i][:])
			copy(pair[32:], hashes[i+1][:])
			hashes[i/2] = sha256.Sum256(pair[:])
		}
	}
	return hashes[0], nil
}
