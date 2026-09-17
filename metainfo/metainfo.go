// Package metainfo parses BitTorrent v1, v2, and hybrid .torrent files.
package metainfo

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/natalie-o-perret/go-torrent/bencode"
)

const v2BlockLength int64 = 16 << 10

// Hash is a 20-byte SHA-1 digest used by BitTorrent v1.
type Hash [20]byte

// String returns the lowercase hex representation of h.
func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}

// HashV2 is a 32-byte SHA-256 digest used by BitTorrent v2.
type HashV2 [32]byte

// String returns the lowercase hex representation of h.
func (h HashV2) String() string {
	return hex.EncodeToString(h[:])
}

// Hashes contains the hashes supported by a metainfo file. A nil field means
// that the corresponding protocol version is not present.
type Hashes struct {
	V1 *Hash
	V2 *HashV2
}

// Node is a bootstrap DHT node from the top-level "nodes" list.
type Node struct {
	Host string
	Port uint16
}

// FileInfo describes a file in a v1 file list or flattened v2 file tree. V2
// Path components preserve their raw byte strings and may not be valid UTF-8.
type FileInfo struct {
	Path        []string
	SymlinkPath []string
	Length      int64
	Offset      int64
	Attr        string
	SHA1        *Hash
	PiecesRoot  *HashV2
}

// IsPadding reports whether f is a BEP 47 padding file.
func (f FileInfo) IsPadding() bool {
	return strings.Contains(f.Attr, "p")
}

// IsSymlink reports whether f is a BEP 47 symlink.
func (f FileInfo) IsSymlink() bool {
	return strings.Contains(f.Attr, "l")
}

// Info is the "info" dictionary of a .torrent file. Files contains the v1
// file list when present, or the flattened v2 tree for a v2-only torrent.
// V2Files always contains the flattened v2 tree when HasV2 reports true.
type Info struct {
	Name        string
	Pieces      []Hash
	Files       []FileInfo
	V2Files     []FileInfo
	PieceLength int64
	Length      int64
	MetaVersion int64
	Private     bool
	Attr        string
	SymlinkPath []string
	SHA1        *Hash

	hasV1        bool
	hasV2        bool
	singleFile   bool
	v2PieceCount int
}

// HasV1 reports whether info contains a complete BitTorrent v1 layout.
func (info *Info) HasV1() bool {
	return info != nil && info.hasV1
}

// HasV2 reports whether info contains a complete BitTorrent v2 layout.
func (info *Info) HasV2() bool {
	return info != nil && info.hasV2
}

// IsHybrid reports whether info contains consistent v1 and v2 layouts.
func (info *Info) IsHybrid() bool {
	return info != nil && info.hasV1 && info.hasV2
}

// TotalLength returns the size of the v1 representation, including explicit
// padding files, or the sum of v2 file lengths for a v2-only torrent.
func (info *Info) TotalLength() int64 {
	if info == nil {
		return 0
	}
	if info.singleFile || info.Length > 0 {
		return info.Length
	}
	var total int64
	for _, f := range info.Files {
		total += f.Length
	}
	return total
}

// PieceCount returns the number of logical pieces in the torrent.
func (info *Info) PieceCount() int {
	if info == nil {
		return 0
	}
	if info.hasV1 || !info.hasV2 {
		return len(info.Pieces)
	}
	return info.v2PieceCount
}

// ValidatePaths checks that all names can be joined beneath a destination
// directory without changing their component boundaries or traversing upward.
// It intentionally runs separately from Decode because valid metainfo names may
// need platform-specific sanitisation before use on a filesystem.
func (info *Info) ValidatePaths() error {
	if info == nil {
		return fmt.Errorf("metainfo: nil info")
	}
	if err := ValidatePath([]string{info.Name}); err != nil {
		return fmt.Errorf("metainfo: name: %w", err)
	}
	if len(info.SymlinkPath) > 0 {
		if err := ValidatePath(info.SymlinkPath); err != nil {
			return fmt.Errorf("metainfo: symlink path: %w", err)
		}
	}
	for _, files := range [][]FileInfo{info.Files, info.V2Files} {
		for _, f := range files {
			if err := ValidatePath(f.Path); err != nil {
				return fmt.Errorf("metainfo: file path %q: %w", strings.Join(f.Path, "/"), err)
			}
			if len(f.SymlinkPath) > 0 {
				if err := ValidatePath(f.SymlinkPath); err != nil {
					return fmt.Errorf("metainfo: symlink path %q: %w", strings.Join(f.SymlinkPath, "/"), err)
				}
			}
		}
	}
	return nil
}

// ValidatePath checks portable path components for traversal and embedded path
// separators. It does not reject platform-specific reserved names.
func ValidatePath(path []string) error {
	if len(path) == 0 {
		return fmt.Errorf("path is empty")
	}
	for i, component := range path {
		switch {
		case component == "":
			return fmt.Errorf("component %d is empty", i)
		case component == "." || component == "..":
			return fmt.Errorf("component %d is %q", i, component)
		case strings.ContainsAny(component, "/\\\x00"):
			return fmt.Errorf("component %d contains a path separator or NUL", i)
		case !utf8.ValidString(component):
			return fmt.Errorf("component %d is not UTF-8", i)
		}
	}
	return nil
}

// MetaInfo represents parsed torrent metadata. PieceLayers maps roots present
// in the top-level v2 piece layers dictionary to hashes for payload checks. For
// v2 metadata it is nil after DecodeInfo until SetPieceLayers succeeds.
type MetaInfo struct {
	Announce     string
	Comment      string
	CreatedBy    string
	Encoding     string
	AnnounceList [][]string
	URLList      []string
	Nodes        []Node
	Info         Info
	CreationDate int64
	RawInfo      []byte
	PieceLayers  map[HashV2][]HashV2

	// InfoHash is the v1 SHA-1 hash. It is zero for v2-only torrents. Use
	// Hashes when protocol-version presence must be distinguished.
	InfoHash Hash
	// InfoHashV2 is the v2 SHA-256 hash. It is zero for v1-only torrents.
	InfoHashV2 HashV2
}

// Hashes returns the protocol-version-aware info hashes.
func (m *MetaInfo) Hashes() Hashes {
	var hashes Hashes
	if m == nil {
		return hashes
	}
	if m.Info.hasV1 {
		h := m.InfoHash
		hashes.V1 = &h
	}
	if m.Info.hasV2 {
		h := m.InfoHashV2
		hashes.V2 = &h
	}
	return hashes
}

// SetPieceLayers validates and copies the complete set of v2 piece layers. It
// leaves m unchanged on failure.
func (m *MetaInfo) SetPieceLayers(layers map[HashV2][]HashV2) error {
	if m == nil {
		return fmt.Errorf("metainfo: nil metainfo")
	}
	if !m.Info.hasV2 {
		return fmt.Errorf("metainfo: piece layers require meta version 2")
	}
	validated, err := validatePieceLayers(layers, &m.Info)
	if err != nil {
		return err
	}
	m.PieceLayers = validated
	return nil
}

// Trackers returns the effective deduplicated tracker URLs in tier order.
// AnnounceList takes precedence over Announce as required by BEP 12.
func (m *MetaInfo) Trackers() []string {
	seen := make(map[string]struct{})
	var result []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		result = append(result, u)
	}
	if m.AnnounceList != nil {
		for _, tier := range m.AnnounceList {
			for _, u := range tier {
				add(u)
			}
		}
	} else {
		add(m.Announce)
	}
	return result
}

// Decode parses and validates a canonical .torrent file from r.
func Decode(r io.Reader) (*MetaInfo, error) {
	if r == nil {
		return nil, fmt.Errorf("metainfo: nil reader")
	}
	data, err := io.ReadAll(io.LimitReader(r, bencode.DefaultMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("metainfo: read: %w", err)
	}
	if int64(len(data)) > bencode.DefaultMaxBytes {
		return nil, fmt.Errorf("metainfo: input exceeds %d-byte limit", bencode.DefaultMaxBytes)
	}

	raw, err := bencode.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("metainfo: decode bencode: %w", err)
	}
	dict, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("metainfo: top-level value is not a dictionary")
	}
	infoValue, ok := dict["info"]
	if !ok {
		return nil, fmt.Errorf("metainfo: missing 'info' key")
	}
	infoDict, ok := infoValue.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("metainfo: 'info' is not a dictionary")
	}
	rawInfo, err := rawDictionaryValue(data, "info")
	if err != nil {
		return nil, err
	}

	m, err := newMetaInfo(infoDict, rawInfo)
	if err != nil {
		return nil, err
	}
	if err := parseTopLevel(m, dict); err != nil {
		return nil, err
	}
	if m.Info.hasV2 {
		layers, err := decodePieceLayers(dict)
		if err != nil {
			return nil, err
		}
		if err := m.SetPieceLayers(layers); err != nil {
			return nil, err
		}
	} else if _, ok := dict["piece layers"]; ok {
		return nil, fmt.Errorf("metainfo: 'piece layers' requires meta version 2")
	}
	return m, nil
}

// DecodeInfo parses and validates exact canonical bencoded info-dictionary
// bytes. V2 piece layers can be supplied later with SetPieceLayers.
func DecodeInfo(rawInfo []byte) (*MetaInfo, error) {
	raw, err := bencode.Decode(bytes.NewReader(rawInfo))
	if err != nil {
		return nil, fmt.Errorf("metainfo: decode info bencode: %w", err)
	}
	infoDict, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("metainfo: info value is not a dictionary")
	}
	return newMetaInfo(infoDict, rawInfo)
}

func newMetaInfo(infoDict map[string]any, rawInfo []byte) (*MetaInfo, error) {
	info, err := parseInfo(infoDict)
	if err != nil {
		return nil, err
	}
	m := &MetaInfo{Info: *info, RawInfo: append([]byte(nil), rawInfo...)}
	if info.hasV1 {
		m.InfoHash = Hash(sha1.Sum(m.RawInfo))
	}
	if info.hasV2 {
		m.InfoHashV2 = HashV2(sha256.Sum256(m.RawInfo))
	}
	return m, nil
}

func rawDictionaryValue(data []byte, wanted string) ([]byte, error) {
	if len(data) < 2 || data[0] != 'd' {
		return nil, fmt.Errorf("metainfo: top-level value is not a dictionary")
	}
	for pos := 1; pos < len(data) && data[pos] != 'e'; {
		keyValue, consumed, err := bencode.DecodePrefix(data[pos:])
		if err != nil {
			return nil, fmt.Errorf("metainfo: locate %q key: %w", wanted, err)
		}
		key, ok := keyValue.(string)
		if !ok {
			return nil, fmt.Errorf("metainfo: top-level dictionary key is not a string")
		}
		pos += consumed
		start := pos
		_, consumed, err = bencode.DecodePrefix(data[pos:])
		if err != nil {
			return nil, fmt.Errorf("metainfo: locate %q value: %w", wanted, err)
		}
		pos += consumed
		if key == wanted {
			return data[start:pos], nil
		}
	}
	return nil, fmt.Errorf("metainfo: missing %q key", wanted)
}

func parseTopLevel(m *MetaInfo, d map[string]any) error {
	var err error
	if m.Announce, err = optionalText(d, "announce"); err != nil {
		return err
	}
	if m.Comment, err = optionalText(d, "comment"); err != nil {
		return err
	}
	if m.CreatedBy, err = optionalText(d, "created by"); err != nil {
		return err
	}
	if m.Encoding, err = optionalText(d, "encoding"); err != nil {
		return err
	}
	if raw, ok := d["creation date"]; ok {
		m.CreationDate, err = integer(raw, "'creation date'")
		if err != nil {
			return err
		}
	}
	if raw, ok := d["announce-list"]; ok {
		tiers, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("metainfo: 'announce-list' is not a list")
		}
		m.AnnounceList = make([][]string, len(tiers))
		for i, rawTier := range tiers {
			tier, ok := rawTier.([]any)
			if !ok {
				return fmt.Errorf("metainfo: 'announce-list' tier %d is not a list", i)
			}
			m.AnnounceList[i] = make([]string, len(tier))
			for j, rawURL := range tier {
				url, err := text(rawURL, fmt.Sprintf("'announce-list' tier %d entry %d", i, j))
				if err != nil {
					return err
				}
				m.AnnounceList[i][j] = url
			}
		}
	}
	if raw, ok := d["url-list"]; ok {
		switch value := raw.(type) {
		case string:
			url, err := text(value, "'url-list'")
			if err != nil {
				return err
			}
			if url != "" {
				m.URLList = []string{url}
			}
		case []any:
			m.URLList = make([]string, 0, len(value))
			for i, rawURL := range value {
				url, err := text(rawURL, fmt.Sprintf("'url-list' entry %d", i))
				if err != nil {
					return err
				}
				if url != "" {
					m.URLList = append(m.URLList, url)
				}
			}
		default:
			return fmt.Errorf("metainfo: 'url-list' is neither a string nor a list")
		}
	}
	if raw, ok := d["nodes"]; ok {
		nodes, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("metainfo: 'nodes' is not a list")
		}
		m.Nodes = make([]Node, len(nodes))
		for i, rawNode := range nodes {
			pair, ok := rawNode.([]any)
			if !ok || len(pair) != 2 {
				return fmt.Errorf("metainfo: 'nodes' entry %d is not a [host, port] pair", i)
			}
			host, err := text(pair[0], fmt.Sprintf("'nodes' entry %d host", i))
			if err != nil {
				return err
			}
			if host == "" {
				return fmt.Errorf("metainfo: 'nodes' entry %d host is empty", i)
			}
			port, err := integer(pair[1], fmt.Sprintf("'nodes' entry %d port", i))
			if err != nil {
				return err
			}
			if port < 1 || port > math.MaxUint16 {
				return fmt.Errorf("metainfo: 'nodes' entry %d port %d is out of range", i, port)
			}
			m.Nodes[i] = Node{Host: host, Port: uint16(port)}
		}
	}
	return nil
}

func parseInfo(d map[string]any) (*Info, error) {
	info := &Info{}
	if rawVersion, ok := d["meta version"]; ok {
		version, err := integer(rawVersion, "'meta version'")
		if err != nil {
			return nil, err
		}
		if version != 2 {
			return nil, fmt.Errorf("metainfo: unsupported meta version %d", version)
		}
		info.MetaVersion = version
		info.hasV2 = true
	}

	name, err := requiredText(d, "name")
	if err != nil {
		return nil, err
	}
	if name == "" {
		return nil, fmt.Errorf("metainfo: 'name' is empty")
	}
	info.Name = name
	info.PieceLength, err = requiredInteger(d, "piece length")
	if err != nil {
		return nil, err
	}
	if info.PieceLength <= 0 {
		return nil, fmt.Errorf("metainfo: 'piece length' must be positive")
	}
	if info.hasV2 && (info.PieceLength < v2BlockLength || info.PieceLength&(info.PieceLength-1) != 0) {
		return nil, fmt.Errorf("metainfo: v2 'piece length' must be a power of two and at least %d", v2BlockLength)
	}
	if rawPrivate, ok := d["private"]; ok {
		private, err := integer(rawPrivate, "'private'")
		if err != nil {
			return nil, err
		}
		switch private {
		case 0:
			info.Private = false
		case 1:
			info.Private = true
		default:
			return nil, fmt.Errorf("metainfo: 'private' must be 0 or 1")
		}
	}
	info.Attr, info.SymlinkPath, info.SHA1, err = parseFileAttributes(d, "info")
	if err != nil {
		return nil, err
	}

	_, hasPieces := d["pieces"]
	_, hasLength := d["length"]
	_, hasFiles := d["files"]
	hasAnyV1 := hasPieces || hasLength || hasFiles
	if !info.hasV2 || hasAnyV1 {
		info.hasV1 = true
		if err := parseV1Info(info, d, hasLength, hasFiles); err != nil {
			return nil, err
		}
	}
	if !info.hasV2 {
		if _, ok := d["file tree"]; ok {
			return nil, fmt.Errorf("metainfo: 'file tree' requires meta version 2")
		}
		return info, nil
	}

	v2Files, v2PieceCount, err := parseV2Files(d, info.PieceLength)
	if err != nil {
		return nil, err
	}
	info.V2Files = v2Files
	if v2PieceCount > int64(maxInt()) {
		return nil, fmt.Errorf("metainfo: v2 piece count overflows int")
	}
	info.v2PieceCount = int(v2PieceCount)
	if _, _, err := pieceLayerRequirements(info); err != nil {
		return nil, err
	}
	if !info.hasV1 {
		info.Files = info.V2Files
		return info, nil
	}
	if err := validateHybrid(info); err != nil {
		return nil, err
	}
	return info, nil
}

func parseV1Info(info *Info, d map[string]any, hasLength, hasFiles bool) error {
	piecesValue, ok := d["pieces"]
	if !ok {
		return fmt.Errorf("metainfo: missing 'pieces' key for v1 layout")
	}
	pieces, ok := piecesValue.(string)
	if !ok {
		return fmt.Errorf("metainfo: 'pieces' is not a string")
	}
	if len(pieces)%len(Hash{}) != 0 {
		return fmt.Errorf("metainfo: 'pieces' length %d is not a multiple of %d", len(pieces), len(Hash{}))
	}
	if hasLength == hasFiles {
		return fmt.Errorf("metainfo: v1 info must contain exactly one of 'length' or 'files'")
	}

	var total int64
	if hasLength {
		length, err := requiredInteger(d, "length")
		if err != nil {
			return err
		}
		if length < 0 {
			return fmt.Errorf("metainfo: 'length' must be nonnegative")
		}
		info.Length = length
		info.singleFile = true
		if strings.Contains(info.Attr, "l") {
			if length != 0 || len(info.SymlinkPath) == 0 {
				return fmt.Errorf("metainfo: single-file symlink must have length 0 and a nonempty 'symlink path'")
			}
		} else if len(info.SymlinkPath) > 0 {
			return fmt.Errorf("metainfo: single-file 'symlink path' requires the 'l' attribute")
		}
		total = length
	} else {
		if strings.Contains(info.Attr, "l") || len(info.SymlinkPath) > 0 {
			return fmt.Errorf("metainfo: info-level symlink attributes require a single-file layout")
		}
		rawFiles, ok := d["files"].([]any)
		if !ok {
			return fmt.Errorf("metainfo: 'files' is not a list")
		}
		if len(rawFiles) == 0 {
			return fmt.Errorf("metainfo: 'files' is empty")
		}
		info.Files = make([]FileInfo, len(rawFiles))
		for i, rawFile := range rawFiles {
			fileDict, ok := rawFile.(map[string]any)
			if !ok {
				return fmt.Errorf("metainfo: file entry %d is not a dictionary", i)
			}
			file, err := parseV1File(fileDict, i)
			if err != nil {
				return err
			}
			file.Offset = total
			total, err = addLength(total, file.Length, fmt.Sprintf("file entry %d", i))
			if err != nil {
				return err
			}
			info.Files[i] = file
		}
	}

	count := len(pieces) / len(Hash{})
	expected := pieceCount(total, info.PieceLength)
	if int64(count) != expected {
		return fmt.Errorf("metainfo: 'pieces' contains %d hashes, want %d for %d bytes", count, expected, total)
	}
	info.Pieces = make([]Hash, count)
	for i := range info.Pieces {
		copy(info.Pieces[i][:], pieces[i*len(Hash{}):(i+1)*len(Hash{})])
	}
	return nil
}

func parseV1File(d map[string]any, index int) (FileInfo, error) {
	label := fmt.Sprintf("file entry %d", index)
	length, err := requiredInteger(d, "length")
	if err != nil {
		return FileInfo{}, fmt.Errorf("metainfo: %s: %w", label, err)
	}
	if length < 0 {
		return FileInfo{}, fmt.Errorf("metainfo: %s 'length' must be nonnegative", label)
	}
	rawPath, ok := d["path"]
	if !ok {
		return FileInfo{}, fmt.Errorf("metainfo: %s is missing 'path'", label)
	}
	path, err := parsePath(rawPath, label+" 'path'")
	if err != nil {
		return FileInfo{}, err
	}
	attr, symlinkPath, fileHash, err := parseFileAttributes(d, label)
	if err != nil {
		return FileInfo{}, err
	}
	file := FileInfo{Path: path, SymlinkPath: symlinkPath, Length: length, Attr: attr, SHA1: fileHash}
	if file.IsSymlink() {
		if file.Length != 0 || len(file.SymlinkPath) == 0 {
			return FileInfo{}, fmt.Errorf("metainfo: %s symlink must have length 0 and a nonempty 'symlink path'", label)
		}
	} else if len(file.SymlinkPath) > 0 {
		return FileInfo{}, fmt.Errorf("metainfo: %s 'symlink path' requires the 'l' attribute", label)
	}
	if file.IsPadding() && file.Length == 0 {
		return FileInfo{}, fmt.Errorf("metainfo: %s padding file must have positive length", label)
	}
	return file, nil
}

func parseV2Files(d map[string]any, pieceLength int64) ([]FileInfo, int64, error) {
	rawTree, ok := d["file tree"]
	if !ok {
		return nil, 0, fmt.Errorf("metainfo: missing 'file tree' key for v2 layout")
	}
	tree, ok := rawTree.(map[string]any)
	if !ok {
		return nil, 0, fmt.Errorf("metainfo: 'file tree' is not a dictionary")
	}
	if len(tree) == 0 {
		return nil, 0, fmt.Errorf("metainfo: 'file tree' is empty")
	}
	if _, ok := tree[""]; ok {
		return nil, 0, fmt.Errorf("metainfo: 'file tree' root cannot be a file")
	}

	var files []FileInfo
	var offset, pieces int64
	if err := walkFileTree(tree, nil, pieceLength, &offset, &pieces, &files); err != nil {
		return nil, 0, err
	}
	if len(files) == 0 {
		return nil, 0, fmt.Errorf("metainfo: 'file tree' contains no files")
	}
	return files, pieces, nil
}

func walkFileTree(tree map[string]any, prefix []string, pieceLength int64, offset, pieces *int64, files *[]FileInfo) error {
	if rawProperties, isFile := tree[""]; isFile {
		if len(prefix) == 0 {
			return fmt.Errorf("metainfo: 'file tree' root cannot be a file")
		}
		if len(tree) != 1 {
			return fmt.Errorf("metainfo: v2 file %q also has child entries", strings.Join(prefix, "/"))
		}
		properties, ok := rawProperties.(map[string]any)
		if !ok {
			return fmt.Errorf("metainfo: v2 file %q properties are not a dictionary", strings.Join(prefix, "/"))
		}
		file, err := parseV2File(properties, prefix)
		if err != nil {
			return err
		}
		if file.Length > 0 {
			*offset, err = align(*offset, pieceLength)
			if err != nil {
				return fmt.Errorf("metainfo: v2 file %q offset: %w", strings.Join(prefix, "/"), err)
			}
		}
		file.Offset = *offset
		*offset, err = addLength(*offset, file.Length, "v2 file offsets")
		if err != nil {
			return err
		}
		filePieces := pieceCount(file.Length, pieceLength)
		*pieces, err = addLength(*pieces, filePieces, "v2 piece count")
		if err != nil {
			return err
		}
		*files = append(*files, file)
		return nil
	}

	keys := make([]string, 0, len(tree))
	for key := range tree {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key == "" {
			continue
		}
		child, ok := tree[key].(map[string]any)
		if !ok {
			return fmt.Errorf("metainfo: v2 path %q is not a dictionary", strings.Join(append(prefix, key), "/"))
		}
		if len(child) == 0 {
			return fmt.Errorf("metainfo: v2 directory %q is empty", strings.Join(append(prefix, key), "/"))
		}
		next := prefix[:len(prefix):len(prefix)]
		next = append(next, key)
		if err := walkFileTree(child, next, pieceLength, offset, pieces, files); err != nil {
			return err
		}
	}
	return nil
}

func parseV2File(d map[string]any, path []string) (FileInfo, error) {
	label := fmt.Sprintf("v2 file %q", strings.Join(path, "/"))
	length, err := requiredInteger(d, "length")
	if err != nil {
		return FileInfo{}, fmt.Errorf("metainfo: %s: %w", label, err)
	}
	if length < 0 {
		return FileInfo{}, fmt.Errorf("metainfo: %s 'length' must be nonnegative", label)
	}
	attr, symlinkPath, fileHash, err := parseFileAttributes(d, label)
	if err != nil {
		return FileInfo{}, err
	}
	file := FileInfo{
		Path:        append([]string(nil), path...),
		SymlinkPath: symlinkPath,
		Length:      length,
		Attr:        attr,
		SHA1:        fileHash,
	}
	if file.IsPadding() {
		return FileInfo{}, fmt.Errorf("metainfo: %s cannot be a padding file in a v2 file tree", label)
	}
	if rawRoot, ok := d["pieces root"]; ok {
		rootString, ok := rawRoot.(string)
		if !ok {
			return FileInfo{}, fmt.Errorf("metainfo: %s 'pieces root' is not a string", label)
		}
		if len(rootString) != len(HashV2{}) {
			return FileInfo{}, fmt.Errorf("metainfo: %s 'pieces root' is %d bytes, want %d", label, len(rootString), len(HashV2{}))
		}
		root := HashV2{}
		copy(root[:], rootString)
		file.PiecesRoot = &root
	}
	if file.IsSymlink() {
		if file.Length != 0 || len(file.SymlinkPath) == 0 {
			return FileInfo{}, fmt.Errorf("metainfo: %s symlink must have length 0 and a nonempty 'symlink path'", label)
		}
	} else if len(file.SymlinkPath) > 0 {
		return FileInfo{}, fmt.Errorf("metainfo: %s 'symlink path' requires the 'l' attribute", label)
	}
	if file.Length == 0 && file.PiecesRoot != nil {
		return FileInfo{}, fmt.Errorf("metainfo: %s empty file must not have a 'pieces root'", label)
	}
	if file.Length > 0 && file.PiecesRoot == nil {
		return FileInfo{}, fmt.Errorf("metainfo: %s nonempty file is missing 'pieces root'", label)
	}
	return file, nil
}

func validateHybrid(info *Info) error {
	if int64(len(info.Pieces)) != int64(info.v2PieceCount) {
		return fmt.Errorf("metainfo: hybrid v1 and v2 layouts have different piece counts")
	}
	if info.singleFile {
		if len(info.V2Files) != 1 {
			return fmt.Errorf("metainfo: hybrid single-file v1 layout does not match v2 file tree")
		}
		v2File := info.V2Files[0]
		if !samePath(v2File.Path, []string{info.Name}) || v2File.Length != info.Length || v2File.Offset != 0 {
			return fmt.Errorf("metainfo: hybrid single-file v1 and v2 layouts differ")
		}
		if strings.Contains(info.Attr, "l") != v2File.IsSymlink() || !samePath(info.SymlinkPath, v2File.SymlinkPath) {
			return fmt.Errorf("metainfo: hybrid single-file symlink metadata differs")
		}
		return nil
	}

	v2Index := 0
	var previousEnd, padding int64
	for i := range info.Files {
		v1File := &info.Files[i]
		if v1File.IsPadding() {
			var err error
			padding, err = addLength(padding, v1File.Length, "hybrid padding")
			if err != nil {
				return err
			}
			continue
		}
		if v2Index == len(info.V2Files) {
			return fmt.Errorf("metainfo: hybrid v1 layout has files absent from v2 file tree")
		}
		v2File := info.V2Files[v2Index]
		if !samePath(v1File.Path, v2File.Path) || v1File.Length != v2File.Length {
			return fmt.Errorf("metainfo: hybrid file %d differs between v1 and v2 layouts", v2Index)
		}
		if v1File.Length > 0 {
			if v2File.Offset < previousEnd || padding != v2File.Offset-previousEnd {
				return fmt.Errorf("metainfo: padding before hybrid file %q does not exactly fill its alignment gap", strings.Join(v1File.Path, "/"))
			}
			previousEnd = v2File.Offset + v2File.Length
			padding = 0
		}
		if v1File.IsSymlink() != v2File.IsSymlink() || !samePath(v1File.SymlinkPath, v2File.SymlinkPath) {
			return fmt.Errorf("metainfo: hybrid file %q has inconsistent symlink metadata", strings.Join(v1File.Path, "/"))
		}
		v1File.PiecesRoot = v2File.PiecesRoot
		v2Index++
	}
	if v2Index != len(info.V2Files) {
		return fmt.Errorf("metainfo: hybrid v2 file tree has files absent from v1 layout")
	}
	if padding > 0 {
		var tail int64
		if remainder := previousEnd % info.PieceLength; remainder != 0 {
			tail = info.PieceLength - remainder
		}
		if padding != tail {
			return fmt.Errorf("metainfo: final hybrid padding is %d bytes, want %d", padding, tail)
		}
	}
	return nil
}

func decodePieceLayers(d map[string]any) (map[HashV2][]HashV2, error) {
	rawLayers, ok := d["piece layers"]
	if !ok {
		return nil, fmt.Errorf("metainfo: missing 'piece layers' key for v2 layout")
	}
	layerDict, ok := rawLayers.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("metainfo: 'piece layers' is not a dictionary")
	}

	layers := make(map[HashV2][]HashV2, len(layerDict))
	for rawRoot, rawLayer := range layerDict {
		if len(rawRoot) != len(HashV2{}) {
			return nil, fmt.Errorf("metainfo: piece layer key is %d bytes, want %d", len(rawRoot), len(HashV2{}))
		}
		root := HashV2{}
		copy(root[:], rawRoot)
		layerString, ok := rawLayer.(string)
		if !ok {
			return nil, fmt.Errorf("metainfo: piece layer for root %s is not a string", root)
		}
		if len(layerString)%len(HashV2{}) != 0 {
			return nil, fmt.Errorf("metainfo: piece layer for root %s is not a multiple of %d bytes", root, len(HashV2{}))
		}
		layer := make([]HashV2, len(layerString)/len(HashV2{}))
		for i := range layer {
			copy(layer[i][:], layerString[i*len(HashV2{}):(i+1)*len(HashV2{})])
		}
		layers[root] = layer
	}
	return layers, nil
}

func validatePieceLayers(layers map[HashV2][]HashV2, info *Info) (map[HashV2][]HashV2, error) {
	allRoots, required, err := pieceLayerRequirements(info)
	if err != nil {
		return nil, err
	}
	validated := make(map[HashV2][]HashV2, len(required))
	for root, layer := range layers {
		if _, exists := allRoots[root]; !exists {
			return nil, fmt.Errorf("metainfo: piece layer root %s is not present in the file tree", root)
		}
		expected, needed := required[root]
		if !needed {
			return nil, fmt.Errorf("metainfo: piece layer root %s belongs to a file no larger than one piece", root)
		}
		if int64(len(layer)) != expected {
			return nil, fmt.Errorf("metainfo: piece layer for root %s has %d hashes, want %d", root, len(layer), expected)
		}
		if !pieceLayerRootMatches(layer, info.PieceLength, root) {
			return nil, fmt.Errorf("metainfo: piece layer hashes do not match root %s", root)
		}
		validated[root] = append([]HashV2(nil), layer...)
		delete(required, root)
	}
	for root := range required {
		return nil, fmt.Errorf("metainfo: missing piece layer for root %s", root)
	}
	return validated, nil
}

func pieceLayerRequirements(info *Info) (map[HashV2]struct{}, map[HashV2]int64, error) {
	allRoots := make(map[HashV2]struct{})
	required := make(map[HashV2]int64)
	for _, file := range info.V2Files {
		if file.PiecesRoot == nil {
			continue
		}
		root := *file.PiecesRoot
		allRoots[root] = struct{}{}
		if file.Length <= info.PieceLength {
			continue
		}
		count := pieceCount(file.Length, info.PieceLength)
		if previous, exists := required[root]; exists && previous != count {
			return nil, nil, fmt.Errorf("metainfo: pieces root %s is reused with incompatible file lengths", root)
		}
		required[root] = count
	}
	return allRoots, required, nil
}

func pieceLayerRootMatches(layer []HashV2, pieceLength int64, root HashV2) bool {
	if len(layer) < 2 {
		return false
	}
	zeroPiece := HashV2{}
	for size := v2BlockLength; size < pieceLength; size *= 2 {
		zeroPiece = hashPair(zeroPiece, zeroPiece)
	}
	target := 1
	for target < len(layer) {
		target *= 2
	}
	var stack [64]HashV2
	var used [64]bool
	add := func(hash HashV2) {
		for level := 0; ; level++ {
			if !used[level] {
				stack[level] = hash
				used[level] = true
				return
			}
			hash = hashPair(stack[level], hash)
			used[level] = false
		}
	}
	for _, hash := range layer {
		add(hash)
	}
	for i := len(layer); i < target; i++ {
		add(zeroPiece)
	}
	level := 0
	for 1<<level < target {
		level++
	}
	return used[level] && stack[level] == root
}

func hashPair(left, right HashV2) HashV2 {
	var pair [64]byte
	copy(pair[:32], left[:])
	copy(pair[32:], right[:])
	return HashV2(sha256.Sum256(pair[:]))
}

func parseFileAttributes(d map[string]any, label string) (string, []string, *Hash, error) {
	attr, err := optionalText(d, "attr")
	if err != nil {
		return "", nil, nil, fmt.Errorf("metainfo: %s: %w", label, err)
	}
	var symlinkPath []string
	if rawPath, ok := d["symlink path"]; ok {
		symlinkPath, err = parsePath(rawPath, label+" 'symlink path'")
		if err != nil {
			return "", nil, nil, err
		}
	}
	var fileHash *Hash
	if rawHash, ok := d["sha1"]; ok {
		hashString, ok := rawHash.(string)
		if !ok {
			return "", nil, nil, fmt.Errorf("metainfo: %s 'sha1' is not a string", label)
		}
		if len(hashString) != len(Hash{}) {
			return "", nil, nil, fmt.Errorf("metainfo: %s 'sha1' is %d bytes, want %d", label, len(hashString), len(Hash{}))
		}
		hash := Hash{}
		copy(hash[:], hashString)
		fileHash = &hash
	}
	return attr, symlinkPath, fileHash, nil
}

func parsePath(raw any, label string) ([]string, error) {
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("metainfo: %s is not a list", label)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("metainfo: %s is empty", label)
	}
	path := make([]string, len(list))
	for i, rawComponent := range list {
		component, err := text(rawComponent, fmt.Sprintf("%s component %d", label, i))
		if err != nil {
			return nil, err
		}
		if component == "" {
			return nil, fmt.Errorf("metainfo: %s component %d is empty", label, i)
		}
		path[i] = component
	}
	return path, nil
}

func requiredText(d map[string]any, key string) (string, error) {
	raw, ok := d[key]
	if !ok {
		return "", fmt.Errorf("metainfo: missing %q key", key)
	}
	return text(raw, fmt.Sprintf("%q", key))
}

func optionalText(d map[string]any, key string) (string, error) {
	raw, ok := d[key]
	if !ok {
		return "", nil
	}
	return text(raw, fmt.Sprintf("%q", key))
}

func text(raw any, label string) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("metainfo: %s is not a string", label)
	}
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("metainfo: %s is not valid UTF-8", label)
	}
	return value, nil
}

func requiredInteger(d map[string]any, key string) (int64, error) {
	raw, ok := d[key]
	if !ok {
		return 0, fmt.Errorf("metainfo: missing %q key", key)
	}
	return integer(raw, fmt.Sprintf("%q", key))
}

func integer(raw any, label string) (int64, error) {
	switch value := raw.(type) {
	case int64:
		return value, nil
	case *big.Int:
		return 0, fmt.Errorf("metainfo: %s is outside the int64 range", label)
	default:
		return 0, fmt.Errorf("metainfo: %s is not an integer", label)
	}
}

func pieceCount(length, pieceLength int64) int64 {
	if length == 0 {
		return 0
	}
	return 1 + (length-1)/pieceLength
}

func addLength(a, b int64, label string) (int64, error) {
	if b < 0 || a > math.MaxInt64-b {
		return 0, fmt.Errorf("metainfo: %s overflows int64", label)
	}
	return a + b, nil
}

func align(offset, alignment int64) (int64, error) {
	remainder := offset % alignment
	if remainder == 0 {
		return offset, nil
	}
	return addLength(offset, alignment-remainder, "v2 file alignment")
}

func maxInt() int {
	return int(^uint(0) >> 1)
}

func samePath(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
