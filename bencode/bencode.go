// Package bencode implements bencoding -- the binary serialisation format
// used by the BitTorrent protocol for .torrent files and tracker responses.
//
// The format supports four value types:
//   - integers: i<decimal>e  (e.g. "i42e")
//   - byte strings: <length>:<data>  (e.g. "4:spam")
//   - lists: l<items>e
//   - dictionaries: d<key><value>...e  (keys must be sorted lexicographically)
//
// [Decode] returns one of int64, *big.Int, string, []any, or map[string]any.
// [Encode] accepts the same set of types and additionally []byte.
package bencode

import (
	"bytes"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

const (
	// DefaultMaxDepth is the maximum number of nested lists and dictionaries.
	DefaultMaxDepth = 100
	// DefaultMaxBytes is the maximum encoded value size accepted by decoders.
	DefaultMaxBytes int64 = 64 << 20
	// DefaultMaxValues is the maximum number of decoded values and dictionary keys.
	DefaultMaxValues = 1_000_000
)

// Decoder reads one complete bencoded value with configurable resource limits.
type Decoder struct {
	r io.Reader

	// MaxDepth limits nested lists and dictionaries.
	MaxDepth int
	// MaxBytes limits both the encoded input and declared string lengths.
	MaxBytes int64
	// MaxValues limits decoded values and dictionary keys, including the root.
	MaxValues int
}

// NewDecoder returns a decoder using the default resource limits.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{
		r:         r,
		MaxDepth:  DefaultMaxDepth,
		MaxBytes:  DefaultMaxBytes,
		MaxValues: DefaultMaxValues,
	}
}

// Decode reads a bencoded value from r and returns it as one of:
// int64, *big.Int, string, []any, or map[string]any. It rejects trailing data.
func Decode(r io.Reader) (any, error) {
	return NewDecoder(r).Decode()
}

// DecodePrefix decodes the first bencoded value in data and returns the number
// of bytes consumed. Bytes after the value are left uninterpreted.
func DecodePrefix(data []byte) (value any, consumed int, err error) {
	return decodePrefix(data, DefaultMaxDepth, DefaultMaxBytes, DefaultMaxValues)
}

// Decode reads one complete bencoded value and rejects trailing data.
func (d *Decoder) Decode() (any, error) {
	if d == nil || d.r == nil {
		return nil, fmt.Errorf("bencode: nil reader")
	}
	if err := validateLimits(d.MaxDepth, d.MaxBytes, d.MaxValues); err != nil {
		return nil, err
	}

	data, err := io.ReadAll(io.LimitReader(d.r, d.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("bencode: read: %w", err)
	}
	if int64(len(data)) > d.MaxBytes {
		return nil, fmt.Errorf("bencode: input exceeds %d-byte limit", d.MaxBytes)
	}

	v, consumed, err := decodePrefix(data, d.MaxDepth, d.MaxBytes, d.MaxValues)
	if err != nil {
		return nil, err
	}
	if consumed != len(data) {
		return nil, fmt.Errorf("bencode: trailing data at byte %d", consumed)
	}
	return v, nil
}

func decodePrefix(data []byte, maxDepth int, maxBytes int64, maxValues int) (any, int, error) {
	if int64(len(data)) > maxBytes+1 {
		data = data[:int(maxBytes+1)]
	}

	p := parser{
		data:      data,
		maxDepth:  maxDepth,
		maxBytes:  uint64(maxBytes),
		maxValues: maxValues,
	}
	v, err := p.decode(0)
	if err != nil {
		return nil, 0, err
	}
	if int64(p.pos) > maxBytes {
		return nil, 0, fmt.Errorf("bencode: value exceeds %d-byte limit", maxBytes)
	}
	return v, p.pos, nil
}

func validateLimits(maxDepth int, maxBytes int64, maxValues int) error {
	if maxDepth <= 0 {
		return fmt.Errorf("bencode: MaxDepth must be positive")
	}
	if maxBytes <= 0 || maxBytes == int64(^uint64(0)>>1) {
		return fmt.Errorf("bencode: MaxBytes must be between 1 and %d", int64(^uint64(0)>>1)-1)
	}
	if maxValues <= 0 {
		return fmt.Errorf("bencode: MaxValues must be positive")
	}
	return nil
}

type parser struct {
	data      []byte
	pos       int
	maxDepth  int
	maxBytes  uint64
	maxValues int
	values    int
}

func (p *parser) decode(depth int) (any, error) {
	if p.pos == len(p.data) {
		return nil, io.ErrUnexpectedEOF
	}
	if err := p.countValue(); err != nil {
		return nil, err
	}

	b := p.data[p.pos]
	p.pos++
	switch {
	case b == 'i':
		return p.decodeInt()
	case b == 'l':
		if depth >= p.maxDepth {
			return nil, fmt.Errorf("bencode: nesting exceeds depth limit %d", p.maxDepth)
		}
		return p.decodeList(depth + 1)
	case b == 'd':
		if depth >= p.maxDepth {
			return nil, fmt.Errorf("bencode: nesting exceeds depth limit %d", p.maxDepth)
		}
		return p.decodeDict(depth + 1)
	case b >= '0' && b <= '9':
		p.pos--
		return p.decodeString()
	default:
		return nil, fmt.Errorf("bencode: unexpected byte %q", b)
	}
}

func (p *parser) countValue() error {
	if p.values >= p.maxValues {
		return fmt.Errorf("bencode: decoded value count exceeds limit %d", p.maxValues)
	}
	p.values++
	return nil
}

// decodeInt parses an integer after the leading 'i' has been consumed.
func (p *parser) decodeInt() (any, error) {
	start := p.pos
	end := bytes.IndexByte(p.data[start:], 'e')
	if end < 0 {
		return nil, fmt.Errorf("bencode: unterminated integer")
	}
	end += start
	p.pos = end + 1
	raw := p.data[start:end]
	if len(raw) == 0 {
		return nil, fmt.Errorf("bencode: empty integer")
	}

	digits := raw
	negative := raw[0] == '-'
	if negative {
		digits = raw[1:]
		if len(digits) == 0 {
			return nil, fmt.Errorf("bencode: invalid integer %q", raw)
		}
	}
	for _, b := range digits {
		if b < '0' || b > '9' {
			return nil, fmt.Errorf("bencode: invalid integer %q", raw)
		}
	}
	if len(digits) > 1 && digits[0] == '0' {
		return nil, fmt.Errorf("bencode: integer %q has a leading zero", raw)
	}
	if negative && len(digits) == 1 && digits[0] == '0' {
		return nil, fmt.Errorf("bencode: negative zero is invalid")
	}

	n, ok := new(big.Int).SetString(string(raw), 10)
	if !ok {
		return nil, fmt.Errorf("bencode: invalid integer %q", raw)
	}
	if n.IsInt64() {
		return n.Int64(), nil
	}
	return n, nil
}

// decodeString parses a length-prefixed string starting with the first digit.
func (p *parser) decodeString() (string, error) {
	start := p.pos
	for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
		p.pos++
	}
	if start == p.pos || p.pos == len(p.data) || p.data[p.pos] != ':' {
		return "", fmt.Errorf("bencode: invalid string length at byte %d", start)
	}

	length := p.data[start:p.pos]
	p.pos++
	if len(length) > 1 && length[0] == '0' {
		return "", fmt.Errorf("bencode: string length %q has a leading zero", length)
	}
	n, err := strconv.ParseUint(string(length), 10, 64)
	if err != nil {
		return "", fmt.Errorf("bencode: invalid string length %q: %w", length, err)
	}
	if n > p.maxBytes {
		return "", fmt.Errorf("bencode: string length %d exceeds %d-byte limit", n, p.maxBytes)
	}
	if n > uint64(len(p.data)-p.pos) {
		return "", fmt.Errorf("bencode: string length %d exceeds remaining input", n)
	}

	end := p.pos + int(n)
	s := string(p.data[p.pos:end])
	p.pos = end
	return s, nil
}

// decodeList parses a list after the leading 'l' has been consumed.
func (p *parser) decodeList(depth int) ([]any, error) {
	var list []any
	for {
		if p.pos == len(p.data) {
			return nil, fmt.Errorf("bencode: unterminated list")
		}
		if p.data[p.pos] == 'e' {
			p.pos++
			return list, nil
		}
		val, err := p.decode(depth)
		if err != nil {
			return nil, err
		}
		list = append(list, val)
	}
}

// decodeDict parses a dictionary after the leading 'd' has been consumed.
func (p *parser) decodeDict(depth int) (map[string]any, error) {
	m := make(map[string]any)
	var previous string
	havePrevious := false
	for {
		if p.pos == len(p.data) {
			return nil, fmt.Errorf("bencode: unterminated dictionary")
		}
		if p.data[p.pos] == 'e' {
			p.pos++
			return m, nil
		}
		if p.data[p.pos] < '0' || p.data[p.pos] > '9' {
			return nil, fmt.Errorf("bencode: dictionary key at byte %d is not a string", p.pos)
		}
		if err := p.countValue(); err != nil {
			return nil, fmt.Errorf("bencode: dict key: %w", err)
		}
		key, err := p.decodeString()
		if err != nil {
			return nil, fmt.Errorf("bencode: dict key: %w", err)
		}
		if havePrevious && key <= previous {
			if key == previous {
				return nil, fmt.Errorf("bencode: duplicate dictionary key %q", key)
			}
			return nil, fmt.Errorf("bencode: dictionary keys %q and %q are not sorted", previous, key)
		}
		previous, havePrevious = key, true

		val, err := p.decode(depth)
		if err != nil {
			return nil, fmt.Errorf("bencode: dict value for %q: %w", key, err)
		}
		m[key] = val
	}
}

// Encode bencodes v and writes the result to w.
// v must be one of: int64, int, big.Int, *big.Int, string, []byte, []any,
// or map[string]any.
func Encode(w io.Writer, v any) error {
	switch val := v.(type) {
	case int64:
		_, err := fmt.Fprintf(w, "i%de", val)
		return err
	case int:
		_, err := fmt.Fprintf(w, "i%de", val)
		return err
	case big.Int:
		_, err := fmt.Fprintf(w, "i%se", val.String())
		return err
	case *big.Int:
		if val == nil {
			return fmt.Errorf("bencode: cannot encode nil *big.Int")
		}
		_, err := fmt.Fprintf(w, "i%se", val.String())
		return err
	case string:
		if _, err := fmt.Fprintf(w, "%d:", len(val)); err != nil {
			return err
		}
		_, err := io.WriteString(w, val)
		return err
	case []byte:
		if _, err := fmt.Fprintf(w, "%d:", len(val)); err != nil {
			return err
		}
		_, err := w.Write(val)
		return err
	case []any:
		if _, err := io.WriteString(w, "l"); err != nil {
			return err
		}
		for _, item := range val {
			if err := Encode(w, item); err != nil {
				return err
			}
		}
		_, err := io.WriteString(w, "e")
		return err
	case map[string]any:
		if _, err := io.WriteString(w, "d"); err != nil {
			return err
		}
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if err := Encode(w, k); err != nil {
				return err
			}
			if err := Encode(w, val[k]); err != nil {
				return err
			}
		}
		_, err := io.WriteString(w, "e")
		return err
	default:
		return fmt.Errorf("bencode: unsupported type %T", v)
	}
}

// EncodeToString bencodes v and returns the result as a string.
func EncodeToString(v any) (string, error) {
	var sb strings.Builder
	if err := Encode(&sb, v); err != nil {
		return "", err
	}
	return sb.String(), nil
}
