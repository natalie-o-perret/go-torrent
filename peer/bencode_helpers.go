package peer

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/natalie-o-perret/go-torrent/bencode"
)

func decodeDictionaryPrefix(data []byte, name string) (map[string]any, int, error) {
	value, consumed, err := bencode.DecodePrefix(data)
	if err != nil {
		return nil, 0, fmt.Errorf("peer: decode %s: %w", name, err)
	}
	dict, ok := value.(map[string]any)
	if !ok {
		return nil, 0, fmt.Errorf("peer: %s is not a dictionary", name)
	}
	return dict, consumed, nil
}

func encodeDictionary(dict map[string]any, name string) ([]byte, error) {
	var buf bytes.Buffer
	if err := bencode.Encode(&buf, dict); err != nil {
		return nil, fmt.Errorf("peer: encode %s: %w", name, err)
	}
	return buf.Bytes(), nil
}

func integerField(value any, name string) (int64, error) {
	switch n := value.(type) {
	case int64:
		return n, nil
	case *big.Int:
		return 0, fmt.Errorf("peer: %s is outside the int64 range", name)
	default:
		return 0, fmt.Errorf("peer: %s is not an integer", name)
	}
}

func copyDictionary(source map[string]any) map[string]any {
	if len(source) == 0 {
		return nil
	}
	destination := make(map[string]any, len(source))
	for key, value := range source {
		destination[key] = value
	}
	return destination
}
