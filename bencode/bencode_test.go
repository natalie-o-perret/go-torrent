package bencode_test

import (
	"bytes"
	"math/big"
	"strings"
	"testing"

	"github.com/natalie-o-perret/go-torrent/bencode"
)

func TestDecodeInt(t *testing.T) {
	tests := []struct {
		in   string
		want int64
	}{
		{"i42e", 42},
		{"i0e", 0},
		{"i-1e", -1},
		{"i1000000e", 1_000_000},
		{"i9223372036854775807e", 1<<63 - 1},
		{"i-9223372036854775808e", -1 << 63},
	}
	for _, tc := range tests {
		got, err := bencode.Decode(strings.NewReader(tc.in))
		if err != nil {
			t.Errorf("Decode(%q): unexpected error: %v", tc.in, err)
			continue
		}
		n, ok := got.(int64)
		if !ok {
			t.Errorf("Decode(%q): got %T, want int64", tc.in, got)
			continue
		}
		if n != tc.want {
			t.Errorf("Decode(%q) = %d, want %d", tc.in, n, tc.want)
		}
	}
}

func TestDecodeBigInt(t *testing.T) {
	for _, in := range []string{
		"i9223372036854775808e",
		"i-9223372036854775809e",
		"i99999999999999999999999999999999999999999999999999e",
	} {
		got, err := bencode.Decode(strings.NewReader(in))
		if err != nil {
			t.Fatalf("Decode(%q): %v", in, err)
		}
		n, ok := got.(*big.Int)
		if !ok {
			t.Fatalf("Decode(%q): got %T, want *big.Int", in, got)
		}
		want, ok := new(big.Int).SetString(in[1:len(in)-1], 10)
		if !ok || n.Cmp(want) != 0 {
			t.Errorf("Decode(%q) = %v, want %v", in, n, want)
		}
		encoded, err := bencode.EncodeToString(n)
		if err != nil {
			t.Fatalf("EncodeToString(%v): %v", n, err)
		}
		if encoded != in {
			t.Errorf("EncodeToString(Decode(%q)) = %q", in, encoded)
		}
	}
}

func TestDecodeRejectsInvalidInt(t *testing.T) {
	for _, in := range []string{
		"ie",
		"i-e",
		"ixe",
		"i+1e",
		"i01e",
		"i-01e",
		"i-0e",
		"i1",
	} {
		if got, err := bencode.Decode(strings.NewReader(in)); err == nil {
			t.Errorf("Decode(%q): want error, got %v", in, got)
		}
	}
}

func TestDecodeString(t *testing.T) {
	tests := []struct {
		in   string
		want string
		err  bool
	}{
		{"4:spam", "spam", false},
		{"0:", "", false},
		{"3:abc", "abc", false},
		{"5:ab", "", true},
	}
	for _, tc := range tests {
		got, err := bencode.Decode(strings.NewReader(tc.in))
		if tc.err {
			if err == nil {
				t.Errorf("Decode(%q): want error, got %v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Decode(%q): unexpected error: %v", tc.in, err)
			continue
		}
		s, ok := got.(string)
		if !ok {
			t.Errorf("Decode(%q): got %T, want string", tc.in, got)
			continue
		}
		if s != tc.want {
			t.Errorf("Decode(%q) = %q, want %q", tc.in, s, tc.want)
		}
	}
}

func TestDecodeRejectsInvalidStringLength(t *testing.T) {
	for _, in := range []string{
		"-1:x",
		"+1:x",
		"00:",
		"01:x",
		"1x:x",
		"1",
		"18446744073709551616:x",
	} {
		if got, err := bencode.Decode(strings.NewReader(in)); err == nil {
			t.Errorf("Decode(%q): want error, got %v", in, got)
		}
	}
}

func TestDecodeList(t *testing.T) {
	got, err := bencode.Decode(strings.NewReader("l4:spami42ee"))
	if err != nil {
		t.Fatal(err)
	}
	list, ok := got.([]any)
	if !ok {
		t.Fatalf("got %T, want []any", got)
	}
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
	if list[0] != "spam" {
		t.Errorf("list[0] = %v, want spam", list[0])
	}
	if list[1] != int64(42) {
		t.Errorf("list[1] = %v, want 42", list[1])
	}
}

func TestDecodeEmptyList(t *testing.T) {
	got, err := bencode.Decode(strings.NewReader("le"))
	if err != nil {
		t.Fatal(err)
	}
	list, ok := got.([]any)
	if !ok {
		t.Fatalf("got %T, want []any", got)
	}
	if len(list) != 0 {
		t.Errorf("len = %d, want 0", len(list))
	}
}

func TestDecodeDict(t *testing.T) {
	got, err := bencode.Decode(strings.NewReader("d3:bar4:spam3:fooi42ee"))
	if err != nil {
		t.Fatal(err)
	}
	d, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("got %T, want map[string]any", got)
	}
	if d["bar"] != "spam" {
		t.Errorf("bar = %v, want spam", d["bar"])
	}
	if d["foo"] != int64(42) {
		t.Errorf("foo = %v, want 42", d["foo"])
	}
}

func TestDecodeEmptyDict(t *testing.T) {
	got, err := bencode.Decode(strings.NewReader("de"))
	if err != nil {
		t.Fatal(err)
	}
	d, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("got %T, want map[string]any", got)
	}
	if len(d) != 0 {
		t.Errorf("len = %d, want 0", len(d))
	}
}

func TestDecodeRejectsInvalidDictionaries(t *testing.T) {
	for _, in := range []string{
		"d1:bi1e1:ai2ee",
		"d1:ai1e1:ai2ee",
		"di1ei2ee",
		"d-1:xi1ee",
		"d+1:xi1ee",
		"d01:ai1ee",
		"d1x:ai1ee",
		"d18446744073709551616:xi1ee",
	} {
		if got, err := bencode.Decode(strings.NewReader(in)); err == nil {
			t.Errorf("Decode(%q): want error, got %v", in, got)
		}
	}
}

func TestDecodeNestedList(t *testing.T) {
	got, err := bencode.Decode(strings.NewReader("ll4:spamee"))
	if err != nil {
		t.Fatal(err)
	}
	outer, ok := got.([]any)
	if !ok {
		t.Fatalf("got %T, want []any", got)
	}
	if len(outer) != 1 {
		t.Fatalf("outer len = %d, want 1", len(outer))
	}
	inner, ok := outer[0].([]any)
	if !ok {
		t.Fatalf("inner is %T, want []any", outer[0])
	}
	if inner[0] != "spam" {
		t.Errorf("inner[0] = %v, want spam", inner[0])
	}
}

func TestDecodeUnexpectedByte(t *testing.T) {
	_, err := bencode.Decode(strings.NewReader("x"))
	if err == nil {
		t.Error("want error for unknown prefix byte, got nil")
	}
}

func TestDecodeRejectsTrailingData(t *testing.T) {
	for _, in := range []string{"i1ee", "0:garbage", "lei1e", "i1e\n"} {
		if got, err := bencode.Decode(strings.NewReader(in)); err == nil {
			t.Errorf("Decode(%q): want error, got %v", in, got)
		}
	}
}

func TestDecodePrefix(t *testing.T) {
	header := "d8:msg_typei1e5:piecei0ee"
	payload := []byte{0, 1, 'e', 0xff}
	data := append([]byte(header), payload...)

	got, consumed, err := bencode.DecodePrefix(data)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(header) {
		t.Fatalf("consumed = %d, want %d", consumed, len(header))
	}
	dict, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("got %T, want map[string]any", got)
	}
	if dict["msg_type"] != int64(1) || dict["piece"] != int64(0) {
		t.Errorf("decoded prefix = %#v", dict)
	}
	if !bytes.Equal(data[consumed:], payload) {
		t.Errorf("remaining payload = %v, want %v", data[consumed:], payload)
	}
	encoded, err := bencode.EncodeToString(got)
	if err != nil {
		t.Fatal(err)
	}
	if encoded != header {
		t.Errorf("re-encoded prefix = %q, want %q", encoded, header)
	}
}

func TestDecodePrefixUsesCanonicalChecks(t *testing.T) {
	for _, in := range []string{
		"01:xpayload",
		"i01epayload",
		"d1:bi1e1:ai2eepayload",
		strings.Repeat("l", bencode.DefaultMaxDepth+1),
	} {
		if got, consumed, err := bencode.DecodePrefix([]byte(in)); err == nil {
			t.Errorf("DecodePrefix(%q): want error, got %v after %d bytes", in, got, consumed)
		}
	}
}

func TestDecoderLimits(t *testing.T) {
	t.Run("bytes", func(t *testing.T) {
		decoder := bencode.NewDecoder(strings.NewReader("5:"))
		decoder.MaxBytes = 4
		if got, err := decoder.Decode(); err == nil {
			t.Fatalf("Decode(): want declared-length error, got %v", got)
		}

		decoder = bencode.NewDecoder(strings.NewReader("4:spam"))
		decoder.MaxBytes = 6
		if got, err := decoder.Decode(); err != nil || got != "spam" {
			t.Fatalf("Decode() = %v, %v; want spam, nil", got, err)
		}
	})

	t.Run("depth", func(t *testing.T) {
		decoder := bencode.NewDecoder(strings.NewReader("llee"))
		decoder.MaxDepth = 1
		if got, err := decoder.Decode(); err == nil {
			t.Fatalf("Decode(): want depth error, got %v", got)
		}

		decoder = bencode.NewDecoder(strings.NewReader("llee"))
		decoder.MaxDepth = 2
		if _, err := decoder.Decode(); err != nil {
			t.Fatalf("Decode(): %v", err)
		}
	})

	t.Run("values", func(t *testing.T) {
		decoder := bencode.NewDecoder(strings.NewReader("l0:0:e"))
		if decoder.MaxValues != bencode.DefaultMaxValues {
			t.Fatalf("default MaxValues = %d, want %d", decoder.MaxValues, bencode.DefaultMaxValues)
		}
		decoder.MaxValues = 2
		if got, err := decoder.Decode(); err == nil {
			t.Fatalf("Decode(): want value-count error, got %v", got)
		}

		decoder = bencode.NewDecoder(strings.NewReader("l0:0:e"))
		decoder.MaxValues = 3
		if _, err := decoder.Decode(); err != nil {
			t.Fatalf("Decode(): %v", err)
		}

		decoder = bencode.NewDecoder(strings.NewReader("d1:ai1ee"))
		decoder.MaxValues = 2
		if got, err := decoder.Decode(); err == nil {
			t.Fatalf("Decode(): want dictionary value-count error, got %v", got)
		}
	})

	tooDeep := strings.Repeat("l", bencode.DefaultMaxDepth+1) + strings.Repeat("e", bencode.DefaultMaxDepth+1)
	if got, err := bencode.Decode(strings.NewReader(tooDeep)); err == nil {
		t.Fatalf("Decode(excessive nesting): want error, got %v", got)
	}
}

func TestEncodeInt(t *testing.T) {
	tests := []struct {
		want string
		val  int64
	}{
		{want: "i0e", val: 0},
		{want: "i42e", val: 42},
		{want: "i-1e", val: -1},
	}
	for _, tc := range tests {
		s, err := bencode.EncodeToString(tc.val)
		if err != nil {
			t.Errorf("EncodeToString(%d): %v", tc.val, err)
			continue
		}
		if s != tc.want {
			t.Errorf("EncodeToString(%d) = %q, want %q", tc.val, s, tc.want)
		}
	}
}

func TestEncodeBigInt(t *testing.T) {
	n, ok := new(big.Int).SetString("99999999999999999999999999999999999999", 10)
	if !ok {
		t.Fatal("invalid test integer")
	}
	for _, value := range []any{n, *n} {
		got, err := bencode.EncodeToString(value)
		if err != nil {
			t.Fatalf("EncodeToString(%T): %v", value, err)
		}
		if want := "i99999999999999999999999999999999999999e"; got != want {
			t.Errorf("EncodeToString(%T) = %q, want %q", value, got, want)
		}
	}
}

func TestEncodeString(t *testing.T) {
	tests := []struct {
		val  string
		want string
	}{
		{"spam", "4:spam"},
		{"", "0:"},
		{"abc", "3:abc"},
	}
	for _, tc := range tests {
		s, err := bencode.EncodeToString(tc.val)
		if err != nil {
			t.Errorf("EncodeToString(%q): %v", tc.val, err)
			continue
		}
		if s != tc.want {
			t.Errorf("EncodeToString(%q) = %q, want %q", tc.val, s, tc.want)
		}
	}
}

func TestEncodeList(t *testing.T) {
	s, err := bencode.EncodeToString([]any{"spam", int64(42)})
	if err != nil {
		t.Fatal(err)
	}
	if s != "l4:spami42ee" {
		t.Errorf("got %q, want l4:spami42ee", s)
	}
}

func TestEncodeDict(t *testing.T) {
	s, err := bencode.EncodeToString(map[string]any{
		"foo": int64(42),
		"bar": "spam",
	})
	if err != nil {
		t.Fatal(err)
	}
	if s != "d3:bar4:spam3:fooi42ee" {
		t.Errorf("got %q, want d3:bar4:spam3:fooi42ee", s)
	}
}

func TestRoundTrip(t *testing.T) {
	tests := []string{
		"i0e",
		"i-1e",
		"i9223372036854775808e",
		"i-9223372036854775809e",
		"4:spam",
		"0:",
		"l4:spami42ee",
		"d3:bar4:spam3:fooi42ee",
		"le",
		"de",
	}
	for _, tc := range tests {
		got, err := bencode.Decode(strings.NewReader(tc))
		if err != nil {
			t.Errorf("Decode(%q): %v", tc, err)
			continue
		}
		s, err := bencode.EncodeToString(got)
		if err != nil {
			t.Errorf("EncodeToString for %q: %v", tc, err)
			continue
		}
		if s != tc {
			t.Errorf("round-trip(%q) = %q", tc, s)
		}
	}
}

func TestEncodeUnsupportedType(t *testing.T) {
	_, err := bencode.EncodeToString(struct{}{})
	if err == nil {
		t.Error("want error for unsupported type, got nil")
	}
}

func TestEncodeBytes(t *testing.T) {
	s, err := bencode.EncodeToString([]byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	if s != "3:abc" {
		t.Errorf("got %q, want 3:abc", s)
	}
}

func FuzzDecodeDoesNotPanic(f *testing.F) {
	for _, seed := range []string{
		"",
		"d-1:xe",
		"d999999999999999999999999999999:x",
		"i+1e",
		"i01e",
		strings.Repeat("l", bencode.DefaultMaxDepth+1),
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = bencode.Decode(bytes.NewReader(data))
		_, _, _ = bencode.DecodePrefix(data)
	})
}
