// Package magnet parses and formats BEP 9 BitTorrent magnet URIs.
package magnet

import (
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/natalie-o-perret/go-torrent/metainfo"
)

const (
	btihPrefix = "urn:btih:"
	btmhPrefix = "urn:btmh:"
)

// URI is a parsed magnet URI. Trackers and Peers retain their query order.
// Unknown contains no xt, dn, tr, or x.pe entries.
type URI struct {
	Hashes      metainfo.Hashes
	DisplayName string
	Trackers    []string
	Peers       []Peer
	Unknown     url.Values
}

// Peer is a BEP 9 peer endpoint. Host does not include IPv6 brackets.
type Peer struct {
	Host string
	Port uint16
}

// String returns the endpoint in host:port form.
func (p Peer) String() string {
	return net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port)))
}

// Parse parses and validates a BEP 9 magnet URI.
func Parse(raw string) (URI, error) {
	if strings.Contains(raw, "#") {
		return URI{}, fmt.Errorf("magnet: fragments are not allowed")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return URI{}, fmt.Errorf("magnet: parse URI: %w", err)
	}
	if len(raw) < len("magnet:?") || !strings.EqualFold(raw[:len("magnet:")], "magnet:") || raw[len("magnet:")] != '?' {
		return URI{}, fmt.Errorf("magnet: URI must use the magnet:? form")
	}
	if !strings.EqualFold(parsed.Scheme, "magnet") || parsed.Opaque != "" || parsed.Host != "" || parsed.Path != "" {
		return URI{}, fmt.Errorf("magnet: URI must use the magnet:? form")
	}

	values, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return URI{}, fmt.Errorf("magnet: parse query: %w", err)
	}
	topics, ok := values["xt"]
	if !ok || len(topics) == 0 {
		return URI{}, fmt.Errorf("magnet: missing xt parameter")
	}

	var result URI
	for i, topic := range topics {
		recognised, err := parseTopic(&result.Hashes, topic)
		if err != nil {
			return URI{}, fmt.Errorf("magnet: xt entry %d: %w", i, err)
		}
		if !recognised {
			continue
		}
	}
	if result.Hashes.V1 == nil && result.Hashes.V2 == nil {
		return URI{}, fmt.Errorf("magnet: xt contains no supported BitTorrent hash")
	}

	if names := values["dn"]; len(names) != 0 {
		result.DisplayName = names[0]
		if !utf8.ValidString(result.DisplayName) {
			return URI{}, fmt.Errorf("magnet: dn is not valid UTF-8")
		}
		for _, name := range names[1:] {
			if name != result.DisplayName {
				return URI{}, fmt.Errorf("magnet: conflicting dn parameters")
			}
		}
	}

	for i, tracker := range values["tr"] {
		if err := validateTracker(tracker); err != nil {
			return URI{}, fmt.Errorf("magnet: tr entry %d: %w", i, err)
		}
		result.Trackers = append(result.Trackers, tracker)
	}
	for i, endpoint := range values["x.pe"] {
		peer, err := parsePeer(endpoint)
		if err != nil {
			return URI{}, fmt.Errorf("magnet: x.pe entry %d: %w", i, err)
		}
		result.Peers = append(result.Peers, peer)
	}

	for key, entries := range values {
		if isKnownKey(key) {
			continue
		}
		if result.Unknown == nil {
			result.Unknown = make(url.Values)
		}
		result.Unknown[key] = append([]string(nil), entries...)
	}
	return result, nil
}

// Format validates uri and returns its canonical magnet URI representation.
func Format(uri URI) (string, error) {
	if uri.Hashes.V1 == nil && uri.Hashes.V2 == nil {
		return "", fmt.Errorf("magnet: at least one info hash is required")
	}

	parts := make([]string, 0, 2+len(uri.Trackers)+len(uri.Peers))
	add := func(key, value string) {
		parts = append(parts, url.QueryEscape(key)+"="+url.QueryEscape(value))
	}
	if uri.Hashes.V1 != nil {
		parts = append(parts, "xt="+btihPrefix+uri.Hashes.V1.String())
	}
	if uri.Hashes.V2 != nil {
		parts = append(parts, "xt="+btmhPrefix+"1220"+uri.Hashes.V2.String())
	}
	if uri.DisplayName != "" {
		if !utf8.ValidString(uri.DisplayName) {
			return "", fmt.Errorf("magnet: dn is not valid UTF-8")
		}
		add("dn", uri.DisplayName)
	}
	for i, tracker := range uri.Trackers {
		if err := validateTracker(tracker); err != nil {
			return "", fmt.Errorf("magnet: tr entry %d: %w", i, err)
		}
		add("tr", tracker)
	}
	for i, peer := range uri.Peers {
		if _, err := parsePeer(peer.String()); err != nil {
			return "", fmt.Errorf("magnet: x.pe entry %d: %w", i, err)
		}
		parts = append(parts, "x.pe="+peer.String())
	}

	extra := make(url.Values)
	for key, entries := range uri.Unknown {
		if !isKnownKey(key) {
			extra[key] = append([]string(nil), entries...)
		}
	}
	if encoded := extra.Encode(); encoded != "" {
		parts = append(parts, encoded)
	}
	return "magnet:?" + strings.Join(parts, "&"), nil
}

func parseTopic(hashes *metainfo.Hashes, topic string) (bool, error) {
	switch {
	case len(topic) >= len(btihPrefix) && strings.EqualFold(topic[:len(btihPrefix)], btihPrefix):
		hash, err := parseV1Hash(topic[len(btihPrefix):])
		if err != nil {
			return true, err
		}
		if hashes.V1 != nil {
			if *hashes.V1 != hash {
				return true, fmt.Errorf("conflicting btih hashes")
			}
			return true, nil
		}
		hashes.V1 = &hash
		return true, nil
	case len(topic) >= len(btmhPrefix) && strings.EqualFold(topic[:len(btmhPrefix)], btmhPrefix):
		hash, err := parseV2Hash(topic[len(btmhPrefix):])
		if err != nil {
			return true, err
		}
		if hashes.V2 != nil {
			if *hashes.V2 != hash {
				return true, fmt.Errorf("conflicting btmh hashes")
			}
			return true, nil
		}
		hashes.V2 = &hash
		return true, nil
	default:
		return false, nil
	}
}

func parseV1Hash(encoded string) (metainfo.Hash, error) {
	var (
		raw []byte
		err error
	)
	switch len(encoded) {
	case 40:
		raw, err = hex.DecodeString(encoded)
	case 32:
		raw, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(encoded))
	default:
		return metainfo.Hash{}, fmt.Errorf("btih hash is %d characters, want 40 hex or 32 base32", len(encoded))
	}
	if err != nil {
		return metainfo.Hash{}, fmt.Errorf("invalid btih hash: %w", err)
	}
	if len(raw) != len(metainfo.Hash{}) {
		return metainfo.Hash{}, fmt.Errorf("btih hash decodes to %d bytes, want %d", len(raw), len(metainfo.Hash{}))
	}
	var hash metainfo.Hash
	copy(hash[:], raw)
	return hash, nil
}

func parseV2Hash(encoded string) (metainfo.HashV2, error) {
	if len(encoded) != 68 {
		return metainfo.HashV2{}, fmt.Errorf("btmh multihash is %d characters, want 68", len(encoded))
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return metainfo.HashV2{}, fmt.Errorf("invalid btmh multihash: %w", err)
	}
	if raw[0] != 0x12 || raw[1] != 0x20 {
		return metainfo.HashV2{}, fmt.Errorf("btmh multihash must use the 1220 SHA-256 tag")
	}
	var hash metainfo.HashV2
	copy(hash[:], raw[2:])
	return hash, nil
}

func validateTracker(raw string) error {
	if raw == "" {
		return fmt.Errorf("tracker URL is empty")
	}
	if strings.Contains(raw, "#") {
		return fmt.Errorf("tracker URL contains a fragment")
	}
	tracker, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid tracker URL: %w", err)
	}
	if tracker.Scheme == "" || tracker.Hostname() == "" {
		return fmt.Errorf("tracker URL must be absolute and have a host")
	}
	return nil
}

func parsePeer(endpoint string) (Peer, error) {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return Peer{}, fmt.Errorf("invalid peer endpoint %q: %w", endpoint, err)
	}
	if host == "" {
		return Peer{}, fmt.Errorf("peer host is empty")
	}
	if portText == "" {
		return Peer{}, fmt.Errorf("peer port is empty")
	}
	for _, char := range portText {
		if char < '0' || char > '9' {
			return Peer{}, fmt.Errorf("peer port %q is not numeric", portText)
		}
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return Peer{}, fmt.Errorf("peer port %q is outside 1-65535", portText)
	}

	bracketed := strings.HasPrefix(endpoint, "[")
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" {
			return Peer{}, fmt.Errorf("scoped IPv6 peer addresses are not allowed")
		}
		if address.Is6() != bracketed {
			return Peer{}, fmt.Errorf("only IPv6 peer addresses may be bracketed")
		}
	} else if bracketed || !validDNSName(host) || numericDNSName(host) {
		return Peer{}, fmt.Errorf("invalid peer host %q", host)
	}

	return Peer{Host: host, Port: uint16(port)}, nil
}

func validDNSName(host string) bool {
	name := strings.TrimSuffix(host, ".")
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || !asciiAlphaNumeric(label[0]) || !asciiAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for i := 1; i < len(label)-1; i++ {
			if !asciiAlphaNumeric(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func asciiAlphaNumeric(char byte) bool {
	return char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9'
}

func numericDNSName(host string) bool {
	for _, char := range host {
		if char != '.' && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func isKnownKey(key string) bool {
	switch key {
	case "xt", "dn", "tr", "x.pe":
		return true
	default:
		return false
	}
}
