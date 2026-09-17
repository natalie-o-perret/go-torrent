// Package tracker implements BitTorrent tracker clients for HTTP and UDP.
package tracker

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/natalie-o-perret/go-torrent/bencode"
	"github.com/natalie-o-perret/go-torrent/metainfo"
)

const (
	// DefaultMaxResponseBody is the maximum HTTP tracker response size.
	DefaultMaxResponseBody int64 = 2 << 20
	// DefaultUDPInitialTimeout is the first BEP 15 retransmission timeout.
	DefaultUDPInitialTimeout = 15 * time.Second
	// DefaultUDPMaxRetries is the BEP 15 retransmission limit after the first send.
	DefaultUDPMaxRetries = 8
)

// Event is the tracker event parameter defined in BEP 3.
type Event string

const (
	// EventNone is used for regular interval announces.
	EventNone Event = ""
	// EventStarted is sent on the first announce for a torrent.
	EventStarted Event = "started"
	// EventStopped is sent when a client gracefully stops downloading.
	EventStopped Event = "stopped"
	// EventCompleted is sent when the download finishes.
	EventCompleted Event = "completed"
)

// AnnounceRequest contains parameters shared by HTTP and UDP announces.
// A zero Key is replaced with a random key and returned in AnnounceResponse.
type AnnounceRequest struct {
	Event      Event
	Uploaded   int64
	Downloaded int64
	Left       int64
	NumWant    int
	Port       uint16
	InfoHash   metainfo.Hash
	PeerID     [20]byte
	Key        uint32
	TrackerID  string
	IP         string
}

// Peer is an endpoint returned by a tracker. Host preserves a noncompact DNS
// name, while IP is populated for compact peers and numeric noncompact hosts.
type Peer struct {
	IP     net.IP
	Host   string
	Port   uint16
	PeerID [20]byte
}

// String returns the peer address in host:port form.
func (p Peer) String() string {
	host := p.Host
	if host == "" && p.IP != nil {
		host = p.IP.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(p.Port)))
}

// AnnounceResponse is a successful tracker announce response.
type AnnounceResponse struct {
	TrackerID   string
	Warning     string
	Peers       []Peer
	Interval    int
	MinInterval int
	Complete    int
	Incomplete  int
	Key         uint32
}

// ScrapeStats contains the tracker statistics for one info hash.
type ScrapeStats struct {
	Complete   int
	Downloaded int
	Incomplete int
}

// ScrapeResponse maps each requested info hash to its statistics.
type ScrapeResponse struct {
	Files map[metainfo.Hash]ScrapeStats
}

// Client sends HTTP and UDP tracker requests. The zero values of optional
// limits use the package defaults.
type Client struct {
	HTTPClient        *http.Client
	MaxResponseBody   int64
	UDPDialer         *net.Dialer
	UDPInitialTimeout time.Duration
	UDPMaxRetries     int
}

// NewClient returns a tracker client using httpClient for HTTP requests.
func NewClient(httpClient *http.Client) *Client {
	return &Client{
		HTTPClient:        httpClient,
		MaxResponseBody:   DefaultMaxResponseBody,
		UDPInitialTimeout: DefaultUDPInitialTimeout,
		UDPMaxRetries:     DefaultUDPMaxRetries,
	}
}

var compatibilityClient = NewClient(&http.Client{Timeout: 30 * time.Second})

// Announce is the compatibility wrapper for a background HTTP or UDP announce.
// New code should use Client.Announce with a context.
func Announce(trackerURL string, req AnnounceRequest) (*AnnounceResponse, error) {
	return compatibilityClient.Announce(context.Background(), trackerURL, req)
}

// Announce sends an HTTP or UDP announce selected by the tracker URL scheme.
func (c *Client) Announce(ctx context.Context, trackerURL string, req AnnounceRequest) (*AnnounceResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("tracker: nil client")
	}
	if ctx == nil {
		return nil, fmt.Errorf("tracker: nil context")
	}
	if err := validateAnnounceRequest(req); err != nil {
		return nil, err
	}
	u, err := parseTrackerURL(trackerURL)
	if err != nil {
		return nil, err
	}
	if req.Key == 0 {
		req.Key, err = randomUint32(true)
		if err != nil {
			return nil, fmt.Errorf("tracker: generate key: %w", err)
		}
	}

	var response *AnnounceResponse
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		response, err = c.httpAnnounce(ctx, u, req)
	case "udp":
		response, err = c.udpAnnounce(ctx, u, req)
	default:
		err = fmt.Errorf("tracker: unsupported URL scheme %q", u.Scheme)
	}
	if err != nil {
		return nil, err
	}
	response.Key = req.Key
	return response, nil
}

// Scrape requests statistics for infoHashes from an HTTP or UDP tracker.
func (c *Client) Scrape(ctx context.Context, trackerURL string, infoHashes []metainfo.Hash) (*ScrapeResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("tracker: nil client")
	}
	if ctx == nil {
		return nil, fmt.Errorf("tracker: nil context")
	}
	if len(infoHashes) == 0 {
		return nil, fmt.Errorf("tracker: scrape requires at least one info hash")
	}
	seen := make(map[metainfo.Hash]struct{}, len(infoHashes))
	for _, hash := range infoHashes {
		if _, ok := seen[hash]; ok {
			return nil, fmt.Errorf("tracker: duplicate scrape info hash %s", hash)
		}
		seen[hash] = struct{}{}
	}
	u, err := parseTrackerURL(trackerURL)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return c.httpScrape(ctx, u, infoHashes)
	case "udp":
		return c.udpScrape(ctx, u, infoHashes)
	default:
		return nil, fmt.Errorf("tracker: unsupported URL scheme %q", u.Scheme)
	}
}

func validateAnnounceRequest(req AnnounceRequest) error {
	switch req.Event {
	case EventNone, EventStarted, EventStopped, EventCompleted:
	default:
		return fmt.Errorf("tracker: invalid event %q", req.Event)
	}
	if req.Uploaded < 0 || req.Downloaded < 0 || req.Left < 0 {
		return fmt.Errorf("tracker: uploaded, downloaded, and left must be nonnegative")
	}
	if req.NumWant < -1 || int64(req.NumWant) > math.MaxInt32 {
		return fmt.Errorf("tracker: numwant %d is outside [-1, %d]", req.NumWant, int64(math.MaxInt32))
	}
	if req.Port == 0 {
		return fmt.Errorf("tracker: port must be nonzero")
	}
	if req.PeerID == [20]byte{} {
		return fmt.Errorf("tracker: peer ID must be a nonzero 20-byte value")
	}
	if strings.ContainsAny(req.IP, "\x00\r\n") {
		return fmt.Errorf("tracker: IP override contains a control character")
	}
	return nil
}

func parseTrackerURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("tracker: parse URL %q: %w", raw, err)
	}
	if u.Scheme == "" || u.Host == "" || u.Hostname() == "" || u.Opaque != "" {
		return nil, fmt.Errorf("tracker: invalid tracker URL %q", raw)
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("tracker: tracker URL must not contain a fragment")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	port := u.Port()
	if port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return nil, fmt.Errorf("tracker: invalid tracker URL port %q", port)
		}
	}
	switch u.Scheme {
	case "http", "https":
	case "udp":
		if port == "" {
			return nil, fmt.Errorf("tracker: UDP tracker URL has no port")
		}
	default:
		return nil, fmt.Errorf("tracker: unsupported URL scheme %q", u.Scheme)
	}
	return u, nil
}

func (c *Client) httpAnnounce(ctx context.Context, u *url.URL, announce AnnounceRequest) (*AnnounceResponse, error) {
	requestURL := *u
	query := requestURL.Query()
	for _, key := range []string{"info_hash", "peer_id", "port", "uploaded", "downloaded", "left", "compact", "numwant", "event", "key", "trackerid", "ip"} {
		query.Del(key)
	}
	query.Set("port", strconv.Itoa(int(announce.Port)))
	query.Set("uploaded", strconv.FormatInt(announce.Uploaded, 10))
	query.Set("downloaded", strconv.FormatInt(announce.Downloaded, 10))
	query.Set("left", strconv.FormatInt(announce.Left, 10))
	query.Set("compact", "1")
	query.Set("key", strconv.FormatUint(uint64(announce.Key), 10))
	if announce.NumWant >= 0 {
		query.Set("numwant", strconv.Itoa(announce.NumWant))
	}
	if announce.Event != EventNone {
		query.Set("event", string(announce.Event))
	}
	if announce.IP != "" {
		query.Set("ip", announce.IP)
	}
	requestURL.RawQuery = query.Encode()
	appendBinaryQuery(&requestURL, "info_hash", announce.InfoHash[:])
	appendBinaryQuery(&requestURL, "peer_id", announce.PeerID[:])
	if announce.TrackerID != "" {
		appendBinaryQuery(&requestURL, "trackerid", []byte(announce.TrackerID))
	}

	body, err := c.httpGet(ctx, &requestURL)
	if err != nil {
		return nil, fmt.Errorf("tracker: announce: %w", err)
	}
	response, err := parseAnnounceResponse(body, c.responseLimit())
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (c *Client) httpScrape(ctx context.Context, announceURL *url.URL, hashes []metainfo.Hash) (*ScrapeResponse, error) {
	scrapeURL, err := makeScrapeURL(announceURL)
	if err != nil {
		return nil, err
	}
	query := scrapeURL.Query()
	query.Del("info_hash")
	scrapeURL.RawQuery = query.Encode()
	for i := range hashes {
		appendBinaryQuery(scrapeURL, "info_hash", hashes[i][:])
	}
	body, err := c.httpGet(ctx, scrapeURL)
	if err != nil {
		return nil, fmt.Errorf("tracker: scrape: %w", err)
	}
	return parseScrapeResponse(body, hashes, c.responseLimit())
}

func (c *Client) httpGet(ctx context.Context, u *url.URL) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build GET request: %w", err)
	}
	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP status %s", response.Status)
	}
	limit := c.responseLimit()
	if limit <= 0 || limit == math.MaxInt64 {
		return nil, fmt.Errorf("invalid response body limit %d", limit)
	}
	if response.ContentLength > limit {
		return nil, fmt.Errorf("response body exceeds %d-byte limit", limit)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response body exceeds %d-byte limit", limit)
	}
	return body, nil
}

func (c *Client) responseLimit() int64 {
	if c != nil && c.MaxResponseBody != 0 {
		return c.MaxResponseBody
	}
	return DefaultMaxResponseBody
}

func appendBinaryQuery(u *url.URL, key string, value []byte) {
	if u.RawQuery != "" {
		u.RawQuery += "&"
	}
	u.RawQuery += url.QueryEscape(key) + "=" + escapeBinary(value)
}

func escapeBinary(value []byte) string {
	const hex = "0123456789ABCDEF"
	escaped := make([]byte, len(value)*3)
	for i, b := range value {
		escaped[i*3] = '%'
		escaped[i*3+1] = hex[b>>4]
		escaped[i*3+2] = hex[b&15]
	}
	return string(escaped)
}

func makeScrapeURL(announceURL *url.URL) (*url.URL, error) {
	u := *announceURL
	slash := strings.LastIndexByte(u.Path, '/')
	segment := u.Path[slash+1:]
	if strings.Contains(segment, "scrape") {
		return &u, nil
	}
	index := strings.Index(segment, "announce")
	if index < 0 {
		return nil, fmt.Errorf("tracker: HTTP announce URL has no scrape convention")
	}
	segment = segment[:index] + "scrape" + segment[index+len("announce"):]
	u.Path = u.Path[:slash+1] + segment
	u.RawPath = ""
	return &u, nil
}

func parseAnnounceResponse(data []byte, limit int64) (*AnnounceResponse, error) {
	dict, err := decodeDictionary(data, limit)
	if err != nil {
		return nil, fmt.Errorf("tracker: decode announce response: %w", err)
	}
	if failure, ok := dict["failure reason"]; ok {
		message, ok := failure.(string)
		if !ok {
			return nil, fmt.Errorf("tracker: 'failure reason' is not a string")
		}
		return nil, fmt.Errorf("tracker failure: %s", message)
	}

	interval, err := requiredPositiveInt(dict, "interval")
	if err != nil {
		return nil, err
	}
	if int64(interval) > math.MaxInt64/int64(time.Second) {
		return nil, fmt.Errorf("tracker: 'interval' is too large")
	}
	rawPeers, ok := dict["peers"]
	if !ok {
		return nil, fmt.Errorf("tracker: response is missing 'peers'")
	}
	response := &AnnounceResponse{Interval: interval}
	switch peers := rawPeers.(type) {
	case string:
		response.Peers, err = parseCompactPeers(peers, 4)
	case []any:
		response.Peers, err = parseNoncompactPeers(peers)
	default:
		err = fmt.Errorf("tracker: 'peers' is neither a string nor a list")
	}
	if err != nil {
		return nil, err
	}
	if raw, ok := dict["peers6"]; ok {
		peers6, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("tracker: 'peers6' is not a string")
		}
		parsed, err := parseCompactPeers(peers6, 16)
		if err != nil {
			return nil, fmt.Errorf("tracker: peers6: %w", err)
		}
		response.Peers = append(response.Peers, parsed...)
	}
	if raw, ok := dict["min interval"]; ok {
		response.MinInterval, err = positiveInt(raw, "'min interval'")
		if err != nil {
			return nil, err
		}
		if int64(response.MinInterval) > math.MaxInt64/int64(time.Second) {
			return nil, fmt.Errorf("tracker: 'min interval' is too large")
		}
	}
	if raw, ok := dict["complete"]; ok {
		response.Complete, err = nonnegativeInt(raw, "'complete'")
		if err != nil {
			return nil, err
		}
	}
	if raw, ok := dict["incomplete"]; ok {
		response.Incomplete, err = nonnegativeInt(raw, "'incomplete'")
		if err != nil {
			return nil, err
		}
	}
	if raw, ok := dict["tracker id"]; ok {
		response.TrackerID, ok = raw.(string)
		if !ok {
			return nil, fmt.Errorf("tracker: 'tracker id' is not a string")
		}
	}
	if raw, ok := dict["warning message"]; ok {
		response.Warning, ok = raw.(string)
		if !ok {
			return nil, fmt.Errorf("tracker: 'warning message' is not a string")
		}
	}
	return response, nil
}

func parseCompactPeers(value string, addressBytes int) ([]Peer, error) {
	stride := addressBytes + 2
	if len(value)%stride != 0 {
		return nil, fmt.Errorf("tracker: compact peer length %d is not a multiple of %d", len(value), stride)
	}
	peers := make([]Peer, 0, len(value)/stride)
	for offset := 0; offset < len(value); offset += stride {
		port := binary.BigEndian.Uint16([]byte(value[offset+addressBytes : offset+stride]))
		if port == 0 {
			return nil, fmt.Errorf("tracker: compact peer %d has port 0", offset/stride)
		}
		ip := make(net.IP, addressBytes)
		copy(ip, value[offset:offset+addressBytes])
		peers = append(peers, Peer{IP: ip, Port: port})
	}
	return peers, nil
}

func parseNoncompactPeers(values []any) ([]Peer, error) {
	peers := make([]Peer, len(values))
	for i, raw := range values {
		dict, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("tracker: peer %d is not a dictionary", i)
		}
		host, ok := dict["ip"].(string)
		if !ok || host == "" || strings.ContainsRune(host, '\x00') {
			return nil, fmt.Errorf("tracker: peer %d has an invalid 'ip'", i)
		}
		port, err := positiveInt(dict["port"], fmt.Sprintf("peer %d 'port'", i))
		if err != nil || port > math.MaxUint16 {
			return nil, fmt.Errorf("tracker: peer %d has an invalid 'port'", i)
		}
		peerID, ok := dict["peer id"].(string)
		if !ok || len(peerID) != 20 {
			return nil, fmt.Errorf("tracker: peer %d has an invalid 'peer id'", i)
		}
		peer := Peer{Host: host, Port: uint16(port)}
		if ip := net.ParseIP(host); ip != nil {
			peer.IP = append(net.IP(nil), ip...)
		}
		copy(peer.PeerID[:], peerID)
		peers[i] = peer
	}
	return peers, nil
}

func parseScrapeResponse(data []byte, hashes []metainfo.Hash, limit int64) (*ScrapeResponse, error) {
	dict, err := decodeDictionary(data, limit)
	if err != nil {
		return nil, fmt.Errorf("tracker: decode scrape response: %w", err)
	}
	if failure, ok := dict["failure reason"]; ok {
		message, ok := failure.(string)
		if !ok {
			return nil, fmt.Errorf("tracker: 'failure reason' is not a string")
		}
		return nil, fmt.Errorf("tracker failure: %s", message)
	}
	files, ok := dict["files"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("tracker: scrape response has no 'files' dictionary")
	}
	response := &ScrapeResponse{Files: make(map[metainfo.Hash]ScrapeStats, len(hashes))}
	for _, hash := range hashes {
		raw, ok := files[string(hash[:])]
		if !ok {
			return nil, fmt.Errorf("tracker: scrape response is missing info hash %s", hash)
		}
		stats, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("tracker: scrape entry for %s is not a dictionary", hash)
		}
		complete, err := requiredNonnegativeInt(stats, "complete")
		if err != nil {
			return nil, fmt.Errorf("tracker: scrape entry for %s: %w", hash, err)
		}
		downloaded, err := requiredNonnegativeInt(stats, "downloaded")
		if err != nil {
			return nil, fmt.Errorf("tracker: scrape entry for %s: %w", hash, err)
		}
		incomplete, err := requiredNonnegativeInt(stats, "incomplete")
		if err != nil {
			return nil, fmt.Errorf("tracker: scrape entry for %s: %w", hash, err)
		}
		response.Files[hash] = ScrapeStats{Complete: complete, Downloaded: downloaded, Incomplete: incomplete}
	}
	return response, nil
}

func decodeDictionary(data []byte, limit int64) (map[string]any, error) {
	decoder := bencode.NewDecoder(bytes.NewReader(data))
	decoder.MaxBytes = limit
	raw, err := decoder.Decode()
	if err != nil {
		return nil, err
	}
	dict, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("response is not a dictionary")
	}
	return dict, nil
}

func requiredPositiveInt(dict map[string]any, key string) (int, error) {
	raw, ok := dict[key]
	if !ok {
		return 0, fmt.Errorf("tracker: response is missing %q", key)
	}
	return positiveInt(raw, fmt.Sprintf("%q", key))
}

func requiredNonnegativeInt(dict map[string]any, key string) (int, error) {
	raw, ok := dict[key]
	if !ok {
		return 0, fmt.Errorf("missing %q", key)
	}
	return nonnegativeInt(raw, fmt.Sprintf("%q", key))
}

func positiveInt(raw any, label string) (int, error) {
	value, err := nonnegativeInt(raw, label)
	if err != nil {
		return 0, err
	}
	if value == 0 {
		return 0, fmt.Errorf("tracker: %s must be positive", label)
	}
	return value, nil
}

func nonnegativeInt(raw any, label string) (int, error) {
	value, ok := raw.(int64)
	if !ok {
		return 0, fmt.Errorf("tracker: %s is not an integer", label)
	}
	if value < 0 || uint64(value) > uint64(maxInt()) {
		return 0, fmt.Errorf("tracker: %s is outside the nonnegative int range", label)
	}
	return int(value), nil
}

func randomUint32(nonzero bool) (uint32, error) {
	var data [4]byte
	for {
		if _, err := io.ReadFull(cryptorand.Reader, data[:]); err != nil {
			return 0, err
		}
		value := binary.BigEndian.Uint32(data[:])
		if !nonzero || value != 0 {
			return value, nil
		}
	}
}

func maxInt() int {
	return int(^uint(0) >> 1)
}
