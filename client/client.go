// Package client coordinates one BitTorrent download over the metainfo,
// tracker, peer, piece, and storage packages.
package client

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/natalie-o-perret/go-torrent/dht"
	"github.com/natalie-o-perret/go-torrent/metainfo"
	"github.com/natalie-o-perret/go-torrent/peer"
	"github.com/natalie-o-perret/go-torrent/storage"
	"github.com/natalie-o-perret/go-torrent/tracker"
	"github.com/natalie-o-perret/go-torrent/webseed"
)

const (
	defaultMaxPeers           = 50
	defaultMaxCandidates      = 500
	defaultMaxActivePieces    = 16
	defaultPipeline           = 8
	defaultEndgameBlocks      = 16
	defaultScheduleInterval   = 100 * time.Millisecond
	defaultDialTimeout        = 10 * time.Second
	defaultHandshakeTimeout   = 10 * time.Second
	defaultRequestTimeout     = 30 * time.Second
	defaultWriteTimeout       = 30 * time.Second
	defaultRetryInterval      = 5 * time.Second
	defaultTrackerStop        = 5 * time.Second
	defaultDHTReannounce      = 15 * time.Minute
	uploadReviewInterval      = 10 * time.Second
	optimisticUnchokePeriod   = 30 * time.Second
	pexInterval               = time.Minute
	regularUploadSlots        = 4
	maxEndgameCopies          = 2
	defaultTrackerHTTPTimeout = 30 * time.Second
	defaultWebSeedHTTPTimeout = 30 * time.Second
	maxInboundRequests        = 64
)

var (
	// ErrClosed reports an operation on a closed client.
	ErrClosed = errors.New("client: closed")
	// ErrAlreadyRunning reports a second call to Run.
	ErrAlreadyRunning = errors.New("client: Run called more than once")
	// ErrCandidateLimit reports a full bounded candidate queue.
	ErrCandidateLimit = errors.New("client: peer candidate limit reached")
	// ErrPrivatePeerSource reports peer discovery forbidden by BEP 27.
	ErrPrivatePeerSource = errors.New("client: private torrent peer must come from its tracker")
	// ErrSelfConnection reports a candidate known to be this client.
	ErrSelfConnection = errors.New("client: peer candidate is this client")
)

// CandidateSource records how a peer endpoint was discovered.
type CandidateSource uint8

const (
	// SourceDirect is an endpoint supplied directly by the caller.
	SourceDirect CandidateSource = iota
	// SourceTracker is an endpoint returned by the tracker named in Tracker.
	SourceTracker
	// SourcePEX is an endpoint supplied by the peer named in Introducer.
	SourcePEX
	// SourceDHT is an endpoint returned by a DHT lookup.
	SourceDHT
	// SourceIncoming is reserved for accepted connections.
	SourceIncoming
)

// Transport identifies a peer transport.
type Transport uint8

const (
	// TransportAuto tries every configured transport, preferring uTP.
	TransportAuto Transport = iota
	// TransportTCP selects a BitTorrent peer-wire TCP connection.
	TransportTCP
	// TransportUTP selects a BitTorrent peer-wire uTP connection.
	TransportUTP
)

// UTPTransport is the listener and dialer required for uTP peer connections.
type UTPTransport interface {
	net.Listener
	DialContext(context.Context, string, string) (net.Conn, error)
}

// Candidate is one bounded peer-discovery result. A zero Protocol selects all
// swarm versions in the metainfo, preferring v2 for an outgoing connection.
type Candidate struct {
	Address    string
	Tracker    string
	PeerID     [20]byte
	Introducer [20]byte
	Protocol   peer.ProtocolVersion
	Source     CandidateSource
	Transport  Transport
}

// Config configures one torrent client. Meta and Storage are required. A
// nonzero PeerID is used as-is; otherwise New generates one for this Client's
// lifetime. WebSeedClient is optional. The default has a bounded timeout.
// Listener and UTP ownership transfer to Client. DHTNode remains owned by the
// caller and must remain open while Run is active.
type Config struct {
	Meta          *metainfo.MetaInfo
	Storage       *storage.Storage
	TrackerClient *tracker.Client
	WebSeedClient *http.Client
	DHTNode       *dht.Node
	PeerID        [20]byte
	Port          uint16
	Listener      net.Listener
	UTP           UTPTransport

	DialContext func(context.Context, string, string) (net.Conn, error)
	Now         func() time.Time
	After       func(time.Duration) <-chan time.Time
	RandIntN    func(int) int

	MaxPeers        int
	MaxCandidates   int
	MaxActivePieces int
	Pipeline        int
	EndgameBlocks   int

	ScheduleInterval      time.Duration
	DialTimeout           time.Duration
	HandshakeTimeout      time.Duration
	RequestTimeout        time.Duration
	WriteTimeout          time.Duration
	RetryInterval         time.Duration
	TrackerStopTimeout    time.Duration
	DHTReannounceInterval time.Duration
}

// SwarmProgressSnapshot reports counters for one wire-compatible swarm.
type SwarmProgressSnapshot struct {
	TotalBytes      int64
	LeftBytes       int64
	DownloadedBytes int64
	UploadedBytes   int64
}

// ProgressSnapshot is a consistent copy of download and connection progress.
type ProgressSnapshot struct {
	PeerID          [20]byte
	StartedAt       time.Time
	VerifiedPieces  []bool
	PieceCount      int
	CompletedPieces int
	TotalBytes      int64
	CompletedBytes  int64
	DownloadedBytes int64
	UploadedBytes   int64
	ConnectedPeers  int
	Candidates      int
	Swarms          map[peer.ProtocolVersion]SwarmProgressSnapshot
}

// CompletionSnapshot reports whether all pieces are verified and whether each
// tracker swarm received its required completed event. A resumed seed does not
// send a completed event, so its map entry remains false.
type CompletionSnapshot struct {
	Complete            bool
	Seeding             bool
	CompletedAt         time.Time
	CompletionAnnounced map[peer.ProtocolVersion]bool
}

type lifecycle uint8

const (
	lifecycleNew lifecycle = iota
	lifecycleRunning
	lifecycleClosed
)

// Client owns all tracker and peer sessions for one metainfo file.
type Client struct {
	meta          *metainfo.MetaInfo
	store         *storage.Storage
	trackerClient *tracker.Client
	dhtNode       *dht.Node
	metadata      *peer.MetadataSource
	hashSource    *v2HashSource
	webseeds      []*webseed.Downloader
	layouts       map[peer.ProtocolVersion]*wireLayout
	primary       peer.ProtocolVersion
	peerID        [20]byte
	port          uint16
	listener      net.Listener
	utp           UTPTransport
	dialContext   func(context.Context, string, string) (net.Conn, error)
	now           func() time.Time
	after         func(time.Duration) <-chan time.Time
	randIntN      func(int) int

	maxPeers              int
	maxCandidates         int
	maxActivePieces       int
	pipeline              int
	endgameBlocks         int
	scheduleInterval      time.Duration
	dialTimeout           time.Duration
	handshakeTimeout      time.Duration
	requestTimeout        time.Duration
	writeTimeout          time.Duration
	retryInterval         time.Duration
	trackerStopTimeout    time.Duration
	dhtReannounceInterval time.Duration

	privateTrackers map[string]struct{}
	events          chan any
	commands        chan addCommand
	completed       chan struct{}
	done            chan struct{}
	completionOnce  sync.Once
	doneOnce        sync.Once

	lifecycleMu sync.Mutex
	lifecycle   lifecycle
	cancel      context.CancelCauseFunc
	pending     map[string]*candidateState

	localMu          sync.RWMutex
	verified         []bool
	downloaded       [3]int64
	uploaded         [3]int64
	trackerCompleted [3]bool
	startedAt        time.Time
	completedAt      time.Time
	connectedPeers   int
	candidateCount   int
	storageMu        sync.Mutex
}

// New validates config without touching the filesystem or network.
func New(config Config) (*Client, error) {
	if config.Meta == nil {
		return nil, fmt.Errorf("client: nil metainfo")
	}
	if config.Storage == nil {
		return nil, fmt.Errorf("client: nil storage")
	}
	layouts, primary, pieceCount, err := buildWireLayouts(config.Meta, config.Storage.Layout())
	if err != nil {
		return nil, err
	}
	metadata, err := peer.NewMetadataSource(config.Meta, 0)
	if err != nil {
		return nil, fmt.Errorf("client: metadata source: %w", err)
	}
	var hashSource *v2HashSource
	if config.Meta.Info.HasV2() {
		hashSource, err = newV2HashSource(config.Meta, config.Storage)
		if err != nil {
			return nil, err
		}
	}
	webSeedClient := config.WebSeedClient
	if len(config.Meta.URLList) != 0 && webSeedClient == nil {
		webSeedClient = &http.Client{Timeout: defaultWebSeedHTTPTimeout}
	}
	webseeds := make([]*webseed.Downloader, 0, len(config.Meta.URLList))
	for index, rawURL := range config.Meta.URLList {
		source, err := webseed.NewSource(webSeedClient, rawURL, config.Meta)
		if err != nil {
			return nil, fmt.Errorf("client: web seed URL %d %q: %w", index, rawURL, err)
		}
		downloader, err := webseed.NewDownloader(source)
		if err != nil {
			return nil, fmt.Errorf("client: web seed URL %d %q: %w", index, rawURL, err)
		}
		webseeds = append(webseeds, downloader)
	}
	if config.PeerID == ([20]byte{}) {
		for config.PeerID == ([20]byte{}) {
			if _, err := io.ReadFull(cryptorand.Reader, config.PeerID[:]); err != nil {
				return nil, fmt.Errorf("client: generate peer ID: %w", err)
			}
		}
	}

	if config.MaxPeers == 0 {
		config.MaxPeers = defaultMaxPeers
	}
	if config.MaxCandidates == 0 {
		config.MaxCandidates = defaultMaxCandidates
	}
	if config.MaxActivePieces == 0 {
		config.MaxActivePieces = defaultMaxActivePieces
	}
	if config.Pipeline == 0 {
		config.Pipeline = defaultPipeline
	}
	if config.EndgameBlocks == 0 {
		config.EndgameBlocks = defaultEndgameBlocks
	}
	if config.MaxPeers < 1 || config.MaxCandidates < 1 || config.MaxActivePieces < 1 || config.Pipeline < 1 || config.EndgameBlocks < 1 {
		return nil, fmt.Errorf("client: peer, candidate, picker, pipeline, and endgame limits must be positive")
	}

	if config.ScheduleInterval == 0 {
		config.ScheduleInterval = defaultScheduleInterval
	}
	if config.DialTimeout == 0 {
		config.DialTimeout = defaultDialTimeout
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = defaultHandshakeTimeout
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = defaultRequestTimeout
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = defaultWriteTimeout
	}
	if config.RetryInterval == 0 {
		config.RetryInterval = defaultRetryInterval
	}
	if config.TrackerStopTimeout == 0 {
		config.TrackerStopTimeout = defaultTrackerStop
	}
	if config.DHTReannounceInterval == 0 {
		config.DHTReannounceInterval = defaultDHTReannounce
	}
	if config.ScheduleInterval < 0 || config.DialTimeout < 0 || config.HandshakeTimeout < 0 || config.RequestTimeout < 0 || config.WriteTimeout < 0 || config.RetryInterval < 0 || config.TrackerStopTimeout < 0 || config.DHTReannounceInterval < 0 {
		return nil, fmt.Errorf("client: durations must be positive")
	}

	if config.DialContext == nil {
		config.DialContext = (&net.Dialer{}).DialContext
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.After == nil {
		config.After = time.After
	}
	if config.RandIntN == nil {
		config.RandIntN = rand.IntN
	}
	if config.Port == 0 {
		tcpPort, utpPort := uint16(0), uint16(0)
		if config.Listener != nil {
			tcpPort = addressPort(config.Listener.Addr())
		}
		if config.UTP != nil {
			utpPort = addressPort(config.UTP.Addr())
		}
		if tcpPort != 0 && utpPort != 0 && tcpPort != utpPort {
			return nil, fmt.Errorf("client: TCP and uTP listeners use different ports")
		}
		config.Port = max(tcpPort, utpPort)
	}
	if config.Port == 0 && (config.Listener != nil || config.UTP != nil) {
		return nil, fmt.Errorf("client: peer listener has no usable port")
	}
	trackers := config.Meta.Trackers()
	if len(trackers) != 0 && config.Port == 0 {
		return nil, fmt.Errorf("client: tracker announces require a nonzero port")
	}
	if config.TrackerClient == nil && len(trackers) != 0 {
		config.TrackerClient = tracker.NewClient(&http.Client{Timeout: defaultTrackerHTTPTimeout})
	}

	privateTrackers := make(map[string]struct{}, len(trackers))
	for _, trackerURL := range trackers {
		privateTrackers[trackerURL] = struct{}{}
	}
	client := &Client{
		meta:                  config.Meta,
		store:                 config.Storage,
		trackerClient:         config.TrackerClient,
		dhtNode:               config.DHTNode,
		metadata:              metadata,
		hashSource:            hashSource,
		webseeds:              webseeds,
		layouts:               layouts,
		primary:               primary,
		peerID:                config.PeerID,
		port:                  config.Port,
		listener:              config.Listener,
		utp:                   config.UTP,
		dialContext:           config.DialContext,
		now:                   config.Now,
		after:                 config.After,
		randIntN:              config.RandIntN,
		maxPeers:              config.MaxPeers,
		maxCandidates:         config.MaxCandidates,
		maxActivePieces:       config.MaxActivePieces,
		pipeline:              config.Pipeline,
		endgameBlocks:         config.EndgameBlocks,
		scheduleInterval:      config.ScheduleInterval,
		dialTimeout:           config.DialTimeout,
		handshakeTimeout:      config.HandshakeTimeout,
		requestTimeout:        config.RequestTimeout,
		writeTimeout:          config.WriteTimeout,
		retryInterval:         config.RetryInterval,
		trackerStopTimeout:    config.TrackerStopTimeout,
		dhtReannounceInterval: config.DHTReannounceInterval,
		privateTrackers:       privateTrackers,
		events:                make(chan any, 4096),
		commands:              make(chan addCommand),
		completed:             make(chan struct{}),
		done:                  make(chan struct{}),
		pending:               make(map[string]*candidateState),
		verified:              make([]bool, pieceCount),
	}
	return client, nil
}

// PeerID returns the stable ID used by this Client.
func (client *Client) PeerID() [20]byte {
	if client == nil {
		return [20]byte{}
	}
	return client.peerID
}

// Done closes after Run has released its listener, tracker sessions, and peer
// sessions. It also closes when Close is called before Run.
func (client *Client) Done() <-chan struct{} {
	if client == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return client.done
}

// Completed closes once every piece has passed storage verification. Run keeps
// seeding after this channel closes.
func (client *Client) Completed() <-chan struct{} {
	if client == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return client.completed
}

// Progress returns a consistent progress snapshot.
func (client *Client) Progress() ProgressSnapshot {
	if client == nil {
		return ProgressSnapshot{}
	}
	client.localMu.RLock()
	defer client.localMu.RUnlock()
	snapshot := ProgressSnapshot{
		PeerID:         client.peerID,
		StartedAt:      client.startedAt,
		VerifiedPieces: append([]bool(nil), client.verified...),
		PieceCount:     len(client.verified),
		ConnectedPeers: client.connectedPeers,
		Candidates:     client.candidateCount,
		Swarms:         make(map[peer.ProtocolVersion]SwarmProgressSnapshot, len(client.layouts)),
	}
	for _, verified := range client.verified {
		if verified {
			snapshot.CompletedPieces++
		}
	}
	for version, layout := range client.layouts {
		left := layout.total
		for index, verified := range client.verified {
			if verified {
				left -= int64(layout.pieces[index].length)
			}
		}
		swarm := SwarmProgressSnapshot{
			TotalBytes:      layout.total,
			LeftBytes:       left,
			DownloadedBytes: client.downloaded[version],
			UploadedBytes:   client.uploaded[version],
		}
		snapshot.Swarms[version] = swarm
		snapshot.DownloadedBytes += swarm.DownloadedBytes
		snapshot.UploadedBytes += swarm.UploadedBytes
		if version == client.primary {
			snapshot.TotalBytes = swarm.TotalBytes
			snapshot.CompletedBytes = swarm.TotalBytes - swarm.LeftBytes
		}
	}
	return snapshot
}

// Completion returns a consistent completion and seeding snapshot.
func (client *Client) Completion() CompletionSnapshot {
	if client == nil {
		return CompletionSnapshot{}
	}
	client.lifecycleMu.Lock()
	running := client.lifecycle == lifecycleRunning
	client.lifecycleMu.Unlock()
	client.localMu.RLock()
	defer client.localMu.RUnlock()
	complete := allVerified(client.verified)
	snapshot := CompletionSnapshot{
		Complete:            complete,
		Seeding:             complete && running,
		CompletedAt:         client.completedAt,
		CompletionAnnounced: make(map[peer.ProtocolVersion]bool, len(client.layouts)),
	}
	for version := range client.layouts {
		snapshot.CompletionAnnounced[version] = client.trackerCompleted[version]
	}
	return snapshot
}

func (client *Client) validateCandidate(candidate Candidate) (Candidate, error) {
	if candidate.Transport > TransportUTP {
		return Candidate{}, fmt.Errorf("client: unsupported peer transport %d", candidate.Transport)
	}
	if candidate.Transport == TransportUTP && client.utp == nil {
		return Candidate{}, fmt.Errorf("client: uTP peer transport is not configured")
	}
	switch candidate.Source {
	case SourceDirect, SourceTracker, SourcePEX, SourceDHT:
	case SourceIncoming:
		return Candidate{}, fmt.Errorf("client: incoming provenance is reserved for accepted connections")
	default:
		return Candidate{}, fmt.Errorf("client: invalid candidate source %d", candidate.Source)
	}
	if client.meta.Info.Private && candidate.Source != SourceTracker {
		return Candidate{}, ErrPrivatePeerSource
	}
	if candidate.Source == SourceTracker {
		if candidate.Tracker == "" {
			return Candidate{}, fmt.Errorf("client: tracker candidate has no tracker provenance")
		}
		if client.meta.Info.Private {
			if _, ok := client.privateTrackers[candidate.Tracker]; !ok {
				return Candidate{}, ErrPrivatePeerSource
			}
		}
	}
	if candidate.Protocol != 0 {
		if _, ok := client.layouts[candidate.Protocol]; !ok {
			return Candidate{}, fmt.Errorf("client: protocol version %d is absent from metainfo", candidate.Protocol)
		}
	}
	if candidate.PeerID != ([20]byte{}) && candidate.PeerID == client.peerID {
		return Candidate{}, ErrSelfConnection
	}
	address, err := canonicalAddress(candidate.Address)
	if err != nil {
		return Candidate{}, err
	}
	candidate.Address = address
	if client.isListenerAddress(address, candidate.Transport) {
		return Candidate{}, ErrSelfConnection
	}
	return candidate, nil
}

func (client *Client) isListenerAddress(address string, transport Transport) bool {
	if transport != TransportUTP && listenerHasAddress(client.listener, address) {
		return true
	}
	return transport != TransportTCP && listenerHasAddress(client.utp, address)
}

func (client *Client) closeListeners() {
	if client.listener != nil {
		_ = client.listener.Close()
	}
	if client.utp != nil {
		_ = client.utp.Close()
	}
}

func listenerHasAddress(listener net.Listener, address string) bool {
	if listener == nil {
		return false
	}
	local, err := canonicalAddress(listener.Addr().String())
	if err != nil {
		return false
	}
	if local == address {
		return true
	}
	localHost, localPort, _ := net.SplitHostPort(local)
	host, port, _ := net.SplitHostPort(address)
	if localPort != port {
		return false
	}
	localIP, localErr := netip.ParseAddr(localHost)
	peerIP, peerErr := netip.ParseAddr(host)
	return localErr == nil && peerErr == nil && localIP.IsUnspecified() && (peerIP.IsLoopback() || peerIP.IsUnspecified())
}

func canonicalAddress(raw string) (string, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil || host == "" {
		return "", fmt.Errorf("client: invalid peer address %q", raw)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return "", fmt.Errorf("client: invalid peer address %q", raw)
	}
	if address, err := netip.ParseAddr(host); err == nil {
		host = address.Unmap().String()
	} else {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if host == "" || strings.ContainsAny(host, "\x00\r\n") {
			return "", fmt.Errorf("client: invalid peer address %q", raw)
		}
	}
	return net.JoinHostPort(host, strconv.FormatUint(port, 10)), nil
}

func addressPort(address net.Addr) uint16 {
	if address == nil {
		return 0
	}
	_, portText, err := net.SplitHostPort(address.String())
	if err != nil {
		return 0
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(port)
}

func allVerified(pieces []bool) bool {
	for _, verified := range pieces {
		if !verified {
			return false
		}
	}
	return true
}
