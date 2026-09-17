package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/natalie-o-perret/go-torrent/metainfo"
)

var (
	// ErrSessionNotReady reports an operation attempted before the initial
	// handshake and messages completed.
	ErrSessionNotReady = errors.New("peer: session is not ready")
	// ErrSessionClosed reports an operation on a closed session.
	ErrSessionClosed = errors.New("peer: session is closed")
	// ErrProtocol reports a peer-wire protocol violation.
	ErrProtocol = errors.New("peer: protocol violation")
	// ErrRequestPipelineFull reports that the configured request bound was hit.
	ErrRequestPipelineFull = errors.New("peer: request pipeline is full")
	// ErrRequestNotFound reports a Cancel for a request not outstanding here.
	ErrRequestNotFound = errors.New("peer: request is not outstanding")
	// ErrRequestRecentlyExpired prevents an ambiguous same-peer retry while a
	// late response can still arrive.
	ErrRequestRecentlyExpired = errors.New("peer: request can still receive a late response")
	// ErrPeerChoking reports a request disallowed by the remote choke state.
	ErrPeerChoking = errors.New("peer: remote peer is choking")
	// ErrPieceUnavailable reports a request for a piece the remote has not
	// advertised or the local peer already has.
	ErrPieceUnavailable = errors.New("peer: piece is unavailable")
	// ErrPEXDisabled reports PEX use on a private torrent.
	ErrPEXDisabled = errors.New("peer: PEX is disabled for private torrents")
)

// ProtocolVersion is the info-hash version selected by the handshake.
type ProtocolVersion uint8

const (
	// ProtocolV1 selected the SHA-1 info hash.
	ProtocolV1 ProtocolVersion = 1
	// ProtocolV2 selected the truncated SHA-256 info hash.
	ProtocolV2 ProtocolVersion = 2
)

// BlockResult is an exact response to an outgoing block request.
type BlockResult struct {
	Request   BlockRequest
	Data      []byte
	Rejected  bool
	Cancelled bool
	Late      bool
}

// SessionCallbacks contains typed protocol callbacks. Callbacks may run
// concurrently and never run with Session's internal locks held.
type SessionCallbacks struct {
	OnBlock          func(BlockResult)
	OnLateResponse   func(BlockResult)
	OnRequestTimeout func(BlockRequest)
	OnUploadRequest  func(context.Context, BlockRequest) ([]byte, error)
	// OnUploadComplete runs after the complete Piece frame is written.
	OnUploadComplete     func(BlockRequest)
	OnUploadCancel       func(BlockRequest)
	OnPort               func(uint16)
	OnExtensionHandshake func(ExtensionHandshake)
	OnMetadata           func(MetadataMessage)
	OnPEX                func(PEXMessage)
	OnHashRequest        func(HashRequest)
	OnHashes             func(Hashes)
	OnHashReject         func(HashRequest)
}

// SessionConfig configures one peer connection. Hashes identifies the torrent.
// Outgoing selects initiator handshake behavior. PieceLengths, when provided,
// supplies exact per-piece bounds and otherwise PieceLength applies to all.
// V1PieceLengths and V2PieceLengths override that shared layout after protocol
// negotiation. MetadataOnly permits a zero-piece metadata bootstrap session.
type SessionConfig struct {
	PeerID         [20]byte
	ExpectedPeerID *[20]byte
	Hashes         metainfo.Hashes
	PreferV2       bool
	Outgoing       bool
	Reserved       Reserved

	PieceCount     uint32
	PieceLength    uint32
	PieceLengths   []uint32
	V1PieceLengths []uint32
	V2PieceLengths []uint32
	LocalPieces    []bool
	MetadataOnly   bool
	Private        bool

	ExtensionHandshake ExtensionHandshake
	DHTPort            uint16
	AllowedFast        []uint32
	Codec              Codec
	Callbacks          SessionCallbacks

	MaxOutstandingRequests int
	MaxInboundRequests     int
	HandshakeTimeout       time.Duration
	RequestTimeout         time.Duration
	LateResponseWindow     time.Duration
	UploadTimeout          time.Duration
	WriteTimeout           time.Duration
	KeepAliveInterval      time.Duration
	ReadIdleTimeout        time.Duration
	PEXMinInterval         time.Duration
	InitialPEXLimits       PEXLimits
	MaxMetadataSize        uint32
}

// SessionSnapshot is a consistent copy of externally useful connection state.
type SessionSnapshot struct {
	Ready              bool
	Closed             bool
	Version            ProtocolVersion
	LocalReserved      Reserved
	RemoteReserved     Reserved
	RemotePeerID       [20]byte
	LocalChoking       bool
	RemoteChoking      bool
	LocalInterested    bool
	RemoteInterested   bool
	RemoteAvailability bool
	LocalPieces        []bool
	RemotePieces       []bool
	Outstanding        []BlockRequest
	Inbound            []BlockRequest
	IncomingExtensions map[string]uint8
	OutgoingExtensions map[string]uint8
	LastRead           time.Time
	LastWrite          time.Time
}

type outgoingRequest struct {
	deadline  time.Time
	cancelled bool
}

type lateRequest struct {
	expires   time.Time
	cancelled bool
}

type inboundRequest struct {
	ctx      context.Context
	cancel   context.CancelFunc
	deadline time.Time
}

// Session owns one net.Conn and the state required to enforce peer-wire
// connection semantics.
type Session struct {
	conn net.Conn

	codec              Codec
	peerID             [20]byte
	expectedPeerID     *[20]byte
	v1                 *metainfo.Hash
	v2                 *metainfo.HashV2
	preferV2           bool
	outgoing           bool
	localReserved      Reserved
	pieceLengths       []uint32
	v1PieceLengths     []uint32
	v2PieceLengths     []uint32
	metadataOnly       bool
	private            bool
	extensionHandshake ExtensionHandshake
	dhtPort            uint16
	allowedFast        map[uint32]struct{}
	callbacks          SessionCallbacks

	maxOutstanding   int
	maxInbound       int
	handshakeTimeout time.Duration
	requestTimeout   time.Duration
	lateWindow       time.Duration
	uploadTimeout    time.Duration
	writeTimeout     time.Duration
	keepAlive        time.Duration
	readIdle         time.Duration
	pexInterval      time.Duration
	initialPEXLimits PEXLimits
	maxMetadataSize  uint32

	writeMu sync.Mutex
	pexMu   sync.Mutex
	mu      sync.Mutex
	started bool
	ready   bool
	closed  bool
	err     error
	ctx     context.Context
	cancel  context.CancelCauseFunc

	version          ProtocolVersion
	remoteReserved   Reserved
	remotePeerID     [20]byte
	localChoking     bool
	remoteChoking    bool
	localInterested  bool
	remoteInterested bool
	availabilitySet  bool
	localPieces      []bool
	remotePieces     []bool
	remoteAllowed    map[uint32]struct{}
	outstanding      map[BlockRequest]outgoingRequest
	late             map[BlockRequest]lateRequest
	inbound          map[BlockRequest]*inboundRequest
	extensions       ExtensionMaps
	lastRead         time.Time
	lastWrite        time.Time
	lastPEXRead      time.Time
	lastPEXWrite     time.Time
	pexReceived      bool
	pexSent          bool

	readyCh   chan struct{}
	doneCh    chan struct{}
	readyOnce sync.Once
	closeOnce sync.Once
	wg        sync.WaitGroup
	uploadWG  sync.WaitGroup
}

// NewSession validates config and transfers ownership of conn to a Session.
func NewSession(conn net.Conn, config SessionConfig) (*Session, error) {
	if conn == nil {
		return nil, fmt.Errorf("peer: nil session connection")
	}
	if config.Hashes.V1 == nil && config.Hashes.V2 == nil {
		return nil, fmt.Errorf("peer: session requires at least one info hash")
	}
	if config.PreferV2 && config.Hashes.V2 == nil {
		return nil, fmt.Errorf("peer: PreferV2 requires a v2 info hash")
	}
	if uint64(config.PieceCount) > uint64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("peer: piece count %d overflows int", config.PieceCount)
	}
	if config.MetadataOnly {
		if config.PieceCount != 0 || len(config.LocalPieces) != 0 {
			return nil, fmt.Errorf("peer: MetadataOnly requires zero PieceCount and empty LocalPieces")
		}
		if config.PieceLength != 0 || len(config.PieceLengths) != 0 || len(config.V1PieceLengths) != 0 || len(config.V2PieceLengths) != 0 {
			return nil, fmt.Errorf("peer: MetadataOnly requires empty piece lengths")
		}
		if len(config.AllowedFast) != 0 {
			return nil, fmt.Errorf("peer: MetadataOnly does not support AllowedFast")
		}
	}
	if len(config.LocalPieces) != int(config.PieceCount) {
		return nil, fmt.Errorf("peer: LocalPieces has %d entries, want %d", len(config.LocalPieces), config.PieceCount)
	}
	var pieceLengths []uint32
	if len(config.PieceLengths) != 0 {
		var err error
		pieceLengths, err = validatePieceLengths("PieceLengths", config.PieceLengths, config.PieceCount)
		if err != nil {
			return nil, err
		}
	} else if config.PieceLength != 0 {
		pieceLengths = make([]uint32, config.PieceCount)
		for index := range pieceLengths {
			pieceLengths[index] = config.PieceLength
		}
	}
	var v1PieceLengths, v2PieceLengths []uint32
	if len(config.V1PieceLengths) != 0 {
		if config.Hashes.V1 == nil {
			return nil, fmt.Errorf("peer: V1PieceLengths requires a v1 info hash")
		}
		var err error
		v1PieceLengths, err = validatePieceLengths("V1PieceLengths", config.V1PieceLengths, config.PieceCount)
		if err != nil {
			return nil, err
		}
	}
	if len(config.V2PieceLengths) != 0 {
		if config.Hashes.V2 == nil {
			return nil, fmt.Errorf("peer: V2PieceLengths requires a v2 info hash")
		}
		var err error
		v2PieceLengths, err = validatePieceLengths("V2PieceLengths", config.V2PieceLengths, config.PieceCount)
		if err != nil {
			return nil, err
		}
	}
	if config.PieceCount != 0 && len(pieceLengths) == 0 && len(v1PieceLengths) == 0 && len(v2PieceLengths) == 0 {
		return nil, fmt.Errorf("peer: PieceLength must be positive")
	}
	if config.Hashes.V1 != nil && len(v1PieceLengths) == 0 {
		if config.PieceCount != 0 && len(pieceLengths) == 0 {
			return nil, fmt.Errorf("peer: V1PieceLengths is required without a shared piece layout")
		}
		v1PieceLengths = pieceLengths
	}
	if config.Hashes.V2 != nil && len(v2PieceLengths) == 0 {
		if config.PieceCount != 0 && len(pieceLengths) == 0 {
			return nil, fmt.Errorf("peer: V2PieceLengths is required without a shared piece layout")
		}
		v2PieceLengths = pieceLengths
	}
	if config.PreferV2 || config.Hashes.V1 == nil {
		pieceLengths = v2PieceLengths
	} else {
		pieceLengths = v1PieceLengths
	}

	if config.MaxOutstandingRequests == 0 {
		config.MaxOutstandingRequests = 64
	}
	if config.MaxInboundRequests == 0 {
		config.MaxInboundRequests = 64
	}
	if config.MaxOutstandingRequests < 1 || config.MaxInboundRequests < 1 {
		return nil, fmt.Errorf("peer: request limits must be positive")
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = 10 * time.Second
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 30 * time.Second
	}
	if config.LateResponseWindow == 0 {
		config.LateResponseWindow = config.RequestTimeout
	}
	if config.UploadTimeout == 0 {
		config.UploadTimeout = config.RequestTimeout
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 30 * time.Second
	}
	if config.KeepAliveInterval == 0 {
		config.KeepAliveInterval = 2 * time.Minute
	}
	if config.ReadIdleTimeout == 0 {
		config.ReadIdleTimeout = 3 * time.Minute
	}
	if config.PEXMinInterval == 0 {
		config.PEXMinInterval = time.Minute
	}
	if config.MaxMetadataSize == 0 {
		config.MaxMetadataSize = DefaultMaxMetadataSize
	}
	if config.RequestTimeout < 0 || config.LateResponseWindow < 0 || config.UploadTimeout < 0 || config.HandshakeTimeout < 0 || config.WriteTimeout < 0 || config.KeepAliveInterval < 0 || config.ReadIdleTimeout < 0 || config.PEXMinInterval < 0 {
		return nil, fmt.Errorf("peer: session durations must be nonnegative")
	}
	if config.InitialPEXLimits.MaxAdded == 0 && config.InitialPEXLimits.MaxDropped == 0 {
		config.InitialPEXLimits = PEXLimits{MaxAdded: 200, MaxDropped: 200}
	}
	initialPEXLimits, err := normalisePEXLimits(config.InitialPEXLimits)
	if err != nil {
		return nil, err
	}

	localReserved := config.Reserved
	localReserved.Set(CapabilityV2Upgrade, config.Hashes.V1 != nil && config.Hashes.V2 != nil)
	if config.ExtensionHandshake.Extensions != nil {
		localReserved.Set(CapabilityExtensionProtocol, true)
	}
	if config.DHTPort != 0 {
		localReserved.Set(CapabilityDHT, true)
	}
	if len(config.AllowedFast) != 0 {
		localReserved.Set(CapabilityFast, true)
	}
	if config.MetadataOnly {
		localReserved.Set(CapabilityFast, false)
	}
	if config.Private && config.ExtensionHandshake.Extensions[ExtensionPEX] != 0 {
		return nil, ErrPEXDisabled
	}

	allowedFast := make(map[uint32]struct{}, len(config.AllowedFast))
	for _, index := range config.AllowedFast {
		if err := ValidatePieceIndex(index, config.PieceCount); err != nil {
			return nil, fmt.Errorf("peer: AllowedFast: %w", err)
		}
		allowedFast[index] = struct{}{}
	}

	localHandshake := cloneExtensionHandshake(config.ExtensionHandshake)
	if _, err := localHandshake.Encode(); err != nil {
		return nil, fmt.Errorf("peer: local extension handshake: %w", err)
	}
	var extensionMaps ExtensionMaps
	if err := extensionMaps.ApplyLocal(localHandshake); err != nil {
		return nil, fmt.Errorf("peer: local extension IDs: %w", err)
	}

	session := &Session{
		conn:               conn,
		codec:              config.Codec,
		peerID:             config.PeerID,
		preferV2:           config.PreferV2,
		outgoing:           config.Outgoing,
		localReserved:      localReserved,
		pieceLengths:       pieceLengths,
		v1PieceLengths:     v1PieceLengths,
		v2PieceLengths:     v2PieceLengths,
		metadataOnly:       config.MetadataOnly,
		private:            config.Private,
		extensionHandshake: localHandshake,
		dhtPort:            config.DHTPort,
		allowedFast:        allowedFast,
		callbacks:          config.Callbacks,
		maxOutstanding:     config.MaxOutstandingRequests,
		maxInbound:         config.MaxInboundRequests,
		handshakeTimeout:   config.HandshakeTimeout,
		requestTimeout:     config.RequestTimeout,
		lateWindow:         config.LateResponseWindow,
		uploadTimeout:      config.UploadTimeout,
		writeTimeout:       config.WriteTimeout,
		keepAlive:          config.KeepAliveInterval,
		readIdle:           config.ReadIdleTimeout,
		pexInterval:        config.PEXMinInterval,
		initialPEXLimits:   initialPEXLimits,
		maxMetadataSize:    config.MaxMetadataSize,
		localChoking:       true,
		remoteChoking:      true,
		localPieces:        append([]bool(nil), config.LocalPieces...),
		remotePieces:       make([]bool, config.PieceCount),
		remoteAllowed:      make(map[uint32]struct{}),
		outstanding:        make(map[BlockRequest]outgoingRequest),
		late:               make(map[BlockRequest]lateRequest),
		inbound:            make(map[BlockRequest]*inboundRequest),
		extensions:         extensionMaps,
		readyCh:            make(chan struct{}),
		doneCh:             make(chan struct{}),
	}
	if config.ExpectedPeerID != nil {
		expected := *config.ExpectedPeerID
		session.expectedPeerID = &expected
	}
	if config.Hashes.V1 != nil {
		hash := *config.Hashes.V1
		session.v1 = &hash
	}
	if config.Hashes.V2 != nil {
		hash := *config.Hashes.V2
		session.v2 = &hash
	}
	return session, nil
}

// Ready is closed after the handshake and complete local initial message
// sequence have been written.
func (session *Session) Ready() <-chan struct{} {
	return session.readyCh
}

// Done is closed when the connection terminates.
func (session *Session) Done() <-chan struct{} {
	return session.doneCh
}

// Run performs the handshake, starts protocol processing, and blocks until the
// connection closes. Run may be called once.
func (session *Session) Run(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("peer: nil session context")
	}
	session.mu.Lock()
	if session.started {
		session.mu.Unlock()
		return fmt.Errorf("peer: session Run called more than once")
	}
	session.started = true
	runCtx, cancel := context.WithCancelCause(ctx)
	session.ctx = runCtx
	session.cancel = cancel
	session.mu.Unlock()

	go func() {
		<-runCtx.Done()
		session.terminate(context.Cause(runCtx))
	}()

	local, remote, version, err := session.performHandshake(runCtx)
	if err != nil {
		session.terminate(err)
		return session.Err()
	}
	now := time.Now()
	session.mu.Lock()
	session.localReserved = local.Reserved
	session.remoteReserved = remote.Reserved
	session.remotePeerID = remote.PeerID
	session.version = version
	if version == ProtocolV2 {
		session.pieceLengths = session.v2PieceLengths
	} else {
		session.pieceLengths = session.v1PieceLengths
	}
	session.lastRead = now
	session.lastWrite = now
	session.mu.Unlock()

	// Reserve the writer before the reader can generate a response. This keeps
	// the availability message first without deadlocking net.Pipe handshakes.
	session.writeMu.Lock()
	session.wg.Add(2)
	go session.readLoop()
	go session.maintenanceLoop()
	err = session.sendInitialMessagesLocked()
	if err != nil {
		session.terminate(err)
	} else {
		session.mu.Lock()
		if !session.closed {
			session.ready = true
			session.readyOnce.Do(func() { close(session.readyCh) })
		}
		session.mu.Unlock()
	}
	session.writeMu.Unlock()

	<-session.doneCh
	session.wg.Wait()
	session.uploadWG.Wait()
	return session.Err()
}

// Close closes the owned connection and terminates Run.
func (session *Session) Close() error {
	session.terminate(ErrSessionClosed)
	return nil
}

// Err returns the terminal error, or nil while the session is running.
func (session *Session) Err() error {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.err
}

// Snapshot returns a copy of connection state.
func (session *Session) Snapshot() SessionSnapshot {
	session.mu.Lock()
	defer session.mu.Unlock()
	snapshot := SessionSnapshot{
		Ready:              session.ready,
		Closed:             session.closed,
		Version:            session.version,
		LocalReserved:      session.localReserved,
		RemoteReserved:     session.remoteReserved,
		RemotePeerID:       session.remotePeerID,
		LocalChoking:       session.localChoking,
		RemoteChoking:      session.remoteChoking,
		LocalInterested:    session.localInterested,
		RemoteInterested:   session.remoteInterested,
		RemoteAvailability: session.availabilitySet,
		LocalPieces:        append([]bool(nil), session.localPieces...),
		RemotePieces:       append([]bool(nil), session.remotePieces...),
		IncomingExtensions: session.extensions.Incoming.Snapshot(),
		OutgoingExtensions: session.extensions.Outgoing.Snapshot(),
		LastRead:           session.lastRead,
		LastWrite:          session.lastWrite,
	}
	for request := range session.outstanding {
		snapshot.Outstanding = append(snapshot.Outstanding, request)
	}
	for request := range session.inbound {
		snapshot.Inbound = append(snapshot.Inbound, request)
	}
	sortBlockRequests(snapshot.Outstanding)
	sortBlockRequests(snapshot.Inbound)
	return snapshot
}

// Request queues and writes one exact outgoing block request.
func (session *Session) Request(request BlockRequest) error {
	if err := session.validateBlock(request); err != nil {
		return err
	}
	payload, _ := request.MarshalBinary()
	session.writeMu.Lock()
	session.mu.Lock()
	if err := session.readyErrorLocked(); err != nil {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return err
	}
	if !session.localInterested {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return fmt.Errorf("peer: request requires local interest")
	}
	if !session.availabilitySet || !session.remotePieces[request.Index] || session.localPieces[request.Index] {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return ErrPieceUnavailable
	}
	_, allowedFast := session.remoteAllowed[request.Index]
	if session.remoteChoking && !(session.fastNegotiatedLocked() && allowedFast) {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return ErrPeerChoking
	}
	if len(session.outstanding) >= session.maxOutstanding {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return ErrRequestPipelineFull
	}
	if _, exists := session.outstanding[request]; exists {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return fmt.Errorf("peer: duplicate request")
	}
	if late, exists := session.late[request]; exists && time.Now().Before(late.expires) {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return ErrRequestRecentlyExpired
	}
	delete(session.late, request)
	session.outstanding[request] = outgoingRequest{}
	session.mu.Unlock()
	err := session.writeMessageLocked(&Message{ID: MsgRequest, Payload: payload})
	if err == nil {
		session.mu.Lock()
		if pending, exists := session.outstanding[request]; exists {
			pending.deadline = time.Now().Add(session.requestTimeout)
			session.outstanding[request] = pending
		}
		session.mu.Unlock()
	}
	session.writeMu.Unlock()
	if err != nil {
		session.terminate(err)
	}
	return err
}

// Cancel writes a Cancel for one outstanding request. With Fast negotiated,
// the request remains correlated until its required Piece or Reject arrives.
func (session *Session) Cancel(request BlockRequest) error {
	if err := session.validateBlock(request); err != nil {
		return err
	}
	payload := FormatCancel(request.Index, request.Begin, request.Length)
	session.writeMu.Lock()
	session.mu.Lock()
	if err := session.readyErrorLocked(); err != nil {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return err
	}
	pending, exists := session.outstanding[request]
	if !exists {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return ErrRequestNotFound
	}
	rejectRequired := session.rejectRequiredLocked()
	if rejectRequired {
		pending.cancelled = true
		session.outstanding[request] = pending
	} else {
		delete(session.outstanding, request)
		session.late[request] = lateRequest{expires: time.Now().Add(session.lateWindow), cancelled: true}
	}
	session.mu.Unlock()
	err := session.writeMessageLocked(&Message{ID: MsgCancel, Payload: payload})
	session.writeMu.Unlock()
	if !rejectRequired && session.callbacks.OnBlock != nil {
		session.callbacks.OnBlock(BlockResult{Request: request, Cancelled: true})
	}
	if err != nil {
		session.terminate(err)
	}
	return err
}

// SetInterested updates local interest and writes the corresponding message.
func (session *Session) SetInterested(interested bool) error {
	session.writeMu.Lock()
	session.mu.Lock()
	if err := session.readyErrorLocked(); err != nil {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return err
	}
	if session.localInterested == interested {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return nil
	}
	session.localInterested = interested
	session.mu.Unlock()
	id := MsgNotInterested
	if interested {
		id = MsgInterested
	}
	err := session.writeMessageLocked(&Message{ID: id})
	session.writeMu.Unlock()
	if err != nil {
		session.terminate(err)
	}
	return err
}

// Have marks one verified local piece and announces it to the remote peer.
func (session *Session) Have(index uint32) error {
	session.mu.Lock()
	pieceCount := uint32(len(session.pieceLengths))
	session.mu.Unlock()
	if err := ValidatePieceIndex(index, pieceCount); err != nil {
		return err
	}
	session.writeMu.Lock()
	session.mu.Lock()
	if err := session.readyErrorLocked(); err != nil {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return err
	}
	if session.localPieces[index] {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return nil
	}
	session.localPieces[index] = true
	session.mu.Unlock()
	err := session.writeMessageLocked(&Message{ID: MsgHave, Payload: FormatHave(index)})
	session.writeMu.Unlock()
	if err != nil {
		session.terminate(err)
	}
	return err
}

// SendMetadata writes one BEP 9 message using the remote peer's current ID.
func (session *Session) SendMetadata(message MetadataMessage) error {
	payload, err := message.Encode()
	if err != nil {
		return err
	}
	return session.sendExtension(ExtensionMetadata, payload)
}

// SendPEX writes one rate-limited BEP 11 message. PEX is unavailable for
// private torrents.
func (session *Session) SendPEX(message PEXMessage) error {
	if session.private {
		return ErrPEXDisabled
	}
	session.pexMu.Lock()
	defer session.pexMu.Unlock()
	session.mu.Lock()
	limits := StandardPEXLimits()
	if !session.pexSent {
		limits = session.initialPEXLimits
	}
	if !session.lastPEXWrite.IsZero() && time.Since(session.lastPEXWrite) < session.pexInterval {
		session.mu.Unlock()
		return fmt.Errorf("peer: PEX send cadence is less than %s", session.pexInterval)
	}
	session.mu.Unlock()
	payload, err := message.Encode(limits)
	if err != nil {
		return err
	}
	if err := session.sendExtension(ExtensionPEX, payload); err != nil {
		return err
	}
	session.mu.Lock()
	session.pexSent = true
	session.lastPEXWrite = time.Now()
	session.mu.Unlock()
	return nil
}

// SendHashRequest writes a BEP 52 Hash Request on a selected v2 connection.
func (session *Session) SendHashRequest(request HashRequest) error {
	payload, err := FormatHashRequest(request)
	if err != nil {
		return err
	}
	return session.sendV2Message(MsgHashRequest, payload)
}

// SendHashes writes a BEP 52 Hashes response on a selected v2 connection.
func (session *Session) SendHashes(hashes Hashes) error {
	payload, err := FormatHashes(hashes)
	if err != nil {
		return err
	}
	return session.sendV2Message(MsgHashes, payload)
}

// SendHashReject writes a BEP 52 Hash Reject on a selected v2 connection.
func (session *Session) SendHashReject(request HashRequest) error {
	payload, err := FormatHashReject(request)
	if err != nil {
		return err
	}
	return session.sendV2Message(MsgHashReject, payload)
}

func (session *Session) sendExtension(name string, payload []byte) error {
	session.writeMu.Lock()
	session.mu.Lock()
	if err := session.readyErrorLocked(); err != nil {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return err
	}
	id, ok := session.extensions.Outgoing.ID(name)
	if !ok {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return fmt.Errorf("peer: remote did not negotiate extension %q", name)
	}
	session.mu.Unlock()
	extended, err := FormatExtended(id, payload)
	if err == nil {
		err = session.writeMessageLocked(&Message{ID: MsgExtended, Payload: extended})
	}
	session.writeMu.Unlock()
	if err != nil {
		session.terminate(err)
	}
	return err
}

func (session *Session) sendV2Message(id MessageID, payload []byte) error {
	session.writeMu.Lock()
	session.mu.Lock()
	if err := session.readyErrorLocked(); err != nil {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return err
	}
	if session.version != ProtocolV2 {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return fmt.Errorf("peer: message %d requires a v2 connection", id)
	}
	session.mu.Unlock()
	err := session.writeMessageLocked(&Message{ID: id, Payload: payload})
	session.writeMu.Unlock()
	if err != nil {
		session.terminate(err)
	}
	return err
}

func (session *Session) readyErrorLocked() error {
	if session.closed {
		return ErrSessionClosed
	}
	if !session.ready {
		return ErrSessionNotReady
	}
	return nil
}

func (session *Session) validateBlock(request BlockRequest) error {
	if err := request.Validate(); err != nil {
		return err
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := ValidatePieceIndex(request.Index, uint32(len(session.pieceLengths))); err != nil {
		return err
	}
	if uint64(request.Begin)+uint64(request.Length) > uint64(session.pieceLengths[request.Index]) {
		return fmt.Errorf("peer: block range %d+%d exceeds piece %d length %d", request.Begin, request.Length, request.Index, session.pieceLengths[request.Index])
	}
	return nil
}

func validatePieceLengths(name string, lengths []uint32, pieceCount uint32) ([]uint32, error) {
	if len(lengths) != int(pieceCount) {
		return nil, fmt.Errorf("peer: %s has %d entries, want %d", name, len(lengths), pieceCount)
	}
	result := append([]uint32(nil), lengths...)
	for index, length := range result {
		if length == 0 {
			return nil, fmt.Errorf("peer: %s piece %d has zero length", name, index)
		}
	}
	return result, nil
}

func (session *Session) fastNegotiatedLocked() bool {
	return session.localReserved.Has(CapabilityFast) && session.remoteReserved.Has(CapabilityFast)
}

func (session *Session) rejectRequiredLocked() bool {
	return session.version == ProtocolV2 || session.fastNegotiatedLocked()
}

func (session *Session) writeMessageLocked(message *Message) error {
	if session.writeTimeout > 0 {
		if err := session.conn.SetWriteDeadline(time.Now().Add(session.writeTimeout)); err != nil {
			return fmt.Errorf("peer: set write deadline: %w", err)
		}
		defer func() { _ = session.conn.SetWriteDeadline(time.Time{}) }()
	}
	if err := session.codec.WriteMessage(session.conn, message); err != nil {
		return err
	}
	session.mu.Lock()
	session.lastWrite = time.Now()
	session.mu.Unlock()
	return nil
}

func (session *Session) writeKeepaliveLocked() error {
	if session.writeTimeout > 0 {
		if err := session.conn.SetWriteDeadline(time.Now().Add(session.writeTimeout)); err != nil {
			return fmt.Errorf("peer: set keepalive deadline: %w", err)
		}
		defer func() { _ = session.conn.SetWriteDeadline(time.Time{}) }()
	}
	if err := session.codec.WriteKeepalive(session.conn); err != nil {
		return err
	}
	session.mu.Lock()
	session.lastWrite = time.Now()
	session.mu.Unlock()
	return nil
}

func (session *Session) terminate(err error) {
	if err == nil {
		err = ErrSessionClosed
	}
	var blocks []BlockResult
	var uploads []BlockRequest
	closed := false
	session.closeOnce.Do(func() {
		closed = true
		session.mu.Lock()
		session.closed = true
		session.err = err
		cancel := session.cancel
		inboundCancels := make([]context.CancelFunc, 0, len(session.inbound))
		for request, state := range session.inbound {
			uploads = append(uploads, request)
			inboundCancels = append(inboundCancels, state.cancel)
		}
		for request := range session.outstanding {
			blocks = append(blocks, BlockResult{Request: request, Cancelled: true})
		}
		session.outstanding = make(map[BlockRequest]outgoingRequest)
		session.inbound = make(map[BlockRequest]*inboundRequest)
		session.mu.Unlock()
		for _, cancelRequest := range inboundCancels {
			cancelRequest()
		}
		if cancel != nil {
			cancel(err)
		}
		_ = session.conn.Close()
	})
	if !closed {
		return
	}
	defer close(session.doneCh)
	if session.callbacks.OnBlock != nil {
		for _, block := range blocks {
			session.callbacks.OnBlock(block)
		}
	}
	if session.callbacks.OnUploadCancel != nil {
		for _, request := range uploads {
			session.callbacks.OnUploadCancel(request)
		}
	}
}

func cloneExtensionHandshake(handshake ExtensionHandshake) ExtensionHandshake {
	clone := handshake
	if handshake.Extensions != nil {
		clone.Extensions = make(map[string]uint8, len(handshake.Extensions))
		for name, id := range handshake.Extensions {
			clone.Extensions[name] = id
		}
	}
	clone.Unknown = copyDictionary(handshake.Unknown)
	return clone
}

func sortBlockRequests(requests []BlockRequest) {
	sort.Slice(requests, func(i, j int) bool {
		if requests[i].Index != requests[j].Index {
			return requests[i].Index < requests[j].Index
		}
		if requests[i].Begin != requests[j].Begin {
			return requests[i].Begin < requests[j].Begin
		}
		return requests[i].Length < requests[j].Length
	})
}

func allSet(pieces []bool) bool {
	if len(pieces) == 0 {
		return false
	}
	for _, piece := range pieces {
		if !piece {
			return false
		}
	}
	return true
}

func noneSet(pieces []bool) bool {
	for _, piece := range pieces {
		if piece {
			return false
		}
	}
	return true
}

func v2HandshakeHash(hash metainfo.HashV2) metainfo.Hash {
	var truncated metainfo.Hash
	copy(truncated[:], hash[:len(truncated)])
	return truncated
}

func samePeerID(expected *[20]byte, actual [20]byte) bool {
	return expected == nil || *expected == actual
}

func wrapProtocol(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrProtocol, fmt.Sprintf(format, args...))
}
