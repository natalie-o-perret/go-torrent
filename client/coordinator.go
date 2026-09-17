package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/natalie-o-perret/go-torrent/metainfo"
	"github.com/natalie-o-perret/go-torrent/peer"
	"github.com/natalie-o-perret/go-torrent/piece"
)

type candidateRoute struct {
	protocol   peer.ProtocolVersion
	transport  Transport
	source     CandidateSource
	tracker    string
	introducer [20]byte
	peerID     [20]byte
}

type candidateState struct {
	address    string
	routes     []candidateRoute
	next       time.Time
	routeIndex int
	dialing    bool
	connected  bool
	failures   int
}

type pexFailure struct {
	address string
	route   candidateRoute
}

type addCommand struct {
	candidate Candidate
	result    chan error
}

type blockKey struct {
	protocol peer.ProtocolVersion
	index    uint32
	begin    uint32
	length   uint32
}

type pieceKey struct {
	protocol peer.ProtocolVersion
	index    uint32
}

type downloadPiece struct {
	state       *piece.State
	assignments map[blockKey]map[uint64]struct{}
}

type peerState struct {
	id                uint64
	session           *peer.Session
	endpoint          string
	protocol          peer.ProtocolVersion
	transport         Transport
	origin            candidateRoute
	routes            []candidateRoute
	candidate         *candidateState
	outgoing          bool
	ready             bool
	retry             bool
	remoteID          [20]byte
	requests          map[blockKey]peer.BlockRequest
	snapshot          peer.SessionSnapshot
	downloaded        int64
	uploaded          int64
	regular           bool
	optimistic        bool
	wasInterested     bool
	discard           bool
	preserveCandidate bool
	nextPEX           time.Time
	pexKnown          map[netip.Addr]netip.AddrPort
	pexFailed         map[pexFailure]struct{}
	pexDisabled       bool
	pexAddress        netip.AddrPort
	remoteIP          netip.Addr
	readyAt           time.Time
}

type coordinator struct {
	client          *Client
	ctx             context.Context
	candidates      map[string]*candidateState
	order           []string
	peers           map[uint64]*peerState
	endpoints       map[string]uint64
	peerIDs         map[[20]byte]uint64
	active          map[pieceKey]*downloadPiece
	webseeds        []*webseedRuntime
	webseedReserved map[uint32]struct{}
	trackers        []*trackerRuntime
	nextPeerID      uint64
	dialing         int
	incoming        int
	workers         sync.WaitGroup
	nextReview      time.Time
	nextOptimistic  time.Time
	optimistic      uint64
	privateTracker  string
}

type acceptedEvent struct {
	conn      net.Conn
	transport Transport
	err       error
}

type inboundEvent struct {
	conn      net.Conn
	endpoint  string
	protocol  peer.ProtocolVersion
	transport Transport
	remoteID  [20]byte
	err       error
}

type dialEvent struct {
	candidate *candidateState
	route     candidateRoute
	conn      net.Conn
	err       error
}

type peerReadyEvent struct{ id uint64 }

type peerDoneEvent struct {
	id  uint64
	err error
}

type peerBlockEvent struct {
	id     uint64
	result peer.BlockResult
}

type peerTimeoutEvent struct {
	id      uint64
	request peer.BlockRequest
}

type peerPEXEvent struct {
	id      uint64
	message peer.PEXMessage
}

type peerExtensionEvent struct {
	id        uint64
	handshake peer.ExtensionHandshake
}

type uploadedEvent struct {
	id    uint64
	bytes int64
}

type peerMetadataEvent struct {
	id      uint64
	message peer.MetadataMessage
}

type peerHashRequestEvent struct {
	id      uint64
	request peer.HashRequest
}

type fatalEvent struct{ err error }

// AddPeer adds one direct, tracker, or PEX candidate. Duplicate additions are
// idempotent and merge their provenance.
func (client *Client) AddPeer(candidate Candidate) error {
	if client == nil {
		return ErrClosed
	}
	validated, err := client.validateCandidate(candidate)
	if err != nil {
		return err
	}
	client.lifecycleMu.Lock()
	switch client.lifecycle {
	case lifecycleNew:
		err = client.addCandidateMap(client.pending, validated)
		client.localMu.Lock()
		client.candidateCount = len(client.pending)
		client.localMu.Unlock()
		client.lifecycleMu.Unlock()
		return err
	case lifecycleClosed:
		client.lifecycleMu.Unlock()
		return ErrClosed
	case lifecycleRunning:
	}
	client.lifecycleMu.Unlock()

	command := addCommand{candidate: validated, result: make(chan error, 1)}
	select {
	case client.commands <- command:
	case <-client.done:
		return ErrClosed
	}
	select {
	case err := <-command.result:
		return err
	case <-client.done:
		return ErrClosed
	}
}

// Run verifies resume data, starts tracker and peer processing, and blocks
// while downloading or seeding. It returns the context cause or ErrClosed.
func (client *Client) Run(ctx context.Context) (runErr error) {
	if client == nil {
		return ErrClosed
	}
	if ctx == nil {
		return fmt.Errorf("client: nil context")
	}
	client.lifecycleMu.Lock()
	switch client.lifecycle {
	case lifecycleRunning:
		client.lifecycleMu.Unlock()
		return ErrAlreadyRunning
	case lifecycleClosed:
		client.lifecycleMu.Unlock()
		return ErrClosed
	}
	runCtx, cancel := context.WithCancelCause(ctx)
	client.lifecycle = lifecycleRunning
	client.cancel = cancel
	client.lifecycleMu.Unlock()

	client.localMu.Lock()
	client.startedAt = client.now()
	client.localMu.Unlock()
	defer func() {
		cancel(runErr)
		client.closeListeners()
		client.lifecycleMu.Lock()
		client.lifecycle = lifecycleClosed
		client.cancel = nil
		client.lifecycleMu.Unlock()
		client.localMu.Lock()
		client.connectedPeers = 0
		client.candidateCount = 0
		client.localMu.Unlock()
		client.doneOnce.Do(func() { close(client.done) })
	}()

	if err := client.store.Prepare(); err != nil {
		return fmt.Errorf("client: prepare storage: %w", err)
	}
	verified, err := client.store.VerifyAll()
	if err != nil {
		return fmt.Errorf("client: verify resume data: %w", err)
	}
	if len(verified) != len(client.verified) {
		return fmt.Errorf("client: resume bitmap has %d pieces, want %d", len(verified), len(client.verified))
	}
	client.localMu.Lock()
	copy(client.verified, verified)
	complete := allVerified(client.verified)
	if complete {
		client.completedAt = client.now()
	}
	client.localMu.Unlock()
	if complete {
		client.completionOnce.Do(func() { close(client.completed) })
	}
	if err := runCtx.Err(); err != nil {
		return context.Cause(runCtx)
	}

	client.lifecycleMu.Lock()
	candidates := client.pending
	client.pending = nil
	client.lifecycleMu.Unlock()
	state := &coordinator{
		client:          client,
		ctx:             runCtx,
		candidates:      candidates,
		peers:           make(map[uint64]*peerState),
		endpoints:       make(map[string]uint64),
		peerIDs:         make(map[[20]byte]uint64),
		active:          make(map[pieceKey]*downloadPiece),
		webseedReserved: make(map[uint32]struct{}),
		nextReview:      client.now(),
		nextOptimistic:  client.now().Add(optimisticUnchokePeriod),
	}
	state.webseeds = make([]*webseedRuntime, len(client.webseeds))
	for index, downloader := range client.webseeds {
		state.webseeds[index] = &webseedRuntime{downloader: downloader}
	}
	for address := range candidates {
		state.order = append(state.order, address)
	}
	sort.Strings(state.order)
	state.updateCounts()

	state.trackers, err = state.startTrackers()
	if err != nil {
		return err
	}
	state.startDHT()
	if client.listener != nil {
		state.workers.Add(1)
		go state.acceptLoop(client.listener, TransportTCP)
	}
	if client.utp != nil {
		state.workers.Add(1)
		go state.acceptLoop(client.utp, TransportUTP)
	}
	runErr = state.loop()
	state.shutdown()
	return runErr
}

// Close stops Run and waits for owned sessions and the listener to close. It is
// safe to call more than once.
func (client *Client) Close() error {
	if client == nil {
		return nil
	}
	client.lifecycleMu.Lock()
	switch client.lifecycle {
	case lifecycleNew:
		client.lifecycle = lifecycleClosed
		client.lifecycleMu.Unlock()
		client.closeListeners()
		client.localMu.Lock()
		client.candidateCount = 0
		client.localMu.Unlock()
		client.doneOnce.Do(func() { close(client.done) })
		return nil
	case lifecycleClosed:
		client.lifecycleMu.Unlock()
		return nil
	case lifecycleRunning:
		cancel := client.cancel
		client.lifecycleMu.Unlock()
		if cancel != nil {
			cancel(ErrClosed)
		}
		client.closeListeners()
		<-client.done
		return nil
	default:
		client.lifecycleMu.Unlock()
		return nil
	}
}

func (client *Client) addCandidateMap(candidates map[string]*candidateState, candidate Candidate) error {
	state := candidates[candidate.Address]
	if state == nil {
		if len(candidates) >= client.maxCandidates {
			return ErrCandidateLimit
		}
		state = &candidateState{address: candidate.Address}
		candidates[candidate.Address] = state
	}
	for _, route := range client.candidateRoutes(candidate) {
		if !containsRoute(state.routes, route) {
			state.routes = append(state.routes, route)
		}
	}
	return nil
}

func (client *Client) candidateRoutes(candidate Candidate) []candidateRoute {
	versions := []peer.ProtocolVersion{candidate.Protocol}
	if candidate.Protocol == 0 {
		versions = versions[:0]
		if client.layouts[peer.ProtocolV2] != nil {
			versions = append(versions, peer.ProtocolV2)
		}
		if client.layouts[peer.ProtocolV1] != nil {
			versions = append(versions, peer.ProtocolV1)
		}
	}
	transports := []Transport{candidate.Transport}
	if candidate.Transport == TransportAuto {
		transports = transports[:0]
		if client.utp != nil {
			transports = append(transports, TransportUTP)
		}
		transports = append(transports, TransportTCP)
	}
	routes := make([]candidateRoute, 0, len(versions)*len(transports))
	for _, version := range versions {
		for _, transport := range transports {
			routes = append(routes, candidateRoute{
				protocol:   version,
				transport:  transport,
				source:     candidate.Source,
				tracker:    candidate.Tracker,
				introducer: candidate.Introducer,
				peerID:     candidate.PeerID,
			})
		}
	}
	return routes
}

func containsRoute(routes []candidateRoute, wanted candidateRoute) bool {
	for _, route := range routes {
		if route == wanted {
			return true
		}
	}
	return false
}

func (state *coordinator) loop() error {
	state.maintain(state.client.now())
	tick := state.client.after(state.client.scheduleInterval)
	for {
		select {
		case <-state.ctx.Done():
			return context.Cause(state.ctx)
		case command := <-state.client.commands:
			command.result <- state.addCandidate(command.candidate)
			state.maintain(state.client.now())
		case event := <-state.client.events:
			if err := state.handleEvent(event); err != nil {
				state.client.cancel(err)
				return err
			}
			state.maintain(state.client.now())
		case <-tick:
			state.maintain(state.client.now())
			tick = state.client.after(state.client.scheduleInterval)
		}
	}
}

func (state *coordinator) handleEvent(event any) error {
	switch event := event.(type) {
	case acceptedEvent:
		state.handleAccepted(event)
	case inboundEvent:
		state.handleInbound(event)
	case dialEvent:
		state.handleDial(event)
	case peerReadyEvent:
		state.handlePeerReady(event.id)
	case peerDoneEvent:
		state.handlePeerDone(event)
	case peerBlockEvent:
		return state.handleBlock(event)
	case peerTimeoutEvent:
		state.handleTimeout(event)
	case peerPEXEvent:
		state.handlePEX(event)
	case peerExtensionEvent:
		state.handleExtension(event)
	case peerMetadataEvent:
		state.handleMetadata(event)
	case peerHashRequestEvent:
		state.handleHashRequest(event)
	case uploadedEvent:
		if managed := state.peers[event.id]; managed != nil {
			managed.uploaded += event.bytes
		}
	case trackerResultEvent:
		state.handleTrackerResult(event)
	case privateTrackerSwitchEvent:
		if state.privateTracker != event.tracker {
			if state.privateTracker != "" {
				state.switchPrivateTracker(event.tracker)
			}
			state.privateTracker = event.tracker
		}
		close(event.done)
	case dhtResultEvent:
		state.handleDHTResult(event)
	case peerDHTPortEvent:
		state.handlePeerDHTPort(event)
	case webseedResultEvent:
		return state.handleWebseedResult(event)
	case fatalEvent:
		return event.err
	}
	state.updateCounts()
	return nil
}

func (state *coordinator) addCandidate(candidate Candidate) error {
	if state.client.meta.Info.Private && state.privateTracker != "" && candidate.Tracker != state.privateTracker {
		return ErrPrivatePeerSource
	}
	if peerID, connected := state.endpoints[candidate.Address]; connected {
		connectedPeer := state.peers[peerID]
		if connectedPeer != nil {
			for _, route := range state.client.candidateRoutes(candidate) {
				if route.protocol == connectedPeer.protocol && !containsRoute(connectedPeer.routes, route) {
					connectedPeer.routes = append(connectedPeer.routes, route)
				}
			}
		}
	}
	_, existed := state.candidates[candidate.Address]
	err := state.client.addCandidateMap(state.candidates, candidate)
	if errors.Is(err, ErrCandidateLimit) && candidate.Source == SourceTracker {
		for _, address := range state.order {
			stale := state.candidates[address]
			if stale != nil && !stale.connected && !stale.dialing {
				state.removeCandidate(address)
				err = state.client.addCandidateMap(state.candidates, candidate)
				break
			}
		}
	}
	if err == nil && !existed {
		state.order = append(state.order, candidate.Address)
	}
	state.updateCounts()
	return err
}

func (state *coordinator) emit(event any) bool {
	if state.ctx.Err() != nil {
		return false
	}
	select {
	case state.client.events <- event:
		return true
	case <-state.ctx.Done():
		return false
	}
}

func (state *coordinator) acceptLoop(listener net.Listener, transport Transport) {
	defer state.workers.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if state.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				state.emit(fatalEvent{err: fmt.Errorf("client: accept peer: %w", err)})
			}
			return
		}
		if !state.emit(acceptedEvent{conn: conn, transport: transport}) {
			_ = conn.Close()
			return
		}
	}
}

func (state *coordinator) handleAccepted(event acceptedEvent) {
	if event.err != nil || event.conn == nil {
		return
	}
	if len(state.peers)+state.dialing+state.incoming >= state.client.maxPeers {
		_ = event.conn.Close()
		return
	}
	state.incoming++
	state.workers.Add(1)
	go state.prepareInbound(event.conn, event.transport)
}

func (state *coordinator) prepareInbound(conn net.Conn, transport Transport) {
	defer state.workers.Done()
	stopClose := context.AfterFunc(state.ctx, func() { _ = conn.Close() })
	defer stopClose()
	result := inboundEvent{conn: conn, transport: transport}
	if state.client.handshakeTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(state.client.handshakeTimeout))
	}
	handshake, err := peer.ReadHandshake(conn)
	if err != nil {
		result.err = fmt.Errorf("client: read incoming handshake: %w", err)
	} else {
		result.protocol, err = state.protocolForHash(handshake.InfoHash)
		result.remoteID = handshake.PeerID
		result.err = err
	}
	_ = conn.SetDeadline(time.Time{})
	if result.err == nil {
		result.endpoint, result.err = canonicalAddress(conn.RemoteAddr().String())
	}
	if result.err == nil {
		raw, _ := handshake.MarshalBinary()
		result.conn = &replayConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(raw), conn)}
	}
	if !state.emit(result) {
		_ = conn.Close()
	}
}

func (state *coordinator) protocolForHash(hash [20]byte) (peer.ProtocolVersion, error) {
	if layout := state.client.layouts[peer.ProtocolV1]; layout != nil && hash == layout.infoHash {
		return peer.ProtocolV1, nil
	}
	if layout := state.client.layouts[peer.ProtocolV2]; layout != nil && hash == layout.infoHash {
		return peer.ProtocolV2, nil
	}
	return 0, fmt.Errorf("client: incoming handshake has an unknown info hash")
}

func (state *coordinator) handleInbound(event inboundEvent) {
	state.incoming--
	if event.err != nil || event.conn == nil || event.remoteID == state.client.peerID || event.remoteID == ([20]byte{}) {
		if event.conn != nil {
			_ = event.conn.Close()
		}
		return
	}
	if state.client.meta.Info.Private {
		_ = event.conn.Close()
		return
	}
	if _, duplicate := state.endpoints[event.endpoint]; duplicate || len(state.peers)+state.dialing >= state.client.maxPeers {
		_ = event.conn.Close()
		return
	}
	if _, duplicate := state.peerIDs[event.remoteID]; duplicate {
		_ = event.conn.Close()
		return
	}
	route := candidateRoute{protocol: event.protocol, transport: event.transport, source: SourceIncoming, peerID: event.remoteID}
	if _, err := state.startPeer(event.conn, event.endpoint, event.protocol, false, event.remoteID, route, []candidateRoute{route}, nil); err != nil {
		_ = event.conn.Close()
	}
}

func (state *coordinator) scheduleDials(now time.Time) {
	for _, address := range state.order {
		if len(state.peers)+state.dialing+state.incoming >= state.client.maxPeers {
			return
		}
		candidate := state.candidates[address]
		if candidate == nil || candidate.dialing || candidate.connected || len(candidate.routes) == 0 || now.Before(candidate.next) {
			continue
		}
		if _, connected := state.endpoints[address]; connected {
			candidate.connected = true
			continue
		}
		route, ok := state.dialRoute(candidate)
		if !ok {
			continue
		}
		candidate.dialing = true
		state.dialing++
		state.workers.Add(1)
		go state.dial(candidate, route)
	}
}

func (state *coordinator) dialRoute(candidate *candidateState) (candidateRoute, bool) {
	if !state.client.meta.Info.Private {
		return candidate.routes[candidate.routeIndex%len(candidate.routes)], true
	}
	if state.privateTracker == "" {
		return candidateRoute{}, false
	}
	for offset := range len(candidate.routes) {
		index := (candidate.routeIndex + offset) % len(candidate.routes)
		route := candidate.routes[index]
		if route.source == SourceTracker && route.tracker == state.privateTracker {
			candidate.routeIndex = index
			return route, true
		}
	}
	return candidateRoute{}, false
}

func (state *coordinator) dial(candidate *candidateState, route candidateRoute) {
	defer state.workers.Done()
	ctx := state.ctx
	var cancel context.CancelFunc
	if state.client.dialTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, state.client.dialTimeout)
		defer cancel()
	}
	var conn net.Conn
	var err error
	if route.transport == TransportUTP {
		conn, err = state.client.utp.DialContext(ctx, "", candidate.address)
	} else {
		conn, err = state.client.dialContext(ctx, "tcp", candidate.address)
	}
	event := dialEvent{candidate: candidate, route: route, conn: conn, err: err}
	if !state.emit(event) && conn != nil {
		_ = conn.Close()
	}
}

func (state *coordinator) handleDial(event dialEvent) {
	state.dialing--
	candidate := state.candidates[event.candidate.address]
	if candidate != event.candidate || !containsRoute(event.candidate.routes, event.route) {
		event.candidate.dialing = false
		if event.conn != nil {
			_ = event.conn.Close()
		}
		if candidate == event.candidate && len(candidate.routes) == 0 && !candidate.connected {
			state.removeCandidate(candidate.address)
		}
		return
	}
	candidate.dialing = false
	if event.err != nil || event.conn == nil {
		state.failCandidateRoute(candidate, event.route)
		return
	}
	if _, duplicate := state.endpoints[candidate.address]; duplicate || len(state.peers)+state.incoming >= state.client.maxPeers {
		_ = event.conn.Close()
		candidate.connected = true
		if peerID := state.endpoints[candidate.address]; peerID != 0 {
			if managed := state.peers[peerID]; managed != nil {
				for _, route := range candidate.routes {
					if route.protocol == managed.protocol && !containsRoute(managed.routes, route) {
						managed.routes = append(managed.routes, route)
					}
				}
			}
		}
		return
	}
	if _, err := state.startPeer(event.conn, candidate.address, event.route.protocol, true, event.route.peerID, event.route, candidate.routesFor(event.route.protocol), candidate); err != nil {
		_ = event.conn.Close()
		state.failCandidateRoute(candidate, event.route)
	}
}

func (state *coordinator) failCandidateRoute(candidate *candidateState, route candidateRoute) {
	if route.source == SourcePEX {
		state.rememberPEXFailure(candidate.address, route)
		candidate.routes = filterRoutes(candidate.routes, func(existing candidateRoute) bool { return existing == route })
		candidate.routeIndex = 0
		if len(candidate.routes) == 0 {
			state.removeCandidate(candidate.address)
			return
		}
	}
	state.retryCandidate(candidate)
}

func (state *coordinator) rememberPEXFailure(address string, route candidateRoute) {
	if route.source != SourcePEX {
		return
	}
	if introducer := state.peers[state.peerIDs[route.introducer]]; introducer != nil {
		if introducer.pexFailed == nil {
			introducer.pexFailed = make(map[pexFailure]struct{})
		}
		if len(introducer.pexFailed) >= min(state.client.maxCandidates, defaultMaxCandidates) {
			introducer.pexDisabled = true
			return
		}
		introducer.pexFailed[pexFailure{address: address, route: route}] = struct{}{}
	}
}

func (candidate *candidateState) routesFor(protocol peer.ProtocolVersion) []candidateRoute {
	var routes []candidateRoute
	for _, route := range candidate.routes {
		if route.protocol == protocol {
			routes = append(routes, route)
		}
	}
	return routes
}

func (state *coordinator) retryCandidate(candidate *candidateState) {
	if candidate == nil || len(candidate.routes) == 0 {
		return
	}
	candidate.connected = false
	candidate.failures++
	candidate.routeIndex = (candidate.routeIndex + 1) % len(candidate.routes)
	delay := state.client.retryInterval
	for range min(candidate.failures-1, 4) {
		if delay > time.Minute/2 {
			delay = time.Minute
			break
		}
		delay *= 2
	}
	candidate.next = state.client.now().Add(delay)
}

func (state *coordinator) startPeer(conn net.Conn, endpoint string, protocol peer.ProtocolVersion, outgoing bool, expectedID [20]byte, origin candidateRoute, routes []candidateRoute, candidate *candidateState) (*peerState, error) {
	layout := state.client.layouts[protocol]
	if layout == nil {
		return nil, fmt.Errorf("client: unsupported peer protocol %d", protocol)
	}
	state.nextPeerID++
	managed := &peerState{
		id:        state.nextPeerID,
		endpoint:  endpoint,
		protocol:  protocol,
		transport: origin.transport,
		origin:    origin,
		routes:    append([]candidateRoute(nil), routes...),
		candidate: candidate,
		outgoing:  outgoing,
		retry:     outgoing,
		requests:  make(map[blockKey]peer.BlockRequest),
		pexKnown:  make(map[netip.Addr]netip.AddrPort),
		pexFailed: make(map[pexFailure]struct{}),
		remoteIP:  remoteConnectionIP(conn.RemoteAddr()),
	}
	if outgoing || origin.transport == TransportUTP {
		managed.pexAddress, _ = netip.ParseAddrPort(endpoint)
	}
	localPieces := state.client.localPieces()
	pieceLengths := state.client.pieceLengths(protocol)
	hashes := state.client.sessionHashes(protocol)
	var reserved peer.Reserved
	reserved.Set(peer.CapabilityFast, true)
	queue := uint32(maxInboundRequests)
	metadataSize := state.client.metadata.Size()
	extension := peer.ExtensionHandshake{
		Client:       "go-torrent",
		RequestQueue: &queue,
		MetadataSize: &metadataSize,
		Extensions:   map[string]uint8{peer.ExtensionMetadata: 1},
	}
	if !state.client.meta.Info.Private {
		extension.Extensions[peer.ExtensionPEX] = 2
	}
	if state.client.listener != nil && state.client.port != 0 {
		port := state.client.port
		extension.Port = &port
	}
	callbacks := peer.SessionCallbacks{
		OnBlock: func(result peer.BlockResult) {
			state.emit(peerBlockEvent{id: managed.id, result: result})
		},
		OnLateResponse: func(result peer.BlockResult) {
			state.emit(peerBlockEvent{id: managed.id, result: result})
		},
		OnRequestTimeout: func(request peer.BlockRequest) {
			state.emit(peerTimeoutEvent{id: managed.id, request: request})
		},
		OnUploadRequest: func(ctx context.Context, request peer.BlockRequest) ([]byte, error) {
			return state.client.readUpload(ctx, managed.session.Snapshot().Version, request)
		},
		OnUploadComplete: func(request peer.BlockRequest) {
			version := managed.session.Snapshot().Version
			state.client.localMu.Lock()
			state.client.uploaded[version] += int64(request.Length)
			state.client.localMu.Unlock()
			state.emit(uploadedEvent{id: managed.id, bytes: int64(request.Length)})
		},
		OnPort: func(port uint16) {
			state.emit(peerDHTPortEvent{id: managed.id, port: port})
		},
		OnExtensionHandshake: func(handshake peer.ExtensionHandshake) {
			state.emit(peerExtensionEvent{id: managed.id, handshake: handshake})
		},
		OnPEX: func(message peer.PEXMessage) {
			state.emit(peerPEXEvent{id: managed.id, message: message})
		},
		OnMetadata: func(message peer.MetadataMessage) {
			state.emit(peerMetadataEvent{id: managed.id, message: message})
		},
		OnHashRequest: func(request peer.HashRequest) {
			state.emit(peerHashRequestEvent{id: managed.id, request: request})
		},
	}
	config := peer.SessionConfig{
		PeerID:                 state.client.peerID,
		Hashes:                 hashes,
		PreferV2:               protocol == peer.ProtocolV2,
		Outgoing:               outgoing,
		Reserved:               reserved,
		PieceCount:             uint32(len(pieceLengths)),
		PieceLengths:           pieceLengths,
		V1PieceLengths:         state.client.pieceLengths(peer.ProtocolV1),
		V2PieceLengths:         state.client.pieceLengths(peer.ProtocolV2),
		LocalPieces:            localPieces,
		Private:                state.client.meta.Info.Private,
		ExtensionHandshake:     extension,
		DHTPort:                state.client.dhtPort(),
		Callbacks:              callbacks,
		MaxOutstandingRequests: state.client.pipeline,
		MaxInboundRequests:     maxInboundRequests,
		HandshakeTimeout:       state.client.handshakeTimeout,
		RequestTimeout:         state.client.requestTimeout,
		LateResponseWindow:     state.client.requestTimeout,
		UploadTimeout:          state.client.requestTimeout,
		WriteTimeout:           state.client.writeTimeout,
		PEXMinInterval:         pexInterval,
	}
	if expectedID != ([20]byte{}) && origin.source != SourceTracker {
		expected := expectedID
		config.ExpectedPeerID = &expected
	}
	session, err := peer.NewSession(conn, config)
	if err != nil {
		return nil, err
	}
	managed.session = session
	state.peers[managed.id] = managed
	state.endpoints[endpoint] = managed.id
	if candidate != nil {
		candidate.connected = true
		candidate.failures = 0
	}
	state.workers.Add(2)
	go func() {
		defer state.workers.Done()
		err := session.Run(state.ctx)
		state.emit(peerDoneEvent{id: managed.id, err: err})
	}()
	go func() {
		defer state.workers.Done()
		select {
		case <-session.Ready():
			state.emit(peerReadyEvent{id: managed.id})
		case <-session.Done():
		case <-state.ctx.Done():
		}
	}()
	state.updateCounts()
	return managed, nil
}

func (client *Client) sessionHashes(protocol peer.ProtocolVersion) metainfo.Hashes {
	if client.meta.Info.IsHybrid() {
		v1 := client.meta.InfoHash
		v2 := client.meta.InfoHashV2
		return metainfo.Hashes{V1: &v1, V2: &v2}
	}
	if protocol == peer.ProtocolV1 {
		hash := client.meta.InfoHash
		return metainfo.Hashes{V1: &hash}
	}
	hash := client.meta.InfoHashV2
	return metainfo.Hashes{V2: &hash}
}

func (client *Client) pieceLengths(protocol peer.ProtocolVersion) []uint32 {
	layout := client.layouts[protocol]
	if layout == nil {
		return nil
	}
	lengths := make([]uint32, len(layout.pieces))
	for index := range layout.pieces {
		lengths[index] = layout.pieces[index].length
	}
	return lengths
}

func (client *Client) localPieces() []bool {
	client.localMu.RLock()
	defer client.localMu.RUnlock()
	return append([]bool(nil), client.verified...)
}

func (client *Client) readUpload(ctx context.Context, protocol peer.ProtocolVersion, request peer.BlockRequest) ([]byte, error) {
	client.localMu.RLock()
	verified := int(request.Index) < len(client.verified) && client.verified[request.Index]
	client.localMu.RUnlock()
	if !verified {
		return nil, fmt.Errorf("client: upload piece %d is not verified", request.Index)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client.storageMu.Lock()
	data, err := client.store.ReadPiece(protocolStorage(protocol), int(request.Index))
	client.storageMu.Unlock()
	if err != nil {
		return nil, err
	}
	end := uint64(request.Begin) + uint64(request.Length)
	if end > uint64(len(data)) {
		return nil, fmt.Errorf("client: upload range %d+%d exceeds piece length %d", request.Begin, request.Length, len(data))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]byte(nil), data[request.Begin:uint32(end)]...), nil
}

func (state *coordinator) handlePeerReady(id uint64) {
	managed := state.peers[id]
	if managed == nil {
		return
	}
	snapshot := managed.session.Snapshot()
	if !snapshot.Ready || state.client.layouts[snapshot.Version] == nil || snapshot.RemotePeerID == ([20]byte{}) || snapshot.RemotePeerID == state.client.peerID {
		managed.retry = false
		managed.discard = true
		_ = managed.session.Close()
		return
	}
	managed.protocol = snapshot.Version
	if existing, duplicate := state.peerIDs[snapshot.RemotePeerID]; duplicate && existing != id {
		managed.retry = false
		managed.discard = true
		_ = managed.session.Close()
		return
	}
	managed.ready = true
	managed.readyAt = state.client.now()
	managed.remoteID = snapshot.RemotePeerID
	managed.snapshot = snapshot
	state.peerIDs[managed.remoteID] = managed.id
	state.updateCounts()
}

func (state *coordinator) handlePeerDone(event peerDoneEvent) {
	managed := state.peers[event.id]
	if managed == nil {
		return
	}
	for key := range managed.requests {
		state.unassign(managed, key, true)
	}
	delete(state.peers, managed.id)
	if state.endpoints[managed.endpoint] == managed.id {
		delete(state.endpoints, managed.endpoint)
	}
	if managed.remoteID != ([20]byte{}) && state.peerIDs[managed.remoteID] == managed.id {
		delete(state.peerIDs, managed.remoteID)
	}
	state.dropPEXIntroducer(managed.remoteID)
	candidate := managed.candidate
	if candidate == nil {
		candidate = state.candidates[managed.endpoint]
	}
	if candidate != nil {
		candidate.connected = false
		if managed.origin.source == SourcePEX {
			state.rememberPEXFailure(candidate.address, managed.origin)
			candidate.routes = filterRoutes(candidate.routes, func(route candidateRoute) bool { return route == managed.origin })
			candidate.routeIndex = 0
		}
		switch {
		case managed.discard && !managed.preserveCandidate:
			state.removeCandidate(candidate.address)
		case managed.retry && state.ctx.Err() == nil:
			if len(candidate.routes) == 0 {
				state.removeCandidate(candidate.address)
			} else {
				state.retryCandidate(candidate)
			}
		case len(candidate.routes) == 0 && !candidate.dialing:
			state.removeCandidate(candidate.address)
		}
	}
	if state.optimistic == managed.id {
		state.optimistic = 0
	}
	state.updateCounts()
}

func (state *coordinator) dropPEXIntroducer(introducer [20]byte) {
	if introducer == ([20]byte{}) {
		return
	}
	for address, candidate := range state.candidates {
		candidate.routes = filterRoutes(candidate.routes, func(route candidateRoute) bool {
			return route.source == SourcePEX && route.introducer == introducer
		})
		if len(candidate.routes) == 0 && !candidate.connected && !candidate.dialing {
			state.removeCandidate(address)
		}
	}
}

func (state *coordinator) handleTimeout(event peerTimeoutEvent) {
	managed := state.peers[event.id]
	if managed == nil {
		return
	}
	key := requestKey(managed.protocol, event.request)
	state.unassign(managed, key, true)
}

func (state *coordinator) handlePEX(event peerPEXEvent) {
	if state.client.meta.Info.Private {
		return
	}
	managed := state.peers[event.id]
	if managed == nil || !managed.ready {
		return
	}
	if !managed.pexDisabled {
		for _, contact := range event.message.Added {
			candidate := Candidate{
				Address:    contact.AddrPort.String(),
				Introducer: managed.remoteID,
				Protocol:   managed.protocol,
				Source:     SourcePEX,
			}
			tcpRoute := state.client.candidateRoutes(Candidate{
				Address: candidate.Address, Introducer: candidate.Introducer, Protocol: candidate.Protocol,
				Source: SourcePEX, Transport: TransportTCP,
			})[0]
			_, tcpFailed := managed.pexFailed[pexFailure{address: candidate.Address, route: tcpRoute}]
			utpFailed := true
			if state.client.utp != nil && contact.Flags&peer.PEXSupportsUTP != 0 {
				utpRoute := state.client.candidateRoutes(Candidate{
					Address: candidate.Address, Introducer: candidate.Introducer, Protocol: candidate.Protocol,
					Source: SourcePEX, Transport: TransportUTP,
				})[0]
				_, utpFailed = managed.pexFailed[pexFailure{address: candidate.Address, route: utpRoute}]
			}
			switch {
			case !tcpFailed && !utpFailed:
				candidate.Transport = TransportAuto
			case !utpFailed:
				candidate.Transport = TransportUTP
			case !tcpFailed:
				candidate.Transport = TransportTCP
			default:
				continue
			}
			validated, err := state.client.validateCandidate(candidate)
			if err == nil {
				_ = state.addCandidate(validated)
			}
		}
	}
	for _, contact := range event.message.Dropped {
		address := contact.String()
		candidate := state.candidates[address]
		if candidate == nil {
			continue
		}
		candidate.routes = filterRoutes(candidate.routes, func(route candidateRoute) bool {
			return route.source == SourcePEX && route.protocol == managed.protocol && route.introducer == managed.remoteID
		})
		if len(candidate.routes) == 0 && !candidate.connected && !candidate.dialing {
			state.removeCandidate(address)
		}
	}
}

func (state *coordinator) handleExtension(event peerExtensionEvent) {
	managed := state.peers[event.id]
	if managed == nil || managed.transport == TransportUTP || event.handshake.Port == nil {
		return
	}
	host, _, err := net.SplitHostPort(managed.endpoint)
	if err != nil {
		return
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return
	}
	managed.pexAddress = netip.AddrPortFrom(address.Unmap(), *event.handshake.Port)
}

func (state *coordinator) handleMetadata(event peerMetadataEvent) {
	managed := state.peers[event.id]
	if managed == nil || !managed.ready || event.message.Type != peer.MetadataRequest {
		return
	}
	response, err := state.client.metadata.Respond(event.message)
	if err == nil {
		_ = managed.session.SendMetadata(response)
	}
}

func (state *coordinator) handleHashRequest(event peerHashRequestEvent) {
	managed := state.peers[event.id]
	if managed == nil || !managed.ready || managed.protocol != peer.ProtocolV2 {
		return
	}
	verified := state.client.localPieces()
	state.client.storageMu.Lock()
	response, ok := state.client.hashSource.Respond(event.request, verified)
	state.client.storageMu.Unlock()
	if ok {
		_ = managed.session.SendHashes(response)
	} else {
		_ = managed.session.SendHashReject(event.request)
	}
}

func filterRoutes(routes []candidateRoute, remove func(candidateRoute) bool) []candidateRoute {
	kept := routes[:0]
	for _, route := range routes {
		if !remove(route) {
			kept = append(kept, route)
		}
	}
	return kept
}

func (state *coordinator) removeCandidate(address string) {
	delete(state.candidates, address)
	for index, ordered := range state.order {
		if ordered == address {
			state.order = append(state.order[:index], state.order[index+1:]...)
			return
		}
	}
}

func (state *coordinator) updateCounts() {
	state.client.localMu.Lock()
	state.client.connectedPeers = len(state.peers)
	state.client.candidateCount = len(state.candidates)
	state.client.localMu.Unlock()
}

func (state *coordinator) shutdown() {
	clear(state.webseedReserved)
	for _, source := range state.webseeds {
		source.active = false
	}
	state.client.closeListeners()
	for _, managed := range state.peers {
		managed.retry = false
		_ = managed.session.Close()
	}
	state.workers.Wait()
	for {
		select {
		case event := <-state.client.events:
			switch event := event.(type) {
			case acceptedEvent:
				if event.conn != nil {
					_ = event.conn.Close()
				}
			case inboundEvent:
				if event.conn != nil {
					_ = event.conn.Close()
				}
			case dialEvent:
				if event.conn != nil {
					_ = event.conn.Close()
				}
			}
		default:
			return
		}
	}
}

func requestKey(protocol peer.ProtocolVersion, request peer.BlockRequest) blockKey {
	return blockKey{protocol: protocol, index: request.Index, begin: request.Begin, length: request.Length}
}

type replayConn struct {
	net.Conn
	reader io.Reader
}

func (conn *replayConn) Read(data []byte) (int, error) {
	return conn.reader.Read(data)
}
