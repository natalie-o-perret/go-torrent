package client

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/natalie-o-perret/go-torrent/dht"
	"github.com/natalie-o-perret/go-torrent/magnet"
	"github.com/natalie-o-perret/go-torrent/metainfo"
	"github.com/natalie-o-perret/go-torrent/peer"
	"github.com/natalie-o-perret/go-torrent/tracker"
)

const (
	defaultMagnetMaxTrackers         = 32
	defaultMagnetMaxPieceLayerHashes = 1 << 20
	defaultMagnetDiscoveryTimeout    = 30 * time.Second
)

// MagnetConfig bounds discovery and metadata bootstrap. Port is required when
// the magnet has trackers. TrackerClient and DHTNode remain caller-owned.
// UsePublicDHT must be true to query DHTNode while private status is unknown.
// MaxCandidates bounds distinct peer endpoints, not their provenance routes.
type MagnetConfig struct {
	TrackerClient *tracker.Client
	DHTNode       *dht.Node
	UsePublicDHT  bool
	PeerID        [20]byte
	Port          uint16
	DialContext   func(context.Context, string, string) (net.Conn, error)

	MaxCandidates       int
	MaxTrackers         int
	MaxMetadataSize     uint32
	MaxPieceLayerHashes uint32
	DiscoveryTimeout    time.Duration
	DialTimeout         time.Duration
	HandshakeTimeout    time.Duration
	RequestTimeout      time.Duration
	WriteTimeout        time.Duration
}

// MagnetResult contains complete metainfo and bounded discovery routes ready
// to pass to Client.AddPeer. An address can occur more than once to preserve
// protocol and provenance; AddPeer merges those routes. PeerID is the stable ID
// used for all bootstrap announces and peer sessions.
type MagnetResult struct {
	MetaInfo   *metainfo.MetaInfo
	Candidates []Candidate
	PeerID     [20]byte
}

type magnetTrackerRegistration struct {
	client     *tracker.Client
	trackerURL string
	start      tracker.AnnounceRequest
	stop       tracker.AnnounceRequest
	active     bool
}

type magnetTrackerLifecycle struct {
	mu            sync.Mutex
	registrations []*magnetTrackerRegistration
}

// ResolveMagnet discovers peers and retrieves a magnet's exact info dictionary
// and required v2 piece layers. Bootstrap tracker announces use left=1 because
// the real size is unavailable and left=0 would incorrectly claim completion.
func ResolveMagnet(ctx context.Context, uri magnet.URI, config MagnetConfig) (MagnetResult, error) {
	if ctx == nil {
		return MagnetResult{}, fmt.Errorf("client: nil magnet context")
	}
	if _, err := magnet.Format(uri); err != nil {
		return MagnetResult{}, fmt.Errorf("client: invalid magnet: %w", err)
	}
	trackers := uniqueMagnetTrackers(uri.Trackers)
	if err := defaultMagnetConfig(&config, len(trackers)); err != nil {
		return MagnetResult{}, err
	}
	if len(trackers) > config.MaxTrackers {
		return MagnetResult{}, fmt.Errorf("client: magnet has %d trackers, limit is %d", len(trackers), config.MaxTrackers)
	}
	if config.PeerID == ([20]byte{}) {
		for config.PeerID == ([20]byte{}) {
			if _, err := io.ReadFull(cryptorand.Reader, config.PeerID[:]); err != nil {
				return MagnetResult{}, fmt.Errorf("client: generate magnet peer ID: %w", err)
			}
		}
	}

	candidates := newMagnetCandidateSet(config.MaxCandidates, config.PeerID)
	for _, endpoint := range uri.Peers {
		for _, protocol := range magnetProtocols(uri.Hashes) {
			candidates.add(Candidate{Address: endpoint.String(), Protocol: protocol, Source: SourceDirect})
		}
		if candidates.endpointCount() >= config.MaxCandidates {
			break
		}
	}

	trackerClient := config.TrackerClient
	if trackerClient == nil && len(trackers) != 0 {
		trackerClient = tracker.NewClient(&http.Client{Timeout: config.DiscoveryTimeout})
	}
	trackerLifecycle := &magnetTrackerLifecycle{}
	defer trackerLifecycle.stopAll()
	dhtCtx, cancelDHT := context.WithCancel(ctx)
	defer cancelDHT()
	var discovery sync.WaitGroup
	for _, trackerURL := range trackers {
		for _, advertised := range magnetTrackerHashes(uri.Hashes) {
			trackerURL, advertised := trackerURL, advertised
			discovery.Add(1)
			go func() {
				defer discovery.Done()
				opCtx, cancel := context.WithTimeout(ctx, config.DiscoveryTimeout)
				defer cancel()
				key, err := magnetTrackerKey()
				if err != nil {
					candidates.addError(fmt.Errorf("tracker %s (%s): %w", trackerURL, protocolName(advertised.protocol), err))
					return
				}
				request := tracker.AnnounceRequest{
					Event:    tracker.EventStarted,
					Left:     1,
					NumWant:  min(config.MaxCandidates, math.MaxInt32),
					Port:     config.Port,
					InfoHash: advertised.hash,
					PeerID:   config.PeerID,
					Key:      key,
				}
				registration := trackerLifecycle.add(trackerClient, trackerURL, request)
				response, err := trackerClient.Announce(opCtx, trackerURL, request)
				if err != nil {
					candidates.addError(fmt.Errorf("tracker %s (%s): %w", trackerURL, protocolName(advertised.protocol), err))
					return
				}
				registration.start.TrackerID = response.TrackerID
				registration.stop.TrackerID = response.TrackerID
				for _, discovered := range response.Peers {
					candidates.add(Candidate{
						Address:  discovered.String(),
						Tracker:  trackerURL,
						PeerID:   discovered.PeerID,
						Protocol: advertised.protocol,
						Source:   SourceTracker,
					})
				}
			}()
		}
	}
	if config.DHTNode != nil {
		for _, advertised := range magnetDHTHashes(uri.Hashes) {
			advertised := advertised
			discovery.Add(1)
			go func() {
				defer discovery.Done()
				opCtx, cancel := context.WithTimeout(dhtCtx, config.DiscoveryTimeout)
				defer cancel()
				lookup, err := config.DHTNode.GetPeers(opCtx, advertised.hash)
				if err != nil {
					if dhtCtx.Err() == nil {
						candidates.addError(fmt.Errorf("dht (%s): %w", protocolName(advertised.protocol), err))
					}
					return
				}
				for _, discovered := range lookup.Peers {
					candidates.add(Candidate{Address: discovered.String(), Protocol: advertised.protocol, Source: SourceDHT})
				}
			}()
		}
	}
	discoveryDone := make(chan struct{})
	go func() {
		discovery.Wait()
		close(discoveryDone)
	}()

	attempted := make(map[magnetAttempt]struct{})
	var failures []error
	var metadata *metainfo.MetaInfo
	var source Candidate
	var bootstrap *magnetPeerSession
	discoveryFinished := false
	for metadata == nil {
		progressed := false
		for _, candidate := range candidates.snapshot() {
			attempt := magnetAttempt{address: candidate.Address, protocol: candidate.Protocol}
			if _, ok := attempted[attempt]; ok {
				continue
			}
			attempted[attempt] = struct{}{}
			progressed = true
			var err error
			metadata, bootstrap, err = fetchMagnetMetadata(ctx, uri.Hashes, candidate, config)
			if err == nil {
				source = candidate
				break
			}
			failures = append(failures, fmt.Errorf("peer %s (%s): %w", candidate.Address, protocolName(candidate.Protocol), err))
			if err := ctx.Err(); err != nil {
				cancelDHT()
				<-discoveryDone
				return MagnetResult{}, context.Cause(ctx)
			}
		}
		if metadata != nil {
			break
		}
		if progressed {
			continue
		}
		if discoveryFinished {
			if ctx.Err() != nil {
				return MagnetResult{}, context.Cause(ctx)
			}
			failures = append(failures, candidates.errors()...)
			if len(attempted) == 0 {
				failures = append(failures, fmt.Errorf("client: magnet discovery returned no peer candidates"))
			}
			return MagnetResult{}, fmt.Errorf("client: resolve magnet: %w", errors.Join(failures...))
		}
		select {
		case <-ctx.Done():
			cancelDHT()
			<-discoveryDone
			return MagnetResult{}, context.Cause(ctx)
		case <-candidates.changed:
		case <-discoveryDone:
			discoveryFinished = true
		}
	}

	// Private status is now known, so no further public-swarm DHT work is safe.
	cancelDHT()
	if metadata.Info.Private && source.Source != SourceTracker {
		bootstrap.close()
	}
	<-discoveryDone
	defer bootstrap.close()
	if err := ctx.Err(); err != nil {
		bootstrap.close()
		return MagnetResult{}, context.Cause(ctx)
	}

	resolvedCandidates := candidates.snapshot()
	if metadata.Info.Private {
		resolvedCandidates = filterMagnetCandidates(resolvedCandidates, func(candidate Candidate) bool {
			return candidate.Source == SourceTracker
		})
		activeTracker := source.Tracker
		if source.Source != SourceTracker && len(resolvedCandidates) != 0 {
			activeTracker = resolvedCandidates[0].Tracker
		}
		if activeTracker != "" {
			if err := trackerLifecycle.activate(ctx, activeTracker, config.DiscoveryTimeout); err != nil {
				bootstrap.close()
				return MagnetResult{}, fmt.Errorf("client: select private tracker: %w", err)
			}
		}
	}
	graftMagnetTrackers(metadata, trackers)
	if metadata.Info.HasV2() {
		needs, err := magnetPieceLayerNeeds(metadata, config.MaxPieceLayerHashes)
		if err != nil {
			bootstrap.close()
			return MagnetResult{}, err
		}
		if len(needs) == 0 {
			err = metadata.SetPieceLayers(map[metainfo.HashV2][]metainfo.HashV2{})
		} else {
			err = resolveMagnetPieceLayers(ctx, metadata, needs, source, bootstrap, resolvedCandidates, trackerLifecycle, config)
			bootstrap = nil
		}
		if err != nil {
			failures = append(failures, candidates.errors()...)
			failures = append(failures, err)
			return MagnetResult{}, fmt.Errorf("client: resolve magnet: %w", errors.Join(failures...))
		}
	}
	if bootstrap != nil {
		bootstrap.close()
	}
	sortMagnetCandidates(resolvedCandidates)
	return MagnetResult{MetaInfo: metadata, Candidates: resolvedCandidates, PeerID: config.PeerID}, nil
}

func (lifecycle *magnetTrackerLifecycle) add(client *tracker.Client, trackerURL string, request tracker.AnnounceRequest) *magnetTrackerRegistration {
	stop := request
	stop.Event = tracker.EventStopped
	stop.NumWant = 0
	registration := &magnetTrackerRegistration{client: client, trackerURL: trackerURL, start: request, stop: stop, active: true}
	lifecycle.mu.Lock()
	lifecycle.registrations = append(lifecycle.registrations, registration)
	lifecycle.mu.Unlock()
	return registration
}

func (lifecycle *magnetTrackerLifecycle) snapshot() []*magnetTrackerRegistration {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	return append([]*magnetTrackerRegistration(nil), lifecycle.registrations...)
}

func (lifecycle *magnetTrackerLifecycle) stopAll() {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTrackerStop)
	defer cancel()
	_ = stopMagnetTrackers(ctx, lifecycle.snapshot())
}

func (lifecycle *magnetTrackerLifecycle) activate(ctx context.Context, trackerURL string, timeout time.Duration) error {
	registrations := lifecycle.snapshot()
	var previous, selected []*magnetTrackerRegistration
	for _, registration := range registrations {
		if registration.trackerURL == trackerURL {
			selected = append(selected, registration)
		} else if registration.active {
			previous = append(previous, registration)
		}
	}
	if len(selected) == 0 {
		return fmt.Errorf("tracker %s has no bootstrap registration", trackerURL)
	}
	stopCtx, cancelStop := context.WithTimeout(ctx, defaultTrackerStop)
	err := stopMagnetTrackers(stopCtx, previous)
	cancelStop()
	if err != nil {
		return fmt.Errorf("stop previous private tracker: %w", err)
	}

	startCtx, cancelStart := context.WithTimeout(ctx, timeout)
	defer cancelStart()
	type result struct {
		registration *magnetTrackerRegistration
		response     *tracker.AnnounceResponse
		err          error
	}
	results := make(chan result, len(selected))
	pending := 0
	for _, registration := range selected {
		if registration.active {
			continue
		}
		pending++
		registration.active = true
		go func(registration *magnetTrackerRegistration) {
			response, err := registration.client.Announce(startCtx, registration.trackerURL, registration.start)
			results <- result{registration: registration, response: response, err: err}
		}(registration)
	}
	var failures []error
	for range pending {
		result := <-results
		if result.err != nil {
			failures = append(failures, fmt.Errorf("tracker %s: %w", trackerURL, result.err))
			continue
		}
		result.registration.start.TrackerID = result.response.TrackerID
		result.registration.stop.TrackerID = result.response.TrackerID
	}
	if len(failures) == 0 {
		return nil
	}
	stopCtx, cancelStop = context.WithTimeout(context.Background(), defaultTrackerStop)
	_ = stopMagnetTrackers(stopCtx, selected)
	cancelStop()
	return errors.Join(failures...)
}

func stopMagnetTrackers(ctx context.Context, registrations []*magnetTrackerRegistration) error {
	var active []*magnetTrackerRegistration
	for _, registration := range registrations {
		if registration.active {
			active = append(active, registration)
		}
	}
	if len(active) == 0 {
		return nil
	}
	var workers sync.WaitGroup
	failures := make(chan error, len(active))
	workers.Add(len(active))
	for _, registration := range active {
		registration := registration
		go func() {
			defer workers.Done()
			if _, err := registration.client.Announce(ctx, registration.trackerURL, registration.stop); err != nil {
				failures <- fmt.Errorf("tracker %s: %w", registration.trackerURL, err)
				return
			}
			registration.active = false
		}()
	}
	workers.Wait()
	close(failures)
	var joined []error
	for err := range failures {
		joined = append(joined, err)
	}
	return errors.Join(joined...)
}

func magnetTrackerKey() (uint32, error) {
	var raw [4]byte
	for {
		if _, err := io.ReadFull(cryptorand.Reader, raw[:]); err != nil {
			return 0, fmt.Errorf("generate announce key: %w", err)
		}
		if key := binary.BigEndian.Uint32(raw[:]); key != 0 {
			return key, nil
		}
	}
}

func defaultMagnetConfig(config *MagnetConfig, trackerCount int) error {
	if config.MaxCandidates == 0 {
		config.MaxCandidates = defaultMaxCandidates
	}
	if config.MaxTrackers == 0 {
		config.MaxTrackers = defaultMagnetMaxTrackers
	}
	if config.MaxMetadataSize == 0 {
		config.MaxMetadataSize = peer.DefaultMaxMetadataSize
	}
	if config.MaxPieceLayerHashes == 0 {
		config.MaxPieceLayerHashes = defaultMagnetMaxPieceLayerHashes
	}
	if config.DiscoveryTimeout == 0 {
		config.DiscoveryTimeout = defaultMagnetDiscoveryTimeout
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
	if config.MaxCandidates < 1 || config.MaxTrackers < 1 || config.MaxMetadataSize == 0 || config.MaxPieceLayerHashes < 1 {
		return fmt.Errorf("client: magnet limits must be positive")
	}
	if config.DiscoveryTimeout < 0 || config.DialTimeout < 0 || config.HandshakeTimeout < 0 || config.RequestTimeout < 0 || config.WriteTimeout < 0 {
		return fmt.Errorf("client: magnet timeouts must be positive")
	}
	if trackerCount != 0 && config.Port == 0 {
		return fmt.Errorf("client: magnet tracker announces require a nonzero port")
	}
	if config.DHTNode != nil && !config.UsePublicDHT {
		return fmt.Errorf("client: UsePublicDHT must acknowledge pre-metadata DHT discovery")
	}
	if config.DialContext == nil {
		config.DialContext = (&net.Dialer{}).DialContext
	}
	return nil
}

type magnetTrackerHash struct {
	protocol peer.ProtocolVersion
	hash     metainfo.Hash
}

func magnetTrackerHashes(hashes metainfo.Hashes) []magnetTrackerHash {
	result := make([]magnetTrackerHash, 0, 2)
	if hashes.V1 != nil {
		result = append(result, magnetTrackerHash{protocol: peer.ProtocolV1, hash: *hashes.V1})
	}
	if hashes.V2 != nil {
		var truncated metainfo.Hash
		copy(truncated[:], hashes.V2[:len(truncated)])
		result = append(result, magnetTrackerHash{protocol: peer.ProtocolV2, hash: truncated})
	}
	return result
}

type magnetDHTHash struct {
	protocol peer.ProtocolVersion
	hash     dht.ID
}

func magnetDHTHashes(hashes metainfo.Hashes) []magnetDHTHash {
	trackerHashes := magnetTrackerHashes(hashes)
	result := make([]magnetDHTHash, len(trackerHashes))
	for index, advertised := range trackerHashes {
		result[index] = magnetDHTHash{protocol: advertised.protocol, hash: dht.ID(advertised.hash)}
	}
	return result
}

func magnetProtocols(hashes metainfo.Hashes) []peer.ProtocolVersion {
	result := make([]peer.ProtocolVersion, 0, 2)
	if hashes.V2 != nil {
		result = append(result, peer.ProtocolV2)
	}
	if hashes.V1 != nil {
		result = append(result, peer.ProtocolV1)
	}
	return result
}

func uniqueMagnetTrackers(trackers []string) []string {
	seen := make(map[string]struct{}, len(trackers))
	result := make([]string, 0, len(trackers))
	for _, trackerURL := range trackers {
		if _, ok := seen[trackerURL]; ok {
			continue
		}
		seen[trackerURL] = struct{}{}
		result = append(result, trackerURL)
	}
	return result
}

type magnetEndpoint struct {
	address string
	routes  []Candidate
}

type magnetCandidateSet struct {
	mu       sync.Mutex
	max      int
	peerID   [20]byte
	byAddr   map[string]*magnetEndpoint
	order    []string
	failures []error
	changed  chan struct{}
}

func newMagnetCandidateSet(maximum int, peerID [20]byte) *magnetCandidateSet {
	return &magnetCandidateSet{
		max:     maximum,
		peerID:  peerID,
		byAddr:  make(map[string]*magnetEndpoint),
		changed: make(chan struct{}, 1),
	}
}

func (set *magnetCandidateSet) add(candidate Candidate) {
	if candidate.PeerID != ([20]byte{}) && candidate.PeerID == set.peerID {
		return
	}
	address, err := canonicalAddress(candidate.Address)
	if err != nil {
		set.addError(err)
		return
	}
	candidate.Address = address
	set.mu.Lock()
	endpoint := set.byAddr[address]
	if endpoint == nil && len(set.byAddr) >= set.max && candidate.Source == SourceTracker {
		for index := len(set.order) - 1; index >= 0; index-- {
			old := set.byAddr[set.order[index]]
			if old != nil && !magnetHasTrackerRoute(old.routes) {
				delete(set.byAddr, old.address)
				set.order = append(set.order[:index], set.order[index+1:]...)
				break
			}
		}
	}
	endpoint = set.byAddr[address]
	if endpoint == nil {
		if len(set.byAddr) >= set.max {
			set.mu.Unlock()
			return
		}
		endpoint = &magnetEndpoint{address: address}
		set.byAddr[address] = endpoint
		set.order = append(set.order, address)
	}
	for _, existing := range endpoint.routes {
		if sameMagnetRoute(existing, candidate) {
			set.mu.Unlock()
			return
		}
	}
	endpoint.routes = append(endpoint.routes, candidate)
	set.mu.Unlock()
	select {
	case set.changed <- struct{}{}:
	default:
	}
}

func sameMagnetRoute(left, right Candidate) bool {
	left.PeerID = [20]byte{}
	right.PeerID = [20]byte{}
	return left == right
}

func (set *magnetCandidateSet) addError(err error) {
	if err == nil {
		return
	}
	set.mu.Lock()
	set.failures = append(set.failures, err)
	set.mu.Unlock()
}

func (set *magnetCandidateSet) endpointCount() int {
	set.mu.Lock()
	defer set.mu.Unlock()
	return len(set.byAddr)
}

func (set *magnetCandidateSet) snapshot() []Candidate {
	set.mu.Lock()
	defer set.mu.Unlock()
	var result []Candidate
	for _, address := range set.order {
		if endpoint := set.byAddr[address]; endpoint != nil {
			result = append(result, endpoint.routes...)
		}
	}
	return result
}

func (set *magnetCandidateSet) errors() []error {
	set.mu.Lock()
	defer set.mu.Unlock()
	return append([]error(nil), set.failures...)
}

func magnetHasTrackerRoute(routes []Candidate) bool {
	for _, route := range routes {
		if route.Source == SourceTracker {
			return true
		}
	}
	return false
}

type magnetAttempt struct {
	address  string
	protocol peer.ProtocolVersion
}

type magnetHashEvent struct {
	hashes *peer.Hashes
	reject *peer.HashRequest
}

type magnetPeerSession struct {
	session   *peer.Session
	cancel    context.CancelFunc
	runDone   chan struct{}
	extension chan peer.ExtensionHandshake
	metadata  chan peer.MetadataMessage
	hashes    chan magnetHashEvent
	closeOnce sync.Once
}

func openMagnetPeer(ctx context.Context, hashes metainfo.Hashes, candidate Candidate, config MagnetConfig) (*magnetPeerSession, error) {
	dialCtx, cancelDial := context.WithTimeout(ctx, config.DialTimeout)
	conn, err := config.DialContext(dialCtx, "tcp", candidate.Address)
	cancelDial()
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	sessionCtx, cancelSession := context.WithCancel(ctx)
	runtime := &magnetPeerSession{
		cancel:    cancelSession,
		runDone:   make(chan struct{}),
		extension: make(chan peer.ExtensionHandshake, 1),
		metadata:  make(chan peer.MetadataMessage, 1),
		hashes:    make(chan magnetHashEvent, 1),
	}
	sendMetadata := func(message peer.MetadataMessage) {
		select {
		case runtime.metadata <- message:
		case <-sessionCtx.Done():
		}
	}
	sendHashes := func(event magnetHashEvent) {
		select {
		case runtime.hashes <- event:
		case <-sessionCtx.Done():
		}
	}
	sessionConfig := peer.SessionConfig{
		PeerID:       config.PeerID,
		Hashes:       hashes,
		PreferV2:     candidate.Protocol == peer.ProtocolV2,
		Outgoing:     true,
		MetadataOnly: true,
		ExtensionHandshake: peer.ExtensionHandshake{
			Client:     "go-torrent",
			Extensions: map[string]uint8{peer.ExtensionMetadata: 1},
		},
		Callbacks: peer.SessionCallbacks{
			OnExtensionHandshake: func(handshake peer.ExtensionHandshake) {
				select {
				case runtime.extension <- handshake:
				default:
				}
			},
			OnMetadata: sendMetadata,
			OnHashes: func(hashes peer.Hashes) {
				copy := hashes
				sendHashes(magnetHashEvent{hashes: &copy})
			},
			OnHashReject: func(request peer.HashRequest) {
				copy := request
				sendHashes(magnetHashEvent{reject: &copy})
			},
		},
		HandshakeTimeout: config.HandshakeTimeout,
		RequestTimeout:   config.RequestTimeout,
		WriteTimeout:     config.WriteTimeout,
		ReadIdleTimeout:  config.RequestTimeout,
		MaxMetadataSize:  config.MaxMetadataSize,
	}
	if candidate.PeerID != ([20]byte{}) && candidate.Source != SourceTracker {
		expected := candidate.PeerID
		sessionConfig.ExpectedPeerID = &expected
	}
	session, err := peer.NewSession(conn, sessionConfig)
	if err != nil {
		cancelSession()
		_ = conn.Close()
		return nil, err
	}
	runtime.session = session
	go func() {
		_ = session.Run(sessionCtx)
		close(runtime.runDone)
	}()
	select {
	case <-session.Ready():
		snapshot := session.Snapshot()
		if snapshot.RemotePeerID == ([20]byte{}) || snapshot.RemotePeerID == config.PeerID {
			runtime.close()
			return nil, fmt.Errorf("peer returned an invalid peer ID")
		}
		if candidate.Protocol == peer.ProtocolV2 && snapshot.Version != peer.ProtocolV2 {
			runtime.close()
			return nil, fmt.Errorf("peer did not select v2")
		}
		return runtime, nil
	case <-session.Done():
		<-runtime.runDone
		return nil, session.Err()
	case <-ctx.Done():
		runtime.close()
		return nil, context.Cause(ctx)
	}
}

func (runtime *magnetPeerSession) close() {
	if runtime == nil {
		return
	}
	runtime.closeOnce.Do(func() {
		runtime.cancel()
		_ = runtime.session.Close()
		<-runtime.runDone
	})
}

func fetchMagnetMetadata(ctx context.Context, hashes metainfo.Hashes, candidate Candidate, config MagnetConfig) (*metainfo.MetaInfo, *magnetPeerSession, error) {
	runtime, err := openMagnetPeer(ctx, hashes, candidate, config)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (*metainfo.MetaInfo, *magnetPeerSession, error) {
		runtime.close()
		return nil, nil, err
	}
	handshake, err := waitMagnetEvent(ctx, runtime, runtime.extension, config.RequestTimeout)
	if err != nil {
		return fail(fmt.Errorf("extension handshake: %w", err))
	}
	if handshake.Extensions[peer.ExtensionMetadata] == 0 {
		return fail(fmt.Errorf("peer did not negotiate %s", peer.ExtensionMetadata))
	}
	if handshake.MetadataSize == nil || *handshake.MetadataSize == 0 || *handshake.MetadataSize > config.MaxMetadataSize {
		var size uint32
		if handshake.MetadataSize != nil {
			size = *handshake.MetadataSize
		}
		return fail(fmt.Errorf("metadata_size %d is outside 1..%d", size, config.MaxMetadataSize))
	}
	assembler, err := peer.NewMetadataAssembler(peer.MetadataAssemblerConfig{
		Size:    *handshake.MetadataSize,
		MaxSize: config.MaxMetadataSize,
		Hashes:  hashes,
	})
	if err != nil {
		return fail(err)
	}
	blocks := (uint64(*handshake.MetadataSize) + uint64(peer.MetadataBlockSize) - 1) / uint64(peer.MetadataBlockSize)
	for pieceIndex := uint64(0); pieceIndex < blocks; pieceIndex++ {
		request := peer.MetadataMessage{Type: peer.MetadataRequest, Piece: uint32(pieceIndex)}
		if err := runtime.session.SendMetadata(request); err != nil {
			return fail(fmt.Errorf("request metadata piece %d: %w", pieceIndex, err))
		}
		message, err := waitMagnetEvent(ctx, runtime, runtime.metadata, config.RequestTimeout)
		if err != nil {
			return fail(fmt.Errorf("metadata piece %d: %w", pieceIndex, err))
		}
		if uint64(message.Piece) != pieceIndex {
			return fail(fmt.Errorf("metadata response piece %d does not match request %d", message.Piece, pieceIndex))
		}
		if message.Type == peer.MetadataReject {
			return fail(fmt.Errorf("metadata piece %d was rejected", pieceIndex))
		}
		if message.Type != peer.MetadataData {
			return fail(fmt.Errorf("metadata piece %d received message type %d", pieceIndex, message.Type))
		}
		complete, err := assembler.Add(message)
		if err != nil {
			return fail(err)
		}
		if complete != (pieceIndex+1 == blocks) {
			return fail(fmt.Errorf("metadata assembly completed at unexpected piece %d", pieceIndex))
		}
	}
	rawInfo, ok := assembler.Bytes()
	if !ok {
		return fail(fmt.Errorf("metadata assembly is incomplete"))
	}
	meta, err := metainfo.DecodeInfo(rawInfo)
	if err != nil {
		return fail(err)
	}
	if err := verifyMagnetHashes(meta, hashes); err != nil {
		return fail(err)
	}
	return meta, runtime, nil
}

func waitMagnetEvent[T any](ctx context.Context, runtime *magnetPeerSession, events <-chan T, timeout time.Duration) (T, error) {
	var zero T
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case event := <-events:
		return event, nil
	case <-runtime.session.Done():
		return zero, runtime.session.Err()
	case <-ctx.Done():
		return zero, context.Cause(ctx)
	case <-timer.C:
		return zero, context.DeadlineExceeded
	}
}

func verifyMagnetHashes(meta *metainfo.MetaInfo, advertised metainfo.Hashes) error {
	decoded := meta.Hashes()
	if advertised.V1 != nil && (decoded.V1 == nil || *decoded.V1 != *advertised.V1) {
		return fmt.Errorf("decoded metadata does not contain the advertised v1 hash")
	}
	if advertised.V2 != nil && (decoded.V2 == nil || *decoded.V2 != *advertised.V2) {
		return fmt.Errorf("decoded metadata does not contain the advertised v2 hash")
	}
	return nil
}

type magnetPieceLayerNeed struct {
	root  metainfo.HashV2
	count uint32
}

func magnetPieceLayerNeeds(meta *metainfo.MetaInfo, maximum uint32) ([]magnetPieceLayerNeed, error) {
	counts := make(map[metainfo.HashV2]uint32)
	var total uint64
	for _, file := range meta.Info.V2Files {
		if file.Length <= meta.Info.PieceLength {
			continue
		}
		count := uint64(1 + (file.Length-1)/meta.Info.PieceLength)
		if count > math.MaxUint32 {
			return nil, fmt.Errorf("client: v2 piece layer for %s exceeds the uint32 wire range", *file.PiecesRoot)
		}
		root := *file.PiecesRoot
		if previous, ok := counts[root]; ok {
			if uint64(previous) != count {
				return nil, fmt.Errorf("client: v2 pieces root %s has incompatible file lengths", root)
			}
			continue
		}
		counts[root] = uint32(count)
		total += count
		if total > uint64(maximum) {
			return nil, fmt.Errorf("client: v2 piece layers require %d hashes, limit is %d", total, maximum)
		}
	}
	needs := make([]magnetPieceLayerNeed, 0, len(counts))
	for root, count := range counts {
		needs = append(needs, magnetPieceLayerNeed{root: root, count: count})
	}
	sort.Slice(needs, func(i, j int) bool { return bytes.Compare(needs[i].root[:], needs[j].root[:]) < 0 })
	return needs, nil
}

func resolveMagnetPieceLayers(ctx context.Context, meta *metainfo.MetaInfo, needs []magnetPieceLayerNeed, source Candidate, bootstrap *magnetPeerSession, candidates []Candidate, trackers *magnetTrackerLifecycle, config MagnetConfig) error {
	defer bootstrap.close()
	allowedSource := !meta.Info.Private || source.Source == SourceTracker
	type attemptKey struct {
		address string
		tracker string
	}
	attempted := make(map[attemptKey]struct{})
	var failures []error
	if allowedSource && bootstrap.session.Snapshot().Version == peer.ProtocolV2 {
		attempted[attemptKey{address: source.Address, tracker: source.Tracker}] = struct{}{}
		if err := fetchMagnetPieceLayers(ctx, bootstrap, meta, needs, config.RequestTimeout); err == nil {
			return nil
		} else {
			failures = append(failures, fmt.Errorf("peer %s (v2 piece layers): %w", source.Address, err))
		}
	}
	bootstrap.close()

	probes := make([]Candidate, 0, len(candidates)+1)
	if !meta.Info.Private {
		probes = append(probes, source)
	}
	if meta.Info.Private {
		var trackers []string
		seen := make(map[string]struct{})
		if source.Source == SourceTracker {
			trackers = append(trackers, source.Tracker)
			seen[source.Tracker] = struct{}{}
		}
		for _, candidate := range candidates {
			if _, ok := seen[candidate.Tracker]; !ok {
				trackers = append(trackers, candidate.Tracker)
				seen[candidate.Tracker] = struct{}{}
			}
		}
		for _, trackerURL := range trackers {
			for _, candidate := range candidates {
				if candidate.Tracker == trackerURL {
					probes = append(probes, candidate)
				}
			}
		}
	} else {
		probes = append(probes, candidates...)
	}
	activeTracker := source.Tracker
	failedTrackers := make(map[string]struct{})
	for _, candidate := range probes {
		if meta.Info.Private && candidate.Tracker != activeTracker {
			if _, failed := failedTrackers[candidate.Tracker]; failed {
				continue
			}
			if err := trackers.activate(ctx, candidate.Tracker, config.DiscoveryTimeout); err != nil {
				failedTrackers[candidate.Tracker] = struct{}{}
				failures = append(failures, fmt.Errorf("tracker %s failover: %w", candidate.Tracker, err))
				continue
			}
			activeTracker = candidate.Tracker
		}
		key := attemptKey{address: candidate.Address, tracker: candidate.Tracker}
		if _, ok := attempted[key]; ok {
			continue
		}
		attempted[key] = struct{}{}
		candidate.Protocol = peer.ProtocolV2
		runtime, err := openMagnetPeer(ctx, meta.Hashes(), candidate, config)
		if err == nil {
			err = fetchMagnetPieceLayers(ctx, runtime, meta, needs, config.RequestTimeout)
			runtime.close()
		}
		if err == nil {
			return nil
		}
		failures = append(failures, fmt.Errorf("peer %s (v2 piece layers): %w", candidate.Address, err))
		if ctx.Err() != nil {
			return context.Cause(ctx)
		}
	}
	if len(attempted) == 0 {
		failures = append(failures, fmt.Errorf("no candidates remain for v2 piece layers"))
	}
	return errors.Join(failures...)
}

func fetchMagnetPieceLayers(ctx context.Context, runtime *magnetPeerSession, meta *metainfo.MetaInfo, needs []magnetPieceLayerNeed, timeout time.Duration) error {
	baseLayer := uint32(bits.TrailingZeros64(uint64(meta.Info.PieceLength / int64(peer.MetadataBlockSize))))
	layers := make(map[metainfo.HashV2][]metainfo.HashV2, len(needs))
	for _, need := range needs {
		padded := uint64(1) << bits.Len64(uint64(need.count)-1)
		if padded > math.MaxUint32 {
			return fmt.Errorf("piece layer for root %s exceeds the BEP 52 index range", need.root)
		}
		if padded > uint64(int(^uint(0)>>1)) {
			return fmt.Errorf("piece layer for root %s exceeds the platform slice limit", need.root)
		}
		values := make([]metainfo.HashV2, 0, padded)
		for index := uint64(0); index < padded; {
			length := min(uint64(peer.RecommendedMaxHashRequestLength), padded-index)
			request := peer.HashRequest{
				PiecesRoot: need.root,
				BaseLayer:  baseLayer,
				Index:      uint32(index),
				Length:     uint32(length),
			}
			if err := runtime.session.SendHashRequest(request); err != nil {
				return fmt.Errorf("request hashes for root %s at %d: %w", need.root, index, err)
			}
			event, err := waitMagnetEvent(ctx, runtime, runtime.hashes, timeout)
			if err != nil {
				return fmt.Errorf("hashes for root %s at %d: %w", need.root, index, err)
			}
			switch {
			case event.reject != nil:
				if *event.reject != request {
					return fmt.Errorf("hash reject does not match request for root %s at %d", need.root, index)
				}
				return fmt.Errorf("hash request for root %s at %d was rejected", need.root, index)
			case event.hashes == nil:
				return fmt.Errorf("empty hash response for root %s at %d", need.root, index)
			case event.hashes.Request != request:
				return fmt.Errorf("hash response does not match request for root %s at %d", need.root, index)
			default:
				values = append(values, event.hashes.Values...)
			}
			index += length
		}
		layers[need.root] = append([]metainfo.HashV2(nil), values[:need.count]...)
	}
	if err := meta.SetPieceLayers(layers); err != nil {
		return fmt.Errorf("validate piece layers: %w", err)
	}
	return nil
}

func graftMagnetTrackers(meta *metainfo.MetaInfo, trackers []string) {
	if len(trackers) == 0 {
		return
	}
	meta.Announce = trackers[0]
	meta.AnnounceList = [][]string{append([]string(nil), trackers...)}
}

func filterMagnetCandidates(candidates []Candidate, keep func(Candidate) bool) []Candidate {
	result := candidates[:0]
	for _, candidate := range candidates {
		if keep(candidate) {
			result = append(result, candidate)
		}
	}
	return result
}

func sortMagnetCandidates(candidates []Candidate) {
	sort.Slice(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if left.Address != right.Address {
			return left.Address < right.Address
		}
		if left.Protocol != right.Protocol {
			return left.Protocol < right.Protocol
		}
		if left.Source != right.Source {
			return left.Source < right.Source
		}
		if left.Tracker != right.Tracker {
			return left.Tracker < right.Tracker
		}
		return bytes.Compare(left.PeerID[:], right.PeerID[:]) < 0
	})
}
