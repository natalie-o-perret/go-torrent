package dht

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

var (
	ErrClosed           = errors.New("dht: node is closed")
	ErrTransactionLimit = errors.New("dht: transaction limit reached")
	ErrNoContacts       = errors.New("dht: no routing contacts")
	ErrNoTokens         = errors.New("dht: no announce tokens")
)

const clientVersion = "GT01"

// Config controls all memory, concurrency, lifetime, and rate bounds.
type Config struct {
	ID                  ID
	ReadOnly            bool
	OwnPacketConn       bool
	Alpha               int
	QueryTimeout        time.Duration
	GoodDuration        time.Duration
	TokenPeriod         time.Duration
	PeerTTL             time.Duration
	MaxContacts         int
	MaxTransactions     int
	MaxCandidates       int
	MaxInfoHashes       int
	MaxPeersPerInfoHash int
	MaxRateSources      int
	MaxPacketsPerSecond int
	Clock               func() time.Time
	Random              io.Reader
}

func (config Config) defaults() (Config, error) {
	if config.Alpha == 0 {
		config.Alpha = 3
	}
	if config.QueryTimeout == 0 {
		config.QueryTimeout = 2 * time.Second
	}
	if config.GoodDuration == 0 {
		config.GoodDuration = 15 * time.Minute
	}
	if config.TokenPeriod == 0 {
		config.TokenPeriod = 5 * time.Minute
	}
	if config.PeerTTL == 0 {
		config.PeerTTL = 30 * time.Minute
	}
	if config.MaxContacts == 0 {
		config.MaxContacts = 512
	}
	if config.MaxTransactions == 0 {
		config.MaxTransactions = 256
	}
	if config.MaxCandidates == 0 {
		config.MaxCandidates = 256
	}
	if config.MaxInfoHashes == 0 {
		config.MaxInfoHashes = 1024
	}
	if config.MaxPeersPerInfoHash == 0 {
		config.MaxPeersPerInfoHash = 128
	}
	if config.MaxRateSources == 0 {
		config.MaxRateSources = 1024
	}
	if config.MaxPacketsPerSecond == 0 {
		config.MaxPacketsPerSecond = 256
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.Random == nil {
		config.Random = cryptorand.Reader
	}
	if config.Alpha < 1 || config.Alpha > K || config.QueryTimeout < time.Millisecond || config.GoodDuration <= 0 || config.TokenPeriod <= 0 || config.PeerTTL <= 0 {
		return Config{}, fmt.Errorf("dht: invalid concurrency or duration limit")
	}
	if config.MaxContacts < 1 || config.MaxContacts > K*IDLength*8 || config.MaxTransactions < 1 || config.MaxTransactions > 1<<16 || config.MaxCandidates < K || config.MaxCandidates > 4096 {
		return Config{}, fmt.Errorf("dht: invalid contact, transaction, or candidate limit")
	}
	if config.MaxInfoHashes < 1 || config.MaxInfoHashes > 65536 || config.MaxPeersPerInfoHash < 1 || config.MaxPeersPerInfoHash > 4096 {
		return Config{}, fmt.Errorf("dht: invalid peer-store limit")
	}
	if config.MaxRateSources < 1 || config.MaxRateSources > 65536 || config.MaxPacketsPerSecond < 1 || config.MaxPacketsPerSecond > 65536 {
		return Config{}, fmt.Errorf("dht: invalid packet-rate limit")
	}
	return config, nil
}

type transactionKey struct {
	endpoint netip.AddrPort
	id       string
}

type pendingCall struct {
	response chan Message
}

// Node is a bounded DHT client and server over one PacketConn.
type Node struct {
	conn   net.PacketConn
	config Config
	id     ID
	owned  bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once

	routing4 *RoutingTable
	routing6 *RoutingTable
	tokens   tokenManager
	peers    *peerStore
	rate     *rateLimiter

	transactionsMu  sync.Mutex
	transactions    map[transactionKey]*pendingCall
	nextTransaction uint16
	closeErr        error
}

// NewNode starts a node on conn. Close leaves conn open unless
// Config.OwnPacketConn is true. The PacketConn must be dedicated to the node
// until Close returns.
func NewNode(conn net.PacketConn, config Config) (*Node, error) {
	if conn == nil {
		return nil, fmt.Errorf("dht: nil PacketConn")
	}
	config, err := config.defaults()
	if err != nil {
		return nil, err
	}
	id := config.ID
	if id == (ID{}) {
		if _, err := io.ReadFull(config.Random, id[:]); err != nil {
			return nil, fmt.Errorf("dht: generate node ID: %w", err)
		}
	}
	secret := make([]byte, 32)
	if _, err := io.ReadFull(config.Random, secret); err != nil {
		return nil, fmt.Errorf("dht: generate token secret: %w", err)
	}
	var transactionSeed [2]byte
	if _, err := io.ReadFull(config.Random, transactionSeed[:]); err != nil {
		return nil, fmt.Errorf("dht: generate transaction seed: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	node := &Node{
		conn:            conn,
		config:          config,
		id:              id,
		owned:           config.OwnPacketConn,
		ctx:             ctx,
		cancel:          cancel,
		routing4:        NewRoutingTable(id, config.MaxContacts, config.GoodDuration),
		routing6:        NewRoutingTable(id, config.MaxContacts, config.GoodDuration),
		tokens:          newTokenManager(secret, config.TokenPeriod),
		peers:           newPeerStore(config.PeerTTL, config.MaxInfoHashes, config.MaxPeersPerInfoHash),
		rate:            newRateLimiter(config.MaxRateSources, config.MaxPacketsPerSecond),
		transactions:    make(map[transactionKey]*pendingCall),
		nextTransaction: binary.BigEndian.Uint16(transactionSeed[:]),
	}
	node.wg.Add(1)
	go node.readLoop()
	return node, nil
}

// Listen creates an owned UDP PacketConn and starts a node on it.
func Listen(network, address string, config Config) (*Node, error) {
	conn, err := net.ListenPacket(network, address)
	if err != nil {
		return nil, fmt.Errorf("dht: listen: %w", err)
	}
	config.OwnPacketConn = true
	node, err := NewNode(conn, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return node, nil
}

// ID returns the local node ID.
func (node *Node) ID() ID { return node.id }

// Addr returns the PacketConn's local endpoint.
func (node *Node) Addr() netip.AddrPort {
	endpoint, _ := endpointFromNetAddr(node.conn.LocalAddr())
	return endpoint
}

// Close stops the node. An owned PacketConn is closed. A caller-owned
// PacketConn is only given a temporary read deadline to stop the read loop.
func (node *Node) Close() error {
	node.once.Do(func() {
		node.cancel()
		if node.owned {
			node.closeErr = node.conn.Close()
		} else if err := node.conn.SetReadDeadline(time.Now()); err != nil {
			node.closeErr = fmt.Errorf("dht: interrupt PacketConn: %w", err)
			return
		}
		node.wg.Wait()
		if !node.owned {
			if err := node.conn.SetReadDeadline(time.Time{}); err != nil && node.closeErr == nil {
				node.closeErr = fmt.Errorf("dht: restore PacketConn deadline: %w", err)
			}
		}
	})
	return node.closeErr
}

func (node *Node) readLoop() {
	defer node.wg.Done()
	defer node.cancel()
	buffer := make([]byte, MaxPacketSize+1)
	for {
		count, source, err := node.conn.ReadFrom(buffer)
		if err != nil {
			if node.ctx.Err() != nil {
				return
			}
			if netError, ok := err.(net.Error); ok && netError.Timeout() {
				continue
			}
			return
		}
		if count == 0 || count > MaxPacketSize {
			continue
		}
		endpoint, err := endpointFromNetAddr(source)
		if err != nil || !validEndpoint(endpoint) || !node.rate.allow(endpoint.Addr(), node.config.Clock()) {
			continue
		}
		message, err := UnmarshalMessage(buffer[:count])
		if err != nil {
			continue
		}
		switch message.Type {
		case ResponseMessage, ErrorMessage:
			node.dispatch(endpoint, message)
		case QueryMessage:
			if !node.config.ReadOnly {
				node.handleQuery(endpoint, message)
			}
		}
	}
}

func (node *Node) dispatch(source netip.AddrPort, message Message) {
	key := transactionKey{endpoint: source, id: string(message.Transaction)}
	node.transactionsMu.Lock()
	pending := node.transactions[key]
	if pending != nil {
		delete(node.transactions, key)
	}
	node.transactionsMu.Unlock()
	if pending != nil {
		pending.response <- message
	}
}

func (node *Node) call(ctx context.Context, endpoint netip.AddrPort, expected *ID, method string, arguments map[string]any) (map[string]any, Contact, error) {
	if ctx == nil {
		return nil, Contact{}, fmt.Errorf("dht: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, Contact{}, err
	}
	endpoint = normalizeEndpoint(endpoint)
	if !validEndpoint(endpoint) {
		return nil, Contact{}, fmt.Errorf("dht: invalid destination %v", endpoint)
	}
	if err := node.ctx.Err(); err != nil {
		return nil, Contact{}, ErrClosed
	}

	key, pending, err := node.reserveTransaction(endpoint)
	if err != nil {
		return nil, Contact{}, err
	}
	message := Message{
		Transaction: []byte(key.id),
		Type:        QueryMessage,
		Query:       method,
		Arguments:   arguments,
		Version:     clientVersion,
		ReadOnly:    node.config.ReadOnly,
	}
	packet, err := MarshalMessage(message)
	if err != nil {
		node.removeTransaction(key, pending)
		return nil, Contact{}, err
	}
	if written, err := node.conn.WriteTo(packet, net.UDPAddrFromAddrPort(endpoint)); err != nil || written != len(packet) {
		node.removeTransaction(key, pending)
		if err == nil {
			err = io.ErrShortWrite
		}
		return nil, Contact{}, fmt.Errorf("dht: send %s: %w", method, err)
	}

	timer := time.NewTimer(node.config.QueryTimeout)
	defer timer.Stop()
	select {
	case response := <-pending.response:
		if response.Type == ErrorMessage {
			return nil, Contact{}, response.Error
		}
		responder, err := node.validateResponder(endpoint, expected, response.Response)
		if err != nil {
			node.markFailure(expected, endpoint)
			return nil, Contact{}, err
		}
		return response.Response, responder, nil
	case <-ctx.Done():
		node.removeTransaction(key, pending)
		return nil, Contact{}, ctx.Err()
	case <-node.ctx.Done():
		node.removeTransaction(key, pending)
		return nil, Contact{}, ErrClosed
	case <-timer.C:
		node.removeTransaction(key, pending)
		node.markFailure(expected, endpoint)
		return nil, Contact{}, fmt.Errorf("dht: %s %v: %w", method, endpoint, context.DeadlineExceeded)
	}
}

func (node *Node) reserveTransaction(endpoint netip.AddrPort) (transactionKey, *pendingCall, error) {
	node.transactionsMu.Lock()
	defer node.transactionsMu.Unlock()
	if len(node.transactions) >= node.config.MaxTransactions {
		return transactionKey{}, nil, ErrTransactionLimit
	}
	for attempts := 0; attempts < 1<<16; attempts++ {
		node.nextTransaction++
		var id [2]byte
		binary.BigEndian.PutUint16(id[:], node.nextTransaction)
		key := transactionKey{endpoint: endpoint, id: string(id[:])}
		if _, exists := node.transactions[key]; exists {
			continue
		}
		pending := &pendingCall{response: make(chan Message, 1)}
		node.transactions[key] = pending
		return key, pending, nil
	}
	return transactionKey{}, nil, ErrTransactionLimit
}

func (node *Node) removeTransaction(key transactionKey, pending *pendingCall) {
	node.transactionsMu.Lock()
	if node.transactions[key] == pending {
		delete(node.transactions, key)
	}
	node.transactionsMu.Unlock()
}

func (node *Node) validateResponder(endpoint netip.AddrPort, expected *ID, response map[string]any) (Contact, error) {
	id, err := idField(response, "id")
	if err != nil {
		return Contact{}, err
	}
	if expected != nil && id != *expected {
		return Contact{}, fmt.Errorf("dht: response node ID %s does not match %s", id, *expected)
	}
	if id == node.id {
		return Contact{}, fmt.Errorf("dht: remote endpoint reused local node ID")
	}
	if !ValidNodeID(id, endpoint.Addr()) {
		return Contact{}, fmt.Errorf("dht: node ID %s is invalid for %v", id, endpoint.Addr())
	}
	now := node.config.Clock()
	contact := Contact{ID: id, Addr: endpoint, LastResponse: now}
	node.routing(endpoint.Addr()).AddVerified(id, endpoint, now)
	return contact, nil
}

func (node *Node) markFailure(expected *ID, endpoint netip.AddrPort) {
	if expected != nil {
		node.routing(endpoint.Addr()).ObserveFailure(*expected, endpoint)
	}
}

func (node *Node) routing(addr netip.Addr) *RoutingTable {
	if familyOf(addr) == IPv4 {
		return node.routing4
	}
	return node.routing6
}

func (node *Node) handleQuery(source netip.AddrPort, message Message) {
	senderID, err := idField(message.Arguments, "id")
	if err != nil {
		node.sendError(source, message.Transaction, 203, "invalid node id")
		return
	}
	if !message.ReadOnly {
		node.routing(source.Addr()).ObserveQuery(senderID, source, node.config.Clock())
	}

	switch message.Query {
	case "ping":
		node.sendResponse(source, message.Transaction, map[string]any{"id": node.id[:]})
	case "find_node":
		target, err := idField(message.Arguments, "target")
		if err != nil {
			node.sendError(source, message.Transaction, 203, "invalid target")
			return
		}
		want4, want6, err := requestedFamilies(message.Arguments, source.Addr())
		if err != nil {
			node.sendError(source, message.Transaction, 203, "invalid want")
			return
		}
		response, err := node.nodeResponse(target, want4, want6)
		if err != nil {
			node.sendError(source, message.Transaction, 202, "server error")
			return
		}
		response["id"] = node.id[:]
		node.sendResponse(source, message.Transaction, response)
	case "get_peers":
		infoHash, err := idField(message.Arguments, "info_hash")
		if err != nil {
			node.sendError(source, message.Transaction, 203, "invalid info_hash")
			return
		}
		want4, want6, err := requestedFamilies(message.Arguments, source.Addr())
		if err != nil {
			node.sendError(source, message.Transaction, 203, "invalid want")
			return
		}
		response, err := node.nodeResponse(infoHash, want4, want6)
		if err != nil {
			node.sendError(source, message.Transaction, 202, "server error")
			return
		}
		response["id"] = node.id[:]
		response["token"] = node.tokens.token(source.Addr(), node.config.Clock())
		peers := node.peers.get(infoHash, familyOf(source.Addr()), node.config.Clock())
		if len(peers) != 0 {
			values := make([]any, 0, len(peers))
			for _, peer := range peers {
				compact, encodeErr := EncodeCompactPeer(peer)
				if encodeErr == nil {
					values = append(values, compact)
				}
			}
			if len(values) != 0 {
				response["values"] = values
			}
		}
		node.sendResponse(source, message.Transaction, response)
	case "announce_peer":
		node.handleAnnounce(source, message, senderID)
	default:
		node.sendError(source, message.Transaction, 204, "method unknown")
	}
}

func (node *Node) handleAnnounce(source netip.AddrPort, message Message, _ ID) {
	infoHash, err := idField(message.Arguments, "info_hash")
	if err != nil {
		node.sendError(source, message.Transaction, 203, "invalid info_hash")
		return
	}
	token, err := bytesField(message.Arguments, "token", 1, 64)
	if err != nil || !node.tokens.valid(token, source.Addr(), node.config.Clock()) {
		node.sendError(source, message.Transaction, 203, "bad token")
		return
	}
	implied := int64(0)
	if raw, exists := message.Arguments["implied_port"]; exists {
		implied, err = integer(raw, "implied_port")
		if err != nil || (implied != 0 && implied != 1) {
			node.sendError(source, message.Transaction, 203, "invalid implied_port")
			return
		}
	}
	port, err := integer(message.Arguments["port"], "port")
	if err != nil || (implied == 0 && (port < 1 || port > 65535)) {
		node.sendError(source, message.Transaction, 203, "invalid port")
		return
	}
	peerPort := uint16(port)
	if implied == 1 {
		peerPort = source.Port()
	}
	node.peers.put(infoHash, netip.AddrPortFrom(source.Addr(), peerPort), node.config.Clock())
	node.sendResponse(source, message.Transaction, map[string]any{"id": node.id[:]})
}

func (node *Node) nodeResponse(target ID, want4, want6 bool) (map[string]any, error) {
	response := make(map[string]any, 2)
	now := node.config.Clock()
	if want4 {
		nodes, err := EncodeCompactNodes(node.routing4.Closest(target, K, now, true), IPv4)
		if err != nil {
			return nil, err
		}
		response["nodes"] = nodes
	}
	if want6 {
		nodes, err := EncodeCompactNodes(node.routing6.Closest(target, K, now, true), IPv6)
		if err != nil {
			return nil, err
		}
		response["nodes6"] = nodes
	}
	return response, nil
}

func requestedFamilies(arguments map[string]any, source netip.Addr) (bool, bool, error) {
	raw, exists := arguments["want"]
	if !exists {
		return familyOf(source) == IPv4, familyOf(source) == IPv6, nil
	}
	values, ok := raw.([]any)
	if !ok || len(values) == 0 || len(values) > 8 {
		return false, false, fmt.Errorf("dht: invalid want list")
	}
	var want4, want6 bool
	for _, rawValue := range values {
		value, ok := rawValue.(string)
		if !ok || len(value) > 16 {
			return false, false, fmt.Errorf("dht: invalid want value")
		}
		switch value {
		case "n4":
			want4 = true
		case "n6":
			want6 = true
		}
	}
	return want4, want6, nil
}

func (node *Node) sendResponse(destination netip.AddrPort, transaction []byte, response map[string]any) {
	node.send(destination, Message{
		Transaction: transaction,
		Type:        ResponseMessage,
		Response:    response,
		Version:     clientVersion,
		IP:          destination,
	})
}

func (node *Node) sendError(destination netip.AddrPort, transaction []byte, code int64, text string) {
	node.send(destination, Message{
		Transaction: transaction,
		Type:        ErrorMessage,
		Error:       &KRPCError{Code: code, Message: text},
		Version:     clientVersion,
		IP:          destination,
	})
}

func (node *Node) send(destination netip.AddrPort, message Message) {
	packet, err := MarshalMessage(message)
	if err != nil || node.ctx.Err() != nil {
		return
	}
	_, _ = node.conn.WriteTo(packet, net.UDPAddrFromAddrPort(destination))
}

func endpointFromNetAddr(address net.Addr) (netip.AddrPort, error) {
	switch value := address.(type) {
	case *net.UDPAddr:
		return normalizeEndpoint(value.AddrPort()), nil
	default:
		endpoint, err := netip.ParseAddrPort(address.String())
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("dht: parse packet address %q: %w", address, err)
		}
		return normalizeEndpoint(endpoint), nil
	}
}

// ContactSnapshot is caller-owned persistence data for a previously verified
// contact. The package intentionally defines no persistence format.
type ContactSnapshot struct {
	ID           ID
	Addr         netip.AddrPort
	LastResponse time.Time
}

// SnapshotContacts returns non-bad contacts which were verified by a matched
// response or supplied through RestoreContacts.
func (node *Node) SnapshotContacts() []ContactSnapshot {
	now := node.config.Clock()
	contacts := append(node.routing4.Contacts(now), node.routing6.Contacts(now)...)
	snapshot := make([]ContactSnapshot, 0, len(contacts))
	for _, contact := range contacts {
		if !contact.LastResponse.IsZero() {
			snapshot = append(snapshot, ContactSnapshot{ID: contact.ID, Addr: contact.Addr, LastResponse: contact.LastResponse})
		}
	}
	return snapshot
}

// RestoreContacts trusts snapshots previously returned by SnapshotContacts,
// validates their addresses and BEP 42 IDs, and returns the number accepted.
func (node *Node) RestoreContacts(snapshot []ContactSnapshot) (int, error) {
	if len(snapshot) > node.config.MaxContacts*2 {
		return 0, fmt.Errorf("dht: %d restored contacts exceed limit %d", len(snapshot), node.config.MaxContacts*2)
	}
	now := node.config.Clock()
	contacts := make([]Contact, len(snapshot))
	for index, saved := range snapshot {
		saved.Addr = normalizeEndpoint(saved.Addr)
		if !validEndpoint(saved.Addr) || saved.LastResponse.IsZero() || !ValidNodeID(saved.ID, saved.Addr.Addr()) {
			return 0, fmt.Errorf("dht: invalid restored contact at index %d", index)
		}
		if saved.LastResponse.After(now) {
			saved.LastResponse = now
		}
		contacts[index] = Contact{ID: saved.ID, Addr: saved.Addr, LastResponse: saved.LastResponse}
	}
	accepted := 0
	for _, contact := range contacts {
		if node.routing(contact.Addr.Addr()).restore(contact, now) {
			accepted++
		}
	}
	return accepted, nil
}

// RoutingContacts returns a copy of all non-bad IPv4 and IPv6 contacts.
func (node *Node) RoutingContacts() []Contact {
	now := node.config.Clock()
	return append(node.routing4.Contacts(now), node.routing6.Contacts(now)...)
}
