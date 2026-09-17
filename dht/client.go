package dht

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

// FindNodeResponse is one find_node response.
type FindNodeResponse struct {
	From   Contact
	Nodes4 []Contact
	Nodes6 []Contact
}

// GetPeersResponse is one get_peers response.
type GetPeersResponse struct {
	From   Contact
	Token  []byte
	Peers  []netip.AddrPort
	Nodes4 []Contact
	Nodes6 []Contact
}

// AnnounceToken binds an opaque get_peers token to the node which issued it.
type AnnounceToken struct {
	Contact Contact
	Token   []byte
}

// PeerLookup is the result of an iterative get_peers lookup.
type PeerLookup struct {
	Peers   []netip.AddrPort
	Closest []Contact
	Tokens  []AnnounceToken
}

// Ping verifies that endpoint responds and returns its contact.
func (node *Node) Ping(ctx context.Context, endpoint netip.AddrPort) (Contact, error) {
	_, contact, err := node.call(ctx, endpoint, nil, "ping", map[string]any{"id": node.id[:]})
	return contact, err
}

// FindNode sends find_node. With no want arguments, the response defaults to
// the destination's address family. IPv4 and IPv6 may both be requested.
func (node *Node) FindNode(ctx context.Context, endpoint netip.AddrPort, target ID, want ...Family) (FindNodeResponse, error) {
	return node.findNode(ctx, Contact{Addr: endpoint}, nil, target, want)
}

func (node *Node) findNode(ctx context.Context, destination Contact, expected *ID, target ID, want []Family) (FindNodeResponse, error) {
	arguments := map[string]any{"id": node.id[:], "target": target[:]}
	if err := addWant(arguments, want); err != nil {
		return FindNodeResponse{}, err
	}
	response, from, err := node.call(ctx, destination.Addr, expected, "find_node", arguments)
	if err != nil {
		return FindNodeResponse{}, err
	}
	nodes4, err := node.responseNodes(response, "nodes", IPv4)
	if err != nil {
		return FindNodeResponse{}, err
	}
	nodes6, err := node.responseNodes(response, "nodes6", IPv6)
	if err != nil {
		return FindNodeResponse{}, err
	}
	return FindNodeResponse{From: from, Nodes4: nodes4, Nodes6: nodes6}, nil
}

// GetPeersFrom sends one get_peers query. With no want arguments, nodes in the
// destination's address family are requested.
func (node *Node) GetPeersFrom(ctx context.Context, endpoint netip.AddrPort, infoHash ID, want ...Family) (GetPeersResponse, error) {
	return node.getPeersFrom(ctx, Contact{Addr: endpoint}, nil, infoHash, want)
}

func (node *Node) getPeersFrom(ctx context.Context, destination Contact, expected *ID, infoHash ID, want []Family) (GetPeersResponse, error) {
	arguments := map[string]any{"id": node.id[:], "info_hash": infoHash[:]}
	if err := addWant(arguments, want); err != nil {
		return GetPeersResponse{}, err
	}
	response, from, err := node.call(ctx, destination.Addr, expected, "get_peers", arguments)
	if err != nil {
		return GetPeersResponse{}, err
	}
	result := GetPeersResponse{From: from}
	if raw, exists := response["token"]; exists {
		value, ok := raw.(string)
		if !ok || value == "" || len(value) > 64 {
			return GetPeersResponse{}, fmt.Errorf("dht: invalid get_peers token")
		}
		result.Token = []byte(value)
	}
	result.Nodes4, err = node.responseNodes(response, "nodes", IPv4)
	if err != nil {
		return GetPeersResponse{}, err
	}
	result.Nodes6, err = node.responseNodes(response, "nodes6", IPv6)
	if err != nil {
		return GetPeersResponse{}, err
	}
	if raw, exists := response["values"]; exists {
		values, ok := raw.([]any)
		if !ok || len(values) > 64 {
			return GetPeersResponse{}, fmt.Errorf("dht: invalid get_peers values")
		}
		seen := make(map[netip.AddrPort]struct{}, len(values))
		for _, rawValue := range values {
			value, ok := rawValue.(string)
			if !ok {
				return GetPeersResponse{}, fmt.Errorf("dht: get_peers value is not a byte string")
			}
			peer, err := DecodeCompactPeer([]byte(value))
			if err != nil {
				return GetPeersResponse{}, fmt.Errorf("dht: get_peers value: %w", err)
			}
			if _, exists := seen[peer]; !exists {
				seen[peer] = struct{}{}
				result.Peers = append(result.Peers, peer)
			}
		}
		sort.Slice(result.Peers, func(i, j int) bool { return result.Peers[i].String() < result.Peers[j].String() })
	}
	return result, nil
}

// AnnouncePeer sends one token-authorized announce_peer query.
func (node *Node) AnnouncePeer(ctx context.Context, target AnnounceToken, infoHash ID, port uint16, impliedPort bool) error {
	if (!impliedPort && port == 0) || len(target.Token) == 0 || len(target.Token) > 64 || !validEndpoint(normalizeEndpoint(target.Contact.Addr)) {
		return fmt.Errorf("dht: invalid announce target, token, or port")
	}
	arguments := map[string]any{
		"id":        node.id[:],
		"info_hash": infoHash[:],
		"port":      int64(port),
		"token":     append([]byte(nil), target.Token...),
	}
	if impliedPort {
		arguments["implied_port"] = int64(1)
	}
	expected := target.Contact.ID
	_, _, err := node.call(ctx, target.Contact.Addr, &expected, "announce_peer", arguments)
	return err
}

func addWant(arguments map[string]any, families []Family) error {
	if len(families) == 0 {
		return nil
	}
	values := make([]any, 0, 2)
	var have4, have6 bool
	for _, family := range families {
		switch family {
		case IPv4:
			if !have4 {
				values, have4 = append(values, "n4"), true
			}
		case IPv6:
			if !have6 {
				values, have6 = append(values, "n6"), true
			}
		default:
			return fmt.Errorf("dht: unsupported address family %d", family)
		}
	}
	arguments["want"] = values
	return nil
}

func (node *Node) responseNodes(response map[string]any, field string, family Family) ([]Contact, error) {
	raw, exists := response[field]
	if !exists {
		return nil, nil
	}
	value, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("dht: field %s is not compact nodes", field)
	}
	contacts, err := DecodeCompactNodes([]byte(value), family, K)
	if err != nil {
		return nil, fmt.Errorf("dht: field %s: %w", field, err)
	}
	valid := contacts[:0]
	for _, contact := range contacts {
		if contact.ID != node.id && ValidNodeID(contact.ID, contact.Addr.Addr()) {
			valid = append(valid, contact)
		}
	}
	return valid, nil
}

type candidateKey struct {
	id       ID
	endpoint netip.AddrPort
}

type lookupCandidate struct {
	contact Contact
	queried bool
	success bool
	active  bool
}

type walkResult struct {
	closest []Contact
	peers   []netip.AddrPort
	tokens  []AnnounceToken
}

type walkOutcome struct {
	key   candidateKey
	from  Contact
	nodes []Contact
	peers []netip.AddrPort
	token []byte
	err   error
}

// Lookup performs an iterative find_node lookup with at most Alpha concurrent
// queries and MaxCandidates retained candidates.
func (node *Node) Lookup(ctx context.Context, target ID) ([]Contact, error) {
	result, err := node.walk(ctx, target, false, false)
	return result.closest, err
}

// GetPeers performs an iterative get_peers lookup, collecting hybrid compact
// peer values and tokens from the closest valid responders.
func (node *Node) GetPeers(ctx context.Context, infoHash ID) (PeerLookup, error) {
	result, err := node.walk(ctx, infoHash, true, false)
	return PeerLookup{Peers: result.peers, Closest: result.closest, Tokens: result.tokens}, err
}

func (node *Node) walk(ctx context.Context, target ID, peers, wantBoth bool) (walkResult, error) {
	if ctx == nil {
		return walkResult{}, fmt.Errorf("dht: nil context")
	}
	now := node.config.Clock()
	initial := append(node.routing4.Closest(target, node.config.MaxCandidates, now, false), node.routing6.Closest(target, node.config.MaxCandidates, now, false)...)
	sortContacts(initial, target)
	candidates := make(map[candidateKey]*lookupCandidate, min(len(initial), node.config.MaxCandidates))
	for _, contact := range initial {
		addCandidate(candidates, contact, node.id, target, node.config.MaxCandidates)
	}
	if len(candidates) == 0 {
		return walkResult{}, ErrNoContacts
	}

	peerSet := make(map[netip.AddrPort]struct{})
	tokenSet := make(map[candidateKey]AnnounceToken)
	queries := 0
	var lastErr error
	for {
		remaining := node.config.MaxCandidates - queries
		if remaining == 0 {
			break
		}
		batch := nearestUnqueried(candidates, target, min(node.config.Alpha, remaining))
		if len(batch) == 0 {
			break
		}
		queries += len(batch)
		outcomes := make(chan walkOutcome, len(batch))
		for _, candidate := range batch {
			candidate.queried, candidate.active = true, true
			key := candidateKey{id: candidate.contact.ID, endpoint: candidate.contact.Addr}
			contact := candidate.contact
			go func() {
				families := []Family(nil)
				if wantBoth {
					families = []Family{IPv4, IPv6}
				}
				expected := contact.ID
				if peers {
					response, err := node.getPeersFrom(ctx, contact, &expected, target, families)
					outcomes <- walkOutcome{key: key, from: response.From, nodes: append(response.Nodes4, response.Nodes6...), peers: response.Peers, token: response.Token, err: err}
					return
				}
				response, err := node.findNode(ctx, contact, &expected, target, families)
				outcomes <- walkOutcome{key: key, from: response.From, nodes: append(response.Nodes4, response.Nodes6...), err: err}
			}()
		}
		for range batch {
			outcome := <-outcomes
			candidate := candidates[outcome.key]
			if outcome.err != nil {
				candidate.active = false
				lastErr = outcome.err
				continue
			}
			candidate.success = true
			candidate.contact = outcome.from
			for _, peer := range outcome.peers {
				if len(peerSet) < node.config.MaxCandidates {
					peerSet[peer] = struct{}{}
				}
			}
			if len(outcome.token) != 0 {
				tokenSet[outcome.key] = AnnounceToken{Contact: outcome.from, Token: append([]byte(nil), outcome.token...)}
			}
			sortContacts(outcome.nodes, target)
			for _, contact := range outcome.nodes {
				addCandidate(candidates, contact, node.id, target, node.config.MaxCandidates)
			}
			candidate.active = false
		}
		if err := ctx.Err(); err != nil {
			return walkResult{}, err
		}
		if lookupConverged(candidates, target) {
			break
		}
	}

	closest := successfulContacts(candidates, target)
	if len(closest) == 0 {
		if lastErr != nil {
			return walkResult{}, fmt.Errorf("dht: lookup failed: %w", lastErr)
		}
		return walkResult{}, ErrNoContacts
	}
	if len(closest) > K {
		closest = closest[:K]
	}
	peerList := make([]netip.AddrPort, 0, len(peerSet))
	for peer := range peerSet {
		peerList = append(peerList, peer)
	}
	sort.Slice(peerList, func(i, j int) bool { return peerList[i].String() < peerList[j].String() })
	tokens := make([]AnnounceToken, 0, len(tokenSet))
	for key := range tokenSet {
		tokens = append(tokens, tokenSet[key])
	}
	sort.Slice(tokens, func(i, j int) bool {
		if comparison := compareDistance(target, tokens[i].Contact.ID, tokens[j].Contact.ID); comparison != 0 {
			return comparison < 0
		}
		return tokens[i].Contact.Addr.String() < tokens[j].Contact.Addr.String()
	})
	if len(tokens) > K {
		tokens = tokens[:K]
	}
	return walkResult{closest: closest, peers: peerList, tokens: tokens}, nil
}

func addCandidate(candidates map[candidateKey]*lookupCandidate, contact Contact, local, target ID, limit int) {
	contact.Addr = normalizeEndpoint(contact.Addr)
	if contact.ID == local || !validEndpoint(contact.Addr) || !ValidNodeID(contact.ID, contact.Addr.Addr()) {
		return
	}
	key := candidateKey{id: contact.ID, endpoint: contact.Addr}
	if _, exists := candidates[key]; exists {
		return
	}
	if len(candidates) >= limit {
		var farthestKey candidateKey
		var farthest *lookupCandidate
		for candidateKey, candidate := range candidates {
			if candidate.active {
				continue
			}
			if farthest == nil || contactFarther(target, candidate.contact, farthest.contact) {
				farthestKey, farthest = candidateKey, candidate
			}
		}
		if farthest == nil || !contactFarther(target, farthest.contact, contact) {
			return
		}
		delete(candidates, farthestKey)
	}
	candidates[key] = &lookupCandidate{contact: contact}
}

func contactFarther(target ID, a, b Contact) bool {
	if comparison := compareDistance(target, a.ID, b.ID); comparison != 0 {
		return comparison > 0
	}
	return a.Addr.String() > b.Addr.String()
}

func nearestUnqueried(candidates map[candidateKey]*lookupCandidate, target ID, limit int) []*lookupCandidate {
	available := make([]*lookupCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if !candidate.queried {
			available = append(available, candidate)
		}
	}
	sort.Slice(available, func(i, j int) bool {
		if comparison := compareDistance(target, available[i].contact.ID, available[j].contact.ID); comparison != 0 {
			return comparison < 0
		}
		return available[i].contact.Addr.String() < available[j].contact.Addr.String()
	})
	if len(available) > limit {
		available = available[:limit]
	}
	return available
}

func lookupConverged(candidates map[candidateKey]*lookupCandidate, target ID) bool {
	successful := successfulContacts(candidates, target)
	if len(successful) < K {
		for _, candidate := range candidates {
			if !candidate.queried {
				return false
			}
		}
		return true
	}
	threshold := successful[K-1]
	for _, candidate := range candidates {
		if !candidate.queried && compareDistance(target, candidate.contact.ID, threshold.ID) < 0 {
			return false
		}
	}
	return true
}

func successfulContacts(candidates map[candidateKey]*lookupCandidate, target ID) []Contact {
	contacts := make([]Contact, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.success {
			contacts = append(contacts, candidate.contact)
		}
	}
	sortContacts(contacts, target)
	return contacts
}

func sortContacts(contacts []Contact, target ID) {
	sort.Slice(contacts, func(i, j int) bool {
		if comparison := compareDistance(target, contacts[i].ID, contacts[j].ID); comparison != 0 {
			return comparison < 0
		}
		return contacts[i].Addr.String() < contacts[j].Addr.String()
	})
}

// Bootstrap verifies seed endpoints and looks up the local ID. Seed work and
// the iterative lookup both obey Alpha and MaxCandidates.
func (node *Node) Bootstrap(ctx context.Context, seeds []netip.AddrPort) error {
	if ctx == nil {
		return fmt.Errorf("dht: nil context")
	}
	unique := make([]netip.AddrPort, 0, min(len(seeds), node.config.MaxCandidates))
	seen := make(map[netip.AddrPort]struct{})
	for _, seed := range seeds {
		seed = normalizeEndpoint(seed)
		if !validEndpoint(seed) {
			return fmt.Errorf("dht: invalid bootstrap endpoint %v", seed)
		}
		if _, exists := seen[seed]; !exists && len(unique) < node.config.MaxCandidates {
			seen[seed] = struct{}{}
			unique = append(unique, seed)
		}
	}
	if len(unique) == 0 {
		return ErrNoContacts
	}
	responded := 0
	var failures []error
	for offset := 0; offset < len(unique); offset += node.config.Alpha {
		end := min(offset+node.config.Alpha, len(unique))
		results := make(chan error, end-offset)
		for _, seed := range unique[offset:end] {
			go func() {
				_, err := node.Ping(ctx, seed)
				results <- err
			}()
		}
		for range end - offset {
			if err := <-results; err != nil {
				failures = append(failures, err)
			} else {
				responded++
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if responded == 0 {
		return fmt.Errorf("dht: bootstrap failed: %w", errors.Join(failures...))
	}
	_, err := node.walk(ctx, node.id, false, true)
	return err
}

// Announce sends announce_peer to at most K closest token issuers, with at
// most Alpha concurrent queries. It returns the number of successful stores.
func (node *Node) Announce(ctx context.Context, infoHash ID, port uint16, impliedPort bool, tokens []AnnounceToken) (int, error) {
	if ctx == nil {
		return 0, fmt.Errorf("dht: nil context")
	}
	if port == 0 && !impliedPort {
		return 0, fmt.Errorf("dht: announce port is zero")
	}
	usable := make([]AnnounceToken, 0, min(len(tokens), K))
	seen := make(map[candidateKey]struct{})
	for index := range tokens {
		if index >= node.config.MaxCandidates {
			break
		}
		token := tokens[index]
		key := candidateKey{id: token.Contact.ID, endpoint: normalizeEndpoint(token.Contact.Addr)}
		if _, exists := seen[key]; exists || len(token.Token) == 0 || len(token.Token) > 64 || !validEndpoint(key.endpoint) || !ValidNodeID(key.id, key.endpoint.Addr()) {
			continue
		}
		token.Contact.Addr = key.endpoint
		token.Token = append([]byte(nil), token.Token...)
		seen[key] = struct{}{}
		usable = append(usable, token)
	}
	sort.Slice(usable, func(i, j int) bool {
		if comparison := compareDistance(infoHash, usable[i].Contact.ID, usable[j].Contact.ID); comparison != 0 {
			return comparison < 0
		}
		return usable[i].Contact.Addr.String() < usable[j].Contact.Addr.String()
	})
	if len(usable) > K {
		usable = usable[:K]
	}
	if len(usable) == 0 {
		return 0, ErrNoTokens
	}

	successes := 0
	var failures []error
	for offset := 0; offset < len(usable); offset += node.config.Alpha {
		end := min(offset+node.config.Alpha, len(usable))
		results := make(chan error, end-offset)
		for index := range usable[offset:end] {
			token := &usable[offset+index]
			go func() { results <- node.AnnouncePeer(ctx, *token, infoHash, port, impliedPort) }()
		}
		for range end - offset {
			if err := <-results; err != nil {
				failures = append(failures, err)
			} else {
				successes++
			}
		}
		if err := ctx.Err(); err != nil {
			return successes, err
		}
	}
	if successes == 0 {
		return 0, fmt.Errorf("dht: announce failed: %w", errors.Join(failures...))
	}
	return successes, nil
}
