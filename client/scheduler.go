package client

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/natalie-o-perret/go-torrent/peer"
	"github.com/natalie-o-perret/go-torrent/piece"
)

func (state *coordinator) maintain(now time.Time) {
	verified := state.client.localPieces()
	rarity := make(map[peer.ProtocolVersion][]int, len(state.client.layouts))
	for version, layout := range state.client.layouts {
		rarity[version] = make([]int, len(layout.pieces))
	}
	slotsDirty := false
	for _, managed := range state.peers {
		if !managed.ready {
			continue
		}
		snapshot := managed.session.Snapshot()
		managed.snapshot = snapshot
		if snapshot.RemoteAvailability {
			for index, present := range snapshot.RemotePieces {
				if present {
					rarity[managed.protocol][index]++
				}
			}
		}
		if managed.wasInterested != snapshot.RemoteInterested {
			managed.wasInterested = snapshot.RemoteInterested
			slotsDirty = true
		}
	}

	state.scheduleWebseeds(now, verified)
	state.updateInterest(verified)
	state.updateUploadSlots(now, slotsDirty, allVerified(verified))
	for _, managed := range state.peers {
		if !managed.ready || !managed.snapshot.RemoteAvailability || managed.snapshot.RemoteChoking || !managed.snapshot.LocalInterested {
			continue
		}
		for len(managed.requests) < state.client.pipeline {
			request, key, ok, err := state.pickRequest(managed, rarity[managed.protocol], verified)
			if err != nil {
				state.client.cancel(err)
				return
			}
			if !ok {
				break
			}
			state.assign(managed, key, request)
			if err := managed.session.Request(request); err != nil {
				state.unassign(managed, key, true)
				if errors.Is(err, peer.ErrPeerChoking) || errors.Is(err, peer.ErrRequestPipelineFull) || errors.Is(err, peer.ErrSessionClosed) {
					break
				}
				// A late-response window is peer-local. Let another peer retry it.
				if errors.Is(err, peer.ErrRequestRecentlyExpired) {
					break
				}
				break
			}
		}
	}
	state.sendPEX(now)
	state.scheduleDials(now)
	state.updateCounts()
}

func (state *coordinator) updateInterest(verified []bool) {
	for _, managed := range state.peers {
		if !managed.ready {
			continue
		}
		interested := false
		if managed.snapshot.RemoteAvailability {
			for index, present := range managed.snapshot.RemotePieces {
				if present && !verified[index] {
					interested = true
					break
				}
			}
		}
		if managed.snapshot.LocalInterested != interested {
			if err := managed.session.SetInterested(interested); err == nil {
				managed.snapshot.LocalInterested = interested
			}
		}
	}
}

func (state *coordinator) updateUploadSlots(now time.Time, dirty, complete bool) {
	if dirty || !now.Before(state.nextReview) {
		interested := make([]*peerState, 0, len(state.peers))
		for _, managed := range state.peers {
			managed.regular = false
			if managed.ready && managed.snapshot.RemoteInterested {
				interested = append(interested, managed)
			}
		}
		state.shufflePeers(interested)
		sort.SliceStable(interested, func(i, j int) bool {
			if complete {
				return interested[i].uploaded > interested[j].uploaded
			}
			return interested[i].downloaded > interested[j].downloaded
		})
		for index := range min(regularUploadSlots, len(interested)) {
			interested[index].regular = true
		}
		for _, managed := range state.peers {
			managed.downloaded = 0
			managed.uploaded = 0
		}
		state.nextReview = now.Add(uploadReviewInterval)
		if optimistic := state.peers[state.optimistic]; optimistic == nil || optimistic.regular || !optimistic.snapshot.RemoteInterested {
			state.optimistic = 0
			state.chooseOptimistic(now)
		}
	}
	if !now.Before(state.nextOptimistic) {
		state.chooseOptimistic(now)
	}
	for _, managed := range state.peers {
		managed.optimistic = managed.id == state.optimistic
		unchoke := managed.ready && managed.snapshot.RemoteInterested && (managed.regular || managed.optimistic)
		if managed.ready && managed.snapshot.LocalChoking == unchoke {
			if err := managed.session.SetChoking(!unchoke); err == nil {
				managed.snapshot.LocalChoking = !unchoke
			}
		}
	}
}

func (state *coordinator) chooseOptimistic(now time.Time) {
	var candidates []*peerState
	for _, managed := range state.peers {
		if managed.ready && managed.snapshot.RemoteInterested && !managed.regular {
			candidates = append(candidates, managed)
		}
	}
	state.optimistic = 0
	if len(candidates) != 0 {
		state.optimistic = candidates[state.randomIndex(len(candidates))].id
	}
	state.nextOptimistic = now.Add(optimisticUnchokePeriod)
}

func (state *coordinator) shufflePeers(peers []*peerState) {
	for index := len(peers) - 1; index > 0; index-- {
		other := state.randomIndex(index + 1)
		peers[index], peers[other] = peers[other], peers[index]
	}
}

func (state *coordinator) randomIndex(length int) int {
	if length <= 1 {
		return 0
	}
	index := state.client.randIntN(length)
	if index < 0 {
		index = -index
	}
	return index % length
}

func (state *coordinator) pickRequest(managed *peerState, rarity []int, verified []bool) (peer.BlockRequest, blockKey, bool, error) {
	remote := managed.snapshot.RemotePieces
	excluded := make(map[uint32]struct{})
	for {
		minimum := int(^uint(0) >> 1)
		var choices []uint32
		activeCount := state.activeCount(managed.protocol)
		for index, present := range remote {
			if !present || verified[index] {
				continue
			}
			pieceIndex := uint32(index)
			if _, reserved := state.webseedReserved[pieceIndex]; reserved {
				continue
			}
			if _, skip := excluded[pieceIndex]; skip {
				continue
			}
			_, active := state.active[pieceKey{protocol: managed.protocol, index: pieceIndex}]
			if !active && activeCount >= state.client.maxActivePieces {
				continue
			}
			if rarity[index] < minimum {
				minimum = rarity[index]
				choices = choices[:0]
			}
			if rarity[index] == minimum {
				choices = append(choices, pieceIndex)
			}
		}
		if len(choices) == 0 {
			if activeCount >= state.client.maxActivePieces && state.evictIdlePiece(managed.protocol) {
				continue
			}
			break
		}
		index := choices[state.randomIndex(len(choices))]
		key := pieceKey{protocol: managed.protocol, index: index}
		download := state.active[key]
		if download == nil {
			pieceState, err := state.client.layouts[managed.protocol].newPiece(int(index))
			if err != nil {
				return peer.BlockRequest{}, blockKey{}, false, err
			}
			download = &downloadPiece{state: pieceState, assignments: make(map[blockKey]map[uint64]struct{})}
			state.active[key] = download
		}
		begin, length, ok := download.state.NextRequest()
		if ok {
			request := peer.BlockRequest{Index: index, Begin: uint32(begin), Length: uint32(length)}
			return request, requestKey(managed.protocol, request), true, nil
		}
		excluded[index] = struct{}{}
	}

	if !state.inEndgame(managed.protocol, verified) {
		return peer.BlockRequest{}, blockKey{}, false, nil
	}
	var duplicates []blockKey
	for key, download := range state.active {
		if key.protocol != managed.protocol || int(key.index) >= len(remote) || !remote[key.index] {
			continue
		}
		for block, owners := range download.assignments {
			if len(owners) == 0 || len(owners) >= maxEndgameCopies {
				continue
			}
			if _, already := owners[managed.id]; !already {
				duplicates = append(duplicates, block)
			}
		}
	}
	if len(duplicates) == 0 {
		return peer.BlockRequest{}, blockKey{}, false, nil
	}
	key := duplicates[state.randomIndex(len(duplicates))]
	request := peer.BlockRequest{Index: key.index, Begin: key.begin, Length: key.length}
	return request, key, true, nil
}

func (state *coordinator) evictIdlePiece(protocol peer.ProtocolVersion) bool {
	for key, download := range state.active {
		if key.protocol == protocol && len(download.assignments) == 0 {
			delete(state.active, key)
			return true
		}
	}
	return false
}

func (state *coordinator) activeCount(protocol peer.ProtocolVersion) int {
	count := 0
	for key := range state.active {
		if key.protocol == protocol {
			count++
		}
	}
	return count
}

func (state *coordinator) inEndgame(protocol peer.ProtocolVersion, verified []bool) bool {
	remaining := 0
	layout := state.client.layouts[protocol]
	for index, present := range verified {
		if present {
			continue
		}
		download := state.active[pieceKey{protocol: protocol, index: uint32(index)}]
		if download == nil {
			remaining += int((layout.pieces[index].length + piece.BlockSize - 1) / piece.BlockSize)
		} else {
			for begin := 0; begin < download.state.Length(); begin += piece.BlockSize {
				status, err := download.state.BlockStatus(begin)
				if err == nil && status != piece.BlockReceived {
					remaining++
				}
			}
		}
		if remaining > state.client.endgameBlocks {
			return false
		}
	}
	return remaining > 0 && remaining <= state.client.endgameBlocks
}

func (state *coordinator) assign(managed *peerState, key blockKey, request peer.BlockRequest) {
	download := state.active[pieceKey{protocol: key.protocol, index: key.index}]
	if download == nil {
		return
	}
	owners := download.assignments[key]
	if owners == nil {
		owners = make(map[uint64]struct{})
		download.assignments[key] = owners
	}
	owners[managed.id] = struct{}{}
	managed.requests[key] = request
}

func (state *coordinator) unassign(managed *peerState, key blockKey, retry bool) {
	delete(managed.requests, key)
	download := state.active[pieceKey{protocol: key.protocol, index: key.index}]
	if download == nil {
		return
	}
	owners := download.assignments[key]
	delete(owners, managed.id)
	if len(owners) != 0 {
		return
	}
	delete(download.assignments, key)
	if retry {
		status, err := download.state.BlockStatus(int(key.begin))
		if err == nil && status == piece.BlockRequested {
			_ = download.state.Retry(int(key.begin))
		}
	}
}

func (state *coordinator) handleBlock(event peerBlockEvent) error {
	managed := state.peers[event.id]
	if managed == nil {
		return nil
	}
	request := event.result.Request
	key := requestKey(managed.protocol, request)
	if len(event.result.Data) == 0 || event.result.Rejected {
		state.unassign(managed, key, true)
		return nil
	}
	state.client.localMu.Lock()
	state.client.downloaded[managed.protocol] += int64(len(event.result.Data))
	state.client.localMu.Unlock()
	managed.downloaded += int64(len(event.result.Data))
	download := state.active[pieceKey{protocol: managed.protocol, index: request.Index}]
	if download == nil {
		delete(managed.requests, key)
		return nil
	}
	status, _ := download.state.BlockStatus(int(request.Begin))
	if status == piece.BlockMissing && !markBlockRequested(download.state, int(request.Begin)) {
		delete(managed.requests, key)
		return nil
	}
	if err := download.state.Store(int(request.Begin), event.result.Data); err != nil {
		state.unassign(managed, key, true)
		managed.retry = false
		managed.discard = true
		_ = managed.session.Close()
		return nil //nolint:nilerr // Invalid block data is isolated to the sending peer.
	}
	state.unassign(managed, key, false)
	state.cancelDuplicates(download, key)
	if !download.state.Complete() {
		return nil
	}
	if err := download.state.Verify(); err != nil {
		state.cancelDownloadAssignments(managed.protocol, request.Index)
		return nil //nolint:nilerr // A hash mismatch resets the piece for another download.
	}
	data := download.state.Data()
	state.client.storageMu.Lock()
	err := state.client.store.WritePiece(protocolStorage(managed.protocol), int(request.Index), data)
	if err == nil {
		var verified bool
		verified, err = state.client.store.VerifyPiece(int(request.Index))
		if err == nil && !verified {
			err = errStorageVerification
		}
	}
	state.client.storageMu.Unlock()
	if errors.Is(err, errStorageVerification) {
		state.discardPiece(request.Index)
		return nil
	}
	if err != nil {
		return fmt.Errorf("client: store piece %d: %w", request.Index, err)
	}
	state.finishPiece(request.Index)
	return nil
}

func markBlockRequested(state *piece.State, wanted int) bool {
	var skipped []int
	for {
		begin, _, ok := state.NextRequest()
		if !ok {
			for _, offset := range skipped {
				_ = state.Retry(offset)
			}
			return false
		}
		if begin == wanted {
			for _, offset := range skipped {
				_ = state.Retry(offset)
			}
			return true
		}
		skipped = append(skipped, begin)
	}
}

var errStorageVerification = errors.New("stored piece failed hybrid verification")

func (state *coordinator) cancelDuplicates(download *downloadPiece, key blockKey) {
	owners := download.assignments[key]
	for ownerID := range owners {
		managed := state.peers[ownerID]
		if managed == nil {
			continue
		}
		request := managed.requests[key]
		state.unassign(managed, key, false)
		_ = managed.session.Cancel(request)
	}
}

func (state *coordinator) cancelDownloadAssignments(protocol peer.ProtocolVersion, index uint32) {
	download := state.active[pieceKey{protocol: protocol, index: index}]
	if download == nil {
		return
	}
	var assignments []struct {
		managed *peerState
		key     blockKey
		request peer.BlockRequest
	}
	for key, owners := range download.assignments {
		for ownerID := range owners {
			if managed := state.peers[ownerID]; managed != nil {
				assignments = append(assignments, struct {
					managed *peerState
					key     blockKey
					request peer.BlockRequest
				}{managed: managed, key: key, request: managed.requests[key]})
			}
		}
	}
	for _, assignment := range assignments {
		state.unassign(assignment.managed, assignment.key, false)
		_ = assignment.managed.session.Cancel(assignment.request)
	}
}

func (state *coordinator) discardPiece(index uint32) {
	for key := range state.active {
		if key.index != index {
			continue
		}
		state.cancelDownloadAssignments(key.protocol, index)
		delete(state.active, key)
	}
}

func (state *coordinator) finishPiece(index uint32) {
	state.discardPiece(index)
	state.client.localMu.Lock()
	if int(index) >= len(state.client.verified) || state.client.verified[index] {
		state.client.localMu.Unlock()
		return
	}
	state.client.verified[index] = true
	complete := allVerified(state.client.verified)
	if complete && state.client.completedAt.IsZero() {
		state.client.completedAt = state.client.now()
	}
	state.client.localMu.Unlock()
	if complete {
		state.client.completionOnce.Do(func() { close(state.client.completed) })
	}
	for _, managed := range state.peers {
		if managed.ready {
			_ = managed.session.Have(index)
		}
	}
}

func (state *coordinator) sendPEX(now time.Time) {
	if state.client.meta.Info.Private {
		return
	}
	for _, target := range state.peers {
		if !target.ready || (!target.nextPEX.IsZero() && now.Before(target.nextPEX)) || target.snapshot.OutgoingExtensions[peer.ExtensionPEX] == 0 {
			continue
		}
		current := make(map[netip.Addr]netip.AddrPort)
		contacts := make(map[netip.AddrPort]*peerState)
		for _, managed := range state.peers {
			if managed.id == target.id || !managed.ready || managed.protocol != target.protocol || !managed.pexAddress.IsValid() {
				continue
			}
			address := managed.pexAddress.Addr().Unmap()
			if _, exists := current[address]; exists {
				continue
			}
			current[address] = managed.pexAddress
			contacts[managed.pexAddress] = managed
		}
		message := peer.PEXMessage{}
		for address, known := range target.pexKnown {
			endpoint, present := current[address]
			if !present || endpoint != known {
				message.Dropped = append(message.Dropped, known)
				if len(message.Dropped) == peer.DefaultPEXContactLimit {
					break
				}
			}
		}
		droppedIPs := make(map[netip.Addr]struct{}, len(message.Dropped))
		for _, endpoint := range message.Dropped {
			droppedIPs[endpoint.Addr().Unmap()] = struct{}{}
		}
		for address, endpoint := range current {
			if _, dropped := droppedIPs[address]; dropped {
				continue
			}
			if known, present := target.pexKnown[address]; present && known == endpoint {
				continue
			}
			flags := peer.PEXFlags(0)
			if contact := contacts[endpoint]; contact != nil && contact.outgoing {
				flags |= peer.PEXOutgoing
			}
			if contact := contacts[endpoint]; contact != nil && contact.transport == TransportUTP {
				flags |= peer.PEXSupportsUTP
			}
			if contact := contacts[endpoint]; contact != nil && contact.snapshot.RemoteAvailability && allVerified(contact.snapshot.RemotePieces) {
				flags |= peer.PEXSeed
			}
			message.Added = append(message.Added, peer.PEXContact{AddrPort: endpoint, Flags: flags})
			if len(message.Added) == peer.DefaultPEXContactLimit {
				break
			}
		}
		if len(message.Added) == 0 && len(message.Dropped) == 0 {
			target.nextPEX = now.Add(pexInterval)
			continue
		}
		sort.Slice(message.Added, func(i, j int) bool { return message.Added[i].AddrPort.String() < message.Added[j].AddrPort.String() })
		sort.Slice(message.Dropped, func(i, j int) bool { return message.Dropped[i].String() < message.Dropped[j].String() })
		if err := target.session.SendPEX(message); err == nil {
			for _, endpoint := range message.Dropped {
				delete(target.pexKnown, endpoint.Addr().Unmap())
			}
			for _, contact := range message.Added {
				target.pexKnown[contact.AddrPort.Addr().Unmap()] = contact.AddrPort
			}
		}
		target.nextPEX = now.Add(pexInterval)
	}
}

func (state *coordinator) switchPrivateTracker(trackerURL string) {
	if !state.client.meta.Info.Private || trackerURL == "" {
		return
	}
	for address, candidate := range state.candidates {
		candidate.routes = filterRoutes(candidate.routes, func(route candidateRoute) bool {
			return route.source != SourceTracker || route.tracker != trackerURL
		})
		if len(candidate.routes) == 0 && !candidate.connected && !candidate.dialing {
			state.removeCandidate(address)
		}
	}
	for _, managed := range state.peers {
		if candidate := state.candidates[managed.endpoint]; candidate != nil && len(candidate.routes) != 0 {
			managed.preserveCandidate = true
		}
		managed.routes = nil
		managed.retry = false
		managed.discard = true
		_ = managed.session.Close()
	}
}
