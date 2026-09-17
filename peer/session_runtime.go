package peer

import (
	"context"
	"fmt"
	"sort"
	"time"
)

func (session *Session) performHandshake(ctx context.Context) (HandshakeMessage, HandshakeMessage, ProtocolVersion, error) {
	deadline := time.Time{}
	if session.handshakeTimeout > 0 {
		deadline = time.Now().Add(session.handshakeTimeout)
	}
	if contextDeadline, ok := ctx.Deadline(); ok && (deadline.IsZero() || contextDeadline.Before(deadline)) {
		deadline = contextDeadline
	}
	if !deadline.IsZero() {
		if err := session.conn.SetDeadline(deadline); err != nil {
			return HandshakeMessage{}, HandshakeMessage{}, 0, fmt.Errorf("peer: set handshake deadline: %w", err)
		}
		defer func() { _ = session.conn.SetDeadline(time.Time{}) }()
	}

	if session.outgoing {
		return session.performOutgoingHandshake(ctx)
	}
	return session.performIncomingHandshake(ctx)
}

func (session *Session) performOutgoingHandshake(ctx context.Context) (HandshakeMessage, HandshakeMessage, ProtocolVersion, error) {
	version := ProtocolV1
	var infoHash [20]byte
	if session.preferV2 || session.v1 == nil {
		version = ProtocolV2
		infoHash = v2HandshakeHash(*session.v2)
	} else {
		infoHash = *session.v1
	}
	localReserved := session.localReserved
	if version == ProtocolV2 {
		localReserved.Set(CapabilityV2Upgrade, false)
	}
	local := HandshakeMessage{Reserved: localReserved, InfoHash: infoHash, PeerID: session.peerID}

	writeResult := make(chan error, 1)
	go func() { writeResult <- WriteHandshake(session.conn, local) }()
	remote, readErr := ReadHandshake(session.conn)
	if readErr != nil {
		_ = session.conn.SetDeadline(time.Now())
	}
	writeErr := <-writeResult
	if err := context.Cause(ctx); err != nil {
		return HandshakeMessage{}, HandshakeMessage{}, 0, err
	}
	if writeErr != nil {
		return HandshakeMessage{}, HandshakeMessage{}, 0, fmt.Errorf("peer: write handshake: %w", writeErr)
	}
	if readErr != nil {
		return HandshakeMessage{}, HandshakeMessage{}, 0, fmt.Errorf("peer: read handshake: %w", readErr)
	}
	if !samePeerID(session.expectedPeerID, remote.PeerID) {
		return HandshakeMessage{}, HandshakeMessage{}, 0, wrapProtocol("unexpected peer ID")
	}
	if remote.InfoHash == infoHash {
		return local, remote, version, nil
	}
	if version == ProtocolV1 && session.v2 != nil && local.Reserved.Has(CapabilityV2Upgrade) && remote.InfoHash == v2HandshakeHash(*session.v2) {
		version = ProtocolV2
		return local, remote, version, nil
	}
	return HandshakeMessage{}, HandshakeMessage{}, 0, wrapProtocol("peer returned a different info hash")
}

func (session *Session) performIncomingHandshake(ctx context.Context) (HandshakeMessage, HandshakeMessage, ProtocolVersion, error) {
	remote, err := ReadHandshake(session.conn)
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return HandshakeMessage{}, HandshakeMessage{}, 0, cause
		}
		return HandshakeMessage{}, HandshakeMessage{}, 0, fmt.Errorf("peer: read handshake: %w", err)
	}
	if !samePeerID(session.expectedPeerID, remote.PeerID) {
		return HandshakeMessage{}, HandshakeMessage{}, 0, wrapProtocol("unexpected peer ID")
	}

	version := ProtocolV1
	responseHash := remote.InfoHash
	switch {
	case session.v1 != nil && remote.InfoHash == *session.v1:
		if session.canUpgrade(remote.Reserved) {
			responseHash = v2HandshakeHash(*session.v2)
			version = ProtocolV2
		}
	case session.v2 != nil && remote.InfoHash == v2HandshakeHash(*session.v2):
		version = ProtocolV2
	default:
		return HandshakeMessage{}, HandshakeMessage{}, 0, wrapProtocol("peer requested an unknown info hash")
	}
	localReserved := session.localReserved
	if version == ProtocolV2 {
		localReserved.Set(CapabilityV2Upgrade, false)
	}
	local := HandshakeMessage{Reserved: localReserved, InfoHash: responseHash, PeerID: session.peerID}
	if err := WriteHandshake(session.conn, local); err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return HandshakeMessage{}, HandshakeMessage{}, 0, cause
		}
		return HandshakeMessage{}, HandshakeMessage{}, 0, fmt.Errorf("peer: write handshake: %w", err)
	}
	return local, remote, version, nil
}

func (session *Session) canUpgrade(remote Reserved) bool {
	return session.v1 != nil && session.v2 != nil &&
		session.localReserved.Has(CapabilityV2Upgrade) && remote.Has(CapabilityV2Upgrade)
}

// sendInitialMessagesLocked writes the complete initial sequence while Run
// holds writeMu.
func (session *Session) sendInitialMessagesLocked() error {
	session.mu.Lock()
	if session.closed {
		session.mu.Unlock()
		return ErrSessionClosed
	}
	localReserved := session.localReserved
	remoteReserved := session.remoteReserved
	metadataOnly := session.metadataOnly
	pieces := append([]bool(nil), session.localPieces...)
	handshake := cloneExtensionHandshake(session.extensionHandshake)
	port := session.dhtPort
	allowedFast := make([]uint32, 0, len(session.allowedFast))
	for index := range session.allowedFast {
		allowedFast = append(allowedFast, index)
	}
	session.mu.Unlock()
	sort.Slice(allowedFast, func(i, j int) bool { return allowedFast[i] < allowedFast[j] })

	fast := localReserved.Has(CapabilityFast) && remoteReserved.Has(CapabilityFast)
	if !metadataOnly {
		availability := &Message{ID: MsgBitfield, Payload: FormatBitfield(pieces)}
		if fast && allSet(pieces) {
			availability = &Message{ID: MsgHaveAll}
		} else if fast && noneSet(pieces) {
			availability = &Message{ID: MsgHaveNone}
		}
		if err := session.writeMessageLocked(availability); err != nil {
			return fmt.Errorf("peer: write initial availability: %w", err)
		}
	}

	if localReserved.Has(CapabilityExtensionProtocol) && remoteReserved.Has(CapabilityExtensionProtocol) {
		payload, err := EncodeExtensionHandshake(handshake)
		if err != nil {
			return err
		}
		extended, err := FormatExtended(ExtendedHandshakeID, payload)
		if err != nil {
			return err
		}
		if err := session.writeMessageLocked(&Message{ID: MsgExtended, Payload: extended}); err != nil {
			return fmt.Errorf("peer: write extension handshake: %w", err)
		}
	}
	if port != 0 && localReserved.Has(CapabilityDHT) && remoteReserved.Has(CapabilityDHT) {
		payload, err := FormatPort(port)
		if err != nil {
			return err
		}
		if err := session.writeMessageLocked(&Message{ID: MsgPort, Payload: payload}); err != nil {
			return fmt.Errorf("peer: write DHT port: %w", err)
		}
	}
	if fast {
		for _, index := range allowedFast {
			if err := session.writeMessageLocked(&Message{ID: MsgAllowedFast, Payload: FormatAllowedFast(index)}); err != nil {
				return fmt.Errorf("peer: write allowed-fast piece: %w", err)
			}
		}
	}
	return nil
}

func (session *Session) readLoop() {
	defer session.wg.Done()
	for {
		message, err := session.codec.ReadMessage(session.conn)
		if err != nil {
			session.mu.Lock()
			closed := session.closed
			session.mu.Unlock()
			if !closed {
				session.terminate(fmt.Errorf("peer: read message: %w", err))
			}
			return
		}
		session.mu.Lock()
		session.lastRead = time.Now()
		session.mu.Unlock()
		if message == nil {
			continue
		}
		if err := session.handleMessage(message); err != nil {
			session.terminate(err)
			return
		}
	}
}

func (session *Session) handleMessage(message *Message) error {
	session.mu.Lock()
	localReserved := session.localReserved
	remoteReserved := session.remoteReserved
	v2 := session.version == ProtocolV2
	metadataOnly := session.metadataOnly
	session.mu.Unlock()
	if err := ValidateMessage(message); err != nil {
		return wrapProtocol("message %d: %v", message.ID, err)
	}
	if metadataOnly {
		switch message.ID {
		case MsgHave, MsgBitfield, MsgRequest, MsgPiece, MsgCancel,
			MsgSuggestPiece, MsgHaveAll, MsgHaveNone, MsgReject, MsgAllowedFast:
			return nil
		}
	}
	if err := ValidateNegotiatedMessage(message.ID, localReserved, remoteReserved); err != nil && !(v2 && message.ID == MsgReject) {
		return wrapProtocol("message %d: %v", message.ID, err)
	}
	if message.ID >= MsgHashRequest && message.ID <= MsgHashReject && !v2 {
		return wrapProtocol("message %d requires a v2 connection", message.ID)
	}
	if message.ID == MsgBitfield || message.ID == MsgHaveAll || message.ID == MsgHaveNone {
		return session.handleAvailability(message)
	}
	if err := session.ensureAvailabilityBefore(message); err != nil {
		return err
	}

	switch message.ID {
	case MsgChoke:
		session.handleRemoteChoke()
	case MsgUnchoke:
		session.mu.Lock()
		session.remoteChoking = false
		session.mu.Unlock()
	case MsgInterested:
		session.mu.Lock()
		session.remoteInterested = true
		session.mu.Unlock()
	case MsgNotInterested:
		session.mu.Lock()
		session.remoteInterested = false
		session.mu.Unlock()
	case MsgHave:
		index, err := ParseHave(message.Payload)
		if err != nil {
			return wrapProtocol("Have: %v", err)
		}
		if err := ValidatePieceIndex(index, uint32(len(session.pieceLengths))); err != nil {
			return wrapProtocol("Have: %v", err)
		}
		session.mu.Lock()
		session.remotePieces[index] = true
		session.mu.Unlock()
	case MsgRequest:
		request, err := ParseRequest(message.Payload)
		if err != nil {
			return wrapProtocol("Request: %v", err)
		}
		return session.handleUploadRequest(request)
	case MsgPiece:
		return session.handlePiece(message.Payload)
	case MsgCancel:
		request, err := ParseCancel(message.Payload)
		if err != nil {
			return wrapProtocol("Cancel: %v", err)
		}
		return session.handleUploadCancel(request)
	case MsgPort:
		port, err := ParsePort(message.Payload)
		if err != nil {
			return wrapProtocol("Port: %v", err)
		}
		if session.callbacks.OnPort != nil {
			session.callbacks.OnPort(port)
		}
	case MsgSuggestPiece:
		index, err := ParseSuggestPiece(message.Payload)
		if err != nil {
			return wrapProtocol("Suggest: %v", err)
		}
		if err := ValidatePieceIndex(index, uint32(len(session.pieceLengths))); err != nil {
			return wrapProtocol("Suggest: %v", err)
		}
	case MsgAllowedFast:
		index, err := ParseAllowedFast(message.Payload)
		if err != nil {
			return wrapProtocol("Allowed Fast: %v", err)
		}
		if err := ValidatePieceIndex(index, uint32(len(session.pieceLengths))); err != nil {
			return wrapProtocol("Allowed Fast: %v", err)
		}
		session.mu.Lock()
		session.remoteAllowed[index] = struct{}{}
		session.mu.Unlock()
	case MsgReject:
		request, err := ParseReject(message.Payload)
		if err != nil {
			return wrapProtocol("Reject: %v", err)
		}
		return session.handleReject(request)
	case MsgExtended:
		return session.handleExtended(message.Payload)
	case MsgHashRequest:
		request, err := ParseHashRequest(message.Payload)
		if err != nil {
			return wrapProtocol("Hash Request: %v", err)
		}
		if session.callbacks.OnHashRequest != nil {
			session.callbacks.OnHashRequest(request)
		}
	case MsgHashes:
		hashes, err := ParseHashes(message.Payload)
		if err != nil {
			return wrapProtocol("Hashes: %v", err)
		}
		if session.callbacks.OnHashes != nil {
			session.callbacks.OnHashes(hashes)
		}
	case MsgHashReject:
		request, err := ParseHashReject(message.Payload)
		if err != nil {
			return wrapProtocol("Hash Reject: %v", err)
		}
		if session.callbacks.OnHashReject != nil {
			session.callbacks.OnHashReject(request)
		}
	}
	return nil
}

func (session *Session) handleAvailability(message *Message) error {
	pieceCount := uint32(len(session.pieceLengths))
	pieces := make([]bool, pieceCount)
	switch message.ID {
	case MsgBitfield:
		bitfield, err := ParseBitfield(message.Payload, pieceCount)
		if err != nil {
			return wrapProtocol("Bitfield: %v", err)
		}
		copy(pieces, bitfield)
	case MsgHaveAll:
		for index := range pieces {
			pieces[index] = true
		}
	case MsgHaveNone:
	}

	session.mu.Lock()
	defer session.mu.Unlock()
	if session.availabilitySet {
		return wrapProtocol("availability message %d was not first", message.ID)
	}
	session.remotePieces = pieces
	session.availabilitySet = true
	return nil
}

func (session *Session) ensureAvailabilityBefore(message *Message) error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.metadataOnly {
		return nil
	}
	if session.availabilitySet {
		return nil
	}
	if message.ID == MsgExtended && len(message.Payload) != 0 && message.Payload[0] == ExtendedHandshakeID {
		return nil
	}
	if session.fastNegotiatedLocked() {
		return wrapProtocol("message %d preceded Fast availability", message.ID)
	}
	// Without Fast, omitting Bitfield means the peer initially has no pieces.
	session.availabilitySet = true
	return nil
}

func (session *Session) handleRemoteChoke() {
	session.mu.Lock()
	session.remoteChoking = true
	if session.rejectRequiredLocked() {
		session.mu.Unlock()
		return
	}
	now := time.Now()
	requests := make([]BlockRequest, 0, len(session.outstanding))
	for request := range session.outstanding {
		requests = append(requests, request)
		delete(session.outstanding, request)
		session.late[request] = lateRequest{expires: now.Add(session.lateWindow), cancelled: true}
	}
	session.mu.Unlock()
	sortBlockRequests(requests)
	if session.callbacks.OnBlock != nil {
		for _, request := range requests {
			session.callbacks.OnBlock(BlockResult{Request: request, Cancelled: true})
		}
	}
}

func (session *Session) handlePiece(payload []byte) error {
	index, begin, data, err := ParsePiece(payload)
	if err != nil {
		return wrapProtocol("Piece: %v", err)
	}
	request := BlockRequest{Index: index, Begin: begin, Length: uint32(len(data))}
	if err := session.validateBlock(request); err != nil {
		return wrapProtocol("Piece: %v", err)
	}

	now := time.Now()
	session.mu.Lock()
	if pending, ok := session.outstanding[request]; ok {
		delete(session.outstanding, request)
		session.mu.Unlock()
		if session.callbacks.OnBlock != nil {
			session.callbacks.OnBlock(BlockResult{Request: request, Data: data, Cancelled: pending.cancelled})
		}
		return nil
	}
	if late, ok := session.late[request]; ok && !now.After(late.expires) {
		delete(session.late, request)
		session.mu.Unlock()
		if session.callbacks.OnLateResponse != nil {
			session.callbacks.OnLateResponse(BlockResult{Request: request, Data: data, Cancelled: late.cancelled, Late: true})
		}
		return nil
	}
	delete(session.late, request)
	session.mu.Unlock()
	return wrapProtocol("unsolicited Piece for %d:%d+%d", request.Index, request.Begin, request.Length)
}

func (session *Session) handleReject(request BlockRequest) error {
	if err := session.validateBlock(request); err != nil {
		return wrapProtocol("Reject: %v", err)
	}
	now := time.Now()
	session.mu.Lock()
	if pending, ok := session.outstanding[request]; ok {
		delete(session.outstanding, request)
		session.mu.Unlock()
		if session.callbacks.OnBlock != nil {
			session.callbacks.OnBlock(BlockResult{Request: request, Rejected: true, Cancelled: pending.cancelled})
		}
		return nil
	}
	if late, ok := session.late[request]; ok && !now.After(late.expires) {
		delete(session.late, request)
		session.mu.Unlock()
		if session.callbacks.OnLateResponse != nil {
			session.callbacks.OnLateResponse(BlockResult{Request: request, Rejected: true, Cancelled: late.cancelled, Late: true})
		}
		return nil
	}
	delete(session.late, request)
	session.mu.Unlock()
	return wrapProtocol("unsolicited Reject for %d:%d+%d", request.Index, request.Begin, request.Length)
}

func (session *Session) handleUploadRequest(request BlockRequest) error {
	if err := session.validateBlock(request); err != nil {
		return wrapProtocol("Request: %v", err)
	}
	session.mu.Lock()
	fast := session.fastNegotiatedLocked()
	rejectRequired := session.rejectRequiredLocked()
	_, allowed := session.allowedFast[request.Index]
	_, duplicate := session.inbound[request]
	if duplicate {
		session.mu.Unlock()
		return wrapProtocol("duplicate Request for %d:%d+%d", request.Index, request.Begin, request.Length)
	}
	reject := !session.remoteInterested || !session.localPieces[request.Index] || (session.localChoking && !(fast && allowed)) ||
		session.callbacks.OnUploadRequest == nil || len(session.inbound) >= session.maxInbound
	if reject {
		session.mu.Unlock()
		if rejectRequired {
			return session.writeReject(request)
		}
		return nil
	}

	requestCtx := session.ctx
	var cancel context.CancelFunc
	deadline := time.Time{}
	if session.uploadTimeout > 0 {
		requestCtx, cancel = context.WithTimeout(requestCtx, session.uploadTimeout)
		deadline, _ = requestCtx.Deadline()
	} else {
		requestCtx, cancel = context.WithCancel(requestCtx)
	}
	state := &inboundRequest{ctx: requestCtx, cancel: cancel, deadline: deadline}
	session.inbound[request] = state
	callback := session.callbacks.OnUploadRequest
	session.uploadWG.Add(1)
	session.mu.Unlock()

	go func() {
		defer session.uploadWG.Done()
		data, err := callback(requestCtx, request)
		session.finishUpload(request, state, data, err)
	}()
	return nil
}

func (session *Session) finishUpload(request BlockRequest, state *inboundRequest, data []byte, callbackErr error) {
	session.writeMu.Lock()
	session.mu.Lock()
	current, ok := session.inbound[request]
	if !ok || current != state || session.closed {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return
	}
	delete(session.inbound, request)
	rejectRequired := session.rejectRequiredLocked()
	expired := !state.deadline.IsZero() && !time.Now().Before(state.deadline)
	cancelled := state.ctx != nil && state.ctx.Err() != nil
	session.mu.Unlock()
	state.cancel()

	var err error
	uploaded := false
	if callbackErr == nil && !cancelled && !expired && len(data) == int(request.Length) {
		payload, formatErr := FormatPiece(request.Index, request.Begin, data)
		if formatErr != nil {
			err = formatErr
		} else {
			err = session.writeMessageLocked(&Message{ID: MsgPiece, Payload: payload})
			uploaded = err == nil
		}
	} else if rejectRequired {
		err = session.writeRejectLocked(request)
	}
	session.writeMu.Unlock()
	if expired && session.callbacks.OnUploadCancel != nil {
		session.callbacks.OnUploadCancel(request)
	}
	if uploaded && session.callbacks.OnUploadComplete != nil {
		session.callbacks.OnUploadComplete(request)
	}
	if err != nil {
		session.terminate(err)
	}
}

func (session *Session) handleUploadCancel(request BlockRequest) error {
	if err := session.validateBlock(request); err != nil {
		return wrapProtocol("Cancel: %v", err)
	}
	session.writeMu.Lock()
	session.mu.Lock()
	state, ok := session.inbound[request]
	if !ok {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return nil
	}
	delete(session.inbound, request)
	rejectRequired := session.rejectRequiredLocked()
	session.mu.Unlock()
	state.cancel()
	var err error
	if rejectRequired {
		err = session.writeRejectLocked(request)
	}
	session.writeMu.Unlock()
	if session.callbacks.OnUploadCancel != nil {
		session.callbacks.OnUploadCancel(request)
	}
	if err != nil {
		session.terminate(err)
	}
	return err
}

func (session *Session) writeReject(request BlockRequest) error {
	session.writeMu.Lock()
	err := session.writeRejectLocked(request)
	session.writeMu.Unlock()
	if err != nil {
		session.terminate(err)
	}
	return err
}

func (session *Session) writeRejectLocked(request BlockRequest) error {
	return session.writeMessageLocked(&Message{ID: MsgReject, Payload: FormatReject(request.Index, request.Begin, request.Length)})
}

// SetChoking updates local choke state. Choking cancels uploads except pieces
// explicitly allowed by Fast, which remain active.
func (session *Session) SetChoking(choking bool) error {
	session.writeMu.Lock()
	session.mu.Lock()
	if err := session.readyErrorLocked(); err != nil {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return err
	}
	if session.localChoking == choking {
		session.mu.Unlock()
		session.writeMu.Unlock()
		return nil
	}
	session.localChoking = choking
	fast := session.fastNegotiatedLocked()
	rejectRequired := session.rejectRequiredLocked()
	type canceledUpload struct {
		request BlockRequest
		state   *inboundRequest
	}
	var canceled []canceledUpload
	if choking {
		for request, state := range session.inbound {
			_, allowed := session.allowedFast[request.Index]
			if fast && allowed {
				continue
			}
			delete(session.inbound, request)
			canceled = append(canceled, canceledUpload{request: request, state: state})
		}
	}
	session.mu.Unlock()
	for _, upload := range canceled {
		upload.state.cancel()
	}
	id := MsgUnchoke
	if choking {
		id = MsgChoke
	}
	err := session.writeMessageLocked(&Message{ID: id})
	if err == nil && rejectRequired {
		for _, upload := range canceled {
			if err = session.writeRejectLocked(upload.request); err != nil {
				break
			}
		}
	}
	session.writeMu.Unlock()
	if session.callbacks.OnUploadCancel != nil {
		for _, upload := range canceled {
			session.callbacks.OnUploadCancel(upload.request)
		}
	}
	if err != nil {
		session.terminate(err)
	}
	return err
}

func (session *Session) handleExtended(payload []byte) error {
	extended, err := ParseExtended(payload)
	if err != nil {
		return wrapProtocol("Extended: %v", err)
	}
	if extended.ID == ExtendedHandshakeID {
		handshake, err := DecodeExtensionHandshake(extended.Payload)
		if err != nil {
			return wrapProtocol("extension handshake: %v", err)
		}
		session.mu.Lock()
		err = session.extensions.ApplyRemote(handshake)
		session.mu.Unlock()
		if err != nil {
			return wrapProtocol("remote extension IDs: %v", err)
		}
		if session.callbacks.OnExtensionHandshake != nil {
			session.callbacks.OnExtensionHandshake(handshake)
		}
		return nil
	}

	session.mu.Lock()
	name, ok := session.extensions.Incoming.Name(extended.ID)
	session.mu.Unlock()
	if !ok {
		return nil
	}
	switch name {
	case ExtensionMetadata:
		message, err := DecodeMetadataMessage(extended.Payload, session.maxMetadataSize)
		if err != nil {
			return wrapProtocol("metadata: %v", err)
		}
		if session.callbacks.OnMetadata != nil {
			session.callbacks.OnMetadata(message)
		}
	case ExtensionPEX:
		if session.private {
			return wrapProtocol("PEX received for a private torrent")
		}
		now := time.Now()
		session.mu.Lock()
		limits := StandardPEXLimits()
		if !session.pexReceived {
			limits = session.initialPEXLimits
		}
		if !session.lastPEXRead.IsZero() && now.Sub(session.lastPEXRead) < session.pexInterval {
			session.mu.Unlock()
			return wrapProtocol("PEX receive cadence is less than %s", session.pexInterval)
		}
		session.mu.Unlock()
		message, err := DecodePEXMessage(extended.Payload, limits)
		if err != nil {
			return wrapProtocol("PEX: %v", err)
		}
		session.mu.Lock()
		session.pexReceived = true
		session.lastPEXRead = now
		session.mu.Unlock()
		if session.callbacks.OnPEX != nil {
			session.callbacks.OnPEX(message)
		}
	}
	return nil
}

func (session *Session) maintenanceLoop() {
	defer session.wg.Done()
	ticker := time.NewTicker(session.maintenanceInterval())
	defer ticker.Stop()
	for {
		select {
		case <-session.ctx.Done():
			return
		case now := <-ticker.C:
			session.maintain(now)
		}
	}
}

func (session *Session) maintenanceInterval() time.Duration {
	interval := time.Second
	for _, duration := range []time.Duration{session.requestTimeout, session.lateWindow, session.uploadTimeout, session.keepAlive, session.readIdle} {
		if duration > 0 && duration/4 < interval {
			interval = duration / 4
		}
	}
	if interval < time.Millisecond {
		return time.Millisecond
	}
	return interval
}

func (session *Session) maintain(now time.Time) {
	var timedOut []BlockRequest
	type expiredUpload struct {
		request BlockRequest
		state   *inboundRequest
	}
	var uploads []expiredUpload

	session.mu.Lock()
	if session.closed {
		session.mu.Unlock()
		return
	}
	for request, state := range session.outstanding {
		if !state.deadline.IsZero() && !now.Before(state.deadline) {
			delete(session.outstanding, request)
			session.late[request] = lateRequest{expires: now.Add(session.lateWindow), cancelled: state.cancelled}
			timedOut = append(timedOut, request)
		}
	}
	for request, state := range session.late {
		if !now.Before(state.expires) {
			delete(session.late, request)
		}
	}
	for request, state := range session.inbound {
		if !state.deadline.IsZero() && !now.Before(state.deadline) {
			delete(session.inbound, request)
			uploads = append(uploads, expiredUpload{request: request, state: state})
		}
	}
	readExpired := session.readIdle > 0 && now.Sub(session.lastRead) >= session.readIdle
	keepAlive := session.keepAlive > 0 && now.Sub(session.lastWrite) >= session.keepAlive
	rejectRequired := session.rejectRequiredLocked()
	session.mu.Unlock()

	sortBlockRequests(timedOut)
	if session.callbacks.OnRequestTimeout != nil {
		for _, request := range timedOut {
			session.callbacks.OnRequestTimeout(request)
		}
	}
	for _, upload := range uploads {
		upload.state.cancel()
		if session.callbacks.OnUploadCancel != nil {
			session.callbacks.OnUploadCancel(upload.request)
		}
	}
	if readExpired {
		session.terminate(fmt.Errorf("peer: read idle timeout after %s", session.readIdle))
		return
	}
	if rejectRequired && len(uploads) != 0 {
		session.writeMu.Lock()
		for _, upload := range uploads {
			if err := session.writeRejectLocked(upload.request); err != nil {
				session.writeMu.Unlock()
				session.terminate(err)
				return
			}
		}
		session.writeMu.Unlock()
	}
	if keepAlive {
		session.writeMu.Lock()
		session.mu.Lock()
		write := !session.closed && time.Since(session.lastWrite) >= session.keepAlive
		session.mu.Unlock()
		if write {
			if err := session.writeKeepaliveLocked(); err != nil {
				session.writeMu.Unlock()
				session.terminate(err)
				return
			}
		}
		session.writeMu.Unlock()
	}
}
