package peer

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/natalie-o-perret/go-torrent/metainfo"
)

func TestSessionTransfersBlock(t *testing.T) {
	hash := metainfo.Hash{1, 2, 3}
	data := []byte("block")
	result := make(chan BlockResult, 1)
	uploaded := make(chan BlockRequest, 1)
	leftConfig := testSessionConfig(&hash, 1, []bool{false})
	leftConfig.Callbacks.OnBlock = func(block BlockResult) { result <- block }
	rightConfig := testSessionConfig(&hash, 2, []bool{true})
	rightConfig.Callbacks.OnUploadRequest = func(_ context.Context, request BlockRequest) ([]byte, error) {
		return append([]byte(nil), data[:request.Length]...), nil
	}
	rightConfig.Callbacks.OnUploadComplete = func(request BlockRequest) { uploaded <- request }
	left, right := startTestSessions(t, leftConfig, rightConfig)
	if err := left.SendHashRequest(HashRequest{Length: 2}); err == nil {
		t.Fatal("v1 session accepted a v2 Hash Request")
	}

	waitSessionState(t, left, func(snapshot SessionSnapshot) bool {
		return snapshot.RemoteAvailability && snapshot.RemotePieces[0]
	})
	if err := left.SetInterested(true); err != nil {
		t.Fatalf("SetInterested: %v", err)
	}
	if err := right.SetChoking(false); err != nil {
		t.Fatalf("SetChoking: %v", err)
	}
	waitSessionState(t, left, func(snapshot SessionSnapshot) bool { return !snapshot.RemoteChoking })

	request := BlockRequest{Index: 0, Length: uint32(len(data))}
	if err := left.Request(request); err != nil {
		t.Fatalf("Request: %v", err)
	}
	select {
	case block := <-result:
		if block.Request != request || block.Rejected || block.Cancelled || block.Late || !bytes.Equal(block.Data, data) {
			t.Fatalf("block result = %+v, want data %q", block, data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for block")
	}
	select {
	case got := <-uploaded:
		if got != request {
			t.Fatalf("completed upload = %+v, want %+v", got, request)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upload completion")
	}
}

func TestSessionFastCancelGetsReject(t *testing.T) {
	hash := metainfo.Hash{4, 5, 6}
	started := make(chan struct{}, 1)
	uploadCancelled := make(chan BlockRequest, 1)
	result := make(chan BlockResult, 1)
	var fast Reserved
	fast.Set(CapabilityFast, true)

	leftConfig := testSessionConfig(&hash, 3, []bool{false})
	leftConfig.Reserved = fast
	leftConfig.Callbacks.OnBlock = func(block BlockResult) { result <- block }
	rightConfig := testSessionConfig(&hash, 4, []bool{true})
	rightConfig.Reserved = fast
	rightConfig.AllowedFast = []uint32{0}
	rightConfig.Callbacks.OnUploadRequest = func(ctx context.Context, _ BlockRequest) ([]byte, error) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	rightConfig.Callbacks.OnUploadCancel = func(request BlockRequest) { uploadCancelled <- request }
	left, _ := startTestSessions(t, leftConfig, rightConfig)

	waitSessionState(t, left, func(snapshot SessionSnapshot) bool {
		return snapshot.RemoteAvailability && snapshot.RemotePieces[0]
	})
	if err := left.SetInterested(true); err != nil {
		t.Fatalf("SetInterested: %v", err)
	}
	request := BlockRequest{Index: 0, Length: 4}
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := left.Request(request)
		if err == nil {
			break
		}
		if !errors.Is(err, ErrPeerChoking) || time.Now().After(deadline) {
			t.Fatalf("Fast Request while choked: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upload did not start")
	}
	if err := left.Cancel(request); err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	select {
	case block := <-result:
		if block.Request != request || !block.Rejected || !block.Cancelled {
			t.Fatalf("block result = %+v, want cancelled rejection", block)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for rejection")
	}
	select {
	case got := <-uploadCancelled:
		if got != request {
			t.Fatalf("cancelled upload = %+v, want %+v", got, request)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upload cancellation")
	}
}

func TestSessionUploadCompleteRequiresSuccessfulPieceWrite(t *testing.T) {
	hash := metainfo.Hash{40}
	request := BlockRequest{Index: 0, Length: 4}
	for _, test := range []struct {
		name        string
		data        []byte
		callbackErr error
		prepare     func(*Session, *inboundRequest, net.Conn)
	}{
		{
			name: "cancelled",
			data: []byte("data"),
			prepare: func(session *Session, state *inboundRequest, _ net.Conn) {
				delete(session.inbound, request)
				state.cancel()
			},
		},
		{
			name: "expired",
			data: []byte("data"),
			prepare: func(_ *Session, state *inboundRequest, _ net.Conn) {
				state.deadline = time.Now().Add(-time.Second)
			},
		},
		{name: "callback error", callbackErr: errors.New("read failed")},
		{name: "short data", data: []byte("bad")},
		{
			name: "closed",
			data: []byte("data"),
			prepare: func(session *Session, _ *inboundRequest, _ net.Conn) {
				session.closed = true
			},
		},
		{
			name: "failed write",
			data: []byte("data"),
			prepare: func(_ *Session, _ *inboundRequest, remote net.Conn) {
				_ = remote.Close()
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			localConn, remoteConn := net.Pipe()
			defer func() { _ = localConn.Close() }()
			defer func() { _ = remoteConn.Close() }()
			completed := make(chan BlockRequest, 1)
			config := testSessionConfig(&hash, 41, []bool{true})
			config.Callbacks.OnUploadComplete = func(request BlockRequest) { completed <- request }
			session, err := NewSession(localConn, config)
			if err != nil {
				t.Fatalf("NewSession: %v", err)
			}
			requestCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			state := &inboundRequest{ctx: requestCtx, cancel: cancel}
			session.version = ProtocolV1
			session.inbound[request] = state
			if test.prepare != nil {
				test.prepare(session, state, remoteConn)
			}

			session.finishUpload(request, state, test.data, test.callbackErr)
			select {
			case got := <-completed:
				t.Fatalf("OnUploadComplete called for %s upload: %+v", test.name, got)
			default:
			}
			if requestCtx.Err() == nil && !session.closed {
				t.Fatal("upload context was not cancelled")
			}
		})
	}
}

func TestSessionRunWaitsForUploadCallback(t *testing.T) {
	hash := metainfo.Hash{42}
	started := make(chan struct{})
	cancelled := make(chan struct{})
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()

	config := testSessionConfig(&hash, 43, []bool{true})
	config.Callbacks.OnUploadRequest = func(ctx context.Context, _ BlockRequest) ([]byte, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		<-release
		return nil, ctx.Err()
	}
	localConn, remoteConn := net.Pipe()
	defer func() { _ = remoteConn.Close() }()
	session, err := NewSession(localConn, config)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- session.Run(ctx) }()

	if err := remoteConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := WriteHandshake(remoteConn, HandshakeMessage{InfoHash: hash, PeerID: [20]byte{44}}); err != nil {
		t.Fatalf("WriteHandshake: %v", err)
	}
	if _, err := ReadHandshake(remoteConn); err != nil {
		t.Fatalf("ReadHandshake: %v", err)
	}
	requirePeerMessage(t, remoteConn, MsgBitfield)
	waitSessionReady(t, session)
	if err := WriteMessage(remoteConn, &Message{ID: MsgInterested}); err != nil {
		t.Fatalf("write Interested: %v", err)
	}
	waitSessionState(t, session, func(snapshot SessionSnapshot) bool { return snapshot.RemoteInterested })
	unchoked := make(chan error, 1)
	go func() { unchoked <- session.SetChoking(false) }()
	requirePeerMessage(t, remoteConn, MsgUnchoke)
	if err := <-unchoked; err != nil {
		t.Fatalf("SetChoking: %v", err)
	}
	request := BlockRequest{Index: 0, Length: 4}
	if err := WriteMessage(remoteConn, &Message{ID: MsgRequest, Payload: FormatRequest(request.Index, request.Begin, request.Length)}); err != nil {
		t.Fatalf("write Request: %v", err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("upload callback did not start")
	}
	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("upload callback was not cancelled")
	}
	select {
	case err := <-result:
		t.Fatalf("Run returned before upload callback exited: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	released = true
	select {
	case err := <-result:
		if !errors.Is(err, ErrSessionClosed) {
			t.Fatalf("Run error = %v, want %v", err, ErrSessionClosed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after upload callback exited")
	}
}

func TestSessionReportsLateBlockAfterTimeout(t *testing.T) {
	hash := metainfo.Hash{7, 8, 9}
	data := []byte("late")
	timedOut := make(chan BlockRequest, 1)
	retry := make(chan error, 1)
	late := make(chan BlockResult, 1)
	var left, right *Session
	leftConfig := testSessionConfig(&hash, 5, []bool{false})
	leftConfig.RequestTimeout = 30 * time.Millisecond
	leftConfig.LateResponseWindow = 500 * time.Millisecond
	leftConfig.Callbacks.OnLateResponse = func(block BlockResult) { late <- block }
	leftConfig.Callbacks.OnRequestTimeout = func(got BlockRequest) {
		timedOut <- got
		retry <- left.Request(BlockRequest{Index: 0, Length: uint32(len(data))})
	}
	rightConfig := testSessionConfig(&hash, 6, []bool{true})
	rightConfig.UploadTimeout = time.Second
	rightConfig.Callbacks.OnUploadRequest = func(_ context.Context, _ BlockRequest) ([]byte, error) {
		time.Sleep(100 * time.Millisecond)
		return append([]byte(nil), data...), nil
	}
	left, right = startTestSessions(t, leftConfig, rightConfig)
	request := BlockRequest{Index: 0, Length: uint32(len(data))}

	waitSessionState(t, left, func(snapshot SessionSnapshot) bool {
		return snapshot.RemoteAvailability && snapshot.RemotePieces[0]
	})
	if err := left.SetInterested(true); err != nil {
		t.Fatalf("SetInterested: %v", err)
	}
	if err := right.SetChoking(false); err != nil {
		t.Fatalf("SetChoking: %v", err)
	}
	waitSessionState(t, left, func(snapshot SessionSnapshot) bool { return !snapshot.RemoteChoking })
	if err := left.Request(request); err != nil {
		t.Fatalf("Request: %v", err)
	}

	select {
	case got := <-timedOut:
		if got != request {
			t.Fatalf("timed out request = %+v, want %+v", got, request)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request did not time out")
	}
	if err := <-retry; !errors.Is(err, ErrRequestRecentlyExpired) {
		t.Fatalf("immediate retry error = %v, want %v", err, ErrRequestRecentlyExpired)
	}
	select {
	case block := <-late:
		if block.Request != request || !block.Late || !bytes.Equal(block.Data, data) {
			t.Fatalf("late result = %+v, want data %q", block, data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for late block")
	}
}

func TestSessionAcceptsExtensionHandshakeBeforeAvailability(t *testing.T) {
	for _, test := range []struct {
		name string
		fast bool
	}{
		{name: "base"},
		{name: "fast", fast: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			hash := metainfo.Hash{30}
			handshakeReceived := make(chan ExtensionHandshake, 1)
			config := testSessionConfig(&hash, 11, []bool{false})
			config.ExtensionHandshake.Extensions = map[string]uint8{ExtensionMetadata: 1}
			config.Callbacks.OnExtensionHandshake = func(handshake ExtensionHandshake) {
				handshakeReceived <- handshake
			}
			var remoteReserved Reserved
			remoteReserved.Set(CapabilityExtensionProtocol, true)
			if test.fast {
				config.Reserved.Set(CapabilityFast, true)
				remoteReserved.Set(CapabilityFast, true)
			}
			remoteHandshake := HandshakeMessage{Reserved: remoteReserved, InfoHash: hash, PeerID: [20]byte{31}}
			session, remoteConn := startManualSession(t, config, remoteHandshake)

			availabilityID := MsgBitfield
			if test.fast {
				availabilityID = MsgHaveNone
			}
			requirePeerMessage(t, remoteConn, availabilityID)
			requirePeerMessage(t, remoteConn, MsgExtended)
			waitSessionReady(t, session)

			payload, err := EncodeExtensionHandshake(ExtensionHandshake{Extensions: map[string]uint8{ExtensionMetadata: 7}})
			if err != nil {
				t.Fatalf("EncodeExtensionHandshake: %v", err)
			}
			extended, err := FormatExtended(ExtendedHandshakeID, payload)
			if err != nil {
				t.Fatalf("FormatExtended: %v", err)
			}
			if err := WriteMessage(remoteConn, &Message{ID: MsgExtended, Payload: extended}); err != nil {
				t.Fatalf("write extension handshake: %v", err)
			}

			select {
			case handshake := <-handshakeReceived:
				if handshake.Extensions[ExtensionMetadata] != 7 {
					t.Fatalf("extension ID = %d, want 7", handshake.Extensions[ExtensionMetadata])
				}
			case <-time.After(2 * time.Second):
				t.Fatal("base extension handshake was not delivered")
			}
			if snapshot := session.Snapshot(); snapshot.RemoteAvailability {
				t.Fatal("extension handshake established availability")
			}
			availability := &Message{ID: MsgBitfield, Payload: FormatBitfield([]bool{true})}
			if test.fast {
				availability = &Message{ID: MsgHaveAll}
			}
			if err := WriteMessage(remoteConn, availability); err != nil {
				t.Fatalf("write availability: %v", err)
			}
			waitSessionState(t, session, func(snapshot SessionSnapshot) bool {
				return snapshot.RemoteAvailability && snapshot.RemotePieces[0]
			})
		})
	}
}

func TestSessionDoesNotServeUninterestedPeer(t *testing.T) {
	for _, test := range []struct {
		name string
		fast bool
		v2   bool
	}{
		{name: "base"},
		{name: "fast", fast: true},
		{name: "v2", v2: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			v1 := metainfo.Hash{32}
			v2 := metainfo.HashV2{33}
			called := make(chan BlockRequest, 1)
			completed := make(chan BlockRequest, 1)
			config := testSessionConfig(&v1, 12, []bool{true})
			config.Callbacks.OnUploadRequest = func(_ context.Context, request BlockRequest) ([]byte, error) {
				called <- request
				return []byte("data"), nil
			}
			config.Callbacks.OnUploadComplete = func(request BlockRequest) { completed <- request }
			remoteHandshake := HandshakeMessage{InfoHash: v1, PeerID: [20]byte{34}}
			if test.fast {
				config.Reserved.Set(CapabilityFast, true)
				remoteHandshake.Reserved.Set(CapabilityFast, true)
			}
			if test.v2 {
				config.Hashes = metainfo.Hashes{V2: &v2}
				remoteHandshake.InfoHash = v2HandshakeHash(v2)
			}
			session, remoteConn := startManualSession(t, config, remoteHandshake)

			availabilityID := MsgBitfield
			if test.fast {
				availabilityID = MsgHaveAll
			}
			requirePeerMessage(t, remoteConn, availabilityID)
			waitSessionReady(t, session)
			remoteAvailability := &Message{ID: MsgNotInterested}
			if test.fast {
				remoteAvailability = &Message{ID: MsgHaveNone}
			}
			if err := WriteMessage(remoteConn, remoteAvailability); err != nil {
				t.Fatalf("write remote availability: %v", err)
			}
			waitSessionState(t, session, func(snapshot SessionSnapshot) bool { return snapshot.RemoteAvailability })

			unchokeResult := make(chan error, 1)
			go func() { unchokeResult <- session.SetChoking(false) }()
			requirePeerMessage(t, remoteConn, MsgUnchoke)
			if err := <-unchokeResult; err != nil {
				t.Fatalf("SetChoking: %v", err)
			}

			request := BlockRequest{Index: 0, Length: 4}
			if err := WriteMessage(remoteConn, &Message{ID: MsgRequest, Payload: FormatRequest(request.Index, request.Begin, request.Length)}); err != nil {
				t.Fatalf("write Request: %v", err)
			}
			if test.fast || test.v2 {
				message := requirePeerMessage(t, remoteConn, MsgReject)
				got, err := ParseReject(message.Payload)
				if err != nil || got != request {
					t.Fatalf("Reject = (%+v, %v), want %+v", got, err, request)
				}
			} else {
				if err := remoteConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
					t.Fatalf("SetReadDeadline: %v", err)
				}
				_, err := ReadMessage(remoteConn)
				var netErr net.Error
				if !errors.As(err, &netErr) || !netErr.Timeout() {
					t.Fatalf("base Request response error = %v, want read timeout", err)
				}
				if err := remoteConn.SetReadDeadline(time.Time{}); err != nil {
					t.Fatalf("clear read deadline: %v", err)
				}
			}
			select {
			case request := <-called:
				t.Fatalf("served uninterested Request %+v", request)
			default:
			}
			select {
			case request := <-completed:
				t.Fatalf("completed rejected upload %+v", request)
			default:
			}
			select {
			case <-session.Done():
				t.Fatalf("session closed after uninterested Request: %v", session.Err())
			default:
			}
		})
	}
}

func TestNewSessionRejectsNegativeIdleDurations(t *testing.T) {
	for _, test := range []struct {
		name string
		set  func(*SessionConfig)
	}{
		{name: "keepalive", set: func(config *SessionConfig) { config.KeepAliveInterval = -time.Second }},
		{name: "read idle", set: func(config *SessionConfig) { config.ReadIdleTimeout = -time.Second }},
	} {
		t.Run(test.name, func(t *testing.T) {
			hash := metainfo.Hash{35}
			config := testSessionConfig(&hash, 13, []bool{false})
			test.set(&config)
			localConn, remoteConn := net.Pipe()
			defer func() { _ = localConn.Close() }()
			defer func() { _ = remoteConn.Close() }()
			if _, err := NewSession(localConn, config); err == nil {
				t.Fatal("NewSession accepted a negative duration")
			}
		})
	}
}

func TestNewSessionValidatesProtocolPieceLengths(t *testing.T) {
	v1 := metainfo.Hash{45}
	v2 := metainfo.HashV2{46}
	for _, test := range []struct {
		name string
		set  func(*SessionConfig)
	}{
		{
			name: "v1 count",
			set: func(config *SessionConfig) {
				config.PieceLength = 0
				config.V1PieceLengths = []uint32{4, 4}
			},
		},
		{
			name: "v1 zero length",
			set: func(config *SessionConfig) {
				config.PieceLength = 0
				config.V1PieceLengths = []uint32{0}
			},
		},
		{
			name: "v2 without hash",
			set: func(config *SessionConfig) {
				config.V2PieceLengths = []uint32{4}
			},
		},
		{
			name: "hybrid missing v2 layout",
			set: func(config *SessionConfig) {
				config.Hashes.V2 = &v2
				config.PieceLength = 0
				config.V1PieceLengths = []uint32{4}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := testSessionConfig(&v1, 47, []bool{false})
			test.set(&config)
			localConn, remoteConn := net.Pipe()
			defer func() { _ = localConn.Close() }()
			defer func() { _ = remoteConn.Close() }()
			if _, err := NewSession(localConn, config); err == nil {
				t.Fatal("NewSession accepted invalid protocol piece lengths")
			}
		})
	}
}

func TestNewSessionMetadataOnlyRequiresEmptyAvailability(t *testing.T) {
	hash := metainfo.Hash{48}
	for _, test := range []struct {
		name   string
		config SessionConfig
	}{
		{
			name:   "pieces",
			config: testSessionConfig(&hash, 49, []bool{false}),
		},
		{
			name:   "piece length",
			config: testSessionConfig(&hash, 49, nil),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := test.config
			config.MetadataOnly = true
			localConn, remoteConn := net.Pipe()
			defer func() { _ = localConn.Close() }()
			defer func() { _ = remoteConn.Close() }()
			if _, err := NewSession(localConn, config); err == nil {
				t.Fatal("NewSession accepted MetadataOnly with piece availability")
			}
		})
	}
}

func TestSessionMetadataOnlyBootstrap(t *testing.T) {
	v2 := metainfo.HashV2{50, 51, 52}
	metadataReceived := make(chan MetadataMessage, 1)
	hashReceived := make(chan HashRequest, 1)
	extensionReceived := make(chan ExtensionHandshake, 1)
	uploadRequested := make(chan BlockRequest, 1)
	config := testSessionConfig(nil, 50, nil)
	config.Hashes = metainfo.Hashes{V2: &v2}
	config.PieceLength = 0
	config.MetadataOnly = true
	config.Reserved.Set(CapabilityFast, true)
	config.ExtensionHandshake.Extensions = map[string]uint8{ExtensionMetadata: 1}
	config.Callbacks.OnExtensionHandshake = func(handshake ExtensionHandshake) { extensionReceived <- handshake }
	config.Callbacks.OnMetadata = func(message MetadataMessage) { metadataReceived <- message }
	config.Callbacks.OnHashRequest = func(request HashRequest) { hashReceived <- request }
	config.Callbacks.OnUploadRequest = func(_ context.Context, request BlockRequest) ([]byte, error) {
		uploadRequested <- request
		return []byte("data"), nil
	}

	localConn, remoteConn := net.Pipe()
	defer func() { _ = remoteConn.Close() }()
	session, err := NewSession(localConn, config)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- session.Run(ctx) }()
	t.Cleanup(func() {
		_ = session.Close()
		select {
		case <-result:
		case <-time.After(2 * time.Second):
			t.Error("session Run did not return")
		}
	})

	if err := remoteConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	var remoteReserved Reserved
	remoteReserved.Set(CapabilityExtensionProtocol, true)
	remoteReserved.Set(CapabilityFast, true)
	if err := WriteHandshake(remoteConn, HandshakeMessage{Reserved: remoteReserved, InfoHash: v2HandshakeHash(v2), PeerID: [20]byte{51}}); err != nil {
		t.Fatalf("WriteHandshake: %v", err)
	}
	response, err := ReadHandshake(remoteConn)
	if err != nil {
		t.Fatalf("ReadHandshake: %v", err)
	}
	if response.Reserved.Has(CapabilityFast) {
		t.Fatal("MetadataOnly handshake advertised Fast support")
	}
	requirePeerMessage(t, remoteConn, MsgExtended)
	waitSessionReady(t, session)

	ignored := []*Message{
		{ID: MsgBitfield, Payload: make([]byte, 64<<10)},
		{ID: MsgHave, Payload: FormatHave(^uint32(0))},
		{ID: MsgHaveAll},
		{ID: MsgHaveNone},
		{ID: MsgSuggestPiece, Payload: FormatSuggestPiece(^uint32(0))},
		{ID: MsgAllowedFast, Payload: FormatAllowedFast(^uint32(0))},
		{ID: MsgRequest, Payload: FormatRequest(^uint32(0), 0, 4)},
		{ID: MsgCancel, Payload: FormatCancel(^uint32(0), 0, 4)},
		{ID: MsgReject, Payload: FormatReject(^uint32(0), 0, 4)},
	}
	for _, message := range ignored {
		if err := WriteMessage(remoteConn, message); err != nil {
			t.Fatalf("write ignored message %d: %v", message.ID, err)
		}
	}

	extensionPayload, err := EncodeExtensionHandshake(ExtensionHandshake{Extensions: map[string]uint8{ExtensionMetadata: 7}})
	if err != nil {
		t.Fatalf("EncodeExtensionHandshake: %v", err)
	}
	extended, err := FormatExtended(ExtendedHandshakeID, extensionPayload)
	if err != nil {
		t.Fatalf("FormatExtended handshake: %v", err)
	}
	if err := WriteMessage(remoteConn, &Message{ID: MsgExtended, Payload: extended}); err != nil {
		t.Fatalf("write extension handshake: %v", err)
	}
	select {
	case <-extensionReceived:
	case <-time.After(2 * time.Second):
		t.Fatal("extension handshake was not delivered")
	}

	wantMetadata := MetadataMessage{Type: MetadataRequest, Piece: 0}
	metadataPayload, err := wantMetadata.Encode()
	if err != nil {
		t.Fatalf("encode metadata: %v", err)
	}
	extended, err = FormatExtended(1, metadataPayload)
	if err != nil {
		t.Fatalf("FormatExtended metadata: %v", err)
	}
	if err := WriteMessage(remoteConn, &Message{ID: MsgExtended, Payload: extended}); err != nil {
		t.Fatalf("write metadata: %v", err)
	}
	wantHash := HashRequest{PiecesRoot: v2, Length: 2}
	hashPayload, err := FormatHashRequest(wantHash)
	if err != nil {
		t.Fatalf("FormatHashRequest: %v", err)
	}
	if err := WriteMessage(remoteConn, &Message{ID: MsgHashRequest, Payload: hashPayload}); err != nil {
		t.Fatalf("write hash request: %v", err)
	}

	select {
	case got := <-metadataReceived:
		if got.Type != wantMetadata.Type || got.Piece != wantMetadata.Piece {
			t.Fatalf("metadata = %+v, want %+v", got, wantMetadata)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("metadata message was not delivered")
	}
	select {
	case got := <-hashReceived:
		if got != wantHash {
			t.Fatalf("hash request = %+v, want %+v", got, wantHash)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hash request was not delivered")
	}
	select {
	case request := <-uploadRequested:
		t.Fatalf("MetadataOnly served block request %+v", request)
	default:
	}
	snapshot := session.Snapshot()
	if snapshot.RemoteAvailability || len(snapshot.RemotePieces) != 0 {
		t.Fatalf("metadata-only availability = (%v, %v), want unset and empty", snapshot.RemoteAvailability, snapshot.RemotePieces)
	}
	select {
	case <-session.Done():
		t.Fatalf("metadata-only session closed: %v", session.Err())
	default:
	}
}

func TestSessionHybridUpgradeAndDirectionalExtensions(t *testing.T) {
	v1 := metainfo.Hash{10, 11, 12}
	v2 := metainfo.HashV2{13, 14, 15}
	metadata := make(chan MetadataMessage, 1)
	uploadStarted := make(chan struct{}, 1)
	blockResult := make(chan BlockResult, 1)
	leftConfig := testSessionConfig(&v1, 7, []bool{false})
	leftConfig.Hashes.V2 = &v2
	leftConfig.ExtensionHandshake.Extensions = map[string]uint8{ExtensionMetadata: 1}
	leftConfig.Callbacks.OnBlock = func(block BlockResult) { blockResult <- block }
	rightConfig := testSessionConfig(&v1, 8, []bool{true})
	rightConfig.Hashes.V2 = &v2
	rightConfig.ExtensionHandshake.Extensions = map[string]uint8{ExtensionMetadata: 7}
	rightConfig.Callbacks.OnMetadata = func(message MetadataMessage) { metadata <- message }
	rightConfig.Callbacks.OnUploadRequest = func(ctx context.Context, _ BlockRequest) ([]byte, error) {
		uploadStarted <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	left, right := startTestSessions(t, leftConfig, rightConfig)

	leftSnapshot := left.Snapshot()
	rightSnapshot := right.Snapshot()
	if leftSnapshot.Version != ProtocolV2 || rightSnapshot.Version != ProtocolV2 {
		t.Fatalf("versions = (%d, %d), want v2", leftSnapshot.Version, rightSnapshot.Version)
	}
	waitSessionState(t, left, func(snapshot SessionSnapshot) bool {
		return snapshot.OutgoingExtensions[ExtensionMetadata] == 7
	})
	waitSessionState(t, right, func(snapshot SessionSnapshot) bool {
		return snapshot.OutgoingExtensions[ExtensionMetadata] == 1
	})
	want := MetadataMessage{Type: MetadataRequest, Piece: 3}
	if err := left.SendMetadata(want); err != nil {
		t.Fatalf("SendMetadata: %v", err)
	}
	select {
	case got := <-metadata:
		if got.Type != want.Type || got.Piece != want.Piece {
			t.Fatalf("metadata = %+v, want %+v", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for metadata")
	}

	waitSessionState(t, left, func(snapshot SessionSnapshot) bool { return snapshot.RemotePieces[0] })
	if err := left.SetInterested(true); err != nil {
		t.Fatalf("SetInterested: %v", err)
	}
	if err := right.SetChoking(false); err != nil {
		t.Fatalf("SetChoking: %v", err)
	}
	waitSessionState(t, left, func(snapshot SessionSnapshot) bool { return !snapshot.RemoteChoking })
	request := BlockRequest{Index: 0, Length: 4}
	if err := left.Request(request); err != nil {
		t.Fatalf("Request: %v", err)
	}
	select {
	case <-uploadStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("v2 upload did not start")
	}
	if err := left.Cancel(request); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	select {
	case result := <-blockResult:
		if !result.Rejected || !result.Cancelled {
			t.Fatalf("v2 cancel result = %+v, want cancelled rejection", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for v2 rejection")
	}
}

func TestSessionHybridUpgradeUsesHandshakeResponse(t *testing.T) {
	v1 := metainfo.Hash{21, 22, 23}
	v2 := metainfo.HashV2{24, 25, 26}
	data := []byte("v2ok")
	localConn, remoteConn := net.Pipe()
	defer func() { _ = remoteConn.Close() }()
	config := testSessionConfig(&v1, 9, []bool{true})
	config.Hashes.V2 = &v2
	config.PieceLength = 0
	config.V1PieceLengths = []uint32{4}
	config.V2PieceLengths = []uint32{8}
	config.Callbacks.OnUploadRequest = func(_ context.Context, request BlockRequest) ([]byte, error) {
		return append([]byte(nil), data[:request.Length]...), nil
	}
	session, err := NewSession(localConn, config)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- session.Run(ctx) }()
	if err := remoteConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	var reserved Reserved
	reserved.Set(CapabilityV2Upgrade, true)
	remoteHandshake := HandshakeMessage{Reserved: reserved, InfoHash: v1, PeerID: [20]byte{99}}
	if err := WriteHandshake(remoteConn, remoteHandshake); err != nil {
		t.Fatalf("WriteHandshake: %v", err)
	}
	response, err := ReadHandshake(remoteConn)
	if err != nil {
		t.Fatalf("ReadHandshake: %v", err)
	}
	if response.InfoHash != v2HandshakeHash(v2) {
		t.Fatalf("response info hash = %x, want truncated v2 %x", response.InfoHash, v2HandshakeHash(v2))
	}
	if response.Reserved.Has(CapabilityV2Upgrade) {
		t.Fatal("v2 handshake response retained the v1 upgrade bit")
	}
	message, err := ReadMessage(remoteConn)
	if err != nil {
		t.Fatalf("read initial availability: %v", err)
	}
	if message == nil || message.ID != MsgBitfield {
		t.Fatalf("initial message = %+v, want Bitfield", message)
	}
	waitSessionReady(t, session)
	if err := WriteMessage(remoteConn, &Message{ID: MsgInterested}); err != nil {
		t.Fatalf("write Interested: %v", err)
	}
	waitSessionState(t, session, func(snapshot SessionSnapshot) bool { return snapshot.RemoteInterested })
	unchoked := make(chan error, 1)
	go func() { unchoked <- session.SetChoking(false) }()
	requirePeerMessage(t, remoteConn, MsgUnchoke)
	if err := <-unchoked; err != nil {
		t.Fatalf("SetChoking: %v", err)
	}
	request := BlockRequest{Index: 0, Begin: 4, Length: uint32(len(data))}
	if err := WriteMessage(remoteConn, &Message{ID: MsgRequest, Payload: FormatRequest(request.Index, request.Begin, request.Length)}); err != nil {
		t.Fatalf("write v2 Request: %v", err)
	}
	piece := requirePeerMessage(t, remoteConn, MsgPiece)
	index, begin, got, err := ParsePiece(piece.Payload)
	if err != nil {
		t.Fatalf("ParsePiece: %v", err)
	}
	if index != request.Index || begin != request.Begin || !bytes.Equal(got, data) {
		t.Fatalf("Piece = %d:%d %q, want %d:%d %q", index, begin, got, request.Index, request.Begin, data)
	}
	_ = remoteConn.Close()
	select {
	case <-result:
	case <-time.After(2 * time.Second):
		t.Fatal("session Run did not return")
	}
}

func TestSessionExchangesPEXAndV2ControlMessages(t *testing.T) {
	v2 := metainfo.HashV2{52, 53, 54}
	request := HashRequest{PiecesRoot: v2, Length: 2}
	wantHashes := Hashes{Request: request, Values: []metainfo.HashV2{{1}, {2}}}
	wantPEX := PEXMessage{Added: []PEXContact{{
		AddrPort: netip.MustParseAddrPort("127.0.0.1:6881"),
		Flags:    PEXSupportsUTP,
	}}}
	pexReceived := make(chan PEXMessage, 1)
	hashRequestReceived := make(chan HashRequest, 1)
	hashesReceived := make(chan Hashes, 1)
	hashRejectReceived := make(chan HashRequest, 1)
	leftPortReceived := make(chan uint16, 1)
	rightPortReceived := make(chan uint16, 1)

	leftConfig := testSessionConfig(nil, 52, []bool{false})
	leftConfig.Hashes = metainfo.Hashes{V2: &v2}
	leftConfig.DHTPort = 6881
	leftConfig.AllowedFast = []uint32{0}
	leftConfig.ExtensionHandshake.Extensions = map[string]uint8{ExtensionPEX: 1}
	leftConfig.Callbacks.OnPort = func(port uint16) { leftPortReceived <- port }
	leftConfig.Callbacks.OnHashes = func(hashes Hashes) { hashesReceived <- hashes }
	leftConfig.Callbacks.OnHashReject = func(got HashRequest) { hashRejectReceived <- got }

	rightConfig := testSessionConfig(nil, 53, []bool{false})
	rightConfig.Hashes = metainfo.Hashes{V2: &v2}
	rightConfig.DHTPort = 6882
	rightConfig.AllowedFast = []uint32{0}
	rightConfig.ExtensionHandshake.Extensions = map[string]uint8{ExtensionPEX: 7}
	rightConfig.Callbacks.OnPort = func(port uint16) { rightPortReceived <- port }
	rightConfig.Callbacks.OnPEX = func(message PEXMessage) { pexReceived <- message }
	rightConfig.Callbacks.OnHashRequest = func(got HashRequest) { hashRequestReceived <- got }

	left, right := startTestSessions(t, leftConfig, rightConfig)
	waitSessionState(t, left, func(snapshot SessionSnapshot) bool {
		return snapshot.OutgoingExtensions[ExtensionPEX] == 7
	})
	waitSessionState(t, right, func(snapshot SessionSnapshot) bool {
		return snapshot.OutgoingExtensions[ExtensionPEX] == 1
	})

	for name, test := range map[string]struct {
		result <-chan uint16
		want   uint16
	}{
		"left":  {result: leftPortReceived, want: 6882},
		"right": {result: rightPortReceived, want: 6881},
	} {
		select {
		case port := <-test.result:
			if port != test.want {
				t.Fatalf("%s received port %d, want %d", name, port, test.want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s did not receive a DHT port", name)
		}
	}

	if err := left.Have(0); err != nil {
		t.Fatalf("Have: %v", err)
	}
	if err := left.Have(0); err != nil {
		t.Fatalf("duplicate Have: %v", err)
	}
	waitSessionState(t, right, func(snapshot SessionSnapshot) bool { return snapshot.RemotePieces[0] })
	if err := left.Have(1); err == nil {
		t.Fatal("Have accepted an out-of-range piece")
	}

	if err := left.SendPEX(wantPEX); err != nil {
		t.Fatalf("SendPEX: %v", err)
	}
	select {
	case got := <-pexReceived:
		if len(got.Added) != 1 || got.Added[0] != wantPEX.Added[0] {
			t.Fatalf("PEX = %+v, want %+v", got, wantPEX)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PEX was not delivered")
	}
	if err := left.SendPEX(wantPEX); err == nil {
		t.Fatal("SendPEX ignored its cadence limit")
	}

	if err := left.SendHashRequest(HashRequest{}); err == nil {
		t.Fatal("SendHashRequest accepted an invalid request")
	}
	if err := left.SendHashes(Hashes{Request: request}); err == nil {
		t.Fatal("SendHashes accepted a missing hash list")
	}
	if err := left.SendHashReject(HashRequest{}); err == nil {
		t.Fatal("SendHashReject accepted an invalid request")
	}
	if err := left.SendHashRequest(request); err != nil {
		t.Fatalf("SendHashRequest: %v", err)
	}
	select {
	case got := <-hashRequestReceived:
		if got != request {
			t.Fatalf("Hash Request = %+v, want %+v", got, request)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Hash Request was not delivered")
	}
	if err := right.SendHashes(wantHashes); err != nil {
		t.Fatalf("SendHashes: %v", err)
	}
	select {
	case got := <-hashesReceived:
		if got.Request != request || len(got.Values) != len(wantHashes.Values) || got.Values[0] != wantHashes.Values[0] || got.Values[1] != wantHashes.Values[1] {
			t.Fatalf("Hashes = %+v, want %+v", got, wantHashes)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Hashes were not delivered")
	}
	if err := right.SendHashReject(request); err != nil {
		t.Fatalf("SendHashReject: %v", err)
	}
	select {
	case got := <-hashRejectReceived:
		if got != request {
			t.Fatalf("Hash Reject = %+v, want %+v", got, request)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Hash Reject was not delivered")
	}
}

func TestNewSessionRejectsPEXForPrivateTorrent(t *testing.T) {
	hash := metainfo.Hash{27}
	localConn, remoteConn := net.Pipe()
	defer func() { _ = localConn.Close() }()
	defer func() { _ = remoteConn.Close() }()
	config := testSessionConfig(&hash, 10, []bool{false})
	config.Private = true
	config.ExtensionHandshake.Extensions = map[string]uint8{ExtensionPEX: 1}
	if _, err := NewSession(localConn, config); !errors.Is(err, ErrPEXDisabled) {
		t.Fatalf("NewSession error = %v, want %v", err, ErrPEXDisabled)
	}
}

func testSessionConfig(hash *metainfo.Hash, peerByte byte, pieces []bool) SessionConfig {
	var peerID [20]byte
	for index := range peerID {
		peerID[index] = peerByte
	}
	return SessionConfig{
		PeerID:                 peerID,
		Hashes:                 metainfo.Hashes{V1: hash},
		PieceCount:             uint32(len(pieces)),
		PieceLength:            MaxBlockLength,
		LocalPieces:            append([]bool(nil), pieces...),
		HandshakeTimeout:       time.Second,
		RequestTimeout:         time.Second,
		LateResponseWindow:     time.Second,
		UploadTimeout:          time.Second,
		WriteTimeout:           time.Second,
		KeepAliveInterval:      time.Hour,
		ReadIdleTimeout:        time.Hour,
		PEXMinInterval:         time.Minute,
		MaxOutstandingRequests: 8,
		MaxInboundRequests:     8,
	}
}

func startTestSessions(t *testing.T, leftConfig, rightConfig SessionConfig) (*Session, *Session) {
	t.Helper()
	leftConn, rightConn := net.Pipe()
	leftConfig.Outgoing = true
	rightConfig.Outgoing = false
	left, err := NewSession(leftConn, leftConfig)
	if err != nil {
		t.Fatalf("NewSession(left): %v", err)
	}
	right, err := NewSession(rightConn, rightConfig)
	if err != nil {
		t.Fatalf("NewSession(right): %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	leftResult := make(chan error, 1)
	rightResult := make(chan error, 1)
	go func() { leftResult <- left.Run(ctx) }()
	go func() { rightResult <- right.Run(ctx) }()
	waitSessionReady(t, left)
	waitSessionReady(t, right)
	t.Cleanup(func() {
		cancel()
		_ = left.Close()
		_ = right.Close()
		for _, result := range []<-chan error{leftResult, rightResult} {
			select {
			case <-result:
			case <-time.After(2 * time.Second):
				t.Error("session Run did not return")
			}
		}
	})
	return left, right
}

func startManualSession(t *testing.T, config SessionConfig, remoteHandshake HandshakeMessage) (*Session, net.Conn) {
	t.Helper()
	localConn, remoteConn := net.Pipe()
	session, err := NewSession(localConn, config)
	if err != nil {
		_ = localConn.Close()
		_ = remoteConn.Close()
		t.Fatalf("NewSession: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- session.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = session.Close()
		_ = remoteConn.Close()
		select {
		case <-result:
		case <-time.After(2 * time.Second):
			t.Error("session Run did not return")
		}
	})
	if err := remoteConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := WriteHandshake(remoteConn, remoteHandshake); err != nil {
		t.Fatalf("WriteHandshake: %v", err)
	}
	if _, err := ReadHandshake(remoteConn); err != nil {
		t.Fatalf("ReadHandshake: %v", err)
	}
	return session, remoteConn
}

func requirePeerMessage(t *testing.T, conn net.Conn, want MessageID) *Message {
	t.Helper()
	message, err := ReadMessage(conn)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if message == nil || message.ID != want {
		t.Fatalf("message = %+v, want ID %d", message, want)
	}
	return message
}

func waitSessionReady(t *testing.T, session *Session) {
	t.Helper()
	select {
	case <-session.Ready():
	case <-session.Done():
		t.Fatalf("session closed before ready: %v", session.Err())
	case <-time.After(2 * time.Second):
		t.Fatal("session did not become ready")
	}
}

func waitSessionState(t *testing.T, session *Session, ready func(SessionSnapshot) bool) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		if ready(session.Snapshot()) {
			return
		}
		select {
		case <-session.Done():
			t.Fatalf("session closed while waiting for state: %v", session.Err())
		case <-ticker.C:
		case <-timer.C:
			t.Fatal("timed out waiting for session state")
		}
	}
}
