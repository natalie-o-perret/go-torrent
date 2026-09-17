package client

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/natalie-o-perret/go-torrent/peer"
	"github.com/natalie-o-perret/go-torrent/tracker"
)

type trackerRuntime struct {
	coordinator *coordinator
	protocol    peer.ProtocolVersion
	session     *tracker.Session
}

type trackerResultEvent struct {
	protocol peer.ProtocolVersion
	result   *tracker.SessionResult
}

type privateTrackerSwitchEvent struct {
	tracker string
	done    chan struct{}
}

type privateTrackerRuntime struct {
	coordinator *coordinator
	protocols   []peer.ProtocolVersion
	trackers    []string
}

type privateTrackerSession struct {
	protocol    peer.ProtocolVersion
	session     *tracker.Session
	initialLeft int64
	completed   bool
}

func (state *coordinator) startTrackers() ([]*trackerRuntime, error) {
	if len(state.client.meta.Trackers()) == 0 {
		return nil, nil
	}
	var announceList [][]string
	if state.client.meta.AnnounceList != nil {
		announceList = state.client.meta.AnnounceList
	}
	if state.client.meta.Info.Private {
		template, err := tracker.NewSession(state.client.trackerClient, state.client.meta.Announce, announceList)
		if err != nil {
			return nil, fmt.Errorf("client: create private tracker controller: %w", err)
		}
		private := &privateTrackerRuntime{coordinator: state, trackers: flattenTrackerTiers(template.Tiers())}
		for _, protocol := range []peer.ProtocolVersion{peer.ProtocolV1, peer.ProtocolV2} {
			if state.client.layouts[protocol] != nil {
				private.protocols = append(private.protocols, protocol)
			}
		}
		state.workers.Add(1)
		go private.run()
		return nil, nil
	}
	var runtimes []*trackerRuntime
	for _, protocol := range []peer.ProtocolVersion{peer.ProtocolV1, peer.ProtocolV2} {
		if state.client.layouts[protocol] == nil {
			continue
		}
		session, err := tracker.NewSession(state.client.trackerClient, state.client.meta.Announce, announceList)
		if err != nil {
			return nil, fmt.Errorf("client: create %s tracker session: %w", protocolName(protocol), err)
		}
		runtime := &trackerRuntime{coordinator: state, protocol: protocol, session: session}
		runtimes = append(runtimes, runtime)
	}
	for _, runtime := range runtimes {
		state.workers.Add(1)
		go runtime.run()
	}
	return runtimes, nil
}

func (runtime *trackerRuntime) run() {
	defer runtime.coordinator.workers.Done()
	state := runtime.coordinator
	client := state.client
	var initialLeft int64
	for {
		request := client.trackerRequest(runtime.protocol)
		result, err := runtime.session.Start(state.ctx, request)
		if err == nil {
			initialLeft = request.Left
			state.emit(trackerResultEvent{protocol: runtime.protocol, result: result})
			break
		}
		if state.ctx.Err() != nil || !runtime.wait(client.retryInterval) {
			return
		}
	}
	defer runtime.stop()

	completion := client.completed
	if initialLeft == 0 {
		completion = nil
	}
	completionPending := false
	completed := false
	for {
		if completionPending && !completed {
			request := client.trackerRequest(runtime.protocol)
			result, err := runtime.session.Complete(state.ctx, request)
			if err == nil {
				completed = true
				completionPending = false
				client.localMu.Lock()
				client.trackerCompleted[runtime.protocol] = true
				client.localMu.Unlock()
				state.emit(trackerResultEvent{protocol: runtime.protocol, result: result})
				continue
			}
			if state.ctx.Err() != nil || !runtime.wait(client.retryInterval) {
				return
			}
			continue
		}

		delay := time.Until(runtime.session.NextAnnounce())
		if delay < 0 {
			delay = 0
		}
		select {
		case <-state.ctx.Done():
			return
		case <-completion:
			completion = nil
			completionPending = true
			continue
		case <-client.after(delay):
		}
		result, err := runtime.session.Announce(state.ctx, client.trackerRequest(runtime.protocol))
		if err == nil {
			state.emit(trackerResultEvent{protocol: runtime.protocol, result: result})
			continue
		}
		if errors.Is(err, tracker.ErrNotDue) {
			continue
		}
		if state.ctx.Err() != nil || !runtime.wait(client.retryInterval) {
			return
		}
	}
}

func (runtime *trackerRuntime) wait(duration time.Duration) bool {
	select {
	case <-runtime.coordinator.ctx.Done():
		return false
	case <-runtime.coordinator.client.after(duration):
		return true
	}
}

func (runtime *trackerRuntime) stop() {
	client := runtime.coordinator.client
	ctx, cancel := context.WithTimeout(context.Background(), client.trackerStopTimeout)
	defer cancel()
	_, _ = runtime.session.Stop(ctx, client.trackerRequest(runtime.protocol))
}

func (runtime *privateTrackerRuntime) run() {
	defer runtime.coordinator.workers.Done()
	index := 0
	for runtime.coordinator.ctx.Err() == nil {
		trackerURL := runtime.trackers[index]
		if !runtime.selectTracker(trackerURL) {
			return
		}
		sessions, results, ok := runtime.start(trackerURL)
		if ok {
			for resultIndex, result := range results {
				runtime.coordinator.emit(trackerResultEvent{protocol: sessions[resultIndex].protocol, result: result})
			}
			runtime.serve(sessions)
		}
		runtime.stop(sessions)
		if runtime.coordinator.ctx.Err() != nil {
			return
		}
		index = (index + 1) % len(runtime.trackers)
		if index == 0 && !runtime.wait() {
			return
		}
	}
}

func (runtime *privateTrackerRuntime) selectTracker(trackerURL string) bool {
	event := privateTrackerSwitchEvent{tracker: trackerURL, done: make(chan struct{})}
	if !runtime.coordinator.emit(event) {
		return false
	}
	select {
	case <-event.done:
		return true
	case <-runtime.coordinator.ctx.Done():
		return false
	}
}

func (runtime *privateTrackerRuntime) start(trackerURL string) ([]*privateTrackerSession, []*tracker.SessionResult, bool) {
	state := runtime.coordinator
	var sessions []*privateTrackerSession
	var results []*tracker.SessionResult
	for _, protocol := range runtime.protocols {
		session, err := tracker.NewSession(state.client.trackerClient, trackerURL, nil)
		if err != nil {
			return sessions, results, false
		}
		request := state.client.trackerRequest(protocol)
		result, err := session.Start(state.ctx, request)
		if err != nil {
			return sessions, results, false
		}
		sessions = append(sessions, &privateTrackerSession{protocol: protocol, session: session, initialLeft: request.Left})
		results = append(results, result)
	}
	return sessions, results, true
}

func (runtime *privateTrackerRuntime) serve(sessions []*privateTrackerSession) {
	state := runtime.coordinator
	completion := state.client.completed
	hasIncomplete := false
	for _, session := range sessions {
		hasIncomplete = hasIncomplete || session.initialLeft != 0
	}
	if !hasIncomplete {
		completion = nil
	}
	completionPending := false
	for {
		if completionPending {
			for _, session := range sessions {
				if session.initialLeft == 0 || session.completed {
					continue
				}
				result, err := session.session.Complete(state.ctx, state.client.trackerRequest(session.protocol))
				if err != nil {
					return
				}
				session.completed = true
				state.client.localMu.Lock()
				state.client.trackerCompleted[session.protocol] = true
				state.client.localMu.Unlock()
				state.emit(trackerResultEvent{protocol: session.protocol, result: result})
			}
			completionPending = false
		}

		delay := time.Duration(math.MaxInt64)
		for _, session := range sessions {
			until := time.Until(session.session.NextAnnounce())
			if until < delay {
				delay = until
			}
		}
		if delay < 0 {
			delay = 0
		}
		select {
		case <-state.ctx.Done():
			return
		case <-completion:
			completion = nil
			completionPending = true
			continue
		case <-state.client.after(delay):
		}
		now := time.Now()
		for _, session := range sessions {
			if !session.session.Due(now) {
				continue
			}
			result, err := session.session.Announce(state.ctx, state.client.trackerRequest(session.protocol))
			if err != nil && !errors.Is(err, tracker.ErrNotDue) {
				return
			}
			if err == nil {
				state.emit(trackerResultEvent{protocol: session.protocol, result: result})
			}
		}
	}
}

func (runtime *privateTrackerRuntime) stop(sessions []*privateTrackerSession) {
	var workers sync.WaitGroup
	workers.Add(len(sessions))
	for _, session := range sessions {
		session := session
		go func() {
			defer workers.Done()
			ctx, cancel := context.WithTimeout(context.Background(), runtime.coordinator.client.trackerStopTimeout)
			defer cancel()
			_, _ = session.session.Stop(ctx, runtime.coordinator.client.trackerRequest(session.protocol))
		}()
	}
	workers.Wait()
}

func (runtime *privateTrackerRuntime) wait() bool {
	select {
	case <-runtime.coordinator.ctx.Done():
		return false
	case <-runtime.coordinator.client.after(runtime.coordinator.client.retryInterval):
		return true
	}
}

func flattenTrackerTiers(tiers [][]string) []string {
	seen := make(map[string]struct{})
	var trackers []string
	for _, tier := range tiers {
		for _, trackerURL := range tier {
			if _, ok := seen[trackerURL]; ok {
				continue
			}
			seen[trackerURL] = struct{}{}
			trackers = append(trackers, trackerURL)
		}
	}
	return trackers
}

func (client *Client) trackerRequest(protocol peer.ProtocolVersion) tracker.AnnounceRequest {
	client.localMu.RLock()
	defer client.localMu.RUnlock()
	layout := client.layouts[protocol]
	left := layout.total
	for index, verified := range client.verified {
		if verified {
			left -= int64(layout.pieces[index].length)
		}
	}
	numWant := client.maxCandidates
	if int64(numWant) > math.MaxInt32 {
		numWant = math.MaxInt32
	}
	return tracker.AnnounceRequest{
		Uploaded:   client.uploaded[protocol],
		Downloaded: client.downloaded[protocol],
		Left:       left,
		NumWant:    numWant,
		Port:       client.port,
		InfoHash:   layout.infoHash,
		PeerID:     client.peerID,
	}
}

func (state *coordinator) handleTrackerResult(event trackerResultEvent) {
	if event.result == nil {
		return
	}
	if state.client.meta.Info.Private && state.privateTracker != event.result.Tracker {
		return
	}
	for _, trackedPeer := range event.result.Peers {
		candidate := Candidate{
			Address:  trackedPeer.String(),
			Tracker:  event.result.Tracker,
			PeerID:   trackedPeer.PeerID,
			Protocol: event.protocol,
			Source:   SourceTracker,
		}
		validated, err := state.client.validateCandidate(candidate)
		if err == nil {
			_ = state.addCandidate(validated)
		}
	}
}

func protocolName(protocol peer.ProtocolVersion) string {
	if protocol == peer.ProtocolV2 {
		return "v2"
	}
	return "v1"
}
