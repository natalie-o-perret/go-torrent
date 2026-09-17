package client

import (
	"fmt"
	"time"

	"github.com/natalie-o-perret/go-torrent/webseed"
)

type webseedRuntime struct {
	downloader *webseed.Downloader
	next       time.Time
	failures   int
	active     bool
	disabled   bool
}

type webseedResultEvent struct {
	source *webseedRuntime
	index  uint32
	data   []byte
	err    error
}

func (state *coordinator) scheduleWebseeds(now time.Time, verified []bool) {
	for _, source := range state.webseeds {
		if source.active || source.disabled || now.Before(source.next) {
			continue
		}
		for index, complete := range verified {
			pieceIndex := uint32(index)
			if complete || state.webseedPieceActive(pieceIndex) {
				continue
			}
			source.active = true
			state.webseedReserved[pieceIndex] = struct{}{}
			state.workers.Add(1)
			go state.downloadWebseed(source, pieceIndex)
			break
		}
	}
}

func (state *coordinator) webseedPieceActive(index uint32) bool {
	if _, reserved := state.webseedReserved[index]; reserved {
		return true
	}
	for key := range state.active {
		if key.index == index {
			return true
		}
	}
	return false
}

func (state *coordinator) downloadWebseed(source *webseedRuntime, index uint32) {
	defer state.workers.Done()
	data, err := source.downloader.ReadPiece(state.ctx, protocolStorage(state.client.primary), int(index))
	state.emit(webseedResultEvent{source: source, index: index, data: data, err: err})
}

func (state *coordinator) handleWebseedResult(event webseedResultEvent) error {
	event.source.active = false
	delete(state.webseedReserved, event.index)
	if event.err != nil {
		if webseed.IsRetryable(event.err) {
			event.source.failures++
			event.source.next = state.client.now().Add(webseedBackoff(state.client.retryInterval, event.source.failures))
		} else {
			event.source.disabled = true
		}
		return nil
	}

	event.source.failures = 0
	event.source.next = time.Time{}
	state.client.storageMu.Lock()
	err := state.client.store.WritePiece(protocolStorage(state.client.primary), int(event.index), event.data)
	verified := false
	if err == nil {
		verified, err = state.client.store.VerifyPiece(int(event.index))
	}
	state.client.storageMu.Unlock()
	if err != nil {
		return fmt.Errorf("client: store web-seed piece %d: %w", event.index, err)
	}
	if !verified {
		event.source.disabled = true
		return nil
	}

	state.client.localMu.Lock()
	alreadyComplete := int(event.index) >= len(state.client.verified) || state.client.verified[event.index]
	if !alreadyComplete {
		state.client.downloaded[state.client.primary] += int64(len(event.data))
	}
	state.client.localMu.Unlock()
	if !alreadyComplete {
		state.finishPiece(event.index)
	}
	return nil
}

func webseedBackoff(base time.Duration, failures int) time.Duration {
	delay := min(base, time.Minute)
	for count := 1; count < failures && delay < time.Minute; count++ {
		if delay > time.Minute/2 {
			return time.Minute
		}
		delay *= 2
	}
	return delay
}
