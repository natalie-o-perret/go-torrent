package tracker

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/natalie-o-perret/go-torrent/metainfo"
)

// ErrNotDue is returned when a regular session announce is attempted before
// the tracker's interval and min interval have elapsed.
var ErrNotDue = errors.New("tracker: regular announce is not due")

// SessionResult identifies the tracker used for an announce. Switched lets a
// private-torrent caller discard peers obtained from PreviousTracker.
type SessionResult struct {
	*AnnounceResponse
	Tracker         string
	PreviousTracker string
	Switched        bool
	NextAnnounce    time.Time
}

// Session manages one torrent's BEP 12 tracker tiers and announce lifecycle.
// A Session is not safe for concurrent use.
type Session struct {
	client      *Client
	tiers       [][]string
	trackerIDs  map[string]string
	key         uint32
	current     string
	next        time.Time
	infoHash    metainfo.Hash
	peerID      [20]byte
	initialLeft int64
	started     bool
	completed   bool
	stopped     bool
}

// NewSession constructs tracker tiers. A nonempty announceList takes
// precedence over announce as required by BEP 12. Each tier is shuffled once.
func NewSession(client *Client, announce string, announceList [][]string) (*Session, error) {
	tiers, err := newSessionTiers(client, announce, announceList)
	if err != nil {
		return nil, err
	}
	return newSession(client, tiers), nil
}

func newSessionTiers(client *Client, announce string, announceList [][]string) ([][]string, error) {
	if client == nil {
		return nil, fmt.Errorf("tracker: nil client")
	}
	var tiers [][]string
	if announceList != nil {
		if len(announceList) == 0 {
			return nil, fmt.Errorf("tracker: announce list is empty")
		}
		tiers = make([][]string, len(announceList))
		for i, tier := range announceList {
			if len(tier) == 0 {
				return nil, fmt.Errorf("tracker: tier %d is empty", i)
			}
			tiers[i] = append([]string(nil), tier...)
		}
	} else {
		if announce == "" {
			return nil, fmt.Errorf("tracker: no announce URL")
		}
		tiers = [][]string{{announce}}
	}
	for i := range tiers {
		for j, trackerURL := range tiers[i] {
			if _, err := parseTrackerURL(trackerURL); err != nil {
				return nil, fmt.Errorf("tracker: tier %d entry %d: %w", i, j, err)
			}
		}
		rand.Shuffle(len(tiers[i]), func(a, b int) {
			tiers[i][a], tiers[i][b] = tiers[i][b], tiers[i][a]
		})
	}
	return tiers, nil
}

func newSession(client *Client, tiers [][]string) *Session {
	copied := make([][]string, len(tiers))
	for index := range tiers {
		copied[index] = append([]string(nil), tiers[index]...)
	}
	return &Session{client: client, tiers: copied, trackerIDs: make(map[string]string)}
}

// Start sends the required first announce.
func (s *Session) Start(ctx context.Context, request AnnounceRequest) (*SessionResult, error) {
	if s.started {
		return nil, fmt.Errorf("tracker: session has already started")
	}
	if s.stopped {
		return nil, fmt.Errorf("tracker: session has stopped")
	}
	request.Event = EventStarted
	result, err := s.send(ctx, request)
	if err != nil {
		return nil, err
	}
	s.started = true
	s.infoHash = request.InfoHash
	s.peerID = request.PeerID
	s.initialLeft = request.Left
	return result, nil
}

// Announce sends a regular announce when NextAnnounce is due.
func (s *Session) Announce(ctx context.Context, request AnnounceRequest) (*SessionResult, error) {
	if !s.started {
		return nil, fmt.Errorf("tracker: session has not started")
	}
	if s.stopped {
		return nil, fmt.Errorf("tracker: session has stopped")
	}
	if time.Now().Before(s.next) {
		return nil, fmt.Errorf("%w until %s", ErrNotDue, s.next.Format(time.RFC3339Nano))
	}
	request.Event = EventNone
	return s.send(ctx, request)
}

// Complete sends a completed announce. It is invalid for a torrent that was
// already complete when the session started.
func (s *Session) Complete(ctx context.Context, request AnnounceRequest) (*SessionResult, error) {
	if !s.started {
		return nil, fmt.Errorf("tracker: session has not started")
	}
	if s.stopped {
		return nil, fmt.Errorf("tracker: session has stopped")
	}
	if s.completed {
		return nil, fmt.Errorf("tracker: session has already completed")
	}
	if s.initialLeft == 0 {
		return nil, fmt.Errorf("tracker: session started complete")
	}
	if request.Left != 0 {
		return nil, fmt.Errorf("tracker: completed announce requires left=0")
	}
	request.Event = EventCompleted
	result, err := s.send(ctx, request)
	if err != nil {
		return nil, err
	}
	s.completed = true
	return result, nil
}

// Stop sends the final stopped announce.
func (s *Session) Stop(ctx context.Context, request AnnounceRequest) (*SessionResult, error) {
	if !s.started {
		return nil, fmt.Errorf("tracker: session has not started")
	}
	if s.stopped {
		return nil, fmt.Errorf("tracker: session has already stopped")
	}
	request.Event = EventStopped
	result, err := s.send(ctx, request)
	if err != nil {
		return nil, err
	}
	s.stopped = true
	s.next = time.Time{}
	result.NextAnnounce = time.Time{}
	return result, nil
}

// NextAnnounce returns the scheduled time for the next regular announce. It is
// zero before Start succeeds and after Stop succeeds.
func (s *Session) NextAnnounce() time.Time {
	return s.next
}

// Due reports whether a regular announce may be sent at now.
func (s *Session) Due(now time.Time) bool {
	return s.started && !s.stopped && !now.Before(s.next)
}

// CurrentTracker returns the last tracker that answered successfully.
func (s *Session) CurrentTracker() string {
	return s.current
}

// Tiers returns a copy of the current tier order.
func (s *Session) Tiers() [][]string {
	tiers := make([][]string, len(s.tiers))
	for i := range s.tiers {
		tiers[i] = append([]string(nil), s.tiers[i]...)
	}
	return tiers
}

func (s *Session) send(ctx context.Context, request AnnounceRequest) (*SessionResult, error) {
	if s.started && (request.InfoHash != s.infoHash || request.PeerID != s.peerID) {
		return nil, fmt.Errorf("tracker: info hash and peer ID must not change during a session")
	}
	if s.key == 0 {
		if request.Key != 0 {
			s.key = request.Key
		} else {
			key, err := randomUint32(true)
			if err != nil {
				return nil, fmt.Errorf("tracker: generate session key: %w", err)
			}
			s.key = key
		}
	} else if request.Key != 0 && request.Key != s.key {
		return nil, fmt.Errorf("tracker: announce key changed during session")
	}
	request.Key = s.key

	var failures []error
	for tierIndex := range s.tiers {
		for trackerIndex, trackerURL := range s.tiers[tierIndex] {
			result, err := s.sendTo(ctx, request, trackerURL)
			if err != nil {
				failures = append(failures, fmt.Errorf("%s: %w", trackerURL, err))
				if ctx.Err() != nil {
					return nil, errors.Join(failures...)
				}
				continue
			}
			if trackerIndex != 0 {
				tier := s.tiers[tierIndex]
				copy(tier[1:trackerIndex+1], tier[:trackerIndex])
				tier[0] = trackerURL
			}
			return result, nil
		}
	}
	return nil, fmt.Errorf("tracker: all trackers failed: %w", errors.Join(failures...))
}

func (s *Session) sendTo(ctx context.Context, request AnnounceRequest, trackerURL string) (*SessionResult, error) {
	request.TrackerID = s.trackerIDs[trackerURL]
	response, err := s.client.Announce(ctx, trackerURL, request)
	if err != nil {
		return nil, err
	}
	if response.TrackerID != "" {
		s.trackerIDs[trackerURL] = response.TrackerID
	}
	previous := s.current
	s.current = trackerURL
	seconds := response.Interval
	if response.MinInterval > seconds {
		seconds = response.MinInterval
	}
	s.next = time.Now().Add(time.Duration(seconds) * time.Second)
	return &SessionResult{
		AnnounceResponse: response,
		Tracker:          trackerURL,
		PreviousTracker:  previous,
		Switched:         previous != "" && previous != trackerURL,
		NextAnnounce:     s.next,
	}, nil
}
