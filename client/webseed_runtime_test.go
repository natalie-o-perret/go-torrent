package client

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/natalie-o-perret/go-torrent/metainfo"
	"github.com/natalie-o-perret/go-torrent/peer"
	"github.com/natalie-o-perret/go-torrent/storage"
)

func TestWebseedV1DownloadCompletion(t *testing.T) {
	data := []byte("webseed-data")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		http.ServeContent(w, request, "payload", time.Time{}, bytes.NewReader(data))
	}))
	t.Cleanup(server.Close)

	meta := testV1Meta(t, data, 4, "", false)
	torrentClient, store, runResult := startWebseedTestClient(t, meta, []string{server.URL + "/payload"}, nil)
	waitClosed(t, torrentClient.Completed(), "web-seed completion")
	progress := torrentClient.Progress()
	if progress.CompletedPieces != 3 || progress.DownloadedBytes != int64(len(data)) || progress.Swarms[peer.ProtocolV1].DownloadedBytes != int64(len(data)) {
		t.Fatalf("progress = %+v", progress)
	}
	stopWebseedTestClient(t, torrentClient, runResult)

	got, err := store.ReadPiece(storage.V1, 0)
	if err != nil || !bytes.Equal(got, data[:4]) {
		t.Fatalf("stored first piece = %q, %v", got, err)
	}
	verified, err := store.VerifyAll()
	if err != nil || len(verified) != 3 || !allVerified(verified) {
		t.Fatalf("VerifyAll = %v, %v", verified, err)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("requests = %d, want 3", got)
	}
}

func TestWebseedHybridUsesPrimaryStorageView(t *testing.T) {
	files := map[string][]byte{
		"/bundle/a": []byte("abc"),
		"/bundle/b": []byte("12345"),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		data, ok := files[request.URL.EscapedPath()]
		if !ok {
			http.NotFound(w, request)
			return
		}
		http.ServeContent(w, request, request.URL.Path, time.Time{}, bytes.NewReader(data))
	}))
	t.Cleanup(server.Close)

	meta := testHybridMeta(t)
	torrentClient, store, runResult := startWebseedTestClient(t, meta, []string{server.URL + "/"}, server.Client())
	waitClosed(t, torrentClient.Completed(), "hybrid web-seed completion")
	if torrentClient.primary != peer.ProtocolV1 {
		t.Fatalf("primary protocol = %d, want v1", torrentClient.primary)
	}
	progress := torrentClient.Progress()
	if got, want := progress.DownloadedBytes, int64((16<<10)+5); got != want {
		t.Fatalf("downloaded bytes = %d, want %d", got, want)
	}
	if progress.Swarms[peer.ProtocolV2].DownloadedBytes != 0 {
		t.Fatalf("v2 downloaded bytes = %d, want 0", progress.Swarms[peer.ProtocolV2].DownloadedBytes)
	}
	stopWebseedTestClient(t, torrentClient, runResult)

	for index, want := range [][]byte{files["/bundle/a"], files["/bundle/b"]} {
		got, err := store.ReadPiece(storage.V2, index)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("stored v2 piece %d = %q, %v, want %q", index, got, err, want)
		}
	}
}

func TestWebseedSourcesDoNotDuplicatePieceOwnership(t *testing.T) {
	data := []byte("abcdefghijkl")
	var mu sync.Mutex
	requests := make(map[string]int)
	var active [2]atomic.Int32
	var maximum [2]atomic.Int32
	servers := make([]*httptest.Server, 2)
	for index := range servers {
		index := index
		servers[index] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			current := active[index].Add(1)
			updateAtomicMaximum(&maximum[index], current)
			defer active[index].Add(-1)
			mu.Lock()
			requests[request.Header.Get("Range")]++
			mu.Unlock()
			time.Sleep(10 * time.Millisecond)
			http.ServeContent(w, request, "payload", time.Time{}, bytes.NewReader(data))
		}))
		t.Cleanup(servers[index].Close)
	}

	meta := testV1Meta(t, data, 4, "", false)
	urls := []string{servers[0].URL + "/payload", servers[1].URL + "/payload"}
	torrentClient, _, runResult := startWebseedTestClient(t, meta, urls, &http.Client{Timeout: time.Second})
	waitClosed(t, torrentClient.Completed(), "multi-source web-seed completion")
	stopWebseedTestClient(t, torrentClient, runResult)

	mu.Lock()
	got := make(map[string]int, len(requests))
	for value, count := range requests {
		got[value] = count
	}
	mu.Unlock()
	want := map[string]int{"bytes=0-3": 1, "bytes=4-7": 1, "bytes=8-11": 1}
	if len(got) != len(want) {
		t.Fatalf("request ranges = %v, want %v", got, want)
	}
	for value, count := range want {
		if got[value] != count {
			t.Fatalf("request ranges = %v, want %v", got, want)
		}
	}
	for index := range maximum {
		if got := maximum[index].Load(); got > 1 {
			t.Fatalf("source %d had %d concurrent piece requests", index, got)
		}
	}
}

func TestWebseedRetriesRetryableResponseAndAccountsSuccessOnce(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
	}{
		{name: "busy", status: http.StatusServiceUnavailable},
		{name: "transient", status: http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := []byte("data")
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if requests.Add(1) == 1 {
					w.WriteHeader(test.status)
					return
				}
				http.ServeContent(w, request, "payload", time.Time{}, bytes.NewReader(data))
			}))
			t.Cleanup(server.Close)

			meta := testV1Meta(t, data, len(data), "", false)
			torrentClient, _, runResult := startWebseedTestClient(t, meta, []string{server.URL + "/payload"}, server.Client())
			waitClosed(t, torrentClient.Completed(), "retried web-seed completion")
			if got := requests.Load(); got != 2 {
				t.Fatalf("requests = %d, want 2", got)
			}
			if got := torrentClient.Progress().DownloadedBytes; got != int64(len(data)) {
				t.Fatalf("downloaded bytes = %d, want %d", got, len(data))
			}
			stopWebseedTestClient(t, torrentClient, runResult)
		})
	}
}

func TestWebseedPermanentAndIntegrityFailuresDisableSource(t *testing.T) {
	for _, test := range []struct {
		name string
		bad  http.HandlerFunc
	}{
		{
			name: "permanent",
			bad: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
		},
		{
			name: "integrity",
			bad: func(w http.ResponseWriter, request *http.Request) {
				corrupt := []byte("evilGOOD")
				http.ServeContent(w, request, "payload", time.Time{}, bytes.NewReader(corrupt))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := []byte("goodGOOD")
			var badRequests atomic.Int32
			badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				badRequests.Add(1)
				test.bad(w, request)
			}))
			t.Cleanup(badServer.Close)

			goodStarted := make(chan struct{})
			releaseGood := make(chan struct{})
			var startOnce, releaseOnce sync.Once
			goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				startOnce.Do(func() { close(goodStarted) })
				<-releaseGood
				http.ServeContent(w, request, "payload", time.Time{}, bytes.NewReader(data))
			}))
			t.Cleanup(goodServer.Close)
			release := func() { releaseOnce.Do(func() { close(releaseGood) }) }
			t.Cleanup(release)

			meta := testV1Meta(t, data, 4, "", false)
			urls := []string{badServer.URL + "/payload", goodServer.URL + "/payload"}
			torrentClient, _, runResult := startWebseedTestClient(t, meta, urls, &http.Client{Timeout: time.Second})
			waitClosed(t, goodStarted, "fallback web-seed request")
			time.Sleep(25 * time.Millisecond)
			if got := badRequests.Load(); got != 1 {
				t.Fatalf("failed source requests = %d, want 1", got)
			}
			select {
			case err := <-runResult:
				t.Fatalf("failed source terminated Run: %v", err)
			default:
			}

			release()
			waitClosed(t, torrentClient.Completed(), "fallback web-seed completion")
			stopWebseedTestClient(t, torrentClient, runResult)
		})
	}
}

func TestWebseedCancellationWaitsForWorker(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	var startedOnce, canceledOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		startedOnce.Do(func() { close(started) })
		<-request.Context().Done()
		canceledOnce.Do(func() { close(canceled) })
	}))
	t.Cleanup(server.Close)

	data := []byte("data")
	meta := testV1Meta(t, data, len(data), "", false)
	torrentClient, _, runResult := startWebseedTestClient(t, meta, []string{server.URL + "/payload"}, server.Client())
	waitClosed(t, started, "blocked web-seed request")
	closed := make(chan error, 1)
	go func() { closed <- torrentClient.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not wait for canceled web-seed worker")
	}
	waitClosed(t, canceled, "web-seed request cancellation")
	if err := <-runResult; !errors.Is(err, ErrClosed) {
		t.Fatalf("Run error = %v, want ErrClosed", err)
	}
}

func TestWebseedReservationBlocksBothPeerWireLayouts(t *testing.T) {
	meta := testHybridMeta(t)
	torrentClient, err := New(Config{Meta: meta, Storage: testStorage(t, meta).Storage, PeerID: testPeerID(31), RandIntN: zeroRandom})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = torrentClient.Close() })
	state := &coordinator{
		client:          torrentClient,
		active:          make(map[pieceKey]*downloadPiece),
		webseedReserved: map[uint32]struct{}{0: {}},
	}
	managed := &peerState{
		id:       1,
		protocol: peer.ProtocolV2,
		requests: make(map[blockKey]peer.BlockRequest),
		snapshot: peer.SessionSnapshot{RemotePieces: []bool{true, true}},
	}
	request, _, ok, err := state.pickRequest(managed, []int{1, 1}, []bool{false, false})
	if err != nil || !ok || request.Index != 1 {
		t.Fatalf("pickRequest = %+v, %t, %v, want unreserved piece 1", request, ok, err)
	}
	state.active[pieceKey{protocol: peer.ProtocolV2, index: 0}] = &downloadPiece{}
	delete(state.webseedReserved, 0)
	if !state.webseedPieceActive(0) {
		t.Fatal("web-seed picker did not see active v2 peer piece")
	}
}

func TestNewRejectsInvalidWebseedURL(t *testing.T) {
	meta := testV1Meta(t, []byte("data"), 4, "", false)
	meta.URLList = []string{"ftp://example.com/payload"}
	_, err := New(Config{Meta: meta, Storage: testStorage(t, meta).Storage})
	if err == nil || !strings.Contains(err.Error(), "web seed URL 0") || !strings.Contains(err.Error(), meta.URLList[0]) {
		t.Fatalf("New error = %v", err)
	}
}

func TestWebseedBackoffIsBounded(t *testing.T) {
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, time.Minute, time.Minute}
	for index, duration := range want {
		if got := webseedBackoff(5*time.Second, index+1); got != duration {
			t.Fatalf("failure %d delay = %s, want %s", index+1, got, duration)
		}
	}
}

func startWebseedTestClient(t *testing.T, meta *metainfo.MetaInfo, urls []string, httpClient *http.Client) (*Client, *storage.Storage, <-chan error) {
	t.Helper()
	meta.URLList = append([]string(nil), urls...)
	store := testStorage(t, meta)
	torrentClient, err := New(Config{
		Meta:             meta,
		Storage:          store.Storage,
		WebSeedClient:    httpClient,
		PeerID:           testPeerID(30),
		ScheduleInterval: time.Millisecond,
		RetryInterval:    5 * time.Millisecond,
		RandIntN:         zeroRandom,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = torrentClient.Close() })
	return torrentClient, store.Storage, runAsync(torrentClient)
}

func stopWebseedTestClient(t *testing.T, torrentClient *Client, runResult <-chan error) {
	t.Helper()
	if err := torrentClient.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-runResult; !errors.Is(err, ErrClosed) {
		t.Fatalf("Run error = %v, want ErrClosed", err)
	}
}

func updateAtomicMaximum(maximum *atomic.Int32, value int32) {
	for {
		previous := maximum.Load()
		if value <= previous || maximum.CompareAndSwap(previous, value) {
			return
		}
	}
}
