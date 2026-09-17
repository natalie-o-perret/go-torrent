package webseed

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/natalie-o-perret/go-torrent/bencode"
	"github.com/natalie-o-perret/go-torrent/metainfo"
	"github.com/natalie-o-perret/go-torrent/storage"
)

func TestSingleFileCompleteAndBaseURLs(t *testing.T) {
	data := []byte("payload")
	meta := singleV1Meta(t, "file #?.bin", data, 8)
	var mu sync.Mutex
	var paths, ranges []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.EscapedPath())
		ranges = append(ranges, r.Header.Get("Range"))
		mu.Unlock()
		switch r.URL.EscapedPath() {
		case "/objects/download.bin", "/base/file%20%23%3F.bin":
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	for _, rawURL := range []string{server.URL + "/objects/download.bin", server.URL + "/base/"} {
		source, err := NewSource(server.Client(), rawURL, meta)
		if err != nil {
			t.Fatal(err)
		}
		got, err := source.ReadPiece(context.Background(), storage.V1, 0)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("ReadPiece(%q) = %q, %v", rawURL, got, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	wantPaths := []string{"/objects/download.bin", "/base/file%20%23%3F.bin"}
	if fmt.Sprint(paths) != fmt.Sprint(wantPaths) {
		t.Fatalf("request paths = %q, want %q", paths, wantPaths)
	}
	for _, value := range ranges {
		if value != "bytes=0-6" {
			t.Errorf("Range = %q, want bytes=0-6", value)
		}
	}
}

func TestMultiFileReadAtCrossesEscapedPaths(t *testing.T) {
	a := []byte("abc")
	b := []byte("defg")
	meta := decodeMeta(t, map[string]any{
		"files": []any{
			map[string]any{"length": int64(len(a)), "path": []any{"dir #1", "a%.txt"}},
			map[string]any{"length": int64(len(b)), "path": []any{"b?.bin"}},
		},
		"name":         "bundle name",
		"piece length": int64(4),
		"pieces":       v1Hashes(append(bytes.Clone(a), b...), 4),
	})
	files := map[string][]byte{
		"/seed/bundle%20name/dir%20%231/a%25.txt": a,
		"/seed/bundle%20name/b%3F.bin":            b,
	}
	var mu sync.Mutex
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.URL.EscapedPath()+" "+r.Header.Get("Range"))
		mu.Unlock()
		data, ok := files[r.URL.EscapedPath()]
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeRange(w, r, data)
	}))
	t.Cleanup(server.Close)

	source, err := NewSource(server.Client(), server.URL+"/seed/", meta)
	if err != nil {
		t.Fatal(err)
	}
	buffer := []byte("xx")
	n, err := source.ReadAt(context.Background(), storage.V1, 0, buffer, 2)
	if err != nil || n != 2 || string(buffer) != "cd" {
		t.Fatalf("ReadAt = %d, %q, %v; want 2, cd, nil", n, buffer, err)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{
		"/seed/bundle%20name/dir%20%231/a%25.txt bytes=2-2",
		"/seed/bundle%20name/b%3F.bin bytes=0-0",
	}
	if fmt.Sprint(requests) != fmt.Sprint(want) {
		t.Fatalf("requests = %q, want %q", requests, want)
	}
}

func TestPaddingIsZeroFilledWithoutRequest(t *testing.T) {
	logical := []byte{'a', 'b', 0, 0, 'c'}
	meta := decodeMeta(t, map[string]any{
		"files": []any{
			map[string]any{"length": int64(2), "path": []any{"a"}},
			map[string]any{"attr": "p", "length": int64(2), "path": []any{".pad", "2"}},
			map[string]any{"length": int64(1), "path": []any{"b"}},
		},
		"name":         "bundle",
		"piece length": int64(4),
		"pieces":       v1Hashes(logical, 4),
	})
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.EscapedPath() != "/bundle/a" {
			http.NotFound(w, r)
			return
		}
		writeRange(w, r, []byte("ab"))
	}))
	t.Cleanup(server.Close)
	source, err := NewSource(server.Client(), server.URL+"/", meta)
	if err != nil {
		t.Fatal(err)
	}
	got, err := source.ReadPiece(context.Background(), storage.V1, 0)
	if err != nil || !bytes.Equal(got, logical[:4]) {
		t.Fatalf("ReadPiece = %v, %v", got, err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
}

func TestResponseLengthAndRangeValidation(t *testing.T) {
	meta := singleV1Meta(t, "file", []byte("data"), 4)
	tests := []struct {
		name  string
		serve func(http.ResponseWriter, *http.Request)
		class ErrorClass
	}{
		{
			name: "short",
			serve: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Range", "bytes 0-3/4")
				w.WriteHeader(http.StatusPartialContent)
				w.(http.Flusher).Flush()
				_, _ = w.Write([]byte("dat"))
			},
			class: ClassTransient,
		},
		{
			name: "oversized",
			serve: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Range", "bytes 0-3/4")
				w.WriteHeader(http.StatusPartialContent)
				w.(http.Flusher).Flush()
				_, _ = w.Write([]byte("datax"))
			},
			class: ClassPermanent,
		},
		{
			name: "wrong content range",
			serve: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Range", "bytes 1-4/5")
				w.Header().Set("Content-Length", "4")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write([]byte("data"))
			},
			class: ClassPermanent,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(test.serve))
			t.Cleanup(server.Close)
			source, err := NewSource(server.Client(), server.URL+"/file", meta)
			if err != nil {
				t.Fatal(err)
			}
			_, err = source.ReadPiece(context.Background(), storage.V1, 0)
			if err == nil || ClassOf(err) != test.class {
				t.Fatalf("ReadPiece error = %v (%q), want class %q", err, ClassOf(err), test.class)
			}
		})
	}
}

func TestIgnoredPartialRangeIsRejected(t *testing.T) {
	data := []byte("data")
	meta := singleV1Meta(t, "file", data, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}))
	t.Cleanup(server.Close)
	source, err := NewSource(server.Client(), server.URL+"/file", meta)
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.ReadAt(context.Background(), storage.V1, 0, make([]byte, 2), 1)
	if err == nil || ClassOf(err) != ClassPermanent {
		t.Fatalf("ReadAt error = %v (%q), want permanent", err, ClassOf(err))
	}
}

func TestContextCancellation(t *testing.T) {
	meta := singleV1Meta(t, "file", []byte("data"), 4)
	started := make(chan struct{})
	var once sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	source, err := NewSource(server.Client(), server.URL+"/file", meta)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-started
		cancel()
	}()
	_, err = source.ReadPiece(ctx, storage.V1, 0)
	if !errors.Is(err, context.Canceled) || ClassOf(err) != ClassCanceled {
		t.Fatalf("ReadPiece error = %v (%q), want context cancellation", err, ClassOf(err))
	}
}

func TestBusyResponseCanBeRetried(t *testing.T) {
	data := []byte("data")
	meta := singleV1Meta(t, "file", data, 4)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writeRange(w, r, data)
	}))
	t.Cleanup(server.Close)
	source, err := NewSource(server.Client(), server.URL+"/file", meta)
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.ReadPiece(context.Background(), storage.V1, 0)
	if ClassOf(err) != ClassBusy || !IsRetryable(err) || source.Bad() {
		t.Fatalf("first error = %v (%q), retryable=%v, bad=%v", err, ClassOf(err), IsRetryable(err), source.Bad())
	}
	got, err := source.ReadPiece(context.Background(), storage.V1, 0)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("retry = %q, %v", got, err)
	}
}

func TestDownloaderVerifiesV1AndV2(t *testing.T) {
	const pieceLength = 16 << 10
	data := []byte("hybrid data")
	logical := make([]byte, pieceLength)
	copy(logical, data)
	root := metainfo.HashV2(sha256.Sum256(data))
	meta := decodeMeta(t, map[string]any{
		"file tree": map[string]any{
			"file": map[string]any{"": map[string]any{
				"length": int64(len(data)), "pieces root": string(root[:]),
			}},
		},
		"files": []any{
			map[string]any{"length": int64(len(data)), "path": []any{"file"}},
			map[string]any{"attr": "p", "length": int64(pieceLength - len(data)), "path": []any{".pad", "tail"}},
		},
		"meta version": int64(2),
		"name":         "bundle",
		"piece length": int64(pieceLength),
		"pieces":       v1Hashes(logical, pieceLength),
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/bundle/file" {
			http.NotFound(w, r)
			return
		}
		writeRange(w, r, data)
	}))
	t.Cleanup(server.Close)
	source, err := NewSource(server.Client(), server.URL+"/", meta)
	if err != nil {
		t.Fatal(err)
	}
	downloader, err := NewDownloader(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []storage.Protocol{storage.V1, storage.V2} {
		got, err := downloader.ReadPiece(context.Background(), protocol, 0)
		want := data
		if protocol == storage.V1 {
			want = logical
		}
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("ReadPiece(%s) = %q, %v", protocol, got, err)
		}
	}
}

func TestHashMismatchDisablesSource(t *testing.T) {
	meta := singleV1Meta(t, "file", []byte("good"), 4)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		writeRange(w, r, []byte("evil"))
	}))
	t.Cleanup(server.Close)
	source, err := NewSource(server.Client(), server.URL+"/file", meta)
	if err != nil {
		t.Fatal(err)
	}
	downloader, err := NewDownloader(source)
	if err != nil {
		t.Fatal(err)
	}
	_, err = downloader.ReadPiece(context.Background(), storage.V1, 0)
	if err == nil || ClassOf(err) != ClassIntegrity || !source.Bad() || IsRetryable(err) {
		t.Fatalf("mismatch error = %v (%q), bad=%v", err, ClassOf(err), source.Bad())
	}
	_, err = source.ReadPiece(context.Background(), storage.V1, 0)
	if ClassOf(err) != ClassDisabled {
		t.Fatalf("disabled read error = %v (%q)", err, ClassOf(err))
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests after disablement = %d, want 1", got)
	}
}

func TestRejectsFTP(t *testing.T) {
	meta := singleV1Meta(t, "file", []byte("data"), 4)
	_, err := NewSource(http.DefaultClient, "ftp://example.com/file", meta)
	if err == nil || ClassOf(err) != ClassPermanent || !strings.Contains(err.Error(), "FTP") {
		t.Fatalf("NewSource FTP error = %v (%q)", err, ClassOf(err))
	}
}

func writeRange(w http.ResponseWriter, r *http.Request, data []byte) {
	var start, end int64
	if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil || start < 0 || end < start || end >= int64(len(data)) {
		http.Error(w, "bad range", http.StatusRequestedRangeNotSatisfiable)
		return
	}
	body := data[start : end+1]
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write(body)
}

func singleV1Meta(t *testing.T, name string, data []byte, pieceLength int) *metainfo.MetaInfo {
	t.Helper()
	return decodeMeta(t, map[string]any{
		"length":       int64(len(data)),
		"name":         name,
		"piece length": int64(pieceLength),
		"pieces":       v1Hashes(data, pieceLength),
	})
}

func decodeMeta(t *testing.T, info map[string]any) *metainfo.MetaInfo {
	t.Helper()
	top := map[string]any{"info": info}
	if _, ok := info["meta version"]; ok {
		top["piece layers"] = map[string]any{}
	}
	encoded, err := bencode.EncodeToString(top)
	if err != nil {
		t.Fatalf("encode metainfo: %v", err)
	}
	meta, err := metainfo.Decode(strings.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode metainfo: %v", err)
	}
	return meta
}

func v1Hashes(data []byte, pieceLength int) string {
	var hashes []byte
	for len(data) > 0 {
		length := min(pieceLength, len(data))
		hash := sha1.Sum(data[:length])
		hashes = append(hashes, hash[:]...)
		data = data[length:]
	}
	return string(hashes)
}
