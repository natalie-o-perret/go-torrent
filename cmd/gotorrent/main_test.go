package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"errors"
	"flag"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/natalie-o-perret/go-torrent/bencode"
	"github.com/natalie-o-perret/go-torrent/client"
	"github.com/natalie-o-perret/go-torrent/dht"
	"github.com/natalie-o-perret/go-torrent/magnet"
	"github.com/natalie-o-perret/go-torrent/storage"
)

func TestJoinPath(t *testing.T) {
	tests := []struct {
		want  string
		parts []string
	}{
		{want: "a/b/c", parts: []string{"a", "b", "c"}},
		{want: "foo", parts: []string{"foo"}},
		{want: "", parts: []string{}},
	}
	for _, tc := range tests {
		if got := joinPath(tc.parts); got != tc.want {
			t.Errorf("joinPath(%v) = %q, want %q", tc.parts, got, tc.want)
		}
	}
}

func TestRunInfoMissingFile(t *testing.T) {
	if err := runInfo([]string{"/nonexistent/file.torrent"}); err == nil {
		t.Fatal("want error for missing file, got nil")
	}
}

func TestRunInfoInvalidBencode(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "*.torrent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("not-bencode"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if err := runInfo([]string{f.Name()}); err == nil {
		t.Fatal("want error for invalid bencode, got nil")
	}
}

func buildMinimalTorrent(t *testing.T, announce, comment, createdBy string, multiFile bool) []byte {
	t.Helper()
	pieces := strings.Repeat("\x00", 20)
	infoDict := map[string]any{
		"piece length": int64(524288),
		"pieces":       pieces,
	}
	if multiFile {
		infoDict["name"] = "mydir"
		infoDict["files"] = []any{
			map[string]any{
				"length": int64(1024),
				"path":   []any{"sub", "file.txt"},
			},
		}
	} else {
		infoDict["name"] = "test.iso"
		infoDict["length"] = int64(524288)
	}
	top := map[string]any{"info": infoDict}
	if announce != "" {
		top["announce"] = announce
	}
	if comment != "" {
		top["comment"] = comment
	}
	if createdBy != "" {
		top["created by"] = createdBy
	}
	s, err := bencode.EncodeToString(top)
	if err != nil {
		t.Fatalf("buildMinimalTorrent: %v", err)
	}
	return []byte(s)
}

func writeTorrentFile(t *testing.T, data []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.torrent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	return f.Name()
}

func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

func TestRunInfoSingleFile(t *testing.T) {
	path := writeTorrentFile(t, buildMinimalTorrent(t, "http://tracker.example.com/announce", "", "", false))
	var runErr error
	out := captureStdout(func() {
		runErr = runInfo([]string{path})
	})
	if runErr != nil {
		t.Fatalf("runInfo: %v", runErr)
	}
	if !strings.Contains(out, "test.iso") {
		t.Errorf("output missing torrent name: %q", out)
	}
	if !strings.Contains(out, "http://tracker.example.com/announce") {
		t.Errorf("output missing announce URL: %q", out)
	}
	if !strings.Contains(out, "InfoHashV1:") {
		t.Errorf("output missing v1 hash label: %q", out)
	}
}

func TestCommandValidationAndPeerListeners(t *testing.T) {
	var output bytes.Buffer
	if err := runInfoContext(context.Background(), []string{"one", "two"}, &output, &output); err == nil {
		t.Fatal("info accepted multiple sources")
	}
	if err := runDownload(context.Background(), []string{"source.torrent"}, &output); err == nil {
		t.Fatal("download accepted a missing output directory")
	}
	tcp, utp, err := listenPeers("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcp.Close() }()
	defer func() { _ = utp.Close() }()
	if listenerPort(tcp) == 0 || listenerPort(tcp) != uint16(utp.Addr().(*net.UDPAddr).Port) {
		t.Fatalf("listener addresses = %s and %s", tcp.Addr(), utp.Addr())
	}
}

func TestRunDispatchAndPeerParsing(t *testing.T) {
	var output bytes.Buffer
	if err := run(context.Background(), nil, &output, &output); err == nil || !strings.Contains(output.String(), "usage:") {
		t.Fatalf("run without command = %v, output %q", err, output.String())
	}
	output.Reset()
	if err := run(context.Background(), []string{"unknown"}, &output, &output); err == nil || !strings.Contains(output.String(), "usage:") {
		t.Fatalf("run unknown command = %v, output %q", err, output.String())
	}
	output.Reset()
	if err := run(context.Background(), []string{"info", "--help"}, &output, &output); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("info --help error = %v, want %v", err, flag.ErrHelp)
	}
	output.Reset()
	if err := run(context.Background(), []string{"download", "--help"}, &output, &output); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("download --help error = %v, want %v", err, flag.ErrHelp)
	}

	peer, err := parseMagnetPeer(" 127.0.0.1:6881 ")
	if err != nil || peer.Host != "127.0.0.1" || peer.Port != 6881 {
		t.Fatalf("parseMagnetPeer = (%+v, %v)", peer, err)
	}
	for _, raw := range []string{"127.0.0.1", ":6881", "127.0.0.1:0", "127.0.0.1:bad"} {
		if _, err := parseMagnetPeer(raw); err == nil {
			t.Fatalf("parseMagnetPeer(%q) accepted invalid address", raw)
		}
	}

	endpoints, err := resolveEndpoints(context.Background(), []string{"127.0.0.1:6881", "[::1]:6882"})
	if err != nil || len(endpoints) != 2 || endpoints[0].Port() != 6881 || endpoints[1].Port() != 6882 {
		t.Fatalf("resolveEndpoints = (%v, %v)", endpoints, err)
	}
	for _, raw := range []string{"127.0.0.1", ":6881", "127.0.0.1:0", "127.0.0.1:bad"} {
		if _, err := resolveEndpoints(context.Background(), []string{raw}); err == nil {
			t.Fatalf("resolveEndpoints(%q) accepted invalid address", raw)
		}
	}
}

func TestRunDownloadOverUTP(t *testing.T) {
	data := bytes.Repeat([]byte("cli-utp-"), 2048)
	hash := sha1.Sum(data)
	torrentText, err := bencode.EncodeToString(map[string]any{
		"info": map[string]any{
			"name":         "payload",
			"piece length": int64(len(data)),
			"pieces":       string(hash[:]),
			"length":       int64(len(data)),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	torrentPath := writeTorrentFile(t, []byte(torrentText))
	meta, err := loadTorrent(torrentPath)
	if err != nil {
		t.Fatal(err)
	}
	seedStore, err := storage.New(t.TempDir(), meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := seedStore.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := seedStore.WritePiece(storage.V1, 0, data); err != nil {
		t.Fatal(err)
	}
	tcp, utp, err := listenPeers("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seed, err := client.New(client.Config{Meta: meta, Storage: seedStore, Listener: tcp, UTP: utp, ScheduleInterval: 5 * time.Millisecond})
	if err != nil {
		_ = tcp.Close()
		_ = utp.Close()
		t.Fatal(err)
	}
	seedResult := make(chan error, 1)
	go func() { seedResult <- seed.Run(context.Background()) }()
	t.Cleanup(func() {
		if err := seed.Close(); err != nil {
			t.Error(err)
		}
		select {
		case err := <-seedResult:
			if !errors.Is(err, client.ErrClosed) {
				t.Errorf("seed Run error = %v, want %v", err, client.ErrClosed)
			}
		case <-time.After(2 * time.Second):
			t.Error("seed Run did not stop")
		}
	})
	select {
	case <-seed.Completed():
	case <-time.After(2 * time.Second):
		t.Fatal("seed resume verification timed out")
	}

	bootstrap, err := dht.Listen("udp4", "127.0.0.1:0", dht.Config{QueryTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bootstrap.Close() }()
	host, portText, _ := net.SplitHostPort(tcp.Addr().String())
	port, _ := strconv.ParseUint(portText, 10, 16)
	magnetSource, err := magnet.Format(magnet.URI{
		Hashes: meta.Hashes(),
		Peers:  []magnet.Peer{{Host: host, Port: uint16(port)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	infoCtx, cancelInfo := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelInfo()
	var info, infoErrors bytes.Buffer
	if err := run(infoCtx, []string{"info", magnetSource}, &info, &infoErrors); err != nil {
		t.Fatalf("magnet info: %v", err)
	}
	if !strings.Contains(info.String(), "Name:         payload") {
		t.Fatalf("magnet info output = %q", info.String())
	}
	if infoErrors.Len() != 0 {
		t.Fatalf("magnet info stderr = %q", infoErrors.String())
	}
	for _, test := range []struct {
		name   string
		source string
		peer   bool
	}{
		{name: "torrent", source: torrentPath, peer: true},
		{name: "magnet", source: magnetSource},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			status := &cancelOnCompleteWriter{cancel: cancel}
			downloadRoot := t.TempDir()
			args := []string{"--output", downloadRoot, "--dht-bootstrap", bootstrap.Addr().String()}
			if test.peer {
				args = append(args, "--peer", tcp.Addr().String())
			}
			args = append(args, test.source)
			if err := runDownload(ctx, args, status); err != nil {
				t.Fatal(err)
			}
			downloaded, err := os.ReadFile(filepath.Join(downloadRoot, "payload"))
			if err != nil || !bytes.Equal(downloaded, data) {
				t.Fatalf("downloaded %d bytes: %v", len(downloaded), err)
			}
			if !strings.Contains(status.String(), "complete: seeding until interrupted") {
				t.Fatalf("status = %q", status.String())
			}
		})
	}
}

type cancelOnCompleteWriter struct {
	mu     sync.Mutex
	buffer bytes.Buffer
	cancel context.CancelFunc
	once   sync.Once
}

func (writer *cancelOnCompleteWriter) Write(data []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	count, err := writer.buffer.Write(data)
	if bytes.Contains(writer.buffer.Bytes(), []byte("complete:")) {
		writer.once.Do(writer.cancel)
	}
	return count, err
}

func (writer *cancelOnCompleteWriter) String() string {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.buffer.String()
}

func TestRunInfoWithMetadata(t *testing.T) {
	path := writeTorrentFile(t, buildMinimalTorrent(t, "http://tracker.example.com/announce", "test comment", "me", false))
	var runErr error
	out := captureStdout(func() {
		runErr = runInfo([]string{path})
	})
	if runErr != nil {
		t.Fatalf("runInfo: %v", runErr)
	}
	if !strings.Contains(out, "test comment") {
		t.Errorf("output missing comment: %q", out)
	}
	if !strings.Contains(out, "me") {
		t.Errorf("output missing createdBy: %q", out)
	}
}

func TestRunInfoMultiFile(t *testing.T) {
	path := writeTorrentFile(t, buildMinimalTorrent(t, "http://tracker.example.com/announce", "", "", true))
	var runErr error
	out := captureStdout(func() {
		runErr = runInfo([]string{path})
	})
	if runErr != nil {
		t.Fatalf("runInfo: %v", runErr)
	}
	if !strings.Contains(out, "sub/file.txt") {
		t.Errorf("output missing file path: %q", out)
	}
	if !strings.Contains(out, "Files:") {
		t.Errorf("output missing Files: section: %q", out)
	}
}
