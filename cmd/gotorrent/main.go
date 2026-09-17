// Command gotorrent inspects and downloads BitTorrent files and magnet URIs.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/anacrolix/go-utp/purego"
	"github.com/natalie-o-perret/go-torrent/client"
	"github.com/natalie-o-perret/go-torrent/dht"
	"github.com/natalie-o-perret/go-torrent/magnet"
	"github.com/natalie-o-perret/go-torrent/metainfo"
	"github.com/natalie-o-perret/go-torrent/storage"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stderr)
		return fmt.Errorf("missing command")
	}
	switch args[0] {
	case "info":
		return runInfoContext(ctx, args[1:], stdout, stderr)
	case "download":
		return runDownload(ctx, args[1:], stderr)
	default:
		usage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(output io.Writer) {
	_, _ = fmt.Fprintln(output, "usage: gotorrent <command> [options] SOURCE")
	_, _ = fmt.Fprintln(output, "commands:")
	_, _ = fmt.Fprintln(output, "  info       print metadata from a .torrent file or magnet URI")
	_, _ = fmt.Fprintln(output, "  download   download and seed a .torrent file or magnet URI")
}

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func runInfo(args []string) error {
	return runInfoContext(context.Background(), args, os.Stdout, os.Stderr)
}

func runInfoContext(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("info", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listen := flags.String("listen", "0.0.0.0:0", "tracker announce address for magnet discovery")
	var bootstrap stringList
	flags.Var(&bootstrap, "dht-bootstrap", "DHT bootstrap host:port (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("usage: gotorrent info [options] SOURCE")
	}

	source := flags.Arg(0)
	if !isMagnet(source) {
		meta, err := loadTorrent(source)
		if err != nil {
			return err
		}
		printInfo(stdout, meta)
		return nil
	}
	uri, err := magnet.Parse(source)
	if err != nil {
		return err
	}
	var listener net.Listener
	if len(uri.Trackers) != 0 {
		listener, err = net.Listen("tcp", *listen)
		if err != nil {
			return fmt.Errorf("listen for magnet tracker announce: %w", err)
		}
		defer func() { _ = listener.Close() }()
	}
	node, err := openDHT(ctx, bootstrap, nil)
	if err != nil {
		return err
	}
	if node != nil {
		defer func() { _ = node.Close() }()
	}
	result, err := client.ResolveMagnet(ctx, uri, client.MagnetConfig{
		DHTNode:      node,
		UsePublicDHT: node != nil,
		Port:         listenerPort(listener),
	})
	if err != nil {
		return err
	}
	printInfo(stdout, result.MetaInfo)
	return nil
}

func runDownload(ctx context.Context, args []string, status io.Writer) error {
	flags := flag.NewFlagSet("download", flag.ContinueOnError)
	flags.SetOutput(status)
	output := flags.String("output", "", "download root directory")
	listen := flags.String("listen", "0.0.0.0:0", "TCP and uTP listen address")
	var bootstrap, directPeers stringList
	flags.Var(&bootstrap, "dht-bootstrap", "DHT bootstrap host:port (repeatable)")
	flags.Var(&directPeers, "peer", "direct peer host:port (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 || *output == "" {
		return fmt.Errorf("usage: gotorrent download --output DIR [options] SOURCE")
	}

	source := flags.Arg(0)
	var meta *metainfo.MetaInfo
	var uri magnet.URI
	var err error
	magnetSource := isMagnet(source)
	if magnetSource {
		uri, err = magnet.Parse(source)
		if err != nil {
			return err
		}
		for _, rawPeer := range directPeers {
			parsed, err := parseMagnetPeer(rawPeer)
			if err != nil {
				return err
			}
			uri.Peers = append(uri.Peers, parsed)
		}
	} else {
		meta, err = loadTorrent(source)
		if err != nil {
			return err
		}
	}

	tcpListener, utpSocket, err := listenPeers(*listen)
	if err != nil {
		return err
	}
	ownedByClient := false
	defer func() {
		if !ownedByClient {
			_ = tcpListener.Close()
			_ = utpSocket.Close()
		}
	}()

	var metainfoNodes []metainfo.Node
	dhtSeeds := bootstrap
	if meta != nil && !meta.Info.Private {
		metainfoNodes = meta.Nodes
	} else if meta != nil {
		dhtSeeds = nil
	}
	node, err := openDHT(ctx, dhtSeeds, metainfoNodes)
	if err != nil {
		return err
	}
	if node != nil {
		defer func() { _ = node.Close() }()
	}

	var candidates []client.Candidate
	var peerID [20]byte
	if magnetSource {
		result, err := client.ResolveMagnet(ctx, uri, client.MagnetConfig{
			DHTNode:      node,
			UsePublicDHT: node != nil,
			Port:         listenerPort(tcpListener),
		})
		if err != nil {
			return err
		}
		meta, candidates, peerID = result.MetaInfo, result.Candidates, result.PeerID
	}

	store, err := storage.New(*output, meta)
	if err != nil {
		return err
	}
	clientDHT := node
	if meta.Info.Private {
		clientDHT = nil
	}
	torrent, err := client.New(client.Config{
		Meta:     meta,
		Storage:  store,
		DHTNode:  clientDHT,
		PeerID:   peerID,
		Listener: tcpListener,
		UTP:      utpSocket,
	})
	if err != nil {
		return err
	}
	ownedByClient = true
	defer func() { _ = torrent.Close() }()
	for _, candidate := range candidates {
		if err := torrent.AddPeer(candidate); err != nil {
			return err
		}
	}
	if !magnetSource {
		for _, address := range directPeers {
			if err := torrent.AddPeer(client.Candidate{Address: address, Source: client.SourceDirect}); err != nil {
				return err
			}
		}
	}
	return runTorrent(ctx, torrent, status)
}

func runTorrent(ctx context.Context, torrent *client.Client, status io.Writer) error {
	result := make(chan error, 1)
	go func() { result <- torrent.Run(ctx) }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	completed := torrent.Completed()
	for {
		select {
		case err := <-result:
			if ctx.Err() != nil && (errors.Is(err, ctx.Err()) || errors.Is(err, client.ErrClosed)) {
				return nil
			}
			return err
		case <-completed:
			printProgress(status, torrent.Progress())
			_, _ = fmt.Fprintln(status, "complete: seeding until interrupted")
			completed = nil
		case <-ticker.C:
			printProgress(status, torrent.Progress())
		}
	}
}

func printProgress(output io.Writer, progress client.ProgressSnapshot) {
	_, _ = fmt.Fprintf(output, "progress: %d/%d bytes, %d/%d pieces, peers=%d, candidates=%d\n",
		progress.CompletedBytes, progress.TotalBytes, progress.CompletedPieces, progress.PieceCount,
		progress.ConnectedPeers, progress.Candidates)
}

func listenPeers(address string) (net.Listener, *purego.Socket, error) {
	tcpListener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, nil, fmt.Errorf("listen TCP: %w", err)
	}
	utpSocket, err := purego.NewSocket("udp", tcpListener.Addr().String())
	if err != nil {
		_ = tcpListener.Close()
		return nil, nil, fmt.Errorf("listen uTP: %w", err)
	}
	return tcpListener, utpSocket, nil
}

func openDHT(ctx context.Context, rawSeeds []string, nodes []metainfo.Node) (*dht.Node, error) {
	if len(rawSeeds) == 0 && len(nodes) == 0 {
		return nil, nil
	}
	seeds := append([]string(nil), rawSeeds...)
	for _, node := range nodes {
		seeds = append(seeds, net.JoinHostPort(node.Host, strconv.Itoa(int(node.Port))))
	}
	endpoints, err := resolveEndpoints(ctx, seeds)
	if err != nil {
		return nil, err
	}
	node, err := dht.Listen("udp", "0.0.0.0:0", dht.Config{})
	if err != nil {
		return nil, err
	}
	if err := node.Bootstrap(ctx, endpoints); err != nil {
		_ = node.Close()
		return nil, err
	}
	return node, nil
}

func resolveEndpoints(ctx context.Context, raw []string) ([]netip.AddrPort, error) {
	var endpoints []netip.AddrPort
	for _, value := range raw {
		host, portText, err := net.SplitHostPort(value)
		if err != nil || host == "" {
			return nil, fmt.Errorf("invalid DHT bootstrap address %q", value)
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("invalid DHT bootstrap address %q", value)
		}
		if address, err := netip.ParseAddr(host); err == nil {
			endpoints = append(endpoints, netip.AddrPortFrom(address.Unmap(), uint16(port)))
			continue
		}
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve DHT bootstrap %q: %w", value, err)
		}
		for _, address := range addresses {
			endpoints = append(endpoints, netip.AddrPortFrom(address.Unmap(), uint16(port)))
		}
	}
	return endpoints, nil
}

func loadTorrent(path string) (*metainfo.MetaInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = file.Close() }()
	meta, err := metainfo.Decode(file)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return meta, nil
}

func printInfo(output io.Writer, meta *metainfo.MetaInfo) {
	_, _ = fmt.Fprintf(output, "Name:         %s\n", meta.Info.Name)
	hashes := meta.Hashes()
	if hashes.V1 != nil {
		_, _ = fmt.Fprintf(output, "InfoHashV1:   %s\n", hashes.V1)
	}
	if hashes.V2 != nil {
		_, _ = fmt.Fprintf(output, "InfoHashV2:   %s\n", hashes.V2)
	}
	_, _ = fmt.Fprintf(output, "PieceLength:  %d\n", meta.Info.PieceLength)
	_, _ = fmt.Fprintf(output, "Pieces:       %d\n", meta.Info.PieceCount())
	_, _ = fmt.Fprintf(output, "TotalLength:  %d\n", meta.Info.TotalLength())
	if meta.Comment != "" {
		_, _ = fmt.Fprintf(output, "Comment:      %s\n", meta.Comment)
	}
	if meta.CreatedBy != "" {
		_, _ = fmt.Fprintf(output, "CreatedBy:    %s\n", meta.CreatedBy)
	}
	if len(meta.Info.Files) > 0 {
		_, _ = fmt.Fprintln(output, "Files:")
		for _, file := range meta.Info.Files {
			_, _ = fmt.Fprintf(output, "  %s  (%d bytes)\n", joinPath(file.Path), file.Length)
		}
	}
	trackers := meta.Trackers()
	if len(trackers) > 0 {
		_, _ = fmt.Fprintln(output, "Trackers:")
		for _, trackerURL := range trackers {
			_, _ = fmt.Fprintf(output, "  %s\n", trackerURL)
		}
	}
}

func parseMagnetPeer(raw string) (magnet.Peer, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil || host == "" {
		return magnet.Peer{}, fmt.Errorf("invalid peer address %q", raw)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return magnet.Peer{}, fmt.Errorf("invalid peer address %q", raw)
	}
	return magnet.Peer{Host: host, Port: uint16(port)}, nil
}

func isMagnet(source string) bool {
	return len(source) >= len("magnet:?") && strings.EqualFold(source[:len("magnet:?")], "magnet:?")
}

func listenerPort(listener net.Listener) uint16 {
	if listener == nil {
		return 0
	}
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return 0
	}
	port, _ := strconv.ParseUint(portText, 10, 16)
	return uint16(port)
}

func joinPath(parts []string) string {
	return strings.Join(parts, "/")
}
