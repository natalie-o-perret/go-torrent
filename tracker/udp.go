package tracker

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/url"
	"time"

	"github.com/natalie-o-perret/go-torrent/metainfo"
)

const (
	udpProtocolID      uint64 = 0x41727101980
	udpActionConnect   uint32 = 0
	udpActionAnnounce  uint32 = 1
	udpActionScrape    uint32 = 2
	udpActionError     uint32 = 3
	maxUDPResponseSize        = 64 << 10
)

func (c *Client) udpAnnounce(ctx context.Context, u *url.URL, announce AnnounceRequest) (*AnnounceResponse, error) {
	conn, err := c.dialUDP(ctx, u)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	connectionID, err := c.udpConnect(ctx, conn)
	if err != nil {
		return nil, err
	}
	transactionID, err := randomUint32(false)
	if err != nil {
		return nil, fmt.Errorf("tracker: generate UDP transaction ID: %w", err)
	}
	packet := make([]byte, 98)
	binary.BigEndian.PutUint64(packet[0:8], connectionID)
	binary.BigEndian.PutUint32(packet[8:12], udpActionAnnounce)
	binary.BigEndian.PutUint32(packet[12:16], transactionID)
	copy(packet[16:36], announce.InfoHash[:])
	copy(packet[36:56], announce.PeerID[:])
	binary.BigEndian.PutUint64(packet[56:64], uint64(announce.Downloaded))
	binary.BigEndian.PutUint64(packet[64:72], uint64(announce.Left))
	binary.BigEndian.PutUint64(packet[72:80], uint64(announce.Uploaded))
	binary.BigEndian.PutUint32(packet[80:84], udpEvent(announce.Event))
	if announce.IP != "" && udpAddressBytes(conn) == 4 {
		ip := net.ParseIP(announce.IP).To4()
		if ip == nil {
			return nil, fmt.Errorf("tracker: UDP IP override is not an IPv4 address")
		}
		copy(packet[84:88], ip)
	}
	binary.BigEndian.PutUint32(packet[88:92], announce.Key)
	binary.BigEndian.PutUint32(packet[92:96], uint32(int32(announce.NumWant)))
	binary.BigEndian.PutUint16(packet[96:98], announce.Port)

	data, err := c.udpExchange(ctx, conn, packet, transactionID, udpActionAnnounce, func() error {
		connectionID, err := c.udpConnect(ctx, conn)
		if err == nil {
			binary.BigEndian.PutUint64(packet[0:8], connectionID)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if len(data) < 20 {
		return nil, fmt.Errorf("tracker: UDP announce response is %d bytes, want at least 20", len(data))
	}
	interval, err := udpInteger(binary.BigEndian.Uint32(data[8:12]), "announce interval")
	if err != nil || interval == 0 || int64(interval) > math.MaxInt64/int64(time.Second) {
		return nil, fmt.Errorf("tracker: UDP announce interval %d is invalid", interval)
	}
	addressBytes := udpAddressBytes(conn)
	peers, err := parseCompactPeers(string(data[20:]), addressBytes)
	if err != nil {
		return nil, fmt.Errorf("tracker: UDP announce response: %w", err)
	}
	incomplete, err := udpInteger(binary.BigEndian.Uint32(data[12:16]), "leecher count")
	if err != nil {
		return nil, err
	}
	complete, err := udpInteger(binary.BigEndian.Uint32(data[16:20]), "seeder count")
	if err != nil {
		return nil, err
	}
	return &AnnounceResponse{
		Peers:      peers,
		Interval:   interval,
		Incomplete: incomplete,
		Complete:   complete,
	}, nil
}

func (c *Client) udpScrape(ctx context.Context, u *url.URL, hashes []metainfo.Hash) (*ScrapeResponse, error) {
	if len(hashes) > 74 {
		return nil, fmt.Errorf("tracker: UDP scrape supports at most 74 info hashes")
	}
	conn, err := c.dialUDP(ctx, u)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	connectionID, err := c.udpConnect(ctx, conn)
	if err != nil {
		return nil, err
	}
	transactionID, err := randomUint32(false)
	if err != nil {
		return nil, fmt.Errorf("tracker: generate UDP transaction ID: %w", err)
	}
	packet := make([]byte, 16+20*len(hashes))
	binary.BigEndian.PutUint64(packet[0:8], connectionID)
	binary.BigEndian.PutUint32(packet[8:12], udpActionScrape)
	binary.BigEndian.PutUint32(packet[12:16], transactionID)
	for i := range hashes {
		copy(packet[16+i*20:16+(i+1)*20], hashes[i][:])
	}
	data, err := c.udpExchange(ctx, conn, packet, transactionID, udpActionScrape, func() error {
		connectionID, err := c.udpConnect(ctx, conn)
		if err == nil {
			binary.BigEndian.PutUint64(packet[0:8], connectionID)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	expected := 8 + 12*len(hashes)
	if len(data) != expected {
		return nil, fmt.Errorf("tracker: UDP scrape response is %d bytes, want %d", len(data), expected)
	}
	response := &ScrapeResponse{Files: make(map[metainfo.Hash]ScrapeStats, len(hashes))}
	for i, hash := range hashes {
		offset := 8 + i*12
		complete, err := udpInteger(binary.BigEndian.Uint32(data[offset:offset+4]), "scrape seeder count")
		if err != nil {
			return nil, err
		}
		downloaded, err := udpInteger(binary.BigEndian.Uint32(data[offset+4:offset+8]), "scrape completed count")
		if err != nil {
			return nil, err
		}
		incomplete, err := udpInteger(binary.BigEndian.Uint32(data[offset+8:offset+12]), "scrape leecher count")
		if err != nil {
			return nil, err
		}
		response.Files[hash] = ScrapeStats{
			Complete:   complete,
			Downloaded: downloaded,
			Incomplete: incomplete,
		}
	}
	return response, nil
}

func (c *Client) dialUDP(ctx context.Context, u *url.URL) (net.Conn, error) {
	dialer := c.UDPDialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	conn, err := dialer.DialContext(ctx, "udp", u.Host)
	if err != nil {
		return nil, fmt.Errorf("tracker: dial UDP tracker: %w", err)
	}
	return conn, nil
}

func (c *Client) udpConnect(ctx context.Context, conn net.Conn) (uint64, error) {
	transactionID, err := randomUint32(false)
	if err != nil {
		return 0, fmt.Errorf("tracker: generate UDP transaction ID: %w", err)
	}
	packet := make([]byte, 16)
	binary.BigEndian.PutUint64(packet[0:8], udpProtocolID)
	binary.BigEndian.PutUint32(packet[8:12], udpActionConnect)
	binary.BigEndian.PutUint32(packet[12:16], transactionID)
	data, err := c.udpExchange(ctx, conn, packet, transactionID, udpActionConnect, nil)
	if err != nil {
		return 0, err
	}
	if len(data) < 16 {
		return 0, fmt.Errorf("tracker: UDP connect response is %d bytes, want at least 16", len(data))
	}
	return binary.BigEndian.Uint64(data[8:16]), nil
}

func (c *Client) udpExchange(ctx context.Context, conn net.Conn, packet []byte, transactionID, action uint32, refreshConnection func() error) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	timeout := c.UDPInitialTimeout
	if timeout == 0 {
		timeout = DefaultUDPInitialTimeout
	}
	if timeout < 0 {
		return nil, fmt.Errorf("tracker: UDP initial timeout must be positive")
	}
	retries := c.UDPMaxRetries
	if retries == 0 {
		retries = DefaultUDPMaxRetries
	}
	if retries < 0 || retries > DefaultUDPMaxRetries {
		return nil, fmt.Errorf("tracker: UDP max retries must be between 0 and %d", DefaultUDPMaxRetries)
	}
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer stop()

	buffer := make([]byte, maxUDPResponseSize)
	connectionExpires := time.Now().Add(time.Minute)
	for attempt := 0; attempt <= retries; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if refreshConnection != nil && !time.Now().Before(connectionExpires) {
			if err := refreshConnection(); err != nil {
				return nil, err
			}
			connectionExpires = time.Now().Add(time.Minute)
		}
		attemptTimeout := timeout
		for i := 0; i < attempt; i++ {
			if attemptTimeout > time.Duration(math.MaxInt64/2) {
				attemptTimeout = time.Duration(math.MaxInt64)
				break
			}
			attemptTimeout *= 2
		}
		deadline := time.Now().Add(attemptTimeout)
		contextLimited := false
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
			contextLimited = true
		}
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("tracker: set UDP deadline: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		written, err := conn.Write(packet)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if netError, ok := err.(net.Error); ok && netError.Timeout() && contextLimited {
				return nil, context.DeadlineExceeded
			}
			return nil, fmt.Errorf("tracker: write UDP request: %w", err)
		}
		if written != len(packet) {
			return nil, fmt.Errorf("tracker: short UDP write: wrote %d of %d bytes", written, len(packet))
		}
		n, err := conn.Read(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if netError, ok := err.(net.Error); ok && netError.Timeout() && contextLimited {
				return nil, context.DeadlineExceeded
			}
			if netError, ok := err.(net.Error); ok && netError.Timeout() && attempt < retries {
				continue
			}
			if netError, ok := err.(net.Error); ok && netError.Timeout() {
				return nil, fmt.Errorf("tracker: UDP request timed out after %d attempts", attempt+1)
			}
			return nil, fmt.Errorf("tracker: read UDP response: %w", err)
		}
		if n < 8 {
			return nil, fmt.Errorf("tracker: UDP response is %d bytes, want at least 8", n)
		}
		responseAction := binary.BigEndian.Uint32(buffer[0:4])
		responseTransactionID := binary.BigEndian.Uint32(buffer[4:8])
		if responseTransactionID != transactionID {
			return nil, fmt.Errorf("tracker: UDP transaction ID mismatch: got %08x, want %08x", responseTransactionID, transactionID)
		}
		if responseAction == udpActionError {
			return nil, fmt.Errorf("tracker: UDP error: %s", string(buffer[8:n]))
		}
		if responseAction != action {
			return nil, fmt.Errorf("tracker: UDP response action %d, want %d", responseAction, action)
		}
		return append([]byte(nil), buffer[:n]...), nil
	}
	panic("unreachable")
}

func udpEvent(event Event) uint32 {
	switch event {
	case EventCompleted:
		return 1
	case EventStarted:
		return 2
	case EventStopped:
		return 3
	default:
		return 0
	}
}

func udpAddressBytes(conn net.Conn) int {
	if address, ok := conn.RemoteAddr().(*net.UDPAddr); ok && address.IP.To4() == nil {
		return 16
	}
	return 4
}

func udpInteger(value uint32, label string) (int, error) {
	if uint64(value) > uint64(maxInt()) {
		return 0, fmt.Errorf("tracker: UDP %s is outside the int range", label)
	}
	return int(value), nil
}
