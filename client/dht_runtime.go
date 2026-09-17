package client

import (
	"net"
	"net/netip"

	"github.com/natalie-o-perret/go-torrent/dht"
	"github.com/natalie-o-perret/go-torrent/peer"
)

type dhtResultEvent struct {
	protocol peer.ProtocolVersion
	peers    []netip.AddrPort
}

type peerDHTPortEvent struct {
	id   uint64
	port uint16
}

func (state *coordinator) startDHT() {
	if state.client.dhtNode == nil || state.client.meta.Info.Private {
		return
	}
	for _, protocol := range []peer.ProtocolVersion{peer.ProtocolV1, peer.ProtocolV2} {
		if state.client.layouts[protocol] == nil {
			continue
		}
		state.workers.Add(1)
		go state.runDHT(protocol)
	}
}

func (state *coordinator) runDHT(protocol peer.ProtocolVersion) {
	defer state.workers.Done()
	hash := state.client.dhtInfoHash(protocol)
	for {
		lookup, err := state.client.dhtNode.GetPeers(state.ctx, hash)
		if err == nil {
			if !state.emit(dhtResultEvent{protocol: protocol, peers: lookup.Peers}) {
				return
			}
			if state.client.port != 0 && len(lookup.Tokens) != 0 {
				_, _ = state.client.dhtNode.Announce(state.ctx, hash, state.client.port, false, lookup.Tokens)
			}
		}
		select {
		case <-state.ctx.Done():
			return
		case <-state.client.after(state.client.dhtReannounceInterval):
		}
	}
}

func (client *Client) dhtInfoHash(protocol peer.ProtocolVersion) dht.ID {
	return dht.ID(client.layouts[protocol].infoHash)
}

func (client *Client) dhtPort() uint16 {
	if client.dhtNode == nil || client.meta.Info.Private {
		return 0
	}
	address := client.dhtNode.Addr()
	if !address.IsValid() {
		return 0
	}
	return address.Port()
}

func (state *coordinator) handleDHTResult(event dhtResultEvent) {
	if state.client.meta.Info.Private {
		return
	}
	for _, endpoint := range event.peers {
		candidate, err := state.client.validateCandidate(Candidate{
			Address:  endpoint.String(),
			Protocol: event.protocol,
			Source:   SourceDHT,
		})
		if err == nil {
			_ = state.addCandidate(candidate)
		}
	}
}

func (state *coordinator) handlePeerDHTPort(event peerDHTPortEvent) {
	managed := state.peers[event.id]
	if state.client.dhtPort() == 0 || managed == nil || !usableDHTAddress(managed.remoteIP) {
		return
	}
	endpoint := netip.AddrPortFrom(managed.remoteIP, event.port)
	state.workers.Add(1)
	go func() {
		defer state.workers.Done()
		_, _ = state.client.dhtNode.Ping(state.ctx, endpoint)
	}()
}

func remoteConnectionIP(address net.Addr) netip.Addr {
	if address == nil {
		return netip.Addr{}
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		return netip.Addr{}
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return parsed.Unmap()
}

func usableDHTAddress(address netip.Addr) bool {
	return address.IsValid() && address.Zone() == "" && !address.IsUnspecified() && !address.IsMulticast()
}
