// Package gotorrent is a BitTorrent protocol library and CLI for Go 1.26.7+.
//
// It provides focused packages for v1, v2, and hybrid torrents over TCP and
// uTP, with bounded decoding, discovery, storage, and peer state.
//
// # Packages
//
// bencode: Canonical, bounded bencoding used by metainfo, trackers, DHT, and
// extension messages.
//
// bitfield: Compact byte-slice bitfield for tracking which pieces a peer has
// downloaded, with O(1) Has/Set and an O(n) popcount.
//
// client: End-to-end downloading and seeding across trackers, DHT, PEX, web
// seeds, TCP, and uTP.
//
// dht: Mainline IPv4 and IPv6 DHT client and server.
//
// magnet: Strict magnet URI parsing and formatting.
//
// metainfo: Strict v1, v2, and hybrid .torrent parsing and info hashes.
//
// peer: Peer wire sessions, Fast, extension negotiation, metadata, PEX, and v2
// hash messages.
//
// piece: Block request state and v1/v2 verification.
//
// storage: Safe file mapping, hybrid layouts, padding, and resume verification.
//
// tracker: HTTP, HTTPS, and UDP announce, scrape, tiers, and lifecycle sessions.
//
// webseed: BEP 19 HTTP web seed downloads.
package gotorrent
