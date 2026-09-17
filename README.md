# go-torrent

[![CI](https://github.com/natalie-o-perret/go-torrent/actions/workflows/ci.yml/badge.svg)](https://github.com/natalie-o-perret/go-torrent/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/natalie-o-perret/go-torrent.svg)](https://pkg.go.dev/github.com/natalie-o-perret/go-torrent)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Contributing](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

A focused, composable BitTorrent protocol library and client for Go 1.26.3+.

> [!NOTE]
> The library supports v1, v2, and hybrid torrents over TCP and uTP. Network,
> storage, discovery, and protocol limits are explicit and bounded.

## Packages

| Package | Description |
| --- | --- |
| `bencode` | Canonical, bounded bencoding |
| `bitfield` | Compact peer piece bitfields |
| `client` | Torrent coordination, scheduling, discovery, and seeding |
| `dht` | IPv4/IPv6 Mainline DHT client and server |
| `magnet` | Magnet URI parsing and formatting |
| `metainfo` | Strict v1, v2, and hybrid `.torrent` parsing |
| `peer` | Peer wire protocol, Fast, extensions, metadata, PEX, and hash |
| `piece` | Block scheduling and piece verification |
| `storage` | Safe multi-file storage, padding, resume, and hybrid layouts |
| `tracker` | HTTP, HTTPS, and UDP announce, scrape, tiers, and sessions |
| `webseed` | Bounded BEP 19 HTTP web seed downloads |

## Quick start

```go
file, err := os.Open("example.torrent")
if err != nil {
    return err
}
defer file.Close()

meta, err := metainfo.Decode(file)
if err != nil {
    return err
}

fmt.Println(meta.Info.Name)
fmt.Println(meta.Hashes())
```

## CLI

```sh
go install github.com/natalie-o-perret/go-torrent/cmd/gotorrent@latest

gotorrent info ubuntu.torrent
gotorrent info 'magnet:?xt=urn:btih:...&tr=https%3A%2F%2Ftracker.example%2Fannounce'

gotorrent download --output ./downloads ubuntu.torrent
gotorrent download --output ./downloads \
  --dht-bootstrap router.bittorrent.com:6881 \
  'magnet:?xt=urn:btih:...'
```

`download` listens on TCP and uTP, verifies existing files for resume, and
continues seeding until interrupted. Use repeatable `--peer HOST:PORT` and
`--dht-bootstrap HOST:PORT` options for direct and DHT bootstrap peers. The
default `--listen 0.0.0.0:0` chooses a free shared TCP/uTP port.

Example output:

```text
Name:         ubuntu-24.04-desktop-amd64.iso
InfoHashV1:   e4be9e4db876e3e3179778b03e906297be5c8dbe
PieceLength:  524288
Pieces:       4560
TotalLength:  2392997888
Trackers:
  https://torrent.ubuntu.com/announce
  https://ipv6.torrent.ubuntu.com/announce
```

## Protocol coverage

| BEP                                                     | Description                              |
| ------------------------------------------------------- | ---------------------------------------- |
| [BEP 3](https://www.bittorrent.org/beps/bep_0003.html)  | v1 metainfo, trackers, and peer protocol |
| [BEP 5](https://www.bittorrent.org/beps/bep_0005.html)  | Mainline DHT                             |
| [BEP 6](https://www.bittorrent.org/beps/bep_0006.html)  | Fast extension                           |
| [BEP 7](https://www.bittorrent.org/beps/bep_0007.html)  | IPv6 tracker peers                       |
| [BEP 9](https://www.bittorrent.org/beps/bep_0009.html)  | Magnet metadata exchange                 |
| [BEP 10](https://www.bittorrent.org/beps/bep_0010.html) | Extension protocol                       |
| [BEP 11](https://www.bittorrent.org/beps/bep_0011.html) | Peer exchange                            |
| [BEP 12](https://www.bittorrent.org/beps/bep_0012.html) | Multi-tracker tiers                      |
| [BEP 15](https://www.bittorrent.org/beps/bep_0015.html) | UDP trackers                             |
| [BEP 19](https://www.bittorrent.org/beps/bep_0019.html) | HTTP web seeds                           |
| [BEP 23](https://www.bittorrent.org/beps/bep_0023.html) | Compact tracker peers                    |
| [BEP 27](https://www.bittorrent.org/beps/bep_0027.html) | Private torrents                         |
| [BEP 29](https://www.bittorrent.org/beps/bep_0029.html) | uTP                                      |
| [BEP 32](https://www.bittorrent.org/beps/bep_0032.html) | IPv6 DHT                                 |
| [BEP 42](https://www.bittorrent.org/beps/bep_0042.html) | DHT node security                        |
| [BEP 43](https://www.bittorrent.org/beps/bep_0043.html) | Read-only DHT nodes                      |
| [BEP 52](https://www.bittorrent.org/beps/bep_0052.html) | v2 and hybrid torrents                   |

## License

MIT. See [LICENSE](LICENSE).
