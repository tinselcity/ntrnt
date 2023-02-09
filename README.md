![ntrnt-ci](https://github.com/tinselcity/ntrnt/workflows/ntrnt-ci/badge.svg)

# ntrnt
BitTorrent client in C++

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Todo](#todo)
- [Contribute](#contribute)
- [License](#license)

## Background

`ntrnt` is a basic BitTorrent client library with support for:

- [UDP Hole Punching](https://en.wikipedia.org/wiki/UDP_hole_punching) via [libminiupnpc](http://miniupnp.free.fr/)
- uTP: via [libutp](https://github.com/bittorrent/libutp)
- [Protocol Header Encryption (aka: Message Sender Encryption)](https://wiki.vuze.com/w/Message_Stream_Encryption)
- [Kademlia DHT](https://xlattice.sourceforge.net/components/protocol/kademlia/specs.html) (for trackerless torrenting)
- [Magnet Links](https://www.bittorrent.org/beps/bep_0053.html) and info hashes (sha1 BitTorrent v1)
- [Extension Negotiation Protocol](http://wiki.vuze.com/w/Extension_negotiation_protocol), including [Peer Exchange](https://www.bittorrent.org/beps/bep_0011.html) and [Metadata](https://www.bittorrent.org/beps/bep_0009.html)
- [UDP](https://www.bittorrent.org/beps/bep_0015.html)/[HTTP(s)](https://www.bittorrent.org/beps/bep_0048.html) Tracker announce and scrape.

#### An example
```bash
>ntrnt sample.torrent
TODO...
...
```

## Install

## OS requirements:
Linux/OS X (kqueue support coming soon-ish)

### Install dependencies:
Library requirements:
* libssl/libcrypto (OpenSSL)

### OS X Build requirements (brew)
```bash
brew install cmake openssl rapidjson miniupnpc
```

### Building the library/cli
```bash
./build.sh
```

And optionally install
```bash
cd ./build
sudo make install
```

## Usage
`ntrnt --help`

```sh
Usage: ntrnt [options]
Options:
  -h, --help           display this help and exit.
  -v, --version        display the version number and exit.
  -t, --torrent        torrent file.
  -i, --info-hash      info hash (hex).
  -e, --ext-port       ext-port (default: 51413)
  -d, --no-dht         disable dht.
  -r, --no-trackers    disable tracker announce/scrape
  -g, --geoip-db       geoip-db
  
Debug Options:
  -D, --display        display torrent+meta-info and exit
  -M, --noportmap      disable portmapping
  -P, --peer           connect to single peer (disable tracker announce)
  -T, --trace          tracing (none/error/warn/debug/verbose/all) (default: none)
  -E, --error-log      log errors to file <file>
```

## Todo
A list of critical missing features that'd be nice to have someday:

- Queue'ing issue causing slow downloads.  Rethink how commands are sent and queue'd.  Maybe sending requests or protocol messages (not piece data immediately), to prevent blocking on receipt for leechers.
- [Fast Extension](https://www.bittorrent.org/beps/bep_0006.html) support.
- TCP connection support for peers (encrypted only)
- Endgame support: when bytes/blocks outstanding >= bytes/blocks remaining, send to all peers (support for cancelling outstanding requests)
 - Better peer curation including connection/bandwidth caps, optimistic unchoking, and [peer priority](http://www.bittorrent.org/beps/bep_0040.html)
 - multiple session support.
 - build in http server support for web-gui (remove [is2](https://github.com/tinselcity/is2) dependency).
- [BitTorrent v2](https://www.bittorrent.org/beps/bep_0052.html) support


## Contribute

- We welcome issues, questions and pull requests.


## License

This project is licensed under the terms of the Apache 2.0 open source license. Please refer to the `LICENSE` file for the full terms.

