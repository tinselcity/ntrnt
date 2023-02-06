![ntrnt-ci](https://github.com/tinselcity/ntrnt/workflows/ntrnt-ci/badge.svg)

# ntrnt
BitTorrent client in C++

## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [License](#license)

## Background

`ntrnt` is a basic BitTorrent client library with support for:
- [UDP Hole Punching](https://en.wikipedia.org/wiki/UDP_hole_punching) via [libminiupnpc](http://miniupnp.free.fr/)
- uTP: via [libutp](https://github.com/bittorrent/libutp)
- [Protocol Header Encryption (aka: Message Sender Encryption)](https://wiki.vuze.com/w/Message_Stream_Encryption)
- [Kademlia DHT](https://xlattice.sourceforge.net/components/protocol/kademlia/specs.html) (for trackerless torrenting)
- Magnet Links

#### An example
```bash
>ntrnt sample.torrent
PEERS [NONE]: 385 [UTP_CONNECTING]: 103 [PHE_SETUP]: 1 [PHE_CONNECTING]: 1 [HANDSHAKING]: 4 [CONNECTED]: 9 [DEAD]: 2
PEERS [NONE]: 385 [UTP_CONNECTING]: 103 [PHE_SETUP]: 1 [PHE_CONNECTING]: 1 [HANDSHAKING]: 4 [CONNECTED]: 9 [DEAD]: 2
PEERS [NONE]: 385 [UTP_CONNECTING]: 103 [PHE_SETUP]: 1 [PHE_CONNECTING]: 1 [HANDSHAKING]: 4 [CONNECTED]: 9 [DEAD]: 2
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
brew install cmake
brew install openssl
```

### Building the tools
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
  -d, --no-dht         disable dht.
  
Debug Options:
  -D, --display        display torrent+meta-info and exit
  -M, --noportmap      disable portmapping
  -P, --peer           connect to single peer (disable tracker announce)
  -T, --trace          tracing (error/warn/debug/verbose/all)
```

## Contribute

- We welcome issues, questions and pull requests.


## License

This project is licensed under the terms of the Apache 2.0 open source license. Please refer to the `LICENSE` file for the full terms.

