# Ruvchain

[![Build status](https://github.com/ruvcoindev/ruvchain/actions/workflows/ci.yml/badge.svg)](https://github.com/ruvcoindev/ruvchain/actions/workflows/ci.yml)

## Introduction

Ruvchain is an early-stage implementation of a fully end-to-end encrypted IPv6
network. It is lightweight, self-arranging, supported on multiple platforms and
allows pretty much any IPv6-capable application to communicate securely with
other Ruvchain nodes. Ruvchain does not require you to have IPv6 Internet
connectivity - it also works over IPv4.

## Supported Platforms

Ruvchain works on a number of platforms, including Linux, macOS, Ubiquiti
EdgeRouter, VyOS, Windows, FreeBSD, OpenBSD and OpenWrt.

Please see our [Installation](https://ruvcoindev.github.io/installation.html)
page for more information. You may also find other platform-specific wrappers, scripts
or tools in the `contrib` folder.

## Building

If you want to build from source, as opposed to installing one of the pre-built
packages:

1. Install [Go](https://golang.org) (requires Go 1.21 or later)
2. Clone this repository
2. Run `./build`

Note that you can cross-compile for other platforms and architectures by
specifying the `GOOS` and `GOARCH` environment variables, e.g. `GOOS=windows
./build` or `GOOS=linux GOARCH=mipsle ./build`.

## Running

### Generate configuration

To generate static configuration, either generate a HJSON file (human-friendly,
complete with comments):

```
./ruvchain -genconf > /path/to/ruvchain.conf
```

... or generate a plain JSON file (which is easy to manipulate
programmatically):

```
./ruvchain -genconf -json > /path/to/ruvchain.conf
```

You will need to edit the `ruvchain.conf` file to add or remove peers, modify
other configuration such as listen addresses or multicast addresses, etc.

### Run Ruvchain

To run with the generated static configuration:

```
./ruvchain -useconffile /path/to/ruvchain.conf
```

To run in auto-configuration mode (which will use sane defaults and random keys
at each startup, instead of using a static configuration file):

```
./ruvchain -autoconf
```

You will likely need to run Ruvchain as a privileged user or under `sudo`,
unless you have permission to create TUN/TAP adapters. On Linux this can be done
by giving the Ruvchain binary the `CAP_NET_ADMIN` capability.

## Documentation

<<<<<<< HEAD
Documentation is available [on our website](https://ruvchain.github.io).

- [Installing Ruvchain](https://ruvchain.github.io/installation.html)
- [Configuring Ruvchain](https://ruvchain.github.io/configuration.html)
- [Frequently asked questions](https://ruvchain.github.io/faq.html)
- [Version changelog](CHANGELOG.md)
=======
Documentation is available [on our website](https://ruvcoindev.github.io).

- [Installing Ruvchain](https://ruvcoindev.github.io/installation.html)
- [Configuring Ruvchain](https://ruvcoindev.github.io/configuration.html)
- [Frequently asked questions](https://ruvcoindev.github.io/faq.html)

>>>>>>> e99b138676e8b6dd8ed88d0def1fd8aa2d1710bd

## Community

Feel free to join us on our [Matrix
channel](https://matrix.to/#/#ruvchain:matrix.org) at `#ruvchain:matrix.org`
or in the `#ruvchain` IRC channel on [libera.chat](https://libera.chat).

## License

This code is released under the terms of the LGPLv3, but with an added exception
that was shamelessly taken from [godeb](https://github.com/niemeyer/godeb).
Under certain circumstances, this exception permits distribution of binaries
that are (statically or dynamically) linked with this code, without requiring
the distribution of Minimal Corresponding Source or Minimal Application Code.
For more details, see: [LICENSE](LICENSE).
