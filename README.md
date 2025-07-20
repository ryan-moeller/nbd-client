# FreeBSD GEOM Gate NBD Client

[![13.5-RELEASE Build Status](https://api.cirrus-ci.com/github/ryan-moeller/nbd-client.svg?branch=main&task=releases/amd64/13.5-RELEASE)](https://cirrus-ci.com/github/ryan-moeller/nbd-client)
[![14.3-RELEASE Build Status](https://api.cirrus-ci.com/github/ryan-moeller/nbd-client.svg?branch=main&task=releases/amd64/14.3-RELEASE)](https://cirrus-ci.com/github/ryan-moeller/nbd-client)
[![15.0-CURRENT Build Status](https://api.cirrus-ci.com/github/ryan-moeller/nbd-client.svg?branch=main&task=snapshots/amd64/15.0-CURRENT)](https://cirrus-ci.com/github/ryan-moeller/nbd-client)

## NOTICE

See https://github.com/ryan-moeller/kernel-nbd-client for a new and improved
kernel NBD client for FreeBSD.

## Synopsis

The Network Block Device is a Linux-originated lightweight block access
protocol that allows one to export a block device to a client.

This client is designed to run on top of FreeBSD's GEOM Gate device driver,
keeping the network client in a userland daemon rather than in a kernel
module.

Casper is used to sandbox the DNS lookup of the server host and the socket
connection to the server, and Capsicum is used to limit the capabilities of the
ggate ctl descriptor and the client socket once connected.

OpenSSL is used for TLS connections.

Messages are logged via syslog, and to stdout and stderr when running
interactively.

The client immediately daemonizes unless passed the `-f` flag, in which
case it remains running in the foreground.

## Caveats

* Manual control (listing, naming, numbering, removal) of the device nodes
  is not yet provided by this tool.
* The client is currently single-threaded.
* GEOM Gate devices cannot report attributes such as `GEOM::candelete` at this
  time, which can prevent TRIM/DELETE from being used.

## Prerequisites

There are no dependencies outside of the FreeBSD base system.

## Compiling

```
$ make
# make install # (optional)
```

## Usage Examples

Connect to an NBD server and print the name of the new device on stdout:

```
# nbd-client 192.168.1.101
ggate0
```

Connect specifying a hostname and port number:

```
# nbd-client nbd.storage.internal-domain.net 10809
ggate1
```

Connect using a UNIX-domain socket:

```
# nbd-client /path/to/nbd-server.socket
ggate2
```
List exports of a server:

```
# nbd-client -l 10.2
abc
xyz
```

Connect to an export named `xyz`:

```
# nbd-client -n xyz 10.2
ggate3
```

You can then use this device as a regular disk device.  For example, create
a ZFS pool named `foo` backed by the NBD storage attached to `ggate0`.

```
# zpool create foo ggate0
```

Use the `ggatec` utility to list all attached GEOM Gate devices.  These may
not all be NBD devices:

```
# ggatec list
ggate0
ggate1
ggate2
ggate3
```

Use the `ggatec` utility to force removal of the GEOM Gate device unit `0`,
which corresponds to the device named `ggate0`:

```
# ggatec destroy -f -u 0
```

## To Do

* rc scripts
* option to drop to a less privileged user?
* parallel connections to an export
