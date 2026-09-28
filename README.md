# xmip-core-transport-nfs

NFS transport: one file on an export is one Stream — NFS version 3 over ONC RPC on TCP, against a server or the in-process one this crate carries. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Send Location creates, writes and commits on a connection kept per server (`transport::Pool`), each export mounted on it once. Until 2026-09-27 every file mounted and unmounted.

A Receive Location lists, reads and removes on the same kept connection, the export mounted on it once. Until 2026-09-28 every receive mounted and unmounted.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls: scheme, authority, path and decoded query. Until 2026-09-28 it was read through the transport capability's `socket::target`, which split it on its first slash and left the query in the path.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
