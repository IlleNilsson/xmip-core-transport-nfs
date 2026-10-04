# xmip-core-transport-nfs

NFS transport: one file on an export is one Stream — NFS version 3 over ONC RPC on TCP, against a server or the in-process one this crate carries. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Send Location creates, writes and commits on a connection kept per server (`transport::Pool`), each export mounted on it once. Until 2026-09-27 every file mounted and unmounted.

A Receive Location lists, reads and removes on the same kept connection, the export mounted on it once. Until 2026-09-28 every receive mounted and unmounted.

## Acknowledgement

A file is consumed only after the runtime's whole receive cycle. A receive lists the export (`READDIR`) and hands each file back unread; its body looks the file up on its first read and reads it a `READ` at a time as the runtime asks, never whole in memory, until the server says it is the end. `Accepted` removes it (`REMOVE`) unless `delete_after_retrieve = false`. `Refused` leaves it where it lies, whatever the setting: a refusal at a transport gate keeps nothing in Xmip, so the file is the only copy. This Location does not receive it again while it is unchanged — the size and modification time the attributes of a `LOOKUP` carry, taken when it is refused and asked again only of a refused name a listing still shows, since `READDIR` gives names alone; written again, it is a new arrival. A server that answers a `LOOKUP` without attributes has a refused file received, and refused, again on every receive — never lost. What is remembered as refused is the node process's: a node started again receives a refused file once more, and refuses it again. `Failed` leaves it, and the next receive lists it again. The connection is locked for one call and its reply, never across a file. Until 2026-10-02 a receive read and removed every file before handing it back.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls: scheme, authority, path and decoded query. Until 2026-09-28 it was read through the transport capability's `socket::target`, which split it on its first slash and left the query in the path.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
