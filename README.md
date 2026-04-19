# ribd

Central RIB daemon. Accepts route pushes from routing / service daemons (ospfd, bgpd, dhcpd, …), arbitrates across sources by administrative distance, and programs the winners into VPP's FIB and the Linux kernel routing table.

This repository is a Cargo workspace with three crates:

| Crate | Purpose | License |
|-------|---------|---------|
| [`ribd/`](ribd) | The daemon binary | AGPL-3.0-or-later |
| [`ribd-proto/`](ribd-proto) | Wire protocol types (serde/bincode) | LGPL-3.0-or-later |
| [`ribd-client/`](ribd-client) | Tokio-based producer-side client library | LGPL-3.0-or-later |

Producers link `ribd-client`; the daemon and the client share types from `ribd-proto`. See each subdirectory's `Cargo.toml` and `LICENSE` for the exact license.

## Build

```sh
cargo build --release
```

Produces `target/release/ribd`. The daemon requires Linux (it uses rtnetlink for kernel route programming); on other targets the kernel backend compiles to a no-op stub and only the VPP backend is active.

## Run

```sh
ribd --vpp-api /run/vpp/api.sock --socket /run/ribd.sock
```

Flags:

| Flag | Default | Purpose |
|------|---------|---------|
| `--vpp-api PATH` | `/run/vpp/core-api.sock` | VPP binary API socket |
| `--socket PATH` | `/run/ribd.sock` | Unix socket producers connect to |
| `--no-kernel` | off | Skip Linux kernel route programming (VPP-only) |

## Protocol

Length-prefixed bincode over a Unix stream socket. See `ribd-proto/src/lib.rs` for message types and `ribd-client/src/lib.rs` for the handshake + bulk/update flow.

## Configuration reload

`ribd` currently has no config file — all runtime state comes from live producer sessions. `SIGHUP` is wired for operational consistency with the other daemons (`systemctl reload ribd` does something predictable) but is a no-op today. When a config file is introduced (e.g. admin-distance policy, static routes), the reload path is already in place.

## License

- `ribd` (the daemon): **AGPL-3.0-or-later** — see [LICENSE-AGPL](LICENSE-AGPL).
- `ribd-proto`, `ribd-client` (libraries): **LGPL-3.0-or-later** — see [LICENSE-LGPL](LICENSE-LGPL) (which incorporates [LICENSE-GPL](LICENSE-GPL)).

If these terms don't fit your use, commercial licenses are available. See [CONTRIBUTING.md](CONTRIBUTING.md).
