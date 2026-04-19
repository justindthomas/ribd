//! ribd entry point.
//!
//! Connects to VPP, opens the Unix socket at `/run/ribd.sock`
//! (or the path from `--socket`), and accepts client connections.
//! One tokio task per client.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use ribd_proto::DEFAULT_SOCKET_PATH;
use ribd::kernel_backend::{IfIndexMap, KernelBackend};
use ribd::local_addrs::LocalAddrs;
use ribd::rib::Rib;
use ribd::session::{handle_session, SharedState};
use ribd::vpp_backend::VppBackend;
use tokio::net::UnixListener;
use tokio::sync::Mutex;

struct Args {
    vpp_api_socket: String,
    socket_path: PathBuf,
    disable_kernel: bool,
}

fn parse_args() -> Args {
    let mut vpp_api_socket = "/run/vpp/core-api.sock".to_string();
    let mut socket_path = PathBuf::from(DEFAULT_SOCKET_PATH);
    let mut disable_kernel = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--vpp-api" => {
                vpp_api_socket = args.next().expect("--vpp-api requires a path");
            }
            "--socket" => {
                socket_path = PathBuf::from(args.next().expect("--socket requires a path"));
            }
            "--no-kernel" => {
                disable_kernel = true;
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: ribd [--vpp-api PATH] [--socket PATH] [--no-kernel]"
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("Unknown argument: {}", other);
                std::process::exit(1);
            }
        }
    }
    Args {
        vpp_api_socket,
        socket_path,
        disable_kernel,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("ribd=info")),
        )
        .init();

    let args = parse_args();

    tracing::info!(
        vpp_api = %args.vpp_api_socket,
        socket = %args.socket_path.display(),
        "starting ribd"
    );

    let vpp = vpp_api::VppClient::connect(&args.vpp_api_socket)
        .await
        .with_context(|| format!("connecting to VPP at {}", args.vpp_api_socket))?;

    // Build the VPP sw_if_index → kernel ifindex map. Even with
    // --no-kernel we keep the map around: it's cheap and surfaces
    // early feedback if linux_cp TAPs are missing. Refresh happens
    // on startup only; Phase 2 doesn't handle dynamic interface
    // changes.
    let ifindex_map = Arc::new(Mutex::new(IfIndexMap::new()));
    {
        let mut m = ifindex_map.lock().await;
        m.refresh(&vpp).await;
    }

    // Cache the set of local interface addresses so the session
    // layer can drop self-routes (next-hop == one of our IPs) before
    // they reach the RIB. See local_addrs.rs.
    let local_addrs = Mutex::new(LocalAddrs::new());
    {
        let mut la = local_addrs.lock().await;
        la.refresh(&vpp).await;
    }

    let kernel = if args.disable_kernel {
        tracing::info!("--no-kernel: kernel netlink backend disabled");
        None
    } else {
        match KernelBackend::new(ifindex_map.clone()) {
            Ok(k) => {
                tracing::info!("kernel netlink backend ready");
                // Scrub any orphan routes left over by a previous
                // ribd / routing daemon before clients connect.
                // Without this, a route the previous daemon installed
                // but the new daemon's first Bulk doesn't include
                // would sit in the kernel forever.
                k.purge_orphans().await;
                Some(k)
            }
            Err(e) => {
                tracing::warn!("kernel backend disabled: {}", e);
                None
            }
        }
    };

    // Best-effort remove a stale socket. Bind will fail loudly if
    // the path is held by another process.
    let _ = std::fs::remove_file(&args.socket_path);

    let listener = UnixListener::bind(&args.socket_path)
        .with_context(|| format!("binding to {}", args.socket_path.display()))?;

    // Socket permissions: 0660, group vpp so operator tools can
    // connect without root. The vpp group may not exist on dev
    // machines; ignore chown failure.
    let _ = set_socket_perms(&args.socket_path);

    // Seed the in-memory RIB with the directly-connected routes
    // for every interface VPP knows about. Producers that resolve
    // recursive next-hops (bgpd most importantly) need these
    // present in the RIB or their resolution attempts hold
    // forever — a connected route is the LPM winner for any
    // upstream peer address. See Phase B10 deployment notes for
    // the bug that motivated this.
    let mut seeded_rib = Rib::new();
    let connected = seed_connected_routes(&vpp).await;
    let connected_count = connected.len();
    for route in &connected {
        seeded_rib.upsert(route);
    }
    if connected_count > 0 {
        tracing::info!(count = connected_count, "seeded connected routes from VPP");
    }

    let state = Arc::new(SharedState {
        rib: Mutex::new(seeded_rib),
        backend: VppBackend::new(),
        kernel,
        vpp,
        local_addrs,
    });

    tracing::info!("ribd ready");

    // SIGHUP: ribd currently has no config file to re-read — all
    // runtime state comes from live producer sessions. The handler
    // is wired anyway for two reasons: (1) consistent operational
    // surface with ospfd/bgpd/dhcpd (`systemctl reload ribd` does
    // something predictable), and (2) when a future config file
    // lands (admin-distance policy, static routes), the plumbing
    // is already in place.
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .context("registering SIGHUP handler")?;

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _addr) = match accepted {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("accept failed: {}", e);
                        continue;
                    }
                };
                let state_clone = state.clone();
                tokio::spawn(async move { handle_session(stream, state_clone).await });
            }
            _ = sighup.recv() => {
                tracing::info!("SIGHUP: no config file to reload; ignoring");
            }
        }
    }
}

/// Dump every interface's IPv4 and IPv6 addresses from VPP and
/// build a `Source::Connected` `Route` for each address's network
/// prefix. Each connected route has a single Direct next-hop with
/// `addr=zero` (no L3 gateway, just the egress interface) and the
/// interface's `sw_if_index`.
///
/// These routes are seeded into the RIB at startup so producers
/// pushing recursive next-hops (bgpd) can resolve through
/// directly-connected interface prefixes — by far the most common
/// eBGP next-hop case. Without this seed, a BGP route via the
/// upstream peer's connected address gets held forever because
/// ribd's LPM resolver finds no covering prefix.
async fn seed_connected_routes(vpp: &vpp_api::VppClient) -> Vec<ribd_proto::Route> {
    use vpp_api::generated::interface::{SwInterfaceDetails, SwInterfaceDump};
    use vpp_api::generated::ip::{IpAddressDetails, IpAddressDump};

    let mut out = Vec::new();
    let ifaces: Vec<SwInterfaceDetails> = match vpp
        .dump::<SwInterfaceDump, SwInterfaceDetails>(SwInterfaceDump::default())
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("seed_connected_routes: SwInterfaceDump failed: {}", e);
            return out;
        }
    };

    for vi in ifaces {
        if !vi.flags.is_admin_up() {
            continue;
        }
        // v4 addresses
        let v4 = vpp
            .dump::<IpAddressDump, IpAddressDetails>(IpAddressDump {
                sw_if_index: vi.sw_if_index,
                is_ipv6: false,
            })
            .await
            .unwrap_or_default();
        for d in v4 {
            let len = d.prefix.len;
            if len == 0 || len > 32 {
                continue;
            }
            let mut full_addr = [0u8; 16];
            full_addr[..4].copy_from_slice(&d.prefix.address[..4]);
            // Mask the address to the network prefix.
            let masked = mask_v4(full_addr, len);
            out.push(ribd_proto::Route {
                prefix: ribd_proto::Prefix {
                    af: ribd_proto::Af::V4,
                    addr: masked,
                    len,
                },
                source: ribd_proto::Source::Connected,
                next_hops: vec![ribd_proto::NextHop {
                    kind: ribd_proto::NextHopKind::Direct,
                    addr: [0u8; 16],
                    sw_if_index: vi.sw_if_index,
                }],
                metric: 0,
                tag: 0,
                admin_distance: None,
            });
        }
        // v6 addresses
        let v6 = vpp
            .dump::<IpAddressDump, IpAddressDetails>(IpAddressDump {
                sw_if_index: vi.sw_if_index,
                is_ipv6: true,
            })
            .await
            .unwrap_or_default();
        for d in v6 {
            let len = d.prefix.len;
            if len == 0 || len > 128 {
                continue;
            }
            let masked = mask_v6(d.prefix.address, len);
            out.push(ribd_proto::Route {
                prefix: ribd_proto::Prefix {
                    af: ribd_proto::Af::V6,
                    addr: masked,
                    len,
                },
                source: ribd_proto::Source::Connected,
                next_hops: vec![ribd_proto::NextHop {
                    kind: ribd_proto::NextHopKind::Direct,
                    addr: [0u8; 16],
                    sw_if_index: vi.sw_if_index,
                }],
                metric: 0,
                tag: 0,
                admin_distance: None,
            });
        }
    }
    out
}

fn mask_v4(addr: [u8; 16], len: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    let plen = len as usize;
    let full = (plen / 8).min(4);
    let tail = plen % 8;
    out[..full].copy_from_slice(&addr[..full]);
    if tail > 0 && full < 4 {
        let mask = 0xFFu8 << (8 - tail);
        out[full] = addr[full] & mask;
    }
    out
}

fn mask_v6(addr: [u8; 16], len: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    let plen = len as usize;
    let full = (plen / 8).min(16);
    let tail = plen % 8;
    out[..full].copy_from_slice(&addr[..full]);
    if tail > 0 && full < 16 {
        let mask = 0xFFu8 << (8 - tail);
        out[full] = addr[full] & mask;
    }
    out
}

#[cfg(unix)]
fn set_socket_perms(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o660);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}
