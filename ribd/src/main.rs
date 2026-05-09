//! ribd entry point.
//!
//! Connects to VPP, opens the Unix socket at `/run/ribd.sock`
//! (or the path from `--socket`), and accepts client connections.
//! One tokio task per client.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Context;
use ribd_proto::DEFAULT_SOCKET_PATH;
use ribd::config::{self as ribd_config, DEFAULT_CONFIG_PATH};
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
    config_path: PathBuf,
}

fn parse_args() -> Args {
    let mut vpp_api_socket = "/run/vpp/core-api.sock".to_string();
    let mut socket_path = PathBuf::from(DEFAULT_SOCKET_PATH);
    let mut disable_kernel = false;
    let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
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
            "--config" => {
                config_path = PathBuf::from(args.next().expect("--config requires a path"));
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: ribd [--vpp-api PATH] [--socket PATH] [--no-kernel] [--config PATH]"
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
        config_path,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Honour NO_COLOR (no-color.org) so the supervisor doesn't see
    // ANSI escapes in captured stderr → journald. tracing_subscriber
    // auto-detects TTY by default but the detection has been spotty
    // across versions, so opt out explicitly when the env is set.
    tracing_subscriber::fmt()
        .with_ansi(std::env::var_os("NO_COLOR").is_none())
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

    // Spawn the VPP supervisor (which will retry until VPP is up)
    // and wait for the first connection so the rest of startup can
    // assume a live client. After this point the supervisor handles
    // disconnects transparently — `vpp_supervisor.client().await`
    // blocks while we're between connections, and the on_reconnect
    // closure registered below re-pushes the full RIB to VPP.
    let vpp_supervisor = vpp_api::VppSupervisor::spawn(args.vpp_api_socket.clone());
    let vpp_initial = vpp_supervisor.wait_ready().await;

    // Build the VPP sw_if_index → kernel ifindex map. Even with
    // --no-kernel we keep the map around: it's cheap and surfaces
    // early feedback if linux_cp TAPs are missing. Refresh happens
    // on startup, on every reconnect, and on SIGHUP — see
    // `refresh_static_state` below.
    let ifindex_map = Arc::new(Mutex::new(IfIndexMap::new()));
    {
        let mut m = ifindex_map.lock().await;
        m.refresh(&vpp_initial).await;
    }

    // Cache the set of local interface addresses so the session
    // layer can drop self-routes (next-hop == one of our IPs) before
    // they reach the RIB. See local_addrs.rs.
    let local_addrs = Mutex::new(LocalAddrs::new());
    {
        let mut la = local_addrs.lock().await;
        la.refresh(&vpp_initial).await;
    }
    drop(vpp_initial);

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

    // Seed the in-memory RIB with directly-connected routes from
    // VPP + the configured interfaces in router.yaml. The yaml pass
    // matters because at ribd startup impd typically hasn't pushed
    // interface IPs to VPP yet (DPDK binding/probe happens earlier
    // than the apply_config step), so `ip_address_dump` returns
    // nothing. Reading yaml directly lets recursive next-hop
    // resolution work on the first apply.
    //
    // Static routes from `routes:` are also reconciled here so they
    // install immediately on ribd startup without waiting for an
    // impd push — avoids the ribd-crash-loses-state problem that
    // forced operators to `commit` again after any ribd restart.
    // Build an empty RIB, construct state, then do a full initial
    // reconcile. Doing it after `state` exists lets us reuse the
    // SIGHUP reconcile path — one code path owns "sync RIB to
    // config + VPP" for both startup and reload, and critically
    // flushes deltas through the VPP + kernel backends (the
    // upsert-directly-into-seeded_rib pattern did not).
    let state = Arc::new(SharedState {
        rib: Mutex::new(Rib::new()),
        backend: VppBackend::new(),
        kernel,
        vpp: vpp_supervisor.clone(),
        local_addrs,
        reconcile_generation: AtomicU64::new(0),
    });

    {
        let cfg = ribd_config::load(&args.config_path);
        let vpp = state.vpp.client().await;
        let vpp_connected = seed_connected_routes(&vpp).await;
        let yaml_connected = build_config_connected(&vpp, &cfg).await;
        let yaml_static = build_config_static(&vpp, &cfg).await;
        tracing::info!(
            vpp_connected = vpp_connected.len(),
            yaml_connected = yaml_connected.len(),
            yaml_static = yaml_static.len(),
            path = %args.config_path.display(),
            "initial reconcile",
        );
        drop(vpp);
        reconcile_from_config(&state, vpp_connected, yaml_connected, yaml_static).await;
    }

    // Register the VPP-reconnect handler. On every reconnect (NOT
    // the initial connect) we:
    //  1. Re-seed connected routes from the freshly-attached VPP
    //     (interface indexes are different now).
    //  2. Re-program every InstalledRoute the in-memory RIB owns
    //     into VPP's empty FIB — producer-pushed BGP/OSPF/DHCP
    //     routes were lost when VPP died, the RIB still has them.
    // The kernel side is untouched on reconnect: kernel routes
    // survive a VPP crash, and reprogramming them would just churn
    // for no benefit.
    {
        let state_for_reinit = state.clone();
        let config_path_for_reinit = args.config_path.clone();
        let ifindex_map_for_reinit = ifindex_map.clone();
        vpp_supervisor
            .on_reconnect(move |client, generation| {
                let state = state_for_reinit.clone();
                let config_path = config_path_for_reinit.clone();
                let ifindex_map = ifindex_map_for_reinit.clone();
                async move {
                    tracing::info!(
                        generation,
                        "VPP reconnected: re-pushing RIB to fresh FIB"
                    );
                    // Refresh the shared sw_if_index → kernel
                    // ifindex map so kernel route installs that
                    // come in after the reconnect can resolve
                    // their next-hop interfaces. Earlier code
                    // built a throwaway local IfIndexMap and
                    // dropped it on the floor — the session-side
                    // map inside KernelBackend went stale and
                    // every producer push for an interface
                    // created post-startup silently bailed at
                    // the unresolved-ifindex check.
                    {
                        let mut m = ifindex_map.lock().await;
                        m.refresh(&client).await;
                    }
                    {
                        let mut la = state.local_addrs.lock().await;
                        la.refresh(&client).await;
                    }
                    let cfg = ribd_config::load(&config_path);
                    let vpp_connected = seed_connected_routes(&client).await;
                    let yaml_connected = build_config_connected(&client, &cfg).await;
                    let yaml_static = build_config_static(&client, &cfg).await;
                    reconcile_from_config(&state, vpp_connected, yaml_connected, yaml_static).await;

                    // Re-push every producer-installed route to VPP's
                    // empty FIB. Connected/Static were just handled by
                    // reconcile_from_config; everything else (BGP,
                    // OSPF, DHCP-PD, …) is in the RIB but no longer in
                    // VPP. Synthesise install-shaped Deltas straight
                    // from `installed_routes()` — the RIB itself is
                    // already correct, this is purely a backend
                    // re-push.
                    let installed = {
                        let rib = state.rib.lock().await;
                        rib.installed_routes()
                    };
                    let deltas: Vec<ribd::rib::Delta> = installed
                        .into_iter()
                        .filter(|ir| {
                            !matches!(
                                ir.source,
                                ribd_proto::Source::Connected | ribd_proto::Source::Static
                            )
                        })
                        .map(|ir| ribd::rib::Delta {
                            table_id: ir.table_id,
                            prefix: ir.prefix,
                            new: Some(ir),
                        })
                        .collect();
                    if !deltas.is_empty() {
                        state.backend.apply(&client, &deltas).await;
                    }
                    tracing::info!(
                        generation,
                        producer_routes = deltas.len(),
                        "VPP reconnect: producer routes re-pushed"
                    );
                    Ok(())
                }
            })
            .await;
    }

    tracing::info!("ribd ready");

    // SIGHUP: impd signals this after `commit` so ribd picks up any
    // added/removed static route or interface-address change.
    // Re-dumps VPP's connected set too — new BVIs or sub-interfaces
    // that impd created via the binary API become visible here.
    //
    // Source-level replace semantics: rebuild a Bulk for Connected
    // and Static respectively, apply through a fresh Rib pass.
    // Removed routes drop out because the new Bulk doesn't mention
    // them; same contract producers already use.
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .context("registering SIGHUP handler")?;
    let config_path = args.config_path.clone();

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
                tracing::info!(path = %config_path.display(), "SIGHUP: reloading config");
                let cfg = ribd_config::load(&config_path);
                let vpp = state.vpp.client().await;
                // Refresh the sw_if_index → kernel ifindex map
                // before any producer-driven route install runs
                // through. Sub-interfaces / BVIs created by
                // impd's apply between ribd startup and now
                // would otherwise be invisible to the kernel
                // backend, and every OSPF/BGP/static route
                // pointing at them would silently miss the
                // kernel FIB while still landing in VPP.
                {
                    let mut m = ifindex_map.lock().await;
                    m.refresh(&vpp).await;
                }
                let vpp_conn = seed_connected_routes(&vpp).await;
                let yaml_conn = build_config_connected(&vpp, &cfg).await;
                let stat = build_config_static(&vpp, &cfg).await;
                drop(vpp);
                reconcile_from_config(&state, vpp_conn, yaml_conn, stat).await;

                // Re-push every producer-installed route (OSPF /
                // BGP / DHCP) through both backends. Producers are
                // event-driven — they only push on LSA / NLRI /
                // lease changes — so a hand-edit to router.yaml
                // that adds a VRF master device or changes
                // interface VRF membership would otherwise leave
                // existing producer routes stuck in whatever
                // kernel/VPP state they were last installed
                // against. Mirrors the on_reconnect re-push
                // pattern, except we hit BOTH backends here (the
                // VPP FIB survives a SIGHUP — the on_reconnect
                // path skips VPP because we're being called
                // *because* VPP died).
                let producer_deltas: Vec<ribd::rib::Delta> = {
                    let rib = state.rib.lock().await;
                    rib.installed_routes()
                        .into_iter()
                        .filter(|ir| {
                            !matches!(
                                ir.source,
                                ribd_proto::Source::Connected | ribd_proto::Source::Static
                            )
                        })
                        .map(|ir| ribd::rib::Delta {
                            table_id: ir.table_id,
                            prefix: ir.prefix,
                            new: Some(ir),
                        })
                        .collect()
                };
                if !producer_deltas.is_empty() {
                    state.apply_deltas(&producer_deltas).await;
                    tracing::info!(
                        producer_routes = producer_deltas.len(),
                        "SIGHUP: re-pushed producer routes through backends"
                    );
                }
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
    use vpp_api::generated::interface::{
        SwInterfaceDetails, SwInterfaceDump, SwInterfaceGetTable, SwInterfaceGetTableReply,
    };
    use vpp_api::generated::ip::{IpAddressDetails, IpAddressDump};

    // Helper: query the v4 or v6 FIB-id assigned to an interface.
    // Returns 0 (the default VRF) on error so a probe failure
    // doesn't drop the connected-route seed entirely — at worst
    // the route lands in the wrong table, which is the same
    // behaviour as before this enhancement.
    async fn interface_fib_id(
        vpp: &vpp_api::VppClient,
        sw_if_index: u32,
        is_ipv6: bool,
    ) -> u32 {
        match vpp
            .request::<SwInterfaceGetTable, SwInterfaceGetTableReply>(SwInterfaceGetTable {
                sw_if_index,
                is_ipv6,
            })
            .await
        {
            Ok(r) if r.retval == 0 => r.vrf_id,
            _ => 0,
        }
    }

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
        // Look up this interface's FIB-id once per AF. Defaults
        // to 0 (the default VRF) on error.
        let v4_table = interface_fib_id(vpp, vi.sw_if_index, false).await;
        let v6_table = interface_fib_id(vpp, vi.sw_if_index, true).await;

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
                table_id: v4_table,
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
                table_id: v6_table,
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

/// Build `Source::Connected` routes from the yaml `interfaces:`
/// section. Complementary to `seed_connected_routes` which dumps
/// VPP — yaml coverage is what lets ribd work on a cold start
/// before impd has programmed interface addresses in VPP.
///
/// Interfaces whose name doesn't resolve to a VPP sw_if_index are
/// silently skipped (logged at debug). That's expected on the
/// first tick after boot before impd's live apply runs; the SIGHUP
/// after `commit` picks them up.
async fn build_config_connected(
    vpp: &vpp_api::VppClient,
    cfg: &ribd_config::RouterConfig,
) -> Vec<ribd_proto::Route> {
    let mut out = Vec::new();
    for iface in &cfg.interfaces {
        let Some(idx) = resolve_iface_index(vpp, &iface.name).await else {
            tracing::debug!(
                iface = %iface.name,
                "config connected: sw_if_index lookup miss (interface not in VPP yet)",
            );
            continue;
        };
        for a in &iface.ipv4 {
            if let Some(r) = build_connected_v4(&a.address, a.prefix, idx) {
                out.push(r);
            }
        }
        for a in &iface.ipv6 {
            if let Some(r) = build_connected_v6(&a.address, a.prefix, idx) {
                out.push(r);
            }
        }
        for sub in &iface.subinterfaces {
            let sub_name = format!("{}.{}", iface.name, sub.vlan_id);
            let Some(sub_idx) = resolve_iface_index(vpp, &sub_name).await else {
                tracing::debug!(
                    iface = %sub_name,
                    "config connected: sub-if sw_if_index miss",
                );
                continue;
            };
            if let (Some(addr), Some(prefix)) = (&sub.ipv4, sub.ipv4_prefix) {
                if let Some(r) = build_connected_v4(addr, prefix, sub_idx) {
                    out.push(r);
                }
            }
            if let (Some(addr), Some(prefix)) = (&sub.ipv6, sub.ipv6_prefix) {
                if let Some(r) = build_connected_v6(addr, prefix, sub_idx) {
                    out.push(r);
                }
            }
        }
    }

    // Loopbacks: VPP names them loop<instance>. impd's render emits
    // `create loopback interface instance N` + `set interface ip
    // address loopN <addr>/<prefix>` in commands-core.txt.
    for lo in &cfg.loopbacks {
        let name = format!("loop{}", lo.instance);
        let Some(idx) = resolve_iface_index(vpp, &name).await else {
            tracing::debug!(
                iface = %name,
                "config connected: loopback sw_if_index miss",
            );
            continue;
        };
        if let (Some(addr), Some(prefix)) = (&lo.ipv4, lo.ipv4_prefix) {
            if let Some(r) = build_connected_v4(addr, prefix, idx) {
                out.push(r);
            }
        }
        if let (Some(addr), Some(prefix)) = (&lo.ipv6, lo.ipv6_prefix) {
            if let Some(r) = build_connected_v6(addr, prefix, idx) {
                out.push(r);
            }
        }
    }

    // BVIs: VPP names them bvi<bridge_id>. Same template pattern as
    // loopbacks (the BVI is a loopback member-of bridge-domain).
    // Without this, BGP redistribute-connected misses the LAN-side
    // prefix and the router stops announcing internal subnets.
    for bvi in &cfg.bvi_domains {
        let name = format!("bvi{}", bvi.bridge_id);
        let Some(idx) = resolve_iface_index(vpp, &name).await else {
            tracing::debug!(
                iface = %name,
                "config connected: bvi sw_if_index miss",
            );
            continue;
        };
        if let (Some(addr), Some(prefix)) = (&bvi.ipv4, bvi.ipv4_prefix) {
            if let Some(r) = build_connected_v4(addr, prefix, idx) {
                out.push(r);
            }
        }
        if let (Some(addr), Some(prefix)) = (&bvi.ipv6, bvi.ipv6_prefix) {
            if let Some(r) = build_connected_v6(addr, prefix, idx) {
                out.push(r);
            }
        }
    }

    // GRE tunnels: VPP names these by the user-chosen name from the
    // config. Each exposes a p2p /32 (or /128) on its tunnel address.
    for tun in &cfg.tunnels {
        let Some(idx) = resolve_iface_index(vpp, &tun.name).await else {
            tracing::debug!(
                iface = %tun.name,
                "config connected: tunnel sw_if_index miss",
            );
            continue;
        };
        if let (Some(addr), Some(prefix)) = (&tun.tunnel_ipv4, tun.tunnel_ipv4_prefix) {
            if let Some(r) = build_connected_v4(addr, prefix, idx) {
                out.push(r);
            }
        }
        if let (Some(addr), Some(prefix)) = (&tun.tunnel_ipv6, tun.tunnel_ipv6_prefix) {
            if let Some(r) = build_connected_v6(addr, prefix, idx) {
                out.push(r);
            }
        }
    }

    out
}

/// Build `Source::Static` routes from the yaml `routes:` section.
/// For each route, resolves the egress interface either from the
/// explicit `interface:` field or by matching `via` against the
/// configured interface subnets. The result is always a Direct
/// next-hop (sw_if_index known) so ribd doesn't need recursive
/// resolution for the common static-default case.
async fn build_config_static(
    vpp: &vpp_api::VppClient,
    cfg: &ribd_config::RouterConfig,
) -> Vec<ribd_proto::Route> {
    use ribd_proto::{Af, NextHop, NextHopKind, Prefix, Route, Source};

    let mut out = Vec::new();
    for r in &cfg.routes {
        let dest = match r.destination.parse::<ipnet::IpNet>() {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(
                    destination = %r.destination,
                    "static route skipped: invalid destination: {}",
                    e,
                );
                continue;
            }
        };

        let prefix = match dest {
            ipnet::IpNet::V4(n) => {
                let mut a = [0u8; 16];
                a[..4].copy_from_slice(&n.network().octets());
                Prefix {
                    af: Af::V4,
                    addr: a,
                    len: n.prefix_len(),
                }
            }
            ipnet::IpNet::V6(n) => Prefix {
                af: Af::V6,
                addr: n.network().octets(),
                len: n.prefix_len(),
            },
        };

        // Explicit `interface:` wins; otherwise match via against
        // configured interface subnets.
        let iface_name = match r.interface.clone() {
            Some(n) => Some(n),
            None if !r.via.is_empty() => {
                match r.via.parse::<std::net::IpAddr>() {
                    Ok(addr) => ribd_config::resolve_via_interface(addr, &cfg.interfaces),
                    Err(e) => {
                        tracing::warn!(
                            destination = %r.destination,
                            via = %r.via,
                            "static route skipped: invalid via: {}",
                            e,
                        );
                        continue;
                    }
                }
            }
            None => None,
        };

        let sw_if_index = match iface_name.as_deref() {
            Some(name) => match resolve_iface_index(vpp, name).await {
                Some(idx) => idx,
                None => {
                    tracing::debug!(
                        destination = %r.destination,
                        iface = name,
                        "static route deferred: sw_if_index miss",
                    );
                    continue;
                }
            },
            None => {
                tracing::warn!(
                    destination = %r.destination,
                    via = %r.via,
                    "static route skipped: no matching interface for via",
                );
                continue;
            }
        };

        let mut via_addr = [0u8; 16];
        if !r.via.is_empty() {
            match r.via.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(v4)) => via_addr[..4].copy_from_slice(&v4.octets()),
                Ok(std::net::IpAddr::V6(v6)) => via_addr = v6.octets(),
                Err(_) => {} // already validated above
            }
        }

        // Resolve the per-route VRF to a table-id. Empty / absent
        // / "default" → the implicit default VRF (table 0). A
        // named VRF must match a declared `vrfs:` entry; on miss
        // we drop the route with a warning rather than silently
        // landing it in table 0 (which is what created the
        // operator-visible default-VRF blackhole that motivated
        // this field in the first place).
        let table_id = match r.vrf.as_deref().filter(|s| !s.is_empty() && *s != "default") {
            None => 0,
            Some(name) => match cfg.vrfs.iter().find(|v| v.name == name) {
                Some(v) => match prefix.af {
                    Af::V4 => v.table_id_v4,
                    Af::V6 => v.table_id_v6,
                },
                None => {
                    tracing::warn!(
                        destination = %r.destination,
                        vrf = name,
                        "static route skipped: vrf not declared in vrfs:",
                    );
                    continue;
                }
            },
        };

        out.push(Route {
            prefix,
            source: Source::Static,
            next_hops: vec![NextHop {
                kind: NextHopKind::Direct,
                addr: via_addr,
                sw_if_index,
            }],
            metric: 0,
            tag: 0,
            admin_distance: None,
            table_id,
        });
    }
    out
}

fn build_connected_v4(address: &str, prefix: u8, sw_if_index: u32) -> Option<ribd_proto::Route> {
    let addr: std::net::Ipv4Addr = address.parse().ok()?;
    if prefix == 0 || prefix > 32 {
        return None;
    }
    let mut full = [0u8; 16];
    full[..4].copy_from_slice(&addr.octets());
    let masked = mask_v4(full, prefix);
    Some(ribd_proto::Route {
        prefix: ribd_proto::Prefix {
            af: ribd_proto::Af::V4,
            addr: masked,
            len: prefix,
        },
        source: ribd_proto::Source::Connected,
        next_hops: vec![ribd_proto::NextHop {
            kind: ribd_proto::NextHopKind::Direct,
            addr: [0u8; 16],
            sw_if_index,
        }],
        metric: 0,
        tag: 0,
        admin_distance: None,
        table_id: 0,
    })
}

fn build_connected_v6(address: &str, prefix: u8, sw_if_index: u32) -> Option<ribd_proto::Route> {
    let addr: std::net::Ipv6Addr = address.parse().ok()?;
    if prefix == 0 || prefix > 128 {
        return None;
    }
    let masked = mask_v6(addr.octets(), prefix);
    Some(ribd_proto::Route {
        prefix: ribd_proto::Prefix {
            af: ribd_proto::Af::V6,
            addr: masked,
            len: prefix,
        },
        source: ribd_proto::Source::Connected,
        next_hops: vec![ribd_proto::NextHop {
            kind: ribd_proto::NextHopKind::Direct,
            addr: [0u8; 16],
            sw_if_index,
        }],
        metric: 0,
        tag: 0,
        admin_distance: None,
        table_id: 0,
    })
}

/// Look up a VPP interface by name and return its sw_if_index.
async fn resolve_iface_index(vpp: &vpp_api::VppClient, name: &str) -> Option<u32> {
    use vpp_api::generated::interface::{SwInterfaceDetails, SwInterfaceDump};
    let all: Vec<SwInterfaceDetails> = vpp
        .dump::<SwInterfaceDump, SwInterfaceDetails>(SwInterfaceDump::default())
        .await
        .ok()?;
    // vpp-api exposes interface_name as a Rust String (trailing
    // NULs trimmed). Direct string compare.
    for d in all {
        if d.interface_name == name {
            return Some(d.sw_if_index);
        }
    }
    None
}

/// Apply a freshly-built Bulk of Connected + Static routes to the
/// running RIB. Uses the same replace-by-source semantics producer
/// sessions use: all prior Connected/Static entries not present in
/// the new set are removed.
///
/// Producer-pushed routes (bgpd, ospfd, dhcpd) are untouched since
/// they live under different Sources.
async fn reconcile_from_config(
    state: &SharedState,
    vpp_connected: Vec<ribd_proto::Route>,
    yaml_connected: Vec<ribd_proto::Route>,
    yaml_static: Vec<ribd_proto::Route>,
) {
    use ribd_proto::Source;

    let mut rib = state.rib.lock().await;

    // Replace Connected source with (VPP dump ∪ yaml-derived). VPP
    // dump comes first so yaml entries can layer in without
    // contradiction; upsert is idempotent per (prefix, source).
    let mut connected_deltas = rib.bulk_replace(Source::Connected, &{
        let mut all = vpp_connected;
        all.extend(yaml_connected);
        all
    });
    let static_deltas = rib.bulk_replace(Source::Static, &yaml_static);
    connected_deltas.extend(static_deltas);

    // Flush deltas through the backends the same way session.rs
    // does after a producer Bulk.
    drop(rib);
    let vpp = state.vpp.client().await;
    state.backend.apply(&vpp, &connected_deltas).await;
    drop(vpp);
    if let Some(kernel) = &state.kernel {
        kernel.apply(&connected_deltas).await;
    }

    // Bump the reconcile generation so impd's boot SIGHUP path can
    // observe that this reconcile finished and proceed to SIGHUP
    // bgpd/ospfd/dhcpd. See QueryRequest::ReadyState in ribd-proto.
    let gen = state.reconcile_generation.fetch_add(1, Ordering::SeqCst) + 1;
    tracing::info!(reconcile_generation = gen, "reconcile complete");
}
