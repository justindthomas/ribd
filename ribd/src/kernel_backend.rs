//! Kernel netlink backend.
//!
//! Programs routes into the Linux kernel routing table via rtnetlink.
//! ribd runs in the dataplane network namespace (via its systemd
//! unit's `NetworkNamespacePath=`), so the netlink socket we open
//! here naturally targets the dataplane namespace's route table.
//!
//! Why bother when VPP already has the FIB? Because iBGP next-hop
//! resolution and diagnostic tooling (ip route, traceroute from the
//! dataplane namespace) read from the kernel FIB. Keeping both in
//! sync avoids surprises.
//!
//! Interface index translation: producers speak in VPP
//! `sw_if_index`, which is NOT the Linux kernel ifindex. We
//! maintain a cached mapping `sw_if_index -> kernel_ifindex` built
//! at startup by dumping VPP's interface list and looking up each
//! name under `/sys/class/net/<name>/ifindex`. linux_cp creates TAP
//! interfaces with the same name as the VPP interface, so this
//! lookup is reliable.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use ribd_proto::{Af, NextHop, Prefix, Source};
use netlink_packet_route::route::RouteProtocol;
use tokio::sync::Mutex;

use crate::rib::Delta;

// kernel_backend processes deltas sequentially. See the doc
// comment on `KernelBackend::apply_one` for why concurrent
// rtnetlink dumps race and why the pipelined version was reverted.
// vpp_backend remains pipelined — its client-side context-ID
// muxing handles concurrent requests cleanly.

/// Map an ribd `Source` to the kernel's `proto` field. This is
/// what `ip route show` displays after the `proto` token. Setting it
/// correctly lets operators tell at a glance which daemon installed
/// each route, and lets `ip route show proto ospf` filter cleanly.
fn kernel_protocol_for(source: Source) -> RouteProtocol {
    match source {
        Source::OspfIntra
        | Source::OspfInter
        | Source::OspfExt1
        | Source::OspfExt2
        | Source::Ospf6Intra
        | Source::Ospf6Inter
        | Source::Ospf6Ext1
        | Source::Ospf6Ext2 => RouteProtocol::Ospf,
        Source::Bgp | Source::BgpInternal => RouteProtocol::Bgp,
        Source::Static => RouteProtocol::Static,
        // `ip route show proto dhcp` filters cleanly to PD-installed
        // customer routes.
        Source::DhcpPd => RouteProtocol::Dhcp,
        // "Connected" routes shouldn't normally hit ribd at all
        // (the kernel auto-creates them from `ip addr add`), but if
        // we ever push one programmatically, label it as such.
        Source::Connected => RouteProtocol::Kernel,
    }
}

/// Maps VPP `sw_if_index` → Linux kernel ifindex. Built from VPP's
/// interface dump + /sys/class/net lookups.
#[derive(Debug, Default)]
pub struct IfIndexMap {
    map: HashMap<u32, u32>,
}

impl IfIndexMap {
    pub fn new() -> Self {
        IfIndexMap::default()
    }

    /// Rebuild from VPP. Safe to call periodically if interfaces
    /// are being created/destroyed at runtime.
    pub async fn refresh(&mut self, vpp: &vpp_api::VppClient) {
        use vpp_api::generated::interface::{SwInterfaceDetails, SwInterfaceDump};
        let details: Vec<SwInterfaceDetails> = match vpp
            .dump::<SwInterfaceDump, SwInterfaceDetails>(SwInterfaceDump::default())
            .await
        {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("VPP sw_interface_dump failed: {}", e);
                return;
            }
        };
        self.map.clear();
        for d in details {
            let name = d.interface_name.trim_end_matches('\0');
            if name.is_empty() {
                continue;
            }
            let path = format!("/sys/class/net/{}/ifindex", name);
            match std::fs::read_to_string(&path) {
                Ok(s) => {
                    if let Ok(idx) = s.trim().parse::<u32>() {
                        self.map.insert(d.sw_if_index, idx);
                    }
                }
                Err(_) => {
                    // Normal for interfaces without an LCP TAP
                    // (memif, tunnels, etc.). Silent skip.
                }
            }
        }
        tracing::info!(count = self.map.len(), "refreshed sw_if_index → kernel ifindex map");
    }

    pub fn get(&self, sw_if_index: u32) -> Option<u32> {
        self.map.get(&sw_if_index).copied()
    }

    /// Test hook — insert a (sw_if_index, kernel_ifindex) pair
    /// without going through VPP. Used by the live netlink test.
    #[doc(hidden)]
    pub fn insert_for_test(&mut self, sw_if_index: u32, kernel_ifindex: u32) {
        self.map.insert(sw_if_index, kernel_ifindex);
    }
}

/// Netlink handle + ifindex map. One per daemon process.
pub struct KernelBackend {
    handle: rtnetlink::Handle,
    ifindex_map: Arc<Mutex<IfIndexMap>>,
    /// Kept alive for the connection task's lifetime.
    _conn_task: tokio::task::JoinHandle<()>,
}

impl KernelBackend {
    /// Open a netlink handle and spawn the background connection
    /// task. Must be called from inside a tokio runtime.
    pub fn new(ifindex_map: Arc<Mutex<IfIndexMap>>) -> std::io::Result<Self> {
        let (connection, handle, _messages) = rtnetlink::new_connection()?;
        let conn_task = tokio::spawn(async move {
            connection.await;
        });
        Ok(KernelBackend {
            handle,
            ifindex_map,
            _conn_task: conn_task,
        })
    }

    /// Remove every kernel route whose `proto` field matches one of
    /// the protocols ribd is responsible for installing (today:
    /// `Ospf` and `Bgp`). Intended to run once at startup, before
    /// the listener accepts any client connections, so any leftover
    /// routes from a previous (possibly buggy) ribd or routing
    /// daemon get scrubbed before fresh state arrives.
    ///
    /// Why we need this: when ribd restarts, its in-memory rib
    /// is empty. Bulk pushes from reconnecting daemons get diffed
    /// against an empty rib so every prefix in the bulk is "new" and
    /// gets installed. But anything that *was* in the kernel and
    /// *isn't* in the new bulk (the bug-of-the-day "self-route" on
    /// jt-router being the canonical example) sits there forever as
    /// an orphan, never touched by anyone.
    ///
    /// Trade-off: this does cause a brief window — between purge
    /// and the first daemon's bulk re-push — where learned routes
    /// are absent from the kernel FIB. In practice the daemon
    /// reconnects within ~1 second so the window is well under a
    /// second. Acceptable on a restart, and far better than
    /// silently keeping a wrong route.
    pub async fn purge_orphans(&self) {
        use futures::TryStreamExt;
        use netlink_packet_route::route::{RouteHeader, RouteMessage, RouteProtocol};

        let mut total_removed = 0usize;
        for af in [Af::V4, Af::V6] {
            let ip_version = match af {
                Af::V4 => rtnetlink::IpVersion::V4,
                Af::V6 => rtnetlink::IpVersion::V6,
            };
            let mut stream = self.handle.route().get(ip_version).execute();
            let mut to_delete: Vec<RouteMessage> = Vec::new();
            loop {
                match stream.try_next().await {
                    Ok(Some(msg)) => {
                        // Only purge routes from the main table — leave
                        // local / link-scope / cache tables alone.
                        if msg.header.table != RouteHeader::RT_TABLE_MAIN {
                            continue;
                        }
                        // Match ribd-installable protos. We don't
                        // touch Static/Kernel/Boot/Ra etc. — those are
                        // managed by the user or the kernel itself.
                        if matches!(
                            msg.header.protocol,
                            RouteProtocol::Ospf | RouteProtocol::Bgp
                        ) {
                            to_delete.push(msg);
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        tracing::warn!(?af, "kernel route dump failed: {}", e);
                        break;
                    }
                }
            }
            for msg in to_delete {
                let proto = msg.header.protocol;
                let prefix_len = msg.header.destination_prefix_length;
                if let Err(e) = self.handle.route().del(msg).execute().await {
                    tracing::debug!(?af, ?proto, prefix_len, "orphan delete failed: {}", e);
                } else {
                    total_removed += 1;
                }
            }
        }
        if total_removed > 0 {
            tracing::info!(
                count = total_removed,
                "purged stale ospf/bgp routes from kernel on startup"
            );
        }
    }

    pub async fn apply(&self, deltas: &[Delta]) {
        // Snapshot the ifindex map once so we don't re-lock per
        // delta. The map is a short-lived clone; refresh() races
        // are tolerable because the worst case is dropping a path
        // on a route that's about to be re-pushed.
        let snapshot: HashMap<u32, u32> = {
            let map = self.ifindex_map.lock().await;
            map.map.clone()
        };

        // Sequential processing — see the doc comment on this
        // function below for why kernel_backend doesn't pipeline
        // the way vpp_backend does.
        for d in deltas {
            self.apply_one(d, &snapshot).await;
        }
    }

    /// Apply a single delta. Split out so [`apply`] reads as a
    /// straight sequential loop and so the per-delta logic can be
    /// unit-tested in isolation later.
    ///
    /// ## Why not pipeline like vpp_backend
    ///
    /// The first cut of this backend used
    /// `for_each_concurrent(KERNEL_PIPELINE_DEPTH, ...)` to mirror
    /// `vpp_backend::apply`. It races: when the cascade reinstalls
    /// many overlapping prefixes from a different source (e.g.
    /// the OSPF→iBGP cutover on jt-router 2026-04-15), concurrent
    /// `delete()` calls each issue a netlink dump on the shared
    /// rtnetlink Handle. The dump-response demuxer doesn't always
    /// route the right reply to the right caller under load, and
    /// some delete tasks complete with an empty match list while
    /// the actual route is still in the kernel. The follow-up
    /// `add()` then trips `EEXIST` and the route stays tagged with
    /// the OLD source's `proto` field. Forwarding remains correct
    /// (the gateway hasn't changed) but the kernel state diverges
    /// from ribd's intent.
    ///
    /// vpp_backend doesn't have this problem because the vpp-api
    /// client correlates replies to requests via per-message
    /// context IDs that the user code never sees. rtnetlink uses
    /// per-stream sequence numbers but the multi-part dump frames
    /// are routed by socket position, not by request ID, which
    /// breaks under concurrent dumps on one Handle.
    ///
    /// Sequential here is fine for v1 scale: jt-router has ~14
    /// routes and the per-route cost is a few ms; even a 1k-route
    /// cascade finishes in ~1 second. A future optimization could
    /// drop the per-delta dump entirely by either issuing a single
    /// batched dump at apply() entry or by switching to
    /// rtnetlink's del-by-message-shape (no dump required). Both
    /// belong in a separate change once we have benchmarks.
    async fn apply_one(&self, d: &Delta, snapshot: &HashMap<u32, u32>) {
        match &d.new {
            None => match self.delete(d.prefix).await {
                Err(e) => {
                    // Route-not-found is fine on withdraw (we may
                    // have never installed it, e.g. a losing
                    // candidate we cleared).
                    tracing::debug!(prefix = %d.prefix, "kernel delete: {}", e);
                }
                Ok(()) => {
                    tracing::info!(prefix = %d.prefix, "kernel withdrew route");
                }
            },
            Some(r) => {
                let mut resolved: Vec<(&NextHop, u32)> = Vec::with_capacity(r.next_hops.len());
                for nh in &r.next_hops {
                    match snapshot.get(&nh.sw_if_index) {
                        Some(kidx) => resolved.push((nh, *kidx)),
                        None => {
                            tracing::debug!(
                                prefix = %d.prefix,
                                sw_if_index = nh.sw_if_index,
                                "no kernel ifindex mapping; dropping this path"
                            );
                        }
                    }
                }
                if resolved.is_empty() {
                    tracing::debug!(
                        prefix = %d.prefix,
                        "no resolvable next-hops for kernel install"
                    );
                    return;
                }
                // Replace semantics: delete any existing entry
                // first, then add. rtnetlink add will fail if an
                // entry already exists.
                let _ = self.delete(d.prefix).await;
                let proto = kernel_protocol_for(r.source);
                if let Err(e) = self.add(d.prefix, &resolved, proto).await {
                    tracing::warn!(
                        prefix = %d.prefix,
                        source = r.source.as_str(),
                        "kernel add failed: {}", e
                    );
                } else {
                    tracing::info!(
                        prefix = %d.prefix,
                        source = r.source.as_str(),
                        paths = resolved.len(),
                        "kernel installed route"
                    );
                }
            }
        }
    }

    async fn add(
        &self,
        prefix: Prefix,
        paths: &[(&NextHop, u32)],
        proto: RouteProtocol,
    ) -> Result<(), rtnetlink::Error> {
        // Single-path: use the high-level RouteAddRequest builder —
        // simpler and clearer for the common case.
        if paths.len() == 1 {
            let (nh, kidx) = paths[0];
            return match prefix.af {
                Af::V4 => {
                    let mut v4 = [0u8; 4];
                    v4.copy_from_slice(&prefix.addr[..4]);
                    let dest = Ipv4Addr::from(v4);
                    let mut nh_v4 = [0u8; 4];
                    nh_v4.copy_from_slice(&nh.addr[..4]);
                    let gw = Ipv4Addr::from(nh_v4);
                    self.handle
                        .route()
                        .add()
                        .v4()
                        .destination_prefix(dest, prefix.len)
                        .output_interface(kidx)
                        .gateway(gw)
                        .protocol(proto)
                        .execute()
                        .await
                }
                Af::V6 => {
                    let dest = Ipv6Addr::from(prefix.addr);
                    let gw = Ipv6Addr::from(nh.addr);
                    self.handle
                        .route()
                        .add()
                        .v6()
                        .destination_prefix(dest, prefix.len)
                        .output_interface(kidx)
                        .gateway(gw)
                        .protocol(proto)
                        .execute()
                        .await
                }
            };
        }

        // Multipath (ECMP): rtnetlink 0.14's builder doesn't expose
        // a `multipath` method, so we construct the base request for
        // address/AF and then reach into the underlying RouteMessage
        // to push a RouteAttribute::MultiPath with all next-hops.
        //
        // Each RouteNextHop carries its own interface_index and a
        // Gateway attribute; the top-level Gateway/Oif MUST NOT be
        // set or the kernel rejects the request.
        use netlink_packet_route::route::{
            RouteAddress, RouteAttribute, RouteNextHop,
        };
        match prefix.af {
            Af::V4 => {
                let mut v4 = [0u8; 4];
                v4.copy_from_slice(&prefix.addr[..4]);
                let dest = Ipv4Addr::from(v4);
                let mut req = self
                    .handle
                    .route()
                    .add()
                    .v4()
                    .destination_prefix(dest, prefix.len);
                let mut hops = Vec::with_capacity(paths.len());
                for (nh, kidx) in paths {
                    let mut nh_v4 = [0u8; 4];
                    nh_v4.copy_from_slice(&nh.addr[..4]);
                    let gw = Ipv4Addr::from(nh_v4);
                    let mut hop = RouteNextHop::default();
                    hop.interface_index = *kidx;
                    hop.attributes = vec![RouteAttribute::Gateway(
                        RouteAddress::Inet(gw),
                    )];
                    hops.push(hop);
                }
                req.message_mut().header.protocol = proto;
                req.message_mut()
                    .attributes
                    .push(RouteAttribute::MultiPath(hops));
                req.execute().await
            }
            Af::V6 => {
                let dest = Ipv6Addr::from(prefix.addr);
                let mut req = self
                    .handle
                    .route()
                    .add()
                    .v6()
                    .destination_prefix(dest, prefix.len);
                let mut hops = Vec::with_capacity(paths.len());
                for (nh, kidx) in paths {
                    let gw = Ipv6Addr::from(nh.addr);
                    let mut hop = RouteNextHop::default();
                    hop.interface_index = *kidx;
                    hop.attributes = vec![RouteAttribute::Gateway(
                        RouteAddress::Inet6(gw),
                    )];
                    hops.push(hop);
                }
                req.message_mut().header.protocol = proto;
                req.message_mut()
                    .attributes
                    .push(RouteAttribute::MultiPath(hops));
                req.execute().await
            }
        }
    }

    async fn delete(&self, prefix: Prefix) -> Result<(), rtnetlink::Error> {
        use futures::TryStreamExt;
        use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};

        // Find and delete matching routes. We search by destination
        // prefix only — any RT table that matches, we drop.
        let mut stream = match prefix.af {
            Af::V4 => self
                .handle
                .route()
                .get(rtnetlink::IpVersion::V4)
                .execute(),
            Af::V6 => self
                .handle
                .route()
                .get(rtnetlink::IpVersion::V6)
                .execute(),
        };
        let mut to_delete: Vec<RouteMessage> = Vec::new();
        while let Some(msg) = stream.try_next().await? {
            if msg.header.destination_prefix_length != prefix.len {
                continue;
            }
            // Special case: the default route (prefix length 0) has
            // no Destination attribute on the wire — the kernel just
            // omits it. Match it on prefix length alone. Without
            // this, delete(0.0.0.0/0) was a no-op and the subsequent
            // add() failed with EEXIST, leaving stale `proto static`
            // entries (jt-router, 2026-04-14).
            let matches = if prefix.len == 0 {
                true
            } else {
                msg.attributes.iter().any(|attr| {
                    if let RouteAttribute::Destination(addr) = attr {
                        match (prefix.af, addr) {
                            (Af::V4, RouteAddress::Inet(a)) => a.octets() == prefix.addr[..4],
                            (Af::V6, RouteAddress::Inet6(a)) => a.octets() == prefix.addr,
                            _ => false,
                        }
                    } else {
                        false
                    }
                })
            };
            if matches {
                to_delete.push(msg);
            }
        }

        for msg in to_delete {
            self.handle.route().del(msg).execute().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifindex_map_get_missing() {
        let m = IfIndexMap::new();
        assert_eq!(m.get(42), None);
    }

    #[test]
    fn ifindex_map_manual_insert() {
        let mut m = IfIndexMap::new();
        m.map.insert(1, 42);
        assert_eq!(m.get(1), Some(42));
        assert_eq!(m.get(2), None);
    }
}
