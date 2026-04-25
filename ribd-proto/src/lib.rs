//! Wire protocol for the ribd daemon.
//!
//! Producers (ospfd, bgpd, dhcpd, or any other route source)
//! speak to ribd over a Unix socket at `/run/ribd.sock`.
//! Frames are length-prefixed: a 4-byte big-endian u32 length, then
//! a bincode-encoded [`ClientMsg`] or [`ServerMsg`] body.
//!
//! Crate contains ONLY serde types, framing helpers, and small pure
//! utilities. It does NOT pull in rtnetlink or vpp-api so that client
//! producers (ospfd) stay lean.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_VERSION: u32 = 1;
pub const DEFAULT_SOCKET_PATH: &str = "/run/ribd.sock";
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Af {
    V4,
    V6,
}

/// A network prefix. The address is stored in 16 bytes regardless of
/// address family; for V4 only the first 4 octets are meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Prefix {
    pub af: Af,
    pub addr: [u8; 16],
    pub len: u8,
}

impl Prefix {
    pub fn v4(addr: Ipv4Addr, len: u8) -> Self {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&addr.octets());
        Prefix { af: Af::V4, addr: a, len }
    }

    pub fn v6(addr: Ipv6Addr, len: u8) -> Self {
        Prefix { af: Af::V6, addr: addr.octets(), len }
    }

    pub fn as_v4(&self) -> Option<Ipv4Addr> {
        if self.af == Af::V4 {
            Some(Ipv4Addr::new(self.addr[0], self.addr[1], self.addr[2], self.addr[3]))
        } else {
            None
        }
    }

    pub fn as_v6(&self) -> Option<Ipv6Addr> {
        if self.af == Af::V6 {
            Some(Ipv6Addr::from(self.addr))
        } else {
            None
        }
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.af {
            Af::V4 => write!(
                f,
                "{}.{}.{}.{}/{}",
                self.addr[0], self.addr[1], self.addr[2], self.addr[3], self.len
            ),
            Af::V6 => write!(f, "{}/{}", Ipv6Addr::from(self.addr), self.len),
        }
    }
}

/// Whether a next-hop is fully resolved (Direct) or needs to be
/// looked up against the RIB before programming (Recursive).
///
/// Producers like ospfd that already know the egress interface
/// send `Direct`. Producers like bgpd that learn next-hops as
/// IP addresses (which themselves resolve through the IGP) send
/// `Recursive` and let ribd do the resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NextHopKind {
    Direct,
    Recursive,
}

/// A single next-hop for a route. For `Direct` next-hops, `addr` is
/// the L3 next-hop and `sw_if_index` is the outgoing VPP interface;
/// for directly-connected / glean paths the `addr` is the zero
/// address and `sw_if_index` alone selects the interface. For
/// `Recursive` next-hops `addr` is the IP to resolve and
/// `sw_if_index` is unset (zero); ribd populates it during
/// resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NextHop {
    pub kind: NextHopKind,
    pub addr: [u8; 16],
    pub sw_if_index: u32,
}

impl NextHop {
    pub fn v4(addr: Ipv4Addr, sw_if_index: u32) -> Self {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&addr.octets());
        NextHop { kind: NextHopKind::Direct, addr: a, sw_if_index }
    }

    pub fn v6(addr: Ipv6Addr, sw_if_index: u32) -> Self {
        NextHop { kind: NextHopKind::Direct, addr: addr.octets(), sw_if_index }
    }

    /// Construct a recursive IPv4 next-hop. The address is the BGP
    /// (or other producer-learned) next-hop that ribd will LPM
    /// against its installed RIB.
    pub fn recursive_v4(addr: Ipv4Addr) -> Self {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&addr.octets());
        NextHop { kind: NextHopKind::Recursive, addr: a, sw_if_index: 0 }
    }

    pub fn recursive_v6(addr: Ipv6Addr) -> Self {
        NextHop {
            kind: NextHopKind::Recursive,
            addr: addr.octets(),
            sw_if_index: 0,
        }
    }

    pub fn is_recursive(&self) -> bool {
        matches!(self.kind, NextHopKind::Recursive)
    }
}

/// Route source. Drives admin-distance arbitration in ribd.
///
/// Sub-types for OSPF (Intra/Inter/Ext1/Ext2) exist so that if the
/// operator later wants to tune AD per sub-type they can, even
/// though at creation time they all collapse to the same default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Source {
    Connected,
    Static,
    OspfIntra,
    OspfInter,
    OspfExt1,
    OspfExt2,
    Ospf6Intra,
    Ospf6Inter,
    Ospf6Ext1,
    Ospf6Ext2,
    Bgp,         // eBGP
    BgpInternal, // iBGP
    /// DHCPv6 Prefix Delegation (dhcpd direct-path install).
    /// Relayed delegations don't reach ribd — the relay owns
    /// the route.
    DhcpPd,
}

impl Source {
    /// Industry-standard admin distance defaults. Matches the
    /// Cisco/FRR conventions (eBGP 20, OSPF 110, iBGP 200).
    pub fn default_admin_distance(self) -> u8 {
        match self {
            Source::Connected => 0,
            Source::Static => 1,
            // DHCP-PD routes sit just above Static because they
            // are functionally static (lease-bound) but explicitly
            // tagged so operators can filter them.
            Source::DhcpPd => 2,
            Source::Bgp => 20,
            Source::OspfIntra
            | Source::OspfInter
            | Source::OspfExt1
            | Source::OspfExt2
            | Source::Ospf6Intra
            | Source::Ospf6Inter
            | Source::Ospf6Ext1
            | Source::Ospf6Ext2 => 110,
            Source::BgpInternal => 200,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Source::Connected => "connected",
            Source::Static => "static",
            Source::DhcpPd => "dhcp-pd",
            Source::OspfIntra => "ospf-intra",
            Source::OspfInter => "ospf-inter",
            Source::OspfExt1 => "ospf-ext1",
            Source::OspfExt2 => "ospf-ext2",
            Source::Ospf6Intra => "ospf6-intra",
            Source::Ospf6Inter => "ospf6-inter",
            Source::Ospf6Ext1 => "ospf6-ext1",
            Source::Ospf6Ext2 => "ospf6-ext2",
            Source::Bgp => "bgp",
            Source::BgpInternal => "bgp-internal",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub prefix: Prefix,
    pub source: Source,
    pub next_hops: Vec<NextHop>,
    /// Protocol metric (e.g. OSPF cost, BGP MED). Used as tie-breaker
    /// between two candidates from the same source.
    pub metric: u32,
    /// Optional tag (carried through; exposed by queries).
    pub tag: u32,
    /// Optional per-route admin-distance override. `None` means use
    /// the source's default AD. Producers can set this explicitly
    /// to hoist a route above its peers.
    pub admin_distance: Option<u8>,
}

impl Route {
    pub fn effective_admin_distance(&self) -> u8 {
        self.admin_distance
            .unwrap_or_else(|| self.source.default_admin_distance())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Add,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryRequest {
    /// All currently-installed routes (after AD arbitration).
    InstalledRoutes,
    /// All candidates, grouped by prefix. Includes losing candidates
    /// so operators can see why a route was (or wasn't) chosen.
    AllCandidates,
    /// Lightweight readiness probe. Returns a counter that increments
    /// after every successful reconcile_from_config (initial seed +
    /// each SIGHUP). Clients sequencing against ribd's reconcile use
    /// it to wait until a fresh reconcile has actually completed,
    /// rather than racing the kernel-level "socket appeared" signal.
    ReadyState,
}

/// Provenance for a route that was installed via recursive
/// next-hop resolution. The actual programmed next-hops live in
/// `InstalledRoute.next_hops` (Direct, possibly ECMP); this struct
/// records *what the producer asked for* and *which RIB entry
/// satisfied the resolution*, so operators can see why a
/// BGP-learned prefix landed on the interface it did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedNextHop {
    /// The producer-supplied recursive next-hop IP (the BGP
    /// next-hop attribute, typically). 16-byte form, zero-padded
    /// for V4.
    pub recursive_addr: [u8; 16],
    /// The RIB entry whose longest-prefix match satisfied the
    /// resolution.
    pub through_prefix: Prefix,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledRoute {
    pub prefix: Prefix,
    pub source: Source,
    pub admin_distance: u8,
    pub metric: u32,
    /// Fully-resolved (Direct) next-hops as programmed to the FIB.
    /// For routes whose producer sent Recursive next-hops, these are
    /// the resolution outputs; the original producer-supplied
    /// next-hops are reported in `recursive_via`.
    pub next_hops: Vec<NextHop>,
    /// For routes installed with a Recursive next-hop, the original
    /// producer-supplied next-hop IP plus the RIB entry it resolved
    /// through. `None` for non-recursive routes.
    pub resolved_via: Option<ResolvedNextHop>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub source: Source,
    pub admin_distance: u8,
    pub metric: u32,
    pub next_hops: Vec<NextHop>,
    /// True if this candidate is the one currently programmed.
    pub installed: bool,
    /// True if this candidate has a Recursive next-hop that ribd
    /// could not resolve (no covering RIB entry). Held candidates
    /// are retained but not programmed; they become installable when
    /// the underlying IGP route arrives.
    pub held: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixCandidates {
    pub prefix: Prefix,
    pub candidates: Vec<Candidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryReply {
    InstalledRoutes(Vec<InstalledRoute>),
    AllCandidates(Vec<PrefixCandidates>),
    /// Reply to `QueryRequest::ReadyState`. `reconcile_generation`
    /// starts at 0 before the initial reconcile completes, becomes 1
    /// after the first reconcile, and increments by 1 on every
    /// subsequent reconcile (e.g. each SIGHUP). Clients capture the
    /// value before signalling and poll until they observe a higher
    /// value to know their signal has been processed.
    ReadyState { reconcile_generation: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientMsg {
    Hello {
        client_name: String,
        protocol_version: u32,
    },
    /// Bulk replace: delete any existing route from `source` not in
    /// `routes`, install the rest. Used on reconnect, after full SPF,
    /// or at producer startup. Bounded by MAX_FRAME_LEN (16 MB) — for
    /// large producers like bgpd carrying a full DFZ table use
    /// the chunked variant below.
    Bulk {
        source: Source,
        routes: Vec<Route>,
    },
    /// Begin a chunked bulk. The producer follows with one or more
    /// `BulkChunk` frames sharing the same `generation`, then exactly
    /// one `BulkEnd` to atomically swap the source's route set.
    /// `generation` is producer-chosen and lets the server reject
    /// interleaved or abandoned bulks unambiguously.
    BulkBegin {
        source: Source,
        generation: u64,
    },
    /// One chunk of a chunked bulk. Order of chunks within a
    /// generation does not matter; the server accumulates until
    /// `BulkEnd`.
    BulkChunk {
        generation: u64,
        routes: Vec<Route>,
    },
    /// Commit a chunked bulk. The server atomically replaces the
    /// source's route set with the union of all `BulkChunk` payloads
    /// for `generation`, then discards the staging buffer. Replies
    /// `Ok` on success or `Error` if the generation is unknown.
    BulkEnd {
        source: Source,
        generation: u64,
    },
    Update {
        action: Action,
        route: Route,
    },
    Query(QueryRequest),
    Heartbeat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerMsg {
    HelloAck { server_version: u32 },
    Ok,
    Error { message: String },
    QueryReply(QueryReply),
}

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame too large: {0} bytes (max {})", MAX_FRAME_LEN)]
    FrameTooLarge(usize),
    #[error("bincode: {0}")]
    Bincode(#[from] bincode::Error),
    #[error("peer closed connection")]
    Closed,
}

/// Encode a message as a length-prefixed frame. The returned bytes
/// are ready to write to a socket in one shot.
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, CodecError> {
    let payload = bincode::serialize(msg)?;
    if payload.len() > MAX_FRAME_LEN {
        return Err(CodecError::FrameTooLarge(payload.len()));
    }
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// Decode a single message body (the `payload` portion, not the
/// length prefix). The reader side is expected to have already
/// consumed the 4-byte length and slurped `payload_len` bytes.
pub fn decode<'a, T: Deserialize<'a>>(payload: &'a [u8]) -> Result<T, CodecError> {
    Ok(bincode::deserialize(payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_client_bulk() {
        let msg = ClientMsg::Bulk {
            source: Source::OspfIntra,
            routes: vec![Route {
                prefix: Prefix::v4(Ipv4Addr::new(10, 0, 0, 0), 24),
                source: Source::OspfIntra,
                next_hops: vec![NextHop::v4(Ipv4Addr::new(172, 30, 0, 1), 1)],
                metric: 10,
                tag: 0,
                admin_distance: None,
            }],
        };
        let frame = encode(&msg).unwrap();
        assert!(frame.len() > 4);
        let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        assert_eq!(len as usize, frame.len() - 4);
        let decoded: ClientMsg = decode(&frame[4..]).unwrap();
        match decoded {
            ClientMsg::Bulk { source, routes } => {
                assert_eq!(source, Source::OspfIntra);
                assert_eq!(routes.len(), 1);
                assert_eq!(routes[0].metric, 10);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_server_query_reply() {
        let msg = ServerMsg::QueryReply(QueryReply::InstalledRoutes(vec![InstalledRoute {
            prefix: Prefix::v6("2001:db8::".parse().unwrap(), 64),
            source: Source::Ospf6Intra,
            admin_distance: 110,
            metric: 10,
            next_hops: vec![NextHop::v6("fe80::1".parse().unwrap(), 1)],
            resolved_via: None,
        }]));
        let frame = encode(&msg).unwrap();
        let decoded: ServerMsg = decode(&frame[4..]).unwrap();
        match decoded {
            ServerMsg::QueryReply(QueryReply::InstalledRoutes(rs)) => {
                assert_eq!(rs.len(), 1);
                assert_eq!(rs[0].admin_distance, 110);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_recursive_nexthop() {
        let nh = NextHop::recursive_v4(Ipv4Addr::new(10, 0, 0, 5));
        assert!(nh.is_recursive());
        assert_eq!(nh.kind, NextHopKind::Recursive);
        assert_eq!(&nh.addr[..4], &[10, 0, 0, 5]);
        assert_eq!(nh.sw_if_index, 0);

        let direct = NextHop::v4(Ipv4Addr::new(10, 0, 0, 1), 7);
        assert!(!direct.is_recursive());

        // Bincode roundtrip preserves variant.
        let bytes = bincode::serialize(&nh).unwrap();
        let back: NextHop = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back, nh);
    }

    #[test]
    fn roundtrip_chunked_bulk_messages() {
        let begin = ClientMsg::BulkBegin {
            source: Source::Bgp,
            generation: 42,
        };
        let chunk = ClientMsg::BulkChunk {
            generation: 42,
            routes: vec![Route {
                prefix: Prefix::v4(Ipv4Addr::new(192, 0, 2, 0), 24),
                source: Source::Bgp,
                next_hops: vec![NextHop::recursive_v4(Ipv4Addr::new(10, 0, 0, 5))],
                metric: 0,
                tag: 0,
                admin_distance: None,
            }],
        };
        let end = ClientMsg::BulkEnd {
            source: Source::Bgp,
            generation: 42,
        };

        for msg in [&begin, &chunk, &end] {
            let frame = encode(msg).unwrap();
            let _: ClientMsg = decode(&frame[4..]).unwrap();
        }

        // Resolved-via roundtrip via InstalledRoute.
        let installed = InstalledRoute {
            prefix: Prefix::v4(Ipv4Addr::new(192, 0, 2, 0), 24),
            source: Source::Bgp,
            admin_distance: 20,
            metric: 0,
            next_hops: vec![NextHop::v4(Ipv4Addr::new(172, 16, 0, 1), 3)],
            resolved_via: Some(ResolvedNextHop {
                recursive_addr: {
                    let mut a = [0u8; 16];
                    a[..4].copy_from_slice(&[10, 0, 0, 5]);
                    a
                },
                through_prefix: Prefix::v4(Ipv4Addr::new(10, 0, 0, 0), 24),
            }),
        };
        let bytes = bincode::serialize(&installed).unwrap();
        let back: InstalledRoute = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back, installed);
        assert!(back.resolved_via.is_some());
    }

    #[test]
    fn admin_distance_defaults() {
        assert_eq!(Source::Connected.default_admin_distance(), 0);
        assert_eq!(Source::Static.default_admin_distance(), 1);
        assert_eq!(Source::Bgp.default_admin_distance(), 20);
        assert_eq!(Source::OspfIntra.default_admin_distance(), 110);
        assert_eq!(Source::Ospf6Inter.default_admin_distance(), 110);
        assert_eq!(Source::BgpInternal.default_admin_distance(), 200);
    }

    #[test]
    fn route_override_ad_wins() {
        let r = Route {
            prefix: Prefix::v4(Ipv4Addr::new(10, 0, 0, 0), 8),
            source: Source::Bgp,
            next_hops: vec![],
            metric: 0,
            tag: 0,
            admin_distance: Some(5),
        };
        assert_eq!(r.effective_admin_distance(), 5);
    }
}
