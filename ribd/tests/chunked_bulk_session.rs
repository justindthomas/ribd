//! End-to-end integration test for chunked bulk + recursive
//! next-hops over the Unix-socket session protocol.
//!
//! Like `session_integration.rs`, this stands up a fake server that
//! mirrors the message handling in `src/session.rs` (without the VPP
//! backend dependency) and drives it through the real
//! `ribd-client`. The goal is to catch wire-protocol regressions
//! and verify the chunked-bulk staging buffer behaves the way the
//! real `session.rs` does:
//!
//! - `push_bulk_chunked` sends BulkBegin → N×BulkChunk → BulkEnd and
//!   the server installs exactly the union of all chunks atomically
//!   on End.
//! - Recursive next-hops sent via the wire reach the Rib's tracker
//!   and are resolved on install.
//! - Dropping the connection mid-bulk (after BulkBegin but before
//!   BulkEnd) discards the staging buffer; subsequent reconnects
//!   start clean and old in-flight routes do not leak in.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use ribd_client::RibConnection;
use ribd_proto::{
    decode, encode, ClientMsg, NextHop, Prefix, QueryReply, QueryRequest, Route, ServerMsg, Source,
    PROTOCOL_VERSION,
};
use ribd::rib::Rib;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::Mutex;

/// Spawn a fake server that handles the full session protocol —
/// Hello, single-frame Bulk, Update, Query, and the new chunked
/// bulk variants — against a shared [`Rib`]. Returns the socket
/// path; the caller should keep the [`tempfile::TempDir`] alive.
fn spawn_fake_server(rib: Arc<Mutex<Rib>>) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("ribd.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let rib = rib.clone();
            tokio::spawn(handle_one_session(stream, rib));
        }
    });

    (dir, sock_path)
}

/// Per-connection state buffer for in-flight chunked bulks. Mirrors
/// the same map in `src/session.rs::handle_session`.
struct Staging {
    source: Source,
    routes: Vec<Route>,
}

async fn handle_one_session(stream: tokio::net::UnixStream, rib: Arc<Mutex<Rib>>) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);
    let mut staging: HashMap<u64, Staging> = HashMap::new();

    loop {
        let mut len_buf = [0u8; 4];
        if reader.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        if reader.read_exact(&mut buf).await.is_err() {
            break;
        }
        let msg: ClientMsg = decode(&buf).unwrap();

        let reply = match msg {
            ClientMsg::Hello { .. } => ServerMsg::HelloAck {
                server_version: PROTOCOL_VERSION,
            },
            ClientMsg::Bulk { source, routes } => {
                let mut g = rib.lock().await;
                g.bulk_replace(source, &routes);
                ServerMsg::Ok
            }
            ClientMsg::BulkBegin { source, generation } => {
                if staging.contains_key(&generation) {
                    ServerMsg::Error {
                        message: format!("generation {} already in flight", generation),
                    }
                } else {
                    staging.insert(generation, Staging { source, routes: Vec::new() });
                    ServerMsg::Ok
                }
            }
            ClientMsg::BulkChunk { generation, routes } => match staging.get_mut(&generation) {
                Some(s) => {
                    s.routes.extend(routes);
                    ServerMsg::Ok
                }
                None => ServerMsg::Error {
                    message: format!("unknown generation {}", generation),
                },
            },
            ClientMsg::BulkEnd { source, generation } => match staging.remove(&generation) {
                Some(s) if s.source == source => {
                    let mut g = rib.lock().await;
                    g.bulk_replace(source, &s.routes);
                    ServerMsg::Ok
                }
                Some(_) => ServerMsg::Error {
                    message: "BulkEnd source mismatch".into(),
                },
                None => ServerMsg::Error {
                    message: format!("unknown generation {}", generation),
                },
            },
            ClientMsg::Update { action, route } => {
                let mut g = rib.lock().await;
                match action {
                    ribd_proto::Action::Add => {
                        g.upsert(&route);
                    }
                    ribd_proto::Action::Delete => {
                        g.remove(route.prefix, route.source);
                    }
                }
                ServerMsg::Ok
            }
            ClientMsg::Query(QueryRequest::InstalledRoutes) => {
                let g = rib.lock().await;
                ServerMsg::QueryReply(QueryReply::InstalledRoutes(g.installed_routes()))
            }
            ClientMsg::Query(QueryRequest::AllCandidates) => {
                let g = rib.lock().await;
                ServerMsg::QueryReply(QueryReply::AllCandidates(g.all_candidates()))
            }
            ClientMsg::Heartbeat => ServerMsg::Ok,
        };

        let out = encode(&reply).unwrap();
        if writer.write_all(&out).await.is_err() {
            break;
        }
    }
}

fn igp_route_v4(prefix_octets: [u8; 4], len: u8, gw: [u8; 4], swi: u32) -> Route {
    Route {
        prefix: Prefix::v4(Ipv4Addr::from(prefix_octets), len),
        source: Source::OspfIntra,
        next_hops: vec![NextHop::v4(Ipv4Addr::from(gw), swi)],
        metric: 10,
        tag: 0,
        admin_distance: None,
    }
}

fn bgp_recursive_v4(prefix_octets: [u8; 4], len: u8, recursive_to: [u8; 4]) -> Route {
    Route {
        prefix: Prefix::v4(Ipv4Addr::from(prefix_octets), len),
        source: Source::Bgp,
        next_hops: vec![NextHop::recursive_v4(Ipv4Addr::from(recursive_to))],
        metric: 0,
        tag: 0,
        admin_distance: None,
    }
}

#[tokio::test]
async fn chunked_bulk_recursive_routes_install_atomically() {
    // Producer 1 (IGP) seeds an OSPF route over the wire, then
    // Producer 2 (BGP) pushes 50 recursive routes via chunked bulk
    // that all resolve through the IGP route. After BulkEnd, all 51
    // routes should be queryable, and the BGP routes should report
    // `resolved_via` populated.
    let rib: Arc<Mutex<Rib>> = Arc::new(Mutex::new(Rib::new()));
    let (_dir, sock_path) = spawn_fake_server(rib.clone());

    // Producer 1: IGP.
    let mut ospf = RibConnection::connect(&sock_path, "test-ospf")
        .await
        .expect("ospf connect");
    let igp = igp_route_v4([10, 0, 0, 0], 24, [10, 0, 0, 1], 7);
    ospf.push_bulk(Source::OspfIntra, vec![igp])
        .await
        .expect("ospf bulk");

    // Producer 2: BGP, 50 recursive routes via chunked bulk.
    let mut bgp = RibConnection::connect(&sock_path, "test-bgp")
        .await
        .expect("bgp connect");
    let mut routes = Vec::with_capacity(50);
    for i in 0..50u8 {
        routes.push(bgp_recursive_v4([192, 0, 2, i], 32, [10, 0, 0, 5]));
    }
    bgp.push_bulk_chunked(Source::Bgp, routes, 7)
        .await
        .expect("chunked bulk");

    // Query installed routes.
    let reply = bgp
        .query(QueryRequest::InstalledRoutes)
        .await
        .expect("query");
    match reply {
        QueryReply::InstalledRoutes(rs) => {
            assert_eq!(rs.len(), 51, "expected 1 IGP + 50 BGP routes");
            let bgp_routes: Vec<_> = rs.iter().filter(|r| r.source == Source::Bgp).collect();
            assert_eq!(bgp_routes.len(), 50);
            for r in &bgp_routes {
                let rv = r.resolved_via.as_ref().expect("BGP route should have resolved_via");
                assert_eq!(&rv.recursive_addr[..4], &[10, 0, 0, 5]);
                assert_eq!(rv.through_prefix, Prefix::v4(Ipv4Addr::new(10, 0, 0, 0), 24));
                assert_eq!(r.next_hops.len(), 1);
                // The resolved Direct path keeps the recursive
                // nexthop IP as the L3 destination and uses the
                // IGP route's egress sw_if_index.
                assert_eq!(&r.next_hops[0].addr[..4], &[10, 0, 0, 5]);
                assert_eq!(r.next_hops[0].sw_if_index, 7);
            }
        }
        _ => panic!("expected InstalledRoutes"),
    }
}

#[tokio::test]
async fn chunked_bulk_aborted_mid_stream_discards_staging() {
    // Send BulkBegin + a chunk, then drop the connection without
    // BulkEnd. Reconnect and verify the BGP routes from the aborted
    // bulk are NOT installed.
    let rib: Arc<Mutex<Rib>> = Arc::new(Mutex::new(Rib::new()));
    let (_dir, sock_path) = spawn_fake_server(rib.clone());

    // Seed an IGP route so the BGP routes would resolve if they
    // landed.
    let mut ospf = RibConnection::connect(&sock_path, "test-ospf")
        .await
        .expect("ospf connect");
    ospf.push_bulk(
        Source::OspfIntra,
        vec![igp_route_v4([10, 0, 0, 0], 24, [10, 0, 0, 1], 7)],
    )
    .await
    .expect("ospf bulk");
    drop(ospf);

    // BGP: send BulkBegin + one chunk, then drop without BulkEnd.
    {
        let bgp = RibConnection::connect(&sock_path, "test-bgp")
            .await
            .expect("bgp connect");
        let routes = (0..10u8)
            .map(|i| bgp_recursive_v4([192, 0, 2, i], 32, [10, 0, 0, 5]))
            .collect::<Vec<_>>();
        // We can't directly send half a chunked bulk through the
        // public client API (push_bulk_chunked is all-or-nothing).
        // Instead: chunk into multiple pieces and drop after one.
        // Easiest path: hand-craft the messages ourselves over a
        // raw stream.
        let _ = routes; // unused — we drive raw frames below.
        let stream = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let (mut r, mut w) = stream.into_split();
        // Hello.
        write_msg(
            &mut w,
            &ClientMsg::Hello {
                client_name: "test-bgp-aborted".into(),
                protocol_version: PROTOCOL_VERSION,
            },
        )
        .await;
        let _ = read_msg(&mut r).await;
        // BulkBegin.
        write_msg(
            &mut w,
            &ClientMsg::BulkBegin {
                source: Source::Bgp,
                generation: 999,
            },
        )
        .await;
        let _ = read_msg(&mut r).await;
        // One chunk.
        write_msg(
            &mut w,
            &ClientMsg::BulkChunk {
                generation: 999,
                routes: vec![bgp_recursive_v4([192, 0, 2, 1], 32, [10, 0, 0, 5])],
            },
        )
        .await;
        let _ = read_msg(&mut r).await;
        // Drop without BulkEnd.
        drop(w);
        drop(r);
        drop(bgp);
    }

    // Give the server a moment to process the disconnect.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Reconnect and query. We should see only the 1 IGP route,
    // not the BGP route from the aborted bulk.
    let mut probe = RibConnection::connect(&sock_path, "test-probe")
        .await
        .expect("probe connect");
    let reply = probe
        .query(QueryRequest::InstalledRoutes)
        .await
        .expect("query");
    match reply {
        QueryReply::InstalledRoutes(rs) => {
            assert_eq!(rs.len(), 1, "aborted chunked bulk must not leak routes");
            assert_eq!(rs[0].source, Source::OspfIntra);
        }
        _ => panic!("expected InstalledRoutes"),
    }
}

#[tokio::test]
async fn recursive_held_route_visible_via_all_candidates() {
    // BGP pushes a recursive route via a single-frame Update, but
    // there's no underlying IGP route — the route should be held,
    // not in InstalledRoutes, but visible in AllCandidates with
    // held=true. Then the IGP route arrives and the BGP route flips
    // to installed.
    let rib: Arc<Mutex<Rib>> = Arc::new(Mutex::new(Rib::new()));
    let (_dir, sock_path) = spawn_fake_server(rib.clone());

    let mut bgp = RibConnection::connect(&sock_path, "test-bgp")
        .await
        .expect("bgp connect");
    bgp.update(
        ribd_proto::Action::Add,
        bgp_recursive_v4([192, 0, 2, 0], 24, [10, 0, 0, 5]),
    )
    .await
    .expect("update");

    // InstalledRoutes should be empty.
    let installed = bgp
        .query(QueryRequest::InstalledRoutes)
        .await
        .expect("query installed");
    match installed {
        QueryReply::InstalledRoutes(rs) => {
            assert!(rs.is_empty(), "held route must not be installed");
        }
        _ => panic!("wrong reply"),
    }

    // AllCandidates should show the BGP route as held.
    let cands = bgp
        .query(QueryRequest::AllCandidates)
        .await
        .expect("query candidates");
    match cands {
        QueryReply::AllCandidates(pcs) => {
            let pc = pcs
                .iter()
                .find(|p| p.prefix == Prefix::v4(Ipv4Addr::new(192, 0, 2, 0), 24))
                .expect("BGP candidate present");
            assert_eq!(pc.candidates.len(), 1);
            assert!(pc.candidates[0].held);
            assert!(!pc.candidates[0].installed);
        }
        _ => panic!("wrong reply"),
    }

    // Now push the IGP route over a separate connection.
    let mut ospf = RibConnection::connect(&sock_path, "test-ospf")
        .await
        .expect("ospf connect");
    ospf.update(
        ribd_proto::Action::Add,
        igp_route_v4([10, 0, 0, 0], 24, [10, 0, 0, 1], 7),
    )
    .await
    .expect("ospf update");

    // BGP route should now be installed via cascade.
    let installed = bgp
        .query(QueryRequest::InstalledRoutes)
        .await
        .expect("re-query installed");
    match installed {
        QueryReply::InstalledRoutes(rs) => {
            assert_eq!(rs.len(), 2);
            let bgp_route = rs
                .iter()
                .find(|r| r.source == Source::Bgp)
                .expect("BGP route now installed");
            assert!(bgp_route.resolved_via.is_some());
            assert_eq!(bgp_route.next_hops[0].sw_if_index, 7);
        }
        _ => panic!("wrong reply"),
    }
}

// ---------- raw-frame helpers (used by aborted-bulk test) ----------

async fn write_msg(w: &mut tokio::net::unix::OwnedWriteHalf, msg: &ClientMsg) {
    let buf = encode(msg).unwrap();
    w.write_all(&buf).await.unwrap();
}

async fn read_msg(r: &mut tokio::net::unix::OwnedReadHalf) -> ServerMsg {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.unwrap();
    decode(&buf).unwrap()
}
