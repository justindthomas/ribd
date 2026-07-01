//! End-to-end tests that drive ribd's **real** Unix-socket server —
//! `ribd::session::handle_session` / `handle_message` — over an
//! actual socket, using the real `ribd-client` (and raw frames where
//! the client API can't express the case).
//!
//! The two pre-existing integration suites (`session_integration.rs`,
//! `chunked_bulk_session.rs`) reimplement a *fake* server that mirrors
//! the message handling, so the real wiring — protocol-version check,
//! source validation, self-route filter, admin-distance arbitration,
//! Bulk/replace, disconnect expiry — was never actually executed under
//! test. These tests close that gap.
//!
//! The obstacle to running the real server is that `handle_message`
//! ultimately calls `SharedState::apply_deltas`, which programs VPP
//! (`ip_route_add_del`) + the Linux kernel FIB (rtnetlink). We use the
//! `DeltaSink` seam added to `SharedState`: production leaves
//! `delta_sink = None` (real dataplane path); here we install a
//! recording sink that captures the exact `Delta` stream the server
//! produces. Nothing touches VPP or the kernel, so this runs in plain
//! `cargo test` on any platform.
//!
//! What is NOT verified here (stays mocked): the actual VPP
//! `ip_route_add_del` calls and kernel rtnetlink programming. We verify
//! everything up to and including the delta stream handed to the FIB
//! layer, plus the RIB state observable via the real Query path.

use std::net::Ipv4Addr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ribd::local_addrs::LocalAddrs;
use ribd::rib::{Delta, Rib};
use ribd::session::{handle_session, DeltaSink, SharedState};
use ribd::vpp_backend::VppBackend;
use ribd_client::RibConnection;
use ribd_proto::{
    decode, encode, Action, ClientMsg, NextHop, Prefix, QueryReply, QueryRequest, Route, ServerMsg,
    Source, PROTOCOL_VERSION,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

/// Recording FIB backend: captures every `Delta` the real server
/// hands to `apply_deltas` instead of programming a dataplane.
#[derive(Default)]
struct RecordingSink {
    deltas: Mutex<Vec<Delta>>,
}

impl RecordingSink {
    fn recorded(&self) -> Vec<Delta> {
        self.deltas.lock().unwrap().clone()
    }

    /// Deltas whose prefix matches `p`, in arrival order.
    fn for_prefix(&self, p: Prefix) -> Vec<Delta> {
        self.recorded()
            .into_iter()
            .filter(|d| d.prefix == p)
            .collect()
    }
}

impl DeltaSink for RecordingSink {
    fn apply(&self, deltas: &[Delta]) {
        self.deltas.lock().unwrap().extend_from_slice(deltas);
    }
}

/// Stand up the real server on a temp socket with a recording FIB
/// sink and a `local_addrs` set seeded with the given v4 addresses
/// (for self-route testing). Returns the tempdir (keep alive), the
/// socket path, and the recording sink for assertions.
fn spawn_real_server(
    local_v4: &[[u8; 4]],
) -> (tempfile::TempDir, std::path::PathBuf, Arc<RecordingSink>) {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("ribd.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();

    let mut local = LocalAddrs::new();
    for a in local_v4 {
        let mut padded = [0u8; 16];
        padded[..4].copy_from_slice(a);
        local.insert_for_test(padded);
    }

    let sink = Arc::new(RecordingSink::default());

    let state = Arc::new(SharedState {
        rib: tokio::sync::Mutex::new(Rib::new()),
        backend: VppBackend::new(),
        kernel: None,
        // A supervisor pointed at a socket that will never exist.
        // `spawn` returns immediately and never blocks; because the
        // `delta_sink` seam short-circuits `apply_deltas`, the real
        // server never calls `vpp.client()`, so this never connects.
        vpp: vpp_api::VppSupervisor::spawn(
            dir.path().join("nonexistent-vpp.sock").to_string_lossy().to_string(),
        ),
        local_addrs: tokio::sync::Mutex::new(local),
        reconcile_generation: AtomicU64::new(0),
        delta_sink: Some(sink.clone() as Arc<dyn DeltaSink>),
    });

    // Accept loop → the REAL handle_session (one task per connection).
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let st = state.clone();
            tokio::spawn(handle_session(stream, st));
        }
    });

    (dir, sock_path, sink)
}

fn v4_route(octets: [u8; 4], len: u8, source: Source, nh: [u8; 4]) -> Route {
    Route {
        prefix: Prefix::v4(Ipv4Addr::from(octets), len),
        source,
        next_hops: vec![NextHop::v4(Ipv4Addr::from(nh), 1)],
        metric: 10,
        tag: 0,
        admin_distance: None,
        table_id: 0,
    }
}

async fn query_installed(sock: &std::path::Path) -> Vec<ribd_proto::InstalledRoute> {
    let mut probe = RibConnection::connect(sock, "probe").await.expect("probe connect");
    match probe.query(QueryRequest::InstalledRoutes).await.expect("query") {
        QueryReply::InstalledRoutes(rs) => rs,
        other => panic!("expected InstalledRoutes, got {:?}", other),
    }
}

/// Poll installed routes until `pred` holds or we give up.
async fn wait_installed<F>(sock: &std::path::Path, mut pred: F) -> Vec<ribd_proto::InstalledRoute>
where
    F: FnMut(&[ribd_proto::InstalledRoute]) -> bool,
{
    for _ in 0..100 {
        let rs = query_installed(sock).await;
        if pred(&rs) {
            return rs;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("condition not reached within timeout");
}

// ---------------- raw-frame helpers ----------------

async fn raw_send(s: &mut UnixStream, msg: &ClientMsg) {
    let buf = encode(msg).unwrap();
    s.write_all(&buf).await.unwrap();
}

async fn raw_recv(s: &mut UnixStream) -> Option<ServerMsg> {
    let mut len = [0u8; 4];
    if s.read_exact(&mut len).await.is_err() {
        return None;
    }
    let n = u32::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    if s.read_exact(&mut buf).await.is_err() {
        return None;
    }
    Some(decode(&buf).unwrap())
}

// =====================================================================
// version / handshake
// =====================================================================

#[tokio::test]
async fn correct_version_handshake_accepted() {
    let (_dir, sock, _sink) = spawn_real_server(&[]);
    // RibConnection::connect sends Hello with the correct
    // PROTOCOL_VERSION and requires a HelloAck.
    let mut c = RibConnection::connect(&sock, "producer").await.expect("connect");
    // And the session is usable.
    c.push_bulk(
        Source::Bgp,
        vec![v4_route([192, 0, 2, 0], 24, Source::Bgp, [10, 0, 0, 1])],
    )
    .await
    .expect("push after handshake");
    let installed = query_installed(&sock).await;
    assert_eq!(installed.len(), 1);
}

#[tokio::test]
async fn wrong_version_rejected_and_session_closed() {
    let (_dir, sock, sink) = spawn_real_server(&[]);
    let mut s = UnixStream::connect(&sock).await.unwrap();
    raw_send(
        &mut s,
        &ClientMsg::Hello {
            client_name: "stale-peer".into(),
            protocol_version: PROTOCOL_VERSION + 1,
        },
    )
    .await;
    // Must get an explicit Error (NOT a HelloAck, NOT silence).
    match raw_recv(&mut s).await {
        Some(ServerMsg::Error { message }) => {
            assert!(
                message.contains("unsupported"),
                "unexpected error text: {message}"
            );
        }
        other => panic!("expected version Error, got {:?}", other),
    }
    // And the server must have closed the session — a mismatched peer
    // must not be able to push anything. Next read is EOF.
    assert!(
        raw_recv(&mut s).await.is_none(),
        "server must close the connection after a version mismatch"
    );
    // Try to push anyway on the (now closed) stream; the write itself
    // may fail with BrokenPipe (the server already hung up) — that's
    // fine, the point is nothing reaches the RIB either way.
    let frame = encode(&ClientMsg::Bulk {
        source: Source::Bgp,
        routes: vec![v4_route([192, 0, 2, 0], 24, Source::Bgp, [10, 0, 0, 1])],
    })
    .unwrap();
    let _ = s.write_all(&frame).await; // best-effort; may BrokenPipe
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        sink.recorded().is_empty(),
        "a version-mismatched peer must not program any routes"
    );
    assert!(query_installed(&sock).await.is_empty());
}

#[tokio::test]
async fn first_message_not_hello_rejected() {
    let (_dir, sock, sink) = spawn_real_server(&[]);
    let mut s = UnixStream::connect(&sock).await.unwrap();
    // Skip the handshake entirely and go straight to a data frame.
    raw_send(&mut s, &ClientMsg::Heartbeat).await;
    match raw_recv(&mut s).await {
        Some(ServerMsg::Error { message }) => {
            assert!(
                message.contains("must be Hello"),
                "unexpected error text: {message}"
            );
        }
        other => panic!("expected 'must be Hello' Error, got {:?}", other),
    }
    assert!(
        raw_recv(&mut s).await.is_none(),
        "server must close after a non-Hello first message"
    );
    assert!(sink.recorded().is_empty());
}

#[tokio::test]
async fn duplicate_hello_after_handshake_is_error() {
    let (_dir, sock, _sink) = spawn_real_server(&[]);
    let mut s = UnixStream::connect(&sock).await.unwrap();
    raw_send(
        &mut s,
        &ClientMsg::Hello {
            client_name: "p".into(),
            protocol_version: PROTOCOL_VERSION,
        },
    )
    .await;
    assert!(matches!(raw_recv(&mut s).await, Some(ServerMsg::HelloAck { .. })));
    // Second Hello mid-session is a protocol error but does not kill
    // the session (handle_message returns an Error reply, loop
    // continues).
    raw_send(
        &mut s,
        &ClientMsg::Hello {
            client_name: "p".into(),
            protocol_version: PROTOCOL_VERSION,
        },
    )
    .await;
    match raw_recv(&mut s).await {
        Some(ServerMsg::Error { message }) => assert!(message.contains("duplicate hello")),
        other => panic!("expected duplicate-hello Error, got {:?}", other),
    }
    // Session still alive: Heartbeat works.
    raw_send(&mut s, &ClientMsg::Heartbeat).await;
    assert!(matches!(raw_recv(&mut s).await, Some(ServerMsg::Ok)));
}

// =====================================================================
// source validation
// =====================================================================

#[tokio::test]
async fn bulk_source_mismatch_rejected() {
    let (_dir, sock, sink) = spawn_real_server(&[]);
    let mut c = RibConnection::connect(&sock, "producer").await.expect("connect");
    // Declared Bulk source is Bgp, but a contained route claims
    // OspfIntra — the server must reject the whole bulk.
    let err = c
        .push_bulk(
            Source::Bgp,
            vec![v4_route([192, 0, 2, 0], 24, Source::OspfIntra, [10, 0, 0, 1])],
        )
        .await
        .expect_err("mismatched-source bulk must be rejected");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("disagrees"),
        "expected source-disagreement error, got {msg}"
    );
    // Nothing installed, nothing programmed.
    assert!(sink.recorded().is_empty());
    assert!(query_installed(&sock).await.is_empty());
}

// =====================================================================
// self-route filter
// =====================================================================

#[tokio::test]
async fn self_route_filtered_but_normal_route_kept() {
    // 23.177.24.9 is one of our own interface addresses.
    let (_dir, sock, sink) = spawn_real_server(&[[23, 177, 24, 9]]);
    let mut c = RibConnection::connect(&sock, "ospf").await.expect("connect");

    let self_prefix = Prefix::v4(Ipv4Addr::new(23, 177, 24, 8), 31);
    let normal_prefix = Prefix::v4(Ipv4Addr::new(10, 20, 30, 0), 24);

    // Push both in one bulk: a self-route (next-hop == our own IP)
    // and a normal route (remote next-hop).
    c.push_bulk(
        Source::OspfIntra,
        vec![
            v4_route([23, 177, 24, 8], 31, Source::OspfIntra, [23, 177, 24, 9]),
            v4_route([10, 20, 30, 0], 24, Source::OspfIntra, [10, 20, 30, 254]),
        ],
    )
    .await
    .expect("push");

    // Only the normal route survives to the RIB.
    let installed = query_installed(&sock).await;
    assert_eq!(installed.len(), 1, "self-route must be dropped");
    assert_eq!(installed[0].prefix, normal_prefix);

    // And the FIB layer only ever saw the normal prefix — the
    // self-route never produced a delta.
    assert!(
        sink.for_prefix(self_prefix).is_empty(),
        "self-route must never reach the FIB layer"
    );
    assert!(!sink.for_prefix(normal_prefix).is_empty());
}

#[tokio::test]
async fn self_route_filtered_on_update_add() {
    // The Update(Add) path has its own self-route guard, separate from
    // the Bulk path — exercise it directly.
    let (_dir, sock, sink) = spawn_real_server(&[[23, 177, 24, 9]]);
    let mut c = RibConnection::connect(&sock, "ospf").await.expect("connect");
    c.update(
        Action::Add,
        v4_route([23, 177, 24, 8], 31, Source::OspfIntra, [23, 177, 24, 9]),
    )
    .await
    .expect("update returns Ok even when route is dropped");
    assert!(query_installed(&sock).await.is_empty());
    assert!(sink.recorded().is_empty());
}

// =====================================================================
// admin-distance arbitration + disconnect-expiry fallback
// =====================================================================

#[tokio::test]
async fn ad_arbitration_bgp_beats_ospf_then_falls_back_on_disconnect() {
    let (_dir, sock, sink) = spawn_real_server(&[]);
    let prefix = Prefix::v4(Ipv4Addr::new(198, 51, 100, 0), 24);

    // OSPF (AD 110) installs first.
    let mut ospf = RibConnection::connect(&sock, "ospf").await.expect("ospf connect");
    ospf.update(
        Action::Add,
        v4_route([198, 51, 100, 0], 24, Source::OspfIntra, [10, 0, 0, 1]),
    )
    .await
    .expect("ospf add");
    let installed = query_installed(&sock).await;
    assert_eq!(installed.len(), 1);
    assert_eq!(installed[0].source, Source::OspfIntra);

    // BGP (AD 20) for the same prefix should win.
    let mut bgp = RibConnection::connect(&sock, "bgp").await.expect("bgp connect");
    bgp.update(
        Action::Add,
        v4_route([198, 51, 100, 0], 24, Source::Bgp, [10, 0, 0, 2]),
    )
    .await
    .expect("bgp add");
    let installed = wait_installed(&sock, |rs| {
        rs.iter().any(|r| r.prefix == prefix && r.source == Source::Bgp)
    })
    .await;
    let win = installed.iter().find(|r| r.prefix == prefix).unwrap();
    assert_eq!(win.source, Source::Bgp);
    assert_eq!(win.admin_distance, 20);

    // Withdraw the winner by dropping the BGP session — the
    // disconnect-expiry path must drop Source::Bgp and promote OSPF.
    drop(bgp);
    let installed = wait_installed(&sock, |rs| {
        rs.iter().any(|r| r.prefix == prefix && r.source == Source::OspfIntra)
    })
    .await;
    let win = installed.iter().find(|r| r.prefix == prefix).unwrap();
    assert_eq!(win.source, Source::OspfIntra, "OSPF must be promoted");
    assert_eq!(win.admin_distance, 110);

    // The recorded delta stream for this prefix should show the
    // transitions: install OSPF → replace with BGP → promote OSPF.
    let seq: Vec<Source> = sink
        .for_prefix(prefix)
        .into_iter()
        .filter_map(|d| d.new.map(|r| r.source))
        .collect();
    assert_eq!(
        seq,
        vec![Source::OspfIntra, Source::Bgp, Source::OspfIntra],
        "FIB delta stream must reflect the arbitration transitions"
    );
}

// =====================================================================
// Bulk/replace atomicity
// =====================================================================

#[tokio::test]
async fn bulk_replace_swaps_source_set_atomically() {
    let (_dir, sock, _sink) = spawn_real_server(&[]);
    let mut bgp = RibConnection::connect(&sock, "bgp").await.expect("connect");

    let a = Prefix::v4(Ipv4Addr::new(192, 0, 2, 0), 24);
    let b = Prefix::v4(Ipv4Addr::new(198, 51, 100, 0), 24);
    let c = Prefix::v4(Ipv4Addr::new(203, 0, 113, 0), 24);

    // First bulk: {A, B}.
    bgp.push_bulk(
        Source::Bgp,
        vec![
            v4_route([192, 0, 2, 0], 24, Source::Bgp, [10, 0, 0, 1]),
            v4_route([198, 51, 100, 0], 24, Source::Bgp, [10, 0, 0, 1]),
        ],
    )
    .await
    .expect("bulk 1");
    let mut prefixes: Vec<Prefix> = query_installed(&sock).await.iter().map(|r| r.prefix).collect();
    prefixes.sort_by_key(|p| p.addr);
    assert_eq!(prefixes, vec![a, b]);

    // Second bulk: {B, C}. Atomic replace → A withdrawn, C added, B kept.
    bgp.push_bulk(
        Source::Bgp,
        vec![
            v4_route([198, 51, 100, 0], 24, Source::Bgp, [10, 0, 0, 1]),
            v4_route([203, 0, 113, 0], 24, Source::Bgp, [10, 0, 0, 1]),
        ],
    )
    .await
    .expect("bulk 2");
    let installed = query_installed(&sock).await;
    let mut got: Vec<Prefix> = installed.iter().map(|r| r.prefix).collect();
    got.sort_by_key(|p| p.addr);
    assert_eq!(got, vec![b, c], "bulk replace must swap the source set");
    assert!(
        !installed.iter().any(|r| r.prefix == a),
        "A must be withdrawn by the replace"
    );
}
