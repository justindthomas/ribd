//! Per-client connection handling.
//!
//! One tokio task per client. Parses framed [`ClientMsg`]s, updates
//! the shared RIB under a Mutex, and pushes deltas to the VPP
//! backend. Replies with [`ServerMsg`].
//!
//! Producer contract (enforced softly): first message must be
//! `Hello`; session rejects any other first message with `Error`.
//!
//! On disconnect we drop the source's routes immediately. The plan
//! document specifies a 30 s hold time; we'll revisit that when we
//! have multi-source producers and see actual flap behavior. Today
//! immediate expiry is simpler and matches the single-producer case.

use std::collections::HashMap;
use std::sync::Arc;

use ribd_proto::{
    decode, encode, ClientMsg, CodecError, QueryReply, QueryRequest, Route, ServerMsg, Source,
    MAX_FRAME_LEN, PROTOCOL_VERSION,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

use crate::kernel_backend::KernelBackend;
use crate::local_addrs::LocalAddrs;
use crate::rib::{Delta, Rib};
use crate::vpp_backend::VppBackend;

/// Shared state handed to every session task.
pub struct SharedState {
    pub rib: Mutex<Rib>,
    pub backend: VppBackend,
    pub kernel: Option<KernelBackend>,
    pub vpp: vpp_api::VppClient,
    /// Cached local interface address set used to filter self-routes
    /// (next-hop = one of our own IPs). See `local_addrs.rs`.
    pub local_addrs: Mutex<LocalAddrs>,
}

/// Returns true if `route` looks like a self-route — i.e. *every*
/// next-hop address is one of our local interface addresses, so
/// installing it would clobber a kernel/VPP connected entry. We
/// require *all* paths to be local: a multipath route with a mix of
/// local and remote next-hops is still useful (the remote path) and
/// the kernel's path-selection takes care of the rest.
fn is_self_route(route: &ribd_proto::Route, local: &LocalAddrs) -> bool {
    if route.next_hops.is_empty() {
        return false;
    }
    route.next_hops.iter().all(|nh| local.contains(&nh.addr))
}

impl SharedState {
    async fn apply_deltas(&self, deltas: &[Delta]) {
        if deltas.is_empty() {
            return;
        }
        self.backend.apply(&self.vpp, deltas).await;
        if let Some(k) = &self.kernel {
            k.apply(deltas).await;
        }
    }
}

pub async fn handle_session(stream: UnixStream, state: Arc<SharedState>) {
    let peer = stream.peer_cred().ok().map(|c| c.pid()).unwrap_or(None);
    tracing::info!(peer_pid = ?peer, "ribd session started");

    let (reader, mut writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);

    // Hello handshake.
    let first = match read_msg(&mut reader).await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("ribd session ended before hello: {}", e);
            return;
        }
    };
    let client_name = match first {
        ClientMsg::Hello {
            client_name,
            protocol_version,
        } => {
            if protocol_version != PROTOCOL_VERSION {
                let _ = write_msg(
                    &mut writer,
                    &ServerMsg::Error {
                        message: format!(
                            "protocol version {} unsupported, expected {}",
                            protocol_version, PROTOCOL_VERSION
                        ),
                    },
                )
                .await;
                return;
            }
            if let Err(e) = write_msg(
                &mut writer,
                &ServerMsg::HelloAck {
                    server_version: PROTOCOL_VERSION,
                },
            )
            .await
            {
                tracing::warn!("failed to send HelloAck: {}", e);
                return;
            }
            client_name
        }
        _ => {
            let _ = write_msg(
                &mut writer,
                &ServerMsg::Error {
                    message: "first message must be Hello".into(),
                },
            )
            .await;
            return;
        }
    };

    tracing::info!(client = %client_name, "ribd session authenticated");

    // Track which sources this client has touched so we can expire
    // them if the session drops. Normally one client = one source,
    // but we don't want to assume that — a client could push
    // multiple sources (e.g. static + connected from one producer).
    let mut touched_sources: Vec<Source> = Vec::new();
    // In-progress chunked bulks, keyed by producer-chosen
    // `generation`. Discarded on disconnect; only committed on
    // matching BulkEnd.
    let mut staging: HashMap<u64, BulkStaging> = HashMap::new();

    loop {
        let msg = match read_msg(&mut reader).await {
            Ok(m) => m,
            Err(CodecError::Closed) => {
                tracing::info!(client = %client_name, "ribd client disconnected");
                break;
            }
            Err(e) => {
                tracing::warn!(client = %client_name, "ribd read error: {}", e);
                break;
            }
        };

        let reply = handle_message(msg, &state, &mut touched_sources, &mut staging).await;
        if let Err(e) = write_msg(&mut writer, &reply).await {
            tracing::warn!(client = %client_name, "ribd write error: {}", e);
            break;
        }
    }

    // Expire anything this client owned.
    if !touched_sources.is_empty() {
        let mut rib = state.rib.lock().await;
        let mut deltas = Vec::new();
        for source in &touched_sources {
            deltas.extend(rib.drop_source(*source));
        }
        drop(rib);
        if !deltas.is_empty() {
            state.apply_deltas(&deltas).await;
            tracing::info!(
                client = %client_name,
                count = deltas.len(),
                "expired routes on disconnect"
            );
        }
    }
}

/// Per-connection chunked-bulk staging buffer. Holds the declared
/// source plus the accumulated routes from all `BulkChunk` frames
/// for a given generation.
struct BulkStaging {
    source: Source,
    routes: Vec<Route>,
}

async fn handle_message(
    msg: ClientMsg,
    state: &SharedState,
    touched_sources: &mut Vec<Source>,
    staging: &mut HashMap<u64, BulkStaging>,
) -> ServerMsg {
    match msg {
        ClientMsg::Hello { .. } => ServerMsg::Error {
            message: "duplicate hello".into(),
        },
        ClientMsg::Bulk { source, routes } => {
            // Validate: every route in the bulk must use the
            // declared source, otherwise AD arbitration gets
            // confused.
            for r in &routes {
                if r.source != source {
                    return ServerMsg::Error {
                        message: format!(
                            "bulk source {} disagrees with route source {}",
                            source.as_str(),
                            r.source.as_str()
                        ),
                    };
                }
            }
            // Defensive self-route filter — drop any route whose
            // every next-hop is one of our own interface addresses.
            // See is_self_route() and local_addrs.rs for rationale.
            let filtered: Vec<_> = {
                let local = state.local_addrs.lock().await;
                routes
                    .into_iter()
                    .filter(|r| {
                        if is_self_route(r, &local) {
                            tracing::warn!(
                                source = source.as_str(),
                                prefix = %r.prefix,
                                "rejecting self-route from producer (next-hop is a local interface address)"
                            );
                            false
                        } else {
                            true
                        }
                    })
                    .collect()
            };
            if !touched_sources.contains(&source) {
                touched_sources.push(source);
            }
            let deltas = {
                let mut rib = state.rib.lock().await;
                rib.bulk_replace(source, &filtered)
            };
            if !deltas.is_empty() {
                state.apply_deltas(&deltas).await;
            }
            ServerMsg::Ok
        }
        ClientMsg::Update { action, route } => {
            if !touched_sources.contains(&route.source) {
                touched_sources.push(route.source);
            }
            // Defensive self-route filter — only on Add. Delete must
            // always be honored (it might be cleaning up a route that
            // existed under a previous policy).
            if matches!(action, ribd_proto::Action::Add) {
                let local = state.local_addrs.lock().await;
                if is_self_route(&route, &local) {
                    tracing::warn!(
                        source = route.source.as_str(),
                        prefix = %route.prefix,
                        "rejecting self-route from producer (next-hop is a local interface address)"
                    );
                    return ServerMsg::Ok;
                }
            }
            let deltas = {
                let mut rib = state.rib.lock().await;
                match action {
                    ribd_proto::Action::Add => rib.upsert(&route),
                    ribd_proto::Action::Delete => rib.remove(route.prefix, route.source),
                }
            };
            if !deltas.is_empty() {
                state.apply_deltas(&deltas).await;
            }
            ServerMsg::Ok
        }
        ClientMsg::BulkBegin { source, generation } => {
            if staging.contains_key(&generation) {
                return ServerMsg::Error {
                    message: format!("generation {} already in flight", generation),
                };
            }
            staging.insert(generation, BulkStaging { source, routes: Vec::new() });
            ServerMsg::Ok
        }
        ClientMsg::BulkChunk { generation, routes } => {
            let stage = match staging.get_mut(&generation) {
                Some(s) => s,
                None => {
                    return ServerMsg::Error {
                        message: format!("unknown generation {}", generation),
                    }
                }
            };
            // Validate every route's source matches the begin.
            for r in &routes {
                if r.source != stage.source {
                    return ServerMsg::Error {
                        message: format!(
                            "chunk source {} disagrees with bulk source {}",
                            r.source.as_str(),
                            stage.source.as_str()
                        ),
                    };
                }
            }
            stage.routes.extend(routes);
            ServerMsg::Ok
        }
        ClientMsg::BulkEnd { source, generation } => {
            let stage = match staging.remove(&generation) {
                Some(s) => s,
                None => {
                    return ServerMsg::Error {
                        message: format!("unknown generation {}", generation),
                    }
                }
            };
            if stage.source != source {
                return ServerMsg::Error {
                    message: format!(
                        "BulkEnd source {} disagrees with BulkBegin source {}",
                        source.as_str(),
                        stage.source.as_str()
                    ),
                };
            }
            // Same self-route filter as the single-frame Bulk path.
            let filtered: Vec<_> = {
                let local = state.local_addrs.lock().await;
                stage
                    .routes
                    .into_iter()
                    .filter(|r| {
                        if is_self_route(r, &local) {
                            tracing::warn!(
                                source = source.as_str(),
                                prefix = %r.prefix,
                                "rejecting self-route from chunked bulk (next-hop is local)"
                            );
                            false
                        } else {
                            true
                        }
                    })
                    .collect()
            };
            if !touched_sources.contains(&source) {
                touched_sources.push(source);
            }
            let deltas = {
                let mut rib = state.rib.lock().await;
                rib.bulk_replace(source, &filtered)
            };
            if !deltas.is_empty() {
                state.apply_deltas(&deltas).await;
            }
            tracing::info!(
                source = source.as_str(),
                generation,
                routes = filtered.len(),
                "committed chunked bulk"
            );
            ServerMsg::Ok
        }
        ClientMsg::Query(req) => {
            let rib = state.rib.lock().await;
            let reply = match req {
                QueryRequest::InstalledRoutes => {
                    QueryReply::InstalledRoutes(rib.installed_routes())
                }
                QueryRequest::AllCandidates => QueryReply::AllCandidates(rib.all_candidates()),
            };
            ServerMsg::QueryReply(reply)
        }
        ClientMsg::Heartbeat => ServerMsg::Ok,
    }
}

async fn read_msg(
    reader: &mut tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
) -> Result<ClientMsg, CodecError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(CodecError::Closed);
        }
        Err(e) => return Err(CodecError::Io(e)),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(CodecError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(decode(&buf)?)
}

async fn write_msg(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    msg: &ServerMsg,
) -> Result<(), CodecError> {
    let buf = encode(msg)?;
    writer.write_all(&buf).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ribd_proto::{NextHop, Prefix, Route, Source};
    use std::net::Ipv4Addr;

    fn route_with_nexthops(nhs: Vec<NextHop>) -> Route {
        Route {
            prefix: Prefix::v4(Ipv4Addr::new(10, 0, 0, 0), 24),
            source: Source::OspfIntra,
            next_hops: nhs,
            metric: 10,
            tag: 0,
            admin_distance: None,
        }
    }

    fn local_addrs_with(addrs: &[[u8; 4]]) -> LocalAddrs {
        let mut la = LocalAddrs::new();
        for a in addrs {
            let mut padded = [0u8; 16];
            padded[..4].copy_from_slice(a);
            la.insert_for_test(padded);
        }
        la
    }

    #[test]
    fn self_route_single_path_local_is_filtered() {
        // Regression for the 23.177.24.8/31 outage: ospfd pushed
        // a stub route via 23.177.24.9 (our own /31 address). The
        // session layer must drop it.
        let local = local_addrs_with(&[[23, 177, 24, 9]]);
        let route = route_with_nexthops(vec![NextHop::v4(
            Ipv4Addr::new(23, 177, 24, 9),
            1,
        )]);
        assert!(is_self_route(&route, &local));
    }

    #[test]
    fn route_with_remote_next_hop_is_not_self_route() {
        let local = local_addrs_with(&[[23, 177, 24, 9]]);
        let route = route_with_nexthops(vec![NextHop::v4(
            Ipv4Addr::new(23, 177, 24, 8),
            1,
        )]);
        assert!(!is_self_route(&route, &local));
    }

    #[test]
    fn ecmp_with_one_remote_nexthop_is_not_self_route() {
        // Mixed local+remote multipath: keep the route — the kernel's
        // path selection sorts it out, and there's a real next-hop.
        let local = local_addrs_with(&[[10, 0, 0, 1]]);
        let route = route_with_nexthops(vec![
            NextHop::v4(Ipv4Addr::new(10, 0, 0, 1), 1),
            NextHop::v4(Ipv4Addr::new(10, 0, 0, 2), 2),
        ]);
        assert!(!is_self_route(&route, &local));
    }

    #[test]
    fn ecmp_with_all_local_nexthops_is_self_route() {
        let local = local_addrs_with(&[[10, 0, 0, 1], [10, 0, 0, 2]]);
        let route = route_with_nexthops(vec![
            NextHop::v4(Ipv4Addr::new(10, 0, 0, 1), 1),
            NextHop::v4(Ipv4Addr::new(10, 0, 0, 2), 2),
        ]);
        assert!(is_self_route(&route, &local));
    }

    #[test]
    fn empty_nexthops_is_not_self_route() {
        // A withdraw-style empty next-hop list shouldn't be treated
        // as a self-route — let it through to the RIB which will
        // handle it as a no-op.
        let local = local_addrs_with(&[[10, 0, 0, 1]]);
        let route = route_with_nexthops(vec![]);
        assert!(!is_self_route(&route, &local));
    }
}
