//! VPP FIB programming backend.
//!
//! Takes [`Delta`]s from `rib::Rib` and programs VPP's IPv4 / IPv6
//! FIB via the binary API. Diff-based at the RIB level — this
//! module just translates individual deltas into VPP API calls.
//!
//! Shape mirrors the original ospfd rib.rs/rib_v3.rs but handles
//! both address families from a single codepath keyed on `Prefix.af`.

use futures::stream::{self, StreamExt};
use ribd_proto::{Af, NextHop, Prefix};
use vpp_api::generated::ip::*;
use vpp_api::VppClient;

use crate::rib::Delta;

/// Maximum number of `ip_route_add_del` calls in flight at once.
/// The vpp-api client correlates replies to requests by context ID
/// (see vpp-api/src/client.rs) so concurrent requests are safe;
/// this just bounds the pipeline depth so we don't unboundedly
/// queue when programming a full DFZ table. Tunable; 64 is a
/// conservative starting point.
const PIPELINE_DEPTH: usize = 64;

#[derive(Debug, Default)]
pub struct VppBackend;

impl VppBackend {
    pub fn new() -> Self {
        VppBackend
    }

    /// Apply a batch of deltas to VPP with bounded pipelining.
    /// Up to [`PIPELINE_DEPTH`] requests are in flight concurrently;
    /// individual failures are logged and do not abort the batch.
    pub async fn apply(&self, vpp: &VppClient, deltas: &[Delta]) {
        stream::iter(deltas.iter())
            .for_each_concurrent(PIPELINE_DEPTH, |d| async move {
                match &d.new {
                    None => match delete_route(vpp, d.prefix).await {
                        Err(e) => {
                            tracing::warn!(prefix = %d.prefix, "VPP delete failed: {}", e);
                        }
                        Ok(()) => {
                            tracing::info!(prefix = %d.prefix, "withdrew route");
                        }
                    },
                    Some(r) => match add_route(vpp, d.prefix, &r.next_hops).await {
                        Err(e) => {
                            tracing::warn!(
                                prefix = %d.prefix,
                                source = r.source.as_str(),
                                "VPP add failed: {}", e
                            );
                        }
                        Ok(()) => {
                            tracing::info!(
                                prefix = %d.prefix,
                                source = r.source.as_str(),
                                ad = r.admin_distance,
                                metric = r.metric,
                                paths = r.next_hops.len(),
                                "installed route"
                            );
                        }
                    },
                }
            })
            .await;
    }
}

async fn add_route(
    vpp: &VppClient,
    prefix: Prefix,
    next_hops: &[NextHop],
) -> Result<(), vpp_api::VppError> {
    if next_hops.is_empty() {
        return Err(vpp_api::VppError::ApiError {
            retval: -1,
            message: format!("no paths for {}", prefix),
        });
    }

    let paths: Vec<FibPath> = match prefix.af {
        Af::V4 => next_hops
            .iter()
            .map(|nh| {
                let mut v4 = [0u8; 4];
                v4.copy_from_slice(&nh.addr[..4]);
                FibPath::via_ipv4(v4, nh.sw_if_index)
            })
            .collect(),
        Af::V6 => next_hops
            .iter()
            .map(|nh| FibPath::via_ipv6(nh.addr, nh.sw_if_index))
            .collect(),
    };
    let n_paths = paths.len() as u8;

    let vpp_prefix = match prefix.af {
        Af::V4 => {
            let mut v4 = [0u8; 4];
            v4.copy_from_slice(&prefix.addr[..4]);
            Prefix_vpp::ipv4(v4, prefix.len)
        }
        Af::V6 => Prefix_vpp::ipv6(prefix.addr, prefix.len),
    };

    let reply: IpRouteAddDelReply = vpp
        .request::<IpRouteAddDel, IpRouteAddDelReply>(IpRouteAddDel {
            is_add: true,
            is_multipath: next_hops.len() > 1,
            route: IpRoute {
                table_id: 0,
                stats_index: 0,
                prefix: vpp_prefix,
                n_paths,
                paths,
            },
        })
        .await?;
    if reply.retval != 0 {
        return Err(vpp_api::VppError::ApiError {
            retval: reply.retval,
            message: format!("ip_route_add_del add for {}", prefix),
        });
    }
    Ok(())
}

async fn delete_route(vpp: &VppClient, prefix: Prefix) -> Result<(), vpp_api::VppError> {
    let vpp_prefix = match prefix.af {
        Af::V4 => {
            let mut v4 = [0u8; 4];
            v4.copy_from_slice(&prefix.addr[..4]);
            Prefix_vpp::ipv4(v4, prefix.len)
        }
        Af::V6 => Prefix_vpp::ipv6(prefix.addr, prefix.len),
    };
    let reply: IpRouteAddDelReply = vpp
        .request::<IpRouteAddDel, IpRouteAddDelReply>(IpRouteAddDel {
            is_add: false,
            is_multipath: false,
            route: IpRoute {
                table_id: 0,
                stats_index: 0,
                prefix: vpp_prefix,
                n_paths: 0,
                paths: vec![],
            },
        })
        .await?;
    if reply.retval != 0 {
        return Err(vpp_api::VppError::ApiError {
            retval: reply.retval,
            message: format!("ip_route_add_del delete for {}", prefix),
        });
    }
    Ok(())
}

/// Compatibility helper so the rest of the codebase can reference
/// `Prefix_vpp::ipv4/ipv6` consistently — the name collision with our
/// proto `Prefix` would otherwise force verbose qualifying everywhere.
#[allow(non_camel_case_types)]
type Prefix_vpp = vpp_api::generated::ip::Prefix;

#[cfg(test)]
mod tests {
    // Nothing here — VPP backend is exercised by the integration
    // test in tests/ that spins up a live VppClient against a real
    // VPP, and we do not want unit-level mocking of the VPP API.
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use std::net::{Ipv4Addr, Ipv6Addr};
}
