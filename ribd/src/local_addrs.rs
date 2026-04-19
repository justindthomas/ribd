//! Cache of local interface addresses for self-route filtering.
//!
//! Producers occasionally push routes whose next-hop is one of our
//! own interface addresses — a self-route. The most common case is a
//! routing daemon that mistakenly emits a "stub network" entry for a
//! prefix it's directly attached to. If we install that route into
//! the kernel as `via <our-own-ip> dev <iface>`, it clobbers the
//! kernel's connected entry and breaks next-hop resolution for *every
//! other* learned route on that segment.
//!
//! We refuse to install any route whose every next-hop address is one
//! of our local addresses. The check happens at the session boundary
//! before routes hit the RIB, so the bogus entry never gets a chance
//! to win admin-distance arbitration.
//!
//! The cache is populated at startup by walking the VPP interface
//! list and dumping `ip_address_dump` (v4 and v6) per interface. It
//! is refreshed lazily on demand — Phase 2 doesn't handle interface
//! churn at runtime, and the kernel's connected route is the
//! authoritative truth anyway. (See ifindex_map for prior art.)

use std::collections::HashSet;

use vpp_api::generated::interface::{SwInterfaceDetails, SwInterfaceDump};
use vpp_api::generated::ip::{IpAddressDetails, IpAddressDump};
use vpp_api::VppClient;

/// A set of local interface addresses (v4 + v6, stored as 16-byte
/// VPP-style buffers — IPv4 right-padded with zeros).
#[derive(Debug, Default, Clone)]
pub struct LocalAddrs {
    addrs: HashSet<[u8; 16]>,
}

impl LocalAddrs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if `addr` is configured on any local interface.
    /// `addr` must be in the same 16-byte layout used by
    /// `ribd_proto::NextHop` (IPv4 right-padded with zeros).
    pub fn contains(&self, addr: &[u8; 16]) -> bool {
        self.addrs.contains(addr)
    }

    pub fn len(&self) -> usize {
        self.addrs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    /// Walk every VPP interface and dump v4 + v6 addresses; replace
    /// the cached set. Errors are logged and partial results are
    /// kept — better to filter on what we know than to filter on
    /// nothing.
    pub async fn refresh(&mut self, vpp: &VppClient) {
        let details: Vec<SwInterfaceDetails> = match vpp
            .dump::<SwInterfaceDump, SwInterfaceDetails>(SwInterfaceDump::default())
            .await
        {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("local_addrs: sw_interface_dump failed: {}", e);
                return;
            }
        };

        let mut new_addrs = HashSet::new();
        for iface in &details {
            for is_ipv6 in [false, true] {
                let dump = IpAddressDump {
                    sw_if_index: iface.sw_if_index,
                    is_ipv6,
                };
                match vpp.dump::<IpAddressDump, IpAddressDetails>(dump).await {
                    Ok(addrs) => {
                        for a in addrs {
                            new_addrs.insert(a.prefix.address);
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            sw_if_index = iface.sw_if_index,
                            v6 = is_ipv6,
                            "local_addrs: ip_address_dump failed: {}",
                            e
                        );
                    }
                }
            }
        }
        tracing::info!(
            count = new_addrs.len(),
            "local_addrs: refreshed local interface address set"
        );
        self.addrs = new_addrs;
    }

    /// Test hook — insert an address directly without going through VPP.
    #[doc(hidden)]
    pub fn insert_for_test(&mut self, addr: [u8; 16]) {
        self.addrs.insert(addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_round_trip() {
        let mut la = LocalAddrs::new();
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&[23, 177, 24, 9]);
        la.insert_for_test(a);
        assert!(la.contains(&a));

        let mut other = [0u8; 16];
        other[..4].copy_from_slice(&[23, 177, 24, 8]);
        assert!(!la.contains(&other));
    }
}
