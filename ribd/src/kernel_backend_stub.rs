//! Non-Linux stub for `kernel_backend`.
//!
//! On FreeBSD (and any future non-Linux target) the kernel backend is a
//! no-op: VPP programs its own FIB and the kernel FIB is not kept in
//! sync. Diagnostic tools like `ip route` / `netstat -rn` on the host
//! won't reflect OSPF/BGP routes until a PF_ROUTE backend is written.
//! See `freebsd/README.md` — this is deliberately deferred for the
//! experiment.
//!
//! The stub keeps the public API identical to the Linux module so
//! `main.rs` and `session.rs` don't need platform gating.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::rib::Delta;

#[derive(Debug, Default)]
pub struct IfIndexMap {
    map: HashMap<u32, u32>,
}

impl IfIndexMap {
    pub fn new() -> Self {
        IfIndexMap::default()
    }

    pub async fn refresh(&mut self, _vpp: &vpp_api::VppClient) {
        // No sysfs on BSD and no linux_cp TAPs to mirror. Leave empty.
    }

    pub fn get(&self, sw_if_index: u32) -> Option<u32> {
        self.map.get(&sw_if_index).copied()
    }

    #[doc(hidden)]
    pub fn insert_for_test(&mut self, sw_if_index: u32, kernel_ifindex: u32) {
        self.map.insert(sw_if_index, kernel_ifindex);
    }
}

pub struct KernelBackend {
    _ifindex_map: Arc<Mutex<IfIndexMap>>,
}

impl KernelBackend {
    pub fn new(ifindex_map: Arc<Mutex<IfIndexMap>>) -> std::io::Result<Self> {
        Ok(KernelBackend {
            _ifindex_map: ifindex_map,
        })
    }

    pub async fn purge_orphans(&self) {}

    pub async fn apply(&self, _deltas: &[Delta]) {}
}
