//! ribd — central RIB daemon.
//!
//! Owns VPP FIB and Linux kernel route programming. Producers
//! (ospfd, bgpd, dhcpd, or any other route source) push routes
//! via the Unix socket at `/run/ribd.sock`; ribd arbitrates
//! across sources by admin distance and installs the winner.

#[cfg(target_os = "linux")]
pub mod kernel_backend;
#[cfg(not(target_os = "linux"))]
#[path = "kernel_backend_stub.rs"]
pub mod kernel_backend;
pub mod local_addrs;
pub mod rib;
pub mod session;
pub mod vpp_backend;
