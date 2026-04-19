//! Live kernel backend test.
//!
//! Requires CAP_NET_ADMIN (runs as root or with the capability set).
//! Installs a dummy interface, programs a route onto it via
//! `KernelBackend`, verifies the route shows up in the kernel FIB,
//! withdraws it, and verifies removal. Skipped if we can't open a
//! netlink handle.
//!
//! Linux-only: uses rtnetlink to create a dummy interface and inspect
//! the kernel FIB. On BSD the kernel backend is a no-op stub so there's
//! nothing to exercise.

#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;
use std::sync::Arc;

use ribd_proto::{NextHop, Prefix, Route, Source};
use ribd::kernel_backend::{IfIndexMap, KernelBackend};
use ribd::rib::Delta;
use tokio::sync::Mutex;

fn have_netlink_admin() -> bool {
    // CAP_NET_ADMIN check: try to spawn `ip -V` as a proxy, and
    // check we're running as root. Skip the test gracefully
    // otherwise — CI / local dev on laptops will skip.
    unsafe { libc::geteuid() == 0 }
}

/// Create a dummy interface for the test to program routes onto.
/// Returns (name, kernel_ifindex). On cleanup the caller deletes
/// the dummy by name.
async fn create_dummy(handle: &rtnetlink::Handle, name: &str) -> Option<u32> {
    use futures::TryStreamExt;
    use netlink_packet_route::link::LinkAttribute;

    // Best-effort delete any leftover with the same name.
    let mut links = handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute();
    while let Ok(Some(msg)) = links.try_next().await {
        let _ = handle.link().del(msg.header.index).execute().await;
    }

    if handle
        .link()
        .add()
        .dummy(name.to_string())
        .execute()
        .await
        .is_err()
    {
        return None;
    }
    // Bring it up.
    let mut links = handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute();
    let msg = links.try_next().await.ok()??;
    let idx = msg.header.index;
    let _ = handle.link().set(idx).up().execute().await;
    // Assign an IP in the gateway's subnet so the route install
    // finds a connected next-hop.
    let _ = handle
        .address()
        .add(idx, std::net::IpAddr::V4(Ipv4Addr::new(10, 99, 99, 254)), 24)
        .execute()
        .await;
    let _ = msg
        .attributes
        .iter()
        .find_map(|a| {
            if let LinkAttribute::IfName(_) = a {
                Some(())
            } else {
                None
            }
        });
    Some(idx)
}

async fn delete_dummy(handle: &rtnetlink::Handle, ifindex: u32) {
    let _ = handle.link().del(ifindex).execute().await;
}

#[tokio::test]
async fn kernel_backend_installs_and_withdraws_v4_route() {
    if !have_netlink_admin() {
        eprintln!("skipping: needs root / CAP_NET_ADMIN");
        return;
    }

    // Open a separate handle for test setup/teardown. The backend
    // owns its own handle internally.
    let (conn, setup_handle, _) = match rtnetlink::new_connection() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("skipping: rtnetlink open failed: {}", e);
            return;
        }
    };
    tokio::spawn(conn);

    // The test programs against a freshly-created dummy interface
    // to keep side effects contained.
    let dummy_name = "impribdtest0";
    let kidx = match create_dummy(&setup_handle, dummy_name).await {
        Some(i) => i,
        None => {
            eprintln!("skipping: dummy create failed");
            return;
        }
    };

    // Fake sw_if_index 42 → this kernel ifindex.
    let ifindex_map = Arc::new(Mutex::new(IfIndexMap::new()));
    {
        let mut m = ifindex_map.lock().await;
        // Reach into the internal map for test setup; kept pub(crate)
        // by default, but IfIndexMap::refresh is the normal path.
        // Instead we monkey-patch by calling refresh against a
        // mock VPP client — no, simpler: use the manual-insert path
        // exposed in the unit test. Since that's module-private,
        // we can't reach it from an integration test. Workaround:
        // insert by re-constructing via refresh on a fake. For now,
        // insert directly using a helper exposed by the crate.
        //
        // We add a pub fn set for tests. See kernel_backend.rs.
        m.insert_for_test(42, kidx);
    }

    let backend = match KernelBackend::new(ifindex_map.clone()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("skipping: KernelBackend::new failed: {}", e);
            delete_dummy(&setup_handle, kidx).await;
            return;
        }
    };

    let prefix = Prefix::v4(Ipv4Addr::new(192, 0, 2, 0), 24);
    let route = Route {
        prefix,
        source: Source::Static,
        next_hops: vec![NextHop::v4(Ipv4Addr::new(10, 99, 99, 1), 42)],
        metric: 0,
        tag: 0,
        admin_distance: None,
    };

    // Install.
    let delta = Delta {
        prefix,
        new: Some(ribd_proto::InstalledRoute {
            prefix,
            source: route.source,
            admin_distance: route.effective_admin_distance(),
            metric: route.metric,
            next_hops: route.next_hops.clone(),
            resolved_via: None,
        }),
    };
    backend.apply(&[delta.clone()]).await;

    // Verify route is present. We don't try to parse the netlink
    // reply here; `ip -4 route show 192.0.2.0/24` is clearer and
    // exercises the same code path kernel consumers use.
    let out = std::process::Command::new("ip")
        .args(["-4", "route", "show", "192.0.2.0/24"])
        .output()
        .expect("ip route show");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("192.0.2.0/24"),
        "route not installed; ip output: {:?}",
        stdout
    );
    assert!(
        stdout.contains(dummy_name),
        "route not on dummy; ip output: {:?}",
        stdout
    );

    // Withdraw.
    let withdraw = Delta { prefix, new: None };
    backend.apply(&[withdraw]).await;
    let out2 = std::process::Command::new("ip")
        .args(["-4", "route", "show", "192.0.2.0/24"])
        .output()
        .expect("ip route show (after withdraw)");
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    assert!(
        !stdout2.contains("192.0.2.0/24"),
        "route still present after withdraw: {:?}",
        stdout2
    );

    delete_dummy(&setup_handle, kidx).await;
}

#[tokio::test]
async fn kernel_backend_installs_ecmp_v4_route() {
    // Two dummy interfaces, each with an IP in its own /24. Install
    // a single /24 prefix with two next-hops (one via each dummy).
    // Verify ECMP shows up in the kernel route table.
    if !have_netlink_admin() {
        eprintln!("skipping: needs root / CAP_NET_ADMIN");
        return;
    }
    let (conn, setup_handle, _) = match rtnetlink::new_connection() {
        Ok(t) => t,
        Err(_) => return,
    };
    tokio::spawn(conn);

    let name_a = "impribdecmpa";
    let name_b = "impribdecmpb";
    // Re-use create_dummy for name_a (it assigns 10.99.99.254/24).
    let kidx_a = match create_dummy(&setup_handle, name_a).await {
        Some(i) => i,
        None => return,
    };
    // Create name_b and give it a DIFFERENT subnet so the two
    // next-hops are on different links.
    let kidx_b = match create_dummy_with_addr(
        &setup_handle,
        name_b,
        Ipv4Addr::new(10, 77, 77, 254),
        24,
    )
    .await
    {
        Some(i) => i,
        None => {
            delete_dummy(&setup_handle, kidx_a).await;
            return;
        }
    };

    let ifindex_map = Arc::new(Mutex::new(IfIndexMap::new()));
    {
        let mut m = ifindex_map.lock().await;
        m.insert_for_test(101, kidx_a);
        m.insert_for_test(102, kidx_b);
    }

    let backend = match KernelBackend::new(ifindex_map.clone()) {
        Ok(b) => b,
        Err(_) => {
            delete_dummy(&setup_handle, kidx_a).await;
            delete_dummy(&setup_handle, kidx_b).await;
            return;
        }
    };

    let prefix = Prefix::v4(Ipv4Addr::new(198, 51, 100, 0), 24);
    let installed = ribd_proto::InstalledRoute {
        prefix,
        source: Source::OspfIntra,
        admin_distance: 110,
        metric: 10,
        next_hops: vec![
            NextHop::v4(Ipv4Addr::new(10, 99, 99, 1), 101),
            NextHop::v4(Ipv4Addr::new(10, 77, 77, 1), 102),
        ],
        resolved_via: None,
    };
    backend
        .apply(&[Delta {
            prefix,
            new: Some(installed),
        }])
        .await;

    let out = std::process::Command::new("ip")
        .args(["-4", "route", "show", "198.51.100.0/24"])
        .output()
        .expect("ip route show");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Multipath routes show as e.g.:
    //   198.51.100.0/24
    //       nexthop via 10.99.99.1 dev impribdecmpa weight 1
    //       nexthop via 10.77.77.1 dev impribdecmpb weight 1
    assert!(
        stdout.contains("198.51.100.0/24"),
        "ECMP route missing: {:?}",
        stdout
    );
    assert!(
        stdout.contains("nexthop") && stdout.contains(name_a) && stdout.contains(name_b),
        "expected ECMP nexthops on both dummies: {:?}",
        stdout
    );
    assert!(
        stdout.contains("10.99.99.1") && stdout.contains("10.77.77.1"),
        "expected both gateway addresses: {:?}",
        stdout
    );

    // Withdraw.
    backend
        .apply(&[Delta {
            prefix,
            new: None,
        }])
        .await;
    let out2 = std::process::Command::new("ip")
        .args(["-4", "route", "show", "198.51.100.0/24"])
        .output()
        .expect("ip route show (after withdraw)");
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    assert!(
        !stdout2.contains("198.51.100.0/24"),
        "ECMP route still present after withdraw: {:?}",
        stdout2
    );

    delete_dummy(&setup_handle, kidx_a).await;
    delete_dummy(&setup_handle, kidx_b).await;
}

/// Regression test for the cascade-reinstall race the OSPF→iBGP
/// cutover on jt-router exposed (2026-04-15). Install N routes
/// from one source, then in a single `apply` call replace all of
/// them with new entries from a different source — the same
/// shape `Rib::drop_source` produces when one routing daemon
/// withdraws and another one's routes win the per-prefix
/// arbitration.
///
/// With the original pipelined `for_each_concurrent` kernel
/// backend, 6 of 11 reinstalls in this scenario hit `EEXIST`
/// because concurrent rtnetlink dumps raced. Sequential
/// processing is straightforward to verify: every reinstall
/// must succeed and every kernel route must end up tagged with
/// the new source's `proto`.
#[tokio::test]
async fn kernel_backend_cascade_reinstall_no_eexist() {
    if !have_netlink_admin() {
        eprintln!("skipping: needs root / CAP_NET_ADMIN");
        return;
    }
    let (conn, setup_handle, _) = match rtnetlink::new_connection() {
        Ok(t) => t,
        Err(_) => return,
    };
    tokio::spawn(conn);

    let dummy_name = "impribdcasc";
    let kidx = match create_dummy(&setup_handle, dummy_name).await {
        Some(i) => i,
        None => return,
    };

    let ifindex_map = Arc::new(Mutex::new(IfIndexMap::new()));
    {
        let mut m = ifindex_map.lock().await;
        m.insert_for_test(101, kidx);
    }
    let backend = match KernelBackend::new(ifindex_map.clone()) {
        Ok(b) => b,
        Err(_) => {
            delete_dummy(&setup_handle, kidx).await;
            return;
        }
    };

    // Phase 1: install 11 routes as Source::OspfIntra (proto ospf).
    let prefixes: Vec<_> = (10..21u8)
        .map(|i| Prefix::v4(Ipv4Addr::new(203, 0, 113, i), 32))
        .collect();
    let install_ospf: Vec<Delta> = prefixes
        .iter()
        .map(|prefix| Delta {
            prefix: *prefix,
            new: Some(ribd_proto::InstalledRoute {
                prefix: *prefix,
                source: Source::OspfIntra,
                admin_distance: 110,
                metric: 10,
                next_hops: vec![NextHop::v4(Ipv4Addr::new(10, 99, 99, 1), 101)],
                resolved_via: None,
            }),
        })
        .collect();
    backend.apply(&install_ospf).await;

    // Confirm all 11 are present with proto ospf.
    for p in &prefixes {
        let p_str = format!("{}", p);
        let out = std::process::Command::new("ip")
            .args(["-4", "route", "show", &p_str, "proto", "ospf"])
            .output()
            .expect("ip route show");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(&p_str),
            "phase 1: route {} missing or wrong proto: {:?}",
            p_str,
            stdout
        );
    }

    // Phase 2: cascade-reinstall all 11 as Source::Bgp (proto bgp)
    // in a SINGLE apply call. With the racy concurrent backend,
    // some of these would fail with EEXIST and stay tagged ospf.
    // With the sequential backend they should all flip to bgp.
    let install_bgp: Vec<Delta> = prefixes
        .iter()
        .map(|prefix| Delta {
            prefix: *prefix,
            new: Some(ribd_proto::InstalledRoute {
                prefix: *prefix,
                source: Source::Bgp,
                admin_distance: 20,
                metric: 0,
                next_hops: vec![NextHop::v4(Ipv4Addr::new(10, 99, 99, 1), 101)],
                resolved_via: None,
            }),
        })
        .collect();
    backend.apply(&install_bgp).await;

    // Every prefix must now exist with proto bgp, and zero remain
    // with proto ospf.
    for p in &prefixes {
        let p_str = format!("{}", p);
        let out_bgp = std::process::Command::new("ip")
            .args(["-4", "route", "show", &p_str, "proto", "bgp"])
            .output()
            .expect("ip route show proto bgp");
        let bgp_stdout = String::from_utf8_lossy(&out_bgp.stdout);
        assert!(
            bgp_stdout.contains(&p_str),
            "phase 2: route {} not tagged proto bgp after cascade: {:?}",
            p_str,
            bgp_stdout
        );
        let out_ospf = std::process::Command::new("ip")
            .args(["-4", "route", "show", &p_str, "proto", "ospf"])
            .output()
            .expect("ip route show proto ospf");
        let ospf_stdout = String::from_utf8_lossy(&out_ospf.stdout);
        assert!(
            !ospf_stdout.contains(&p_str),
            "phase 2: route {} still tagged proto ospf — cascade race regression",
            p_str
        );
    }

    // Cleanup.
    let withdraw: Vec<Delta> = prefixes
        .iter()
        .map(|prefix| Delta {
            prefix: *prefix,
            new: None,
        })
        .collect();
    backend.apply(&withdraw).await;
    delete_dummy(&setup_handle, kidx).await;
}

/// Like [`create_dummy`] but accepts an explicit IPv4 address.
async fn create_dummy_with_addr(
    handle: &rtnetlink::Handle,
    name: &str,
    addr: Ipv4Addr,
    prefix_len: u8,
) -> Option<u32> {
    use futures::TryStreamExt;
    let mut links = handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute();
    while let Ok(Some(msg)) = links.try_next().await {
        let _ = handle.link().del(msg.header.index).execute().await;
    }
    if handle
        .link()
        .add()
        .dummy(name.to_string())
        .execute()
        .await
        .is_err()
    {
        return None;
    }
    let mut links = handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute();
    let msg = links.try_next().await.ok()??;
    let idx = msg.header.index;
    let _ = handle.link().set(idx).up().execute().await;
    let _ = handle
        .address()
        .add(idx, std::net::IpAddr::V4(addr), prefix_len)
        .execute()
        .await;
    Some(idx)
}
