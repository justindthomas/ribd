//! Synthetic large-table scale benchmark.
//!
//! Not a correctness test — a measurement target. Loads up to 1M
//! synthetic routes through the **pure RIB layer** (no VPP, no
//! kernel) so we can characterise:
//!
//! - bulk_replace cost as a function of route count
//! - cost of an IGP underlay change with a large dependent BGP set
//!   (the BGP next-hop tracking optimization in NexthopTracker)
//! - lpm_resolve linear-scan cost (the v1 implementation; we'll
//!   know if/when this needs to become a trie)
//!
//! Marked `#[ignore]` so it doesn't run on every `cargo test`.
//! Invoke explicitly:
//!
//! ```sh
//! cargo test -p ribd --release --test dfz_scale_bench -- --ignored --nocapture
//! ```
//!
//! Numbers are reported via `println!` with `--nocapture` so they
//! land in the test stdout. There are no assertions on absolute
//! timing — assertions on functional outcomes only (route counts).
//! We want to *know* the numbers, not gate CI on them.

use std::net::Ipv4Addr;
use std::time::Instant;

use ribd_proto::{NextHop, Prefix, Route, Source};
use ribd::rib::Rib;

fn synth_igp_routes(count: usize) -> Vec<Route> {
    // /24 routes spread across 10/8 with deterministic next-hops so
    // the LPM resolver has a real haystack to search.
    let mut routes = Vec::with_capacity(count);
    for i in 0..count {
        let a = (i / 65536) as u8;
        let b = ((i / 256) % 256) as u8;
        let c = (i % 256) as u8;
        routes.push(Route {
            prefix: Prefix::v4(Ipv4Addr::new(10, a, b, c), 24),
            source: Source::OspfIntra,
            next_hops: vec![NextHop::v4(Ipv4Addr::new(172, 16, 0, 1), 1)],
            metric: 10,
            tag: 0,
            admin_distance: None,
        });
    }
    routes
}

fn synth_bgp_recursive_routes(count: usize, recursive_to: Ipv4Addr) -> Vec<Route> {
    // Recursive BGP routes covering 192/8 + 198/8 — enough address
    // space for hundreds of thousands of /24s.
    let mut routes = Vec::with_capacity(count);
    for i in 0..count {
        let upper = if i < 65536 * 256 { 192u8 } else { 198u8 };
        let i_mod = i % (65536 * 256);
        let a = (i_mod / 65536) as u8;
        let b = ((i_mod / 256) % 256) as u8;
        let c = (i_mod % 256) as u8;
        routes.push(Route {
            prefix: Prefix::v4(Ipv4Addr::new(upper, a, b, c), 24),
            source: Source::Bgp,
            next_hops: vec![NextHop::recursive_v4(recursive_to)],
            metric: 0,
            tag: 0,
            admin_distance: None,
        });
    }
    routes
}

#[test]
#[ignore]
fn dfz_scale_bulk_install() {
    // Simulate a routing daemon dumping a full DFZ-sized table into
    // ribd via a single bulk_replace call. Reports the wall-clock
    // time for arbitration + recursive resolution. Backend
    // programming time is not measured here (the backends have their
    // own pipelining).
    const IGP_COUNT: usize = 200; // realistic IGP underlay
    const BGP_COUNT: usize = 1_000_000;

    let mut rib = Rib::new();

    // Seed the IGP underlay first so all BGP routes resolve.
    let igp_routes = synth_igp_routes(IGP_COUNT);
    let t = Instant::now();
    rib.bulk_replace(Source::OspfIntra, &igp_routes);
    println!(
        "IGP bulk install: {} routes in {:.3}s",
        IGP_COUNT,
        t.elapsed().as_secs_f64()
    );

    // Push BGP — all recursive through 10.0.0.5 which falls under
    // one of the IGP /24s.
    let bgp_routes = synth_bgp_recursive_routes(BGP_COUNT, Ipv4Addr::new(10, 0, 0, 5));
    let t = Instant::now();
    let deltas = rib.bulk_replace(Source::Bgp, &bgp_routes);
    let elapsed = t.elapsed();
    println!(
        "BGP bulk install: {} recursive routes in {:.3}s ({:.0} routes/s)",
        BGP_COUNT,
        elapsed.as_secs_f64(),
        BGP_COUNT as f64 / elapsed.as_secs_f64()
    );
    println!("  -> {} deltas produced", deltas.len());
    assert_eq!(rib.installed_count(), IGP_COUNT + BGP_COUNT);
}

#[test]
#[ignore]
fn dfz_scale_igp_underlay_change() {
    // The headline scenario: full DFZ already installed, then the
    // IGP route that all BGP routes resolve through changes egress.
    // The NexthopTracker should re-resolve ONCE for the unique
    // recursive nexthop and walk all dependents — not re-resolve
    // per-route. We measure how long the cascade takes.
    const IGP_COUNT: usize = 200;
    const BGP_COUNT: usize = 1_000_000;

    let mut rib = Rib::new();
    rib.bulk_replace(Source::OspfIntra, &synth_igp_routes(IGP_COUNT));
    rib.bulk_replace(
        Source::Bgp,
        &synth_bgp_recursive_routes(BGP_COUNT, Ipv4Addr::new(10, 0, 0, 5)),
    );
    assert_eq!(rib.installed_count(), IGP_COUNT + BGP_COUNT);

    // Replace the LPM-winning IGP route (10.0.0.0/24) with a new
    // egress. Every BGP route should re-resolve.
    let new_igp = Route {
        prefix: Prefix::v4(Ipv4Addr::new(10, 0, 0, 0), 24),
        source: Source::OspfIntra,
        next_hops: vec![NextHop::v4(Ipv4Addr::new(172, 31, 0, 1), 9)],
        metric: 10,
        tag: 0,
        admin_distance: None,
    };

    let t = Instant::now();
    let deltas = rib.upsert(&new_igp);
    let elapsed = t.elapsed();
    println!(
        "IGP underlay flap with {} dependent BGP routes: {:.3}s",
        BGP_COUNT,
        elapsed.as_secs_f64()
    );
    println!("  -> {} cascade deltas", deltas.len());

    // Spot-check: every BGP route must now point at the new egress.
    let installed = rib.installed_routes();
    let bgp_sample: Vec<_> = installed
        .iter()
        .filter(|r| r.source == Source::Bgp)
        .take(100)
        .collect();
    assert_eq!(bgp_sample.len(), 100);
    for r in &bgp_sample {
        assert_eq!(r.next_hops[0].sw_if_index, 9);
    }
}

#[test]
#[ignore]
fn dfz_scale_lpm_resolve_cost() {
    // Microbenchmark for the LPM resolver under a 200-route IGP
    // underlay. Done indirectly by repeatedly upserting recursive
    // BGP routes one at a time (each upsert triggers an LPM lookup).
    const IGP_COUNT: usize = 200;
    const BGP_PROBES: usize = 10_000;

    let mut rib = Rib::new();
    rib.bulk_replace(Source::OspfIntra, &synth_igp_routes(IGP_COUNT));

    let t = Instant::now();
    for i in 0..BGP_PROBES {
        let prefix_octets = [192, 0, ((i / 256) % 256) as u8, (i % 256) as u8];
        rib.upsert(&Route {
            prefix: Prefix::v4(Ipv4Addr::from(prefix_octets), 32),
            source: Source::Bgp,
            next_hops: vec![NextHop::recursive_v4(Ipv4Addr::new(10, 0, 0, 5))],
            metric: 0,
            tag: 0,
            admin_distance: None,
        });
    }
    let elapsed = t.elapsed();
    println!(
        "{} recursive BGP upserts (each does LPM over {} IGP routes): {:.3}s ({:.0}/s)",
        BGP_PROBES,
        IGP_COUNT,
        elapsed.as_secs_f64(),
        BGP_PROBES as f64 / elapsed.as_secs_f64()
    );
}
