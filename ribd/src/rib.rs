//! In-memory RIB with admin-distance arbitration and recursive
//! next-hop resolution.
//!
//! For each (prefix, source) we keep at most one candidate. When a
//! producer pushes a new route from source X, we replace X's slot
//! and recompute the installed winner. The winner is the candidate
//! with the lowest effective admin distance; ties are broken by
//! metric (lower wins); further ties by source ordering (arbitrary
//! but stable).
//!
//! ## Recursive next-hops
//!
//! BGP and other multi-hop protocols send next-hops as IP addresses
//! that have to be resolved through the IGP-installed RIB to find a
//! real (egress-interface, link-layer-nexthop) tuple. Producers mark
//! such next-hops with `NextHopKind::Recursive`. The [`NexthopTracker`]
//! does longest-prefix-match resolution against the currently-installed
//! table, fans out across the LPM winner's Direct paths (so an iBGP
//! route inherits IGP ECMP for free), and re-resolves dependents
//! whenever an IGP route changes.
//!
//! Routes whose recursive next-hops cannot be resolved (no covering
//! Direct route) are *held*: kept in the candidate table but not
//! installed, not visible to the FIB backends. They become
//! installable as soon as the underlying IGP route arrives.
//!
//! Sharing matters. A 1M-route DFZ table typically resolves through
//! ~10-100 unique next-hops, so the tracker keys per-nexthop and
//! re-resolves once per unique IP, then walks the dependents set.
//! IGP flap → re-resolve a handful of nexthops, not a million routes.
//!
//! This module is pure: no VPP, no I/O, no async. Fully unit-testable.

use std::collections::{HashMap, HashSet};

use ribd_proto::{
    Af, Candidate, InstalledRoute, NextHop, NextHopKind, Prefix, PrefixCandidates,
    ResolvedNextHop, Route, Source,
};

/// A stored candidate for a single (prefix, source) slot. Holds the
/// producer's view, including any Recursive next-hops awaiting
/// resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    admin_distance: u8,
    metric: u32,
    next_hops: Vec<NextHop>,
    tag: u32,
}

impl Entry {
    fn from_route(r: &Route) -> Self {
        Entry {
            admin_distance: r.effective_admin_distance(),
            metric: r.metric,
            next_hops: r.next_hops.clone(),
            tag: r.tag,
        }
    }

    fn has_recursive(&self) -> bool {
        self.next_hops.iter().any(|nh| nh.is_recursive())
    }
}

/// A post-resolution installed entry. `direct_next_hops` is what the
/// backend programs; `resolved_via` records the recursion provenance
/// so query consumers can show "via 10.0.0.5 (recursive, through
/// 10.0.0.0/24)".
#[derive(Debug, Clone, PartialEq, Eq)]
struct InstalledEntry {
    admin_distance: u8,
    metric: u32,
    /// All Direct, post-resolution. May contain ECMP fanout from
    /// the LPM winner.
    direct_next_hops: Vec<NextHop>,
    tag: u32,
    /// `Some` iff the candidate held any Recursive next-hops. The
    /// `recursive_addr` is the producer-supplied IP; the
    /// `through_prefix` is the LPM winner used to resolve.
    resolved_via: Option<ResolvedNextHop>,
}

/// A delta produced by a RIB mutation — what the backend needs to
/// program. `None` for `new` means "withdraw this prefix entirely".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delta {
    pub prefix: Prefix,
    pub new: Option<InstalledRoute>,
}

/// Local (ribd-internal) resolution shape. Differs from the
/// proto's `ResolvedNextHop` because we need the full Direct path
/// list for ECMP fanout.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NhResolution {
    direct_paths: Vec<NextHop>,
    through_prefix: Prefix,
}

/// Pure dependency index for recursive next-hops: maps each
/// `(Af, recursive nexthop IP)` to the set of `(Prefix, Source)`
/// candidates that have at least one Recursive next-hop pointing at
/// that IP.
///
/// We deliberately do NOT cache the resolution itself here. Caching
/// it created a stale-state bug: install-time used [`Rib::recompute`]
/// (which compares previous-vs-new installed entries directly) but
/// cascade compared against the cached field, so cascades after a
/// fresh install would mis-skip. Recomputing dependents
/// unconditionally during cascade is cheap now that `recompute` is
/// O(sources_for_this_prefix) thanks to the `by_prefix` index, and
/// `lpm_resolve` is O(prefix-length-bits) thanks to direct masked
/// HashMap lookups.
///
/// The address family is part of the key so v4 and v6 nexthops with
/// numerically-equal byte patterns don't collide and so cascade can
/// match each entry against its same-family changed prefixes only.
#[derive(Debug, Default)]
struct NexthopTracker {
    entries: HashMap<(Af, [u8; 16]), HashSet<(Prefix, Source)>>,
}

impl NexthopTracker {
    fn add_dependent(&mut self, af: Af, addr: [u8; 16], dep: (Prefix, Source)) {
        self.entries.entry((af, addr)).or_default().insert(dep);
    }

    fn remove_dependent(&mut self, af: Af, addr: [u8; 16], dep: (Prefix, Source)) {
        if let Some(set) = self.entries.get_mut(&(af, addr)) {
            set.remove(&dep);
            if set.is_empty() {
                self.entries.remove(&(af, addr));
            }
        }
    }
}

/// Maximum number of cascade iterations after a single mutation.
/// Bounds runaway iBGP-via-iBGP recursion (which shouldn't form
/// cycles per RFC 4271, but defense in depth).
const CASCADE_ITERATION_BOUND: usize = 8;

#[derive(Debug, Default)]
pub struct Rib {
    /// (prefix, source) -> candidate entry. Producer-supplied;
    /// next-hops may be Recursive. The indexes below let us answer
    /// "which sources have a candidate for prefix P?" and "which
    /// prefixes does source S own?" without scanning the whole map,
    /// which matters at DFZ scale (1M+ candidates).
    candidates: HashMap<(Prefix, Source), Entry>,
    by_prefix: HashMap<Prefix, HashSet<Source>>,
    by_source: HashMap<Source, HashSet<Prefix>>,
    /// Currently-installed winner per prefix. Entry holds resolved
    /// (Direct-only) next-hops.
    installed: HashMap<Prefix, (Source, InstalledEntry)>,
    /// Per-recursive-nexthop dependency index.
    nh_tracker: NexthopTracker,
}

impl Rib {
    pub fn new() -> Self {
        Rib::default()
    }

    /// Number of installed routes (post-arbitration).
    pub fn installed_count(&self) -> usize {
        self.installed.len()
    }

    /// Insert/replace a single candidate slot, keeping the prefix
    /// and source indexes in sync. Centralises the bookkeeping so
    /// the mutator paths stay readable.
    fn insert_candidate(&mut self, prefix: Prefix, source: Source, entry: Entry) {
        self.candidates.insert((prefix, source), entry);
        self.by_prefix.entry(prefix).or_default().insert(source);
        self.by_source.entry(source).or_default().insert(prefix);
    }

    /// Remove a candidate slot and drop tracker dependents for any
    /// Recursive next-hops it held. Returns the removed entry so
    /// callers can react to its tag/etc. if needed.
    fn delete_candidate(&mut self, prefix: Prefix, source: Source) -> Option<Entry> {
        let entry = self.candidates.remove(&(prefix, source))?;
        if let Some(set) = self.by_prefix.get_mut(&prefix) {
            set.remove(&source);
            if set.is_empty() {
                self.by_prefix.remove(&prefix);
            }
        }
        if let Some(set) = self.by_source.get_mut(&source) {
            set.remove(&prefix);
            if set.is_empty() {
                self.by_source.remove(&source);
            }
        }
        for nh in &entry.next_hops {
            if nh.is_recursive() {
                self.nh_tracker
                    .remove_dependent(prefix.af, nh.addr, (prefix, source));
            }
        }
        Some(entry)
    }

    /// Add or replace a single (prefix, source) slot. Returns the
    /// set of deltas that affect the installed table — usually one
    /// (the prefix being upserted), but recursive cascades may add
    /// more if dependents change resolution.
    pub fn upsert(&mut self, route: &Route) -> Vec<Delta> {
        let new_entry = Entry::from_route(route);
        let af = route.prefix.af;

        // Drop tracker dependents for the previous version of this
        // candidate (if any). delete_candidate would also remove the
        // entry, so do this manually to avoid a churned re-insert.
        if let Some(prev) = self.candidates.get(&(route.prefix, route.source)) {
            for nh in &prev.next_hops {
                if nh.is_recursive() {
                    self.nh_tracker
                        .remove_dependent(af, nh.addr, (route.prefix, route.source));
                }
            }
        }
        for nh in &new_entry.next_hops {
            if nh.is_recursive() {
                self.nh_tracker
                    .add_dependent(af, nh.addr, (route.prefix, route.source));
            }
        }
        self.insert_candidate(route.prefix, route.source, new_entry);

        let mut deltas = Vec::new();
        let mut changed = Vec::new();
        if let Some(d) = self.recompute(route.prefix) {
            changed.push(d.prefix);
            deltas.push(d);
        }
        if !changed.is_empty() {
            self.cascade(changed, &mut deltas);
        }
        deltas
    }

    /// Remove a single (prefix, source) slot. Returns deltas for the
    /// installed-set changes (own withdrawal + any cascading
    /// dependent re-resolutions).
    pub fn remove(&mut self, prefix: Prefix, source: Source) -> Vec<Delta> {
        if self.delete_candidate(prefix, source).is_none() {
            return Vec::new();
        }
        let mut deltas = Vec::new();
        let mut changed = Vec::new();
        if let Some(d) = self.recompute(prefix) {
            changed.push(d.prefix);
            deltas.push(d);
        }
        if !changed.is_empty() {
            self.cascade(changed, &mut deltas);
        }
        deltas
    }

    /// Bulk replace everything from `source` with exactly `routes`.
    /// Returns the set of deltas that affect the installed table.
    pub fn bulk_replace(&mut self, source: Source, routes: &[Route]) -> Vec<Delta> {
        // Existing prefixes for this source — O(this_source's_count).
        let existing: Vec<Prefix> = self
            .by_source
            .get(&source)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();

        let mut incoming: HashMap<Prefix, Entry> = HashMap::with_capacity(routes.len());
        for r in routes {
            // Defensive: if producer pushes multiple routes for the
            // same prefix in one Bulk, the last one wins.
            incoming.insert(r.prefix, Entry::from_route(r));
        }

        let mut deltas = Vec::new();
        let mut changed_prefixes: Vec<Prefix> = Vec::new();

        // Prefixes that vanish in this bulk.
        for p in &existing {
            if !incoming.contains_key(p) {
                self.delete_candidate(*p, source);
                if let Some(d) = self.recompute(*p) {
                    changed_prefixes.push(d.prefix);
                    deltas.push(d);
                }
            }
        }
        // Prefixes that arrive or change.
        for (prefix, entry) in incoming {
            let af = prefix.af;
            // Update tracker for the difference between previous and
            // new next-hops. Same shape as upsert above.
            if let Some(prev) = self.candidates.get(&(prefix, source)) {
                for nh in &prev.next_hops {
                    if nh.is_recursive() {
                        self.nh_tracker
                            .remove_dependent(af, nh.addr, (prefix, source));
                    }
                }
            }
            for nh in &entry.next_hops {
                if nh.is_recursive() {
                    self.nh_tracker
                        .add_dependent(af, nh.addr, (prefix, source));
                }
            }
            self.insert_candidate(prefix, source, entry);
            if let Some(d) = self.recompute(prefix) {
                changed_prefixes.push(d.prefix);
                deltas.push(d);
            }
        }
        // One cascade pass at the end of the whole bulk.
        if !changed_prefixes.is_empty() {
            self.cascade(changed_prefixes, &mut deltas);
        }
        deltas
    }

    /// Drop every candidate from `source`. Returns deltas for any
    /// installed changes (used on client disconnect / expiry).
    pub fn drop_source(&mut self, source: Source) -> Vec<Delta> {
        let prefixes: Vec<Prefix> = self
            .by_source
            .get(&source)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        let mut deltas = Vec::new();
        let mut changed_prefixes: Vec<Prefix> = Vec::new();
        for p in prefixes {
            self.delete_candidate(p, source);
            if let Some(d) = self.recompute(p) {
                changed_prefixes.push(d.prefix);
                deltas.push(d);
            }
        }
        if !changed_prefixes.is_empty() {
            self.cascade(changed_prefixes, &mut deltas);
        }
        deltas
    }

    /// Recompute the winner for one prefix. If the installed state
    /// changed (including disappearing or going held), return a
    /// Delta. Resolves Recursive next-hops against the *current*
    /// installed table.
    fn recompute(&mut self, prefix: Prefix) -> Option<Delta> {
        // Use by_prefix to limit the scan to this prefix's candidate
        // set — typically 1-2 entries, never the whole RIB.
        let best = self
            .by_prefix
            .get(&prefix)
            .and_then(|sources| {
                sources
                    .iter()
                    .filter_map(|src| {
                        self.candidates
                            .get(&(prefix, *src))
                            .map(|e| (*src, e.clone()))
                    })
                    .min_by(|(sa, ea), (sb, eb)| {
                        ea.admin_distance
                            .cmp(&eb.admin_distance)
                            .then(ea.metric.cmp(&eb.metric))
                            .then(sa.cmp(sb))
                    })
            });

        let resolved = best.and_then(|(src, entry)| {
            self.try_resolve(prefix, &entry).map(|ie| (src, ie))
        });

        let previous = self.installed.get(&prefix).cloned();
        match (previous, resolved) {
            (None, None) => None,
            (None, Some((src, entry))) => {
                let installed = to_installed(prefix, src, &entry);
                self.installed.insert(prefix, (src, entry));
                Some(Delta {
                    prefix,
                    new: Some(installed),
                })
            }
            (Some(_), None) => {
                self.installed.remove(&prefix);
                Some(Delta { prefix, new: None })
            }
            (Some((psrc, pentry)), Some((nsrc, nentry))) => {
                if psrc == nsrc && pentry == nentry {
                    None
                } else {
                    let installed = to_installed(prefix, nsrc, &nentry);
                    self.installed.insert(prefix, (nsrc, nentry));
                    Some(Delta {
                        prefix,
                        new: Some(installed),
                    })
                }
            }
        }
    }

    /// Attempt to materialize an [`InstalledEntry`] from a
    /// candidate. Resolves any Recursive next-hops against the
    /// current installed table. Returns `None` if the candidate
    /// has Recursive next-hops and *none* of them resolve (held).
    ///
    /// Resolution policy:
    /// - All-Direct candidate: pass through unchanged.
    /// - Mixed Direct + Recursive: Direct paths kept, Recursive
    ///   ones expanded to the LPM winner's Direct paths. If a
    ///   Recursive nexthop fails to resolve, it's silently dropped
    ///   from the path set; the route still installs as long as at
    ///   least one path survives.
    /// - All-Recursive, none resolve: held (returns None).
    fn try_resolve(&self, prefix: Prefix, entry: &Entry) -> Option<InstalledEntry> {
        if !entry.has_recursive() {
            return Some(InstalledEntry {
                admin_distance: entry.admin_distance,
                metric: entry.metric,
                direct_next_hops: entry.next_hops.clone(),
                tag: entry.tag,
                resolved_via: None,
            });
        }

        let mut direct_paths: Vec<NextHop> = Vec::new();
        let mut resolved_via: Option<ResolvedNextHop> = None;

        for nh in &entry.next_hops {
            match nh.kind {
                NextHopKind::Direct => direct_paths.push(*nh),
                NextHopKind::Recursive => {
                    if let Some(res) = self.lpm_resolve(prefix.af, nh.addr) {
                        // Preserve the *original recursive next-hop
                        // IP* as the new L3 destination; use the LPM
                        // winner's egress interface for the
                        // sw_if_index. This is the standard BGP NHT
                        // shape: VPP / kernel ARP/ND for the
                        // recursive IP itself on the resolved
                        // outgoing interface. Copying the resolved
                        // route's nexthop verbatim would either give
                        // us a zero L3 nexthop (for connected routes)
                        // or the wrong L3 nexthop (for transitive
                        // recursive resolutions).
                        for resolved_path in &res.direct_paths {
                            let egress = NextHop {
                                kind: NextHopKind::Direct,
                                addr: nh.addr,
                                sw_if_index: resolved_path.sw_if_index,
                            };
                            if !direct_paths.contains(&egress) {
                                direct_paths.push(egress);
                            }
                        }
                        // Record provenance of the first successful
                        // resolution; subsequent ones are visible in
                        // direct_paths but only one winner is named.
                        if resolved_via.is_none() {
                            resolved_via = Some(ResolvedNextHop {
                                recursive_addr: nh.addr,
                                through_prefix: res.through_prefix,
                            });
                        }
                    }
                }
            }
        }

        if direct_paths.is_empty() {
            return None;
        }

        Some(InstalledEntry {
            admin_distance: entry.admin_distance,
            metric: entry.metric,
            direct_next_hops: direct_paths,
            tag: entry.tag,
            resolved_via,
        })
    }

    /// Longest-prefix-match resolution over the installed table.
    /// Probes each prefix length from the longest possible down to
    /// /0, masking the address and doing a direct HashMap lookup at
    /// each length. O(prefix-bit-count) regardless of table size:
    /// 33 lookups for v4, 129 for v6. Avoids the linear scan that
    /// dominated cost at DFZ scale.
    ///
    /// Skips matches whose installed entry has no Direct paths
    /// (held-via-cycle defense).
    fn lpm_resolve(&self, af: Af, addr: [u8; 16]) -> Option<NhResolution> {
        let max_len = match af {
            Af::V4 => 32u8,
            Af::V6 => 128u8,
        };
        for len in (0..=max_len).rev() {
            let masked = mask_addr(af, addr, len);
            let probe = Prefix { af, addr: masked, len };
            if let Some((_src, entry)) = self.installed.get(&probe) {
                if entry.direct_next_hops.is_empty() {
                    continue;
                }
                return Some(NhResolution {
                    direct_paths: entry.direct_next_hops.clone(),
                    through_prefix: probe,
                });
            }
        }
        None
    }

    /// After a set of prefixes have changed installed state, walk
    /// the tracker for any entries whose recursive address falls
    /// inside one of those prefixes (only those entries' dependents
    /// could possibly need re-resolution) and recompute each
    /// dependent. Recompute's own previous-vs-new comparison decides
    /// whether to emit a Delta; the tracker is just a pure
    /// dependency index. Bounded to [`CASCADE_ITERATION_BOUND`]
    /// iterations so a pathological iBGP-via-iBGP cycle can't loop
    /// forever.
    fn cascade(&mut self, mut changed: Vec<Prefix>, deltas: &mut Vec<Delta>) {
        for _ in 0..CASCADE_ITERATION_BOUND {
            if changed.is_empty() {
                break;
            }
            let round = std::mem::take(&mut changed);

            // Collect the set of dependents to recompute. Dedupe so
            // we don't recompute the same prefix twice in one round
            // when several recursive nexthops resolve through the
            // same changed underlay prefix. Tracker entries are
            // keyed by AF, so cross-family changes are naturally
            // skipped.
            let mut dependents_to_recompute: HashSet<(Prefix, Source)> = HashSet::new();
            for changed_prefix in &round {
                for ((af, addr), deps) in &self.nh_tracker.entries {
                    if *af != changed_prefix.af {
                        continue;
                    }
                    if prefix_contains_addr(changed_prefix, addr) {
                        for dep in deps {
                            dependents_to_recompute.insert(*dep);
                        }
                    }
                }
            }

            for (dep_prefix, _dep_source) in dependents_to_recompute {
                if let Some(d) = self.recompute(dep_prefix) {
                    // The dependent's own installed state changed —
                    // it might in turn cover some other tracker
                    // entry (iBGP-via-iBGP). Queue it for the next
                    // iteration.
                    changed.push(d.prefix);
                    deltas.push(d);
                }
            }
        }
    }

    pub fn installed_routes(&self) -> Vec<InstalledRoute> {
        self.installed
            .iter()
            .map(|(prefix, (src, entry))| to_installed(*prefix, *src, entry))
            .collect()
    }

    pub fn all_candidates(&self) -> Vec<PrefixCandidates> {
        // Group candidates by prefix.
        let mut by_prefix: HashMap<Prefix, Vec<(Source, Entry)>> = HashMap::new();
        for ((prefix, source), entry) in &self.candidates {
            by_prefix
                .entry(*prefix)
                .or_default()
                .push((*source, entry.clone()));
        }
        let mut out = Vec::new();
        for (prefix, mut entries) in by_prefix {
            entries.sort_by(|(sa, ea), (sb, eb)| {
                ea.admin_distance
                    .cmp(&eb.admin_distance)
                    .then(ea.metric.cmp(&eb.metric))
                    .then(sa.cmp(sb))
            });
            let installed_src = self.installed.get(&prefix).map(|(s, _)| *s);
            let candidates = entries
                .into_iter()
                .map(|(source, entry)| {
                    let held = entry.has_recursive() && self.try_resolve(prefix, &entry).is_none();
                    Candidate {
                        source,
                        admin_distance: entry.admin_distance,
                        metric: entry.metric,
                        next_hops: entry.next_hops,
                        installed: Some(source) == installed_src,
                        held,
                    }
                })
                .collect();
            out.push(PrefixCandidates { prefix, candidates });
        }
        out
    }
}

fn to_installed(prefix: Prefix, source: Source, entry: &InstalledEntry) -> InstalledRoute {
    InstalledRoute {
        prefix,
        source,
        admin_distance: entry.admin_distance,
        metric: entry.metric,
        next_hops: entry.direct_next_hops.clone(),
        resolved_via: entry.resolved_via.clone(),
    }
}

/// Mask `addr` to its first `len` bits, zeroing the rest. Used by
/// [`Rib::lpm_resolve`] to construct the canonical prefix at each
/// length for a HashMap probe. V4 only touches the first 4 bytes
/// (the rest are already zero by convention).
fn mask_addr(af: Af, addr: [u8; 16], len: u8) -> [u8; 16] {
    let nbytes_total = match af {
        Af::V4 => 4,
        Af::V6 => 16,
    };
    let mut out = [0u8; 16];
    let plen = len as usize;
    let full_bytes = (plen / 8).min(nbytes_total);
    let tail_bits = plen % 8;
    out[..full_bytes].copy_from_slice(&addr[..full_bytes]);
    if tail_bits > 0 && full_bytes < nbytes_total {
        let mask = 0xFFu8 << (8 - tail_bits);
        out[full_bytes] = addr[full_bytes] & mask;
    }
    out
}

/// Return true if the 16-byte address `addr` falls inside `prefix`.
/// V4 prefixes only consider the first 4 bytes; V6 considers all 16.
fn prefix_contains_addr(prefix: &Prefix, addr: &[u8; 16]) -> bool {
    let nbytes_total = match prefix.af {
        ribd_proto::Af::V4 => 4,
        ribd_proto::Af::V6 => 16,
    };
    let plen = prefix.len as usize;
    if plen > nbytes_total * 8 {
        return false;
    }
    let full_bytes = plen / 8;
    let tail_bits = plen % 8;
    if prefix.addr[..full_bytes] != addr[..full_bytes] {
        return false;
    }
    if tail_bits > 0 {
        let mask = 0xFFu8 << (8 - tail_bits);
        if (prefix.addr[full_bytes] & mask) != (addr[full_bytes] & mask) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use ribd_proto::{NextHop, Prefix, Route, Source};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn r(prefix: Prefix, source: Source, metric: u32, nh_last: u8) -> Route {
        Route {
            prefix,
            source,
            next_hops: vec![NextHop::v4(Ipv4Addr::new(10, 0, 0, nh_last), 1)],
            metric,
            tag: 0,
            admin_distance: None,
        }
    }

    fn r_recursive(prefix: Prefix, source: Source, recursive_to: Ipv4Addr) -> Route {
        Route {
            prefix,
            source,
            next_hops: vec![NextHop::recursive_v4(recursive_to)],
            metric: 0,
            tag: 0,
            admin_distance: None,
        }
    }

    fn p4(a: u8, b: u8, c: u8, d: u8, len: u8) -> Prefix {
        Prefix::v4(Ipv4Addr::new(a, b, c, d), len)
    }

    /// Helper for tests: extract the (single expected) delta from
    /// a mutation that should produce exactly one.
    fn one(deltas: Vec<Delta>) -> Delta {
        assert_eq!(deltas.len(), 1, "expected exactly one delta, got {:?}", deltas);
        deltas.into_iter().next().unwrap()
    }

    #[test]
    fn test_single_source_upsert() {
        let mut rib = Rib::new();
        let d = rib.upsert(&r(p4(10, 1, 0, 0, 24), Source::OspfIntra, 10, 1));
        assert_eq!(d.len(), 1);
        assert_eq!(rib.installed_count(), 1);

        // Re-upserting identical route produces no delta.
        let d2 = rib.upsert(&r(p4(10, 1, 0, 0, 24), Source::OspfIntra, 10, 1));
        assert!(d2.is_empty());
    }

    #[test]
    fn test_ad_arbitration_bgp_beats_ospf() {
        let mut rib = Rib::new();
        let prefix = p4(10, 2, 0, 0, 24);

        let d1 = one(rib.upsert(&r(prefix, Source::OspfIntra, 10, 1)));
        assert_eq!(d1.new.unwrap().source, Source::OspfIntra);

        let d2 = one(rib.upsert(&r(prefix, Source::Bgp, 100, 2)));
        let inst = d2.new.unwrap();
        assert_eq!(inst.source, Source::Bgp);
        assert_eq!(inst.admin_distance, 20);
    }

    #[test]
    fn test_withdraw_winner_promotes_runner_up() {
        let mut rib = Rib::new();
        let prefix = p4(10, 3, 0, 0, 24);

        rib.upsert(&r(prefix, Source::OspfIntra, 10, 1));
        rib.upsert(&r(prefix, Source::Bgp, 100, 2));
        assert_eq!(rib.installed_routes()[0].source, Source::Bgp);

        let d = one(rib.remove(prefix, Source::Bgp));
        let inst = d.new.unwrap();
        assert_eq!(inst.source, Source::OspfIntra);
    }

    #[test]
    fn test_withdraw_only_candidate_removes_install() {
        let mut rib = Rib::new();
        let prefix = p4(10, 4, 0, 0, 24);
        rib.upsert(&r(prefix, Source::Static, 0, 1));
        let d = one(rib.remove(prefix, Source::Static));
        assert!(d.new.is_none());
        assert_eq!(rib.installed_count(), 0);
    }

    #[test]
    fn test_bulk_replace_deletes_missing() {
        let mut rib = Rib::new();
        let a = p4(10, 5, 1, 0, 24);
        let b = p4(10, 5, 2, 0, 24);
        let c = p4(10, 5, 3, 0, 24);

        rib.upsert(&r(a, Source::OspfIntra, 10, 1));
        rib.upsert(&r(b, Source::OspfIntra, 10, 1));
        rib.upsert(&r(c, Source::OspfIntra, 10, 1));
        assert_eq!(rib.installed_count(), 3);

        let deltas = rib.bulk_replace(
            Source::OspfIntra,
            &[
                r(a, Source::OspfIntra, 10, 1),
                r(c, Source::OspfIntra, 10, 1),
            ],
        );
        let withdrawals: Vec<_> = deltas.iter().filter(|d| d.new.is_none()).collect();
        assert_eq!(withdrawals.len(), 1);
        assert_eq!(withdrawals[0].prefix, b);
        assert_eq!(rib.installed_count(), 2);
    }

    #[test]
    fn test_drop_source_cascades() {
        let mut rib = Rib::new();
        let prefix = p4(10, 6, 0, 0, 24);
        rib.upsert(&r(prefix, Source::OspfIntra, 10, 1));
        rib.upsert(&r(prefix, Source::Bgp, 100, 2));
        assert_eq!(rib.installed_routes()[0].source, Source::Bgp);

        let deltas = rib.drop_source(Source::Bgp);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].new.as_ref().unwrap().source, Source::OspfIntra);
    }

    #[test]
    fn test_metric_breaks_ad_tie() {
        let mut rib = Rib::new();
        let prefix = p4(10, 7, 0, 0, 24);

        rib.upsert(&r(prefix, Source::OspfIntra, 20, 1));
        let d = one(rib.upsert(&r(prefix, Source::Ospf6Intra, 10, 2)));
        assert_eq!(d.new.unwrap().source, Source::Ospf6Intra);
    }

    #[test]
    fn test_per_route_ad_override() {
        let mut rib = Rib::new();
        let prefix = p4(10, 8, 0, 0, 24);

        rib.upsert(&r(prefix, Source::OspfIntra, 10, 1));
        let mut route = r(prefix, Source::Bgp, 100, 2);
        route.admin_distance = Some(200);
        let d = rib.upsert(&route);
        // BGP was never installed (lost to OSPF from the start) so
        // no delta is emitted.
        assert!(d.is_empty());
        assert_eq!(rib.installed_routes()[0].source, Source::OspfIntra);
    }

    #[test]
    fn test_all_candidates_marks_installed() {
        let mut rib = Rib::new();
        let prefix = p4(10, 9, 0, 0, 24);
        rib.upsert(&r(prefix, Source::OspfIntra, 10, 1));
        rib.upsert(&r(prefix, Source::Bgp, 100, 2));

        let cands = rib.all_candidates();
        assert_eq!(cands.len(), 1);
        let pc = &cands[0];
        assert_eq!(pc.candidates.len(), 2);
        let installed: Vec<_> = pc.candidates.iter().filter(|c| c.installed).collect();
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].source, Source::Bgp);
    }

    // ---------- recursive next-hop tests ----------

    #[test]
    fn test_prefix_contains_addr_v4() {
        let p = p4(10, 0, 0, 0, 24);
        let inside = {
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&[10, 0, 0, 5]);
            a
        };
        let outside = {
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&[10, 0, 1, 5]);
            a
        };
        assert!(prefix_contains_addr(&p, &inside));
        assert!(!prefix_contains_addr(&p, &outside));
        // /0 covers everything.
        assert!(prefix_contains_addr(&p4(0, 0, 0, 0, 0), &inside));
    }

    #[test]
    fn test_prefix_contains_addr_v6() {
        let p = Prefix::v6("2001:db8::".parse().unwrap(), 32);
        let inside = Ipv6Addr::from_str("2001:db8:1::1").unwrap().octets();
        let outside = Ipv6Addr::from_str("2001:db9::1").unwrap().octets();
        assert!(prefix_contains_addr(&p, &inside));
        assert!(!prefix_contains_addr(&p, &outside));
    }

    use std::str::FromStr;

    #[test]
    fn test_recursive_install_through_existing_igp_route() {
        let mut rib = Rib::new();
        // IGP route via a real interface.
        let igp_prefix = p4(10, 0, 0, 0, 24);
        rib.upsert(&r(igp_prefix, Source::OspfIntra, 10, 1));
        assert_eq!(rib.installed_count(), 1);

        // BGP route recursive through 10.0.0.5 (which falls inside
        // the IGP /24).
        let bgp_prefix = p4(192, 0, 2, 0, 24);
        let deltas =
            rib.upsert(&r_recursive(bgp_prefix, Source::Bgp, Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(deltas.len(), 1);
        let inst = deltas[0].new.as_ref().unwrap();
        assert_eq!(inst.source, Source::Bgp);
        assert_eq!(inst.next_hops.len(), 1);
        // The resolved direct path keeps the recursive nexthop IP
        // as the L3 destination (so VPP can ARP for it) and uses
        // the IGP route's egress interface for the sw_if_index.
        assert_eq!(&inst.next_hops[0].addr[..4], &[10, 0, 0, 5]);
        assert_eq!(inst.next_hops[0].sw_if_index, 1);
        // resolved_via captures the original recursive intent.
        let rv = inst.resolved_via.as_ref().unwrap();
        assert_eq!(&rv.recursive_addr[..4], &[10, 0, 0, 5]);
        assert_eq!(rv.through_prefix, igp_prefix);
    }

    #[test]
    fn test_recursive_with_no_underlying_route_is_held() {
        let mut rib = Rib::new();
        let bgp_prefix = p4(192, 0, 2, 0, 24);
        // No IGP route exists yet.
        let deltas = rib.upsert(&r_recursive(
            bgp_prefix,
            Source::Bgp,
            Ipv4Addr::new(10, 0, 0, 5),
        ));
        assert!(deltas.is_empty(), "held route must not produce deltas");
        assert_eq!(rib.installed_count(), 0);

        // The candidate should still be visible in all_candidates as held.
        let cands = rib.all_candidates();
        let pc = cands.iter().find(|p| p.prefix == bgp_prefix).unwrap();
        assert!(pc.candidates[0].held);
        assert!(!pc.candidates[0].installed);
    }

    #[test]
    fn test_held_route_installs_when_underlying_arrives() {
        let mut rib = Rib::new();
        let bgp_prefix = p4(192, 0, 2, 0, 24);
        // BGP route arrives first — held.
        let d1 = rib.upsert(&r_recursive(
            bgp_prefix,
            Source::Bgp,
            Ipv4Addr::new(10, 0, 0, 5),
        ));
        assert!(d1.is_empty());
        assert_eq!(rib.installed_count(), 0);

        // IGP route arrives — should install both prefixes via cascade.
        let igp_prefix = p4(10, 0, 0, 0, 24);
        let d2 = rib.upsert(&r(igp_prefix, Source::OspfIntra, 10, 1));
        // Delta for the IGP route plus a cascade delta for the BGP route.
        assert_eq!(d2.len(), 2);
        let prefixes: Vec<_> = d2.iter().map(|d| d.prefix).collect();
        assert!(prefixes.contains(&igp_prefix));
        assert!(prefixes.contains(&bgp_prefix));
        assert_eq!(rib.installed_count(), 2);
    }

    #[test]
    fn test_recursive_is_withdrawn_when_underlying_disappears() {
        let mut rib = Rib::new();
        let igp_prefix = p4(10, 0, 0, 0, 24);
        let bgp_prefix = p4(192, 0, 2, 0, 24);

        rib.upsert(&r(igp_prefix, Source::OspfIntra, 10, 1));
        rib.upsert(&r_recursive(bgp_prefix, Source::Bgp, Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(rib.installed_count(), 2);

        // Withdraw IGP. BGP should go back to held.
        let deltas = rib.remove(igp_prefix, Source::OspfIntra);
        assert_eq!(deltas.len(), 2);
        // Both deltas should have new=None (withdrawals).
        for d in &deltas {
            assert!(d.new.is_none(), "expected withdrawal, got {:?}", d);
        }
        assert_eq!(rib.installed_count(), 0);

        // BGP candidate remains, marked held.
        let cands = rib.all_candidates();
        let pc = cands.iter().find(|p| p.prefix == bgp_prefix).unwrap();
        assert!(pc.candidates[0].held);
    }

    #[test]
    fn test_recursive_inherits_ecmp_from_underlying() {
        let mut rib = Rib::new();
        let igp_prefix = p4(10, 0, 0, 0, 24);
        // Multipath IGP route with two direct paths on different
        // interfaces.
        let mut igp_route = r(igp_prefix, Source::OspfIntra, 10, 1);
        igp_route.next_hops = vec![
            NextHop::v4(Ipv4Addr::new(10, 0, 0, 1), 1),
            NextHop::v4(Ipv4Addr::new(10, 0, 0, 2), 2),
        ];
        rib.upsert(&igp_route);

        let bgp_prefix = p4(192, 0, 2, 0, 24);
        let deltas = rib.upsert(&r_recursive(
            bgp_prefix,
            Source::Bgp,
            Ipv4Addr::new(10, 0, 0, 5),
        ));
        let inst = deltas[0].new.as_ref().unwrap();
        assert_eq!(inst.next_hops.len(), 2, "BGP route should fan out across both IGP egresses");
        // Both resolved paths share the recursive nexthop IP as
        // the L3 destination, but differ in sw_if_index.
        for nh in &inst.next_hops {
            assert_eq!(&nh.addr[..4], &[10, 0, 0, 5]);
        }
        let mut sw_if_indexes: Vec<u32> = inst.next_hops.iter().map(|nh| nh.sw_if_index).collect();
        sw_if_indexes.sort();
        assert_eq!(sw_if_indexes, vec![1, 2]);
    }

    #[test]
    fn test_recursive_through_connected_route_works() {
        // Connected routes have a Direct nexthop with addr=zero
        // (no L3 next-hop, just an egress interface). Recursive
        // resolution through them must produce a Direct path that
        // keeps the original recursive IP — otherwise we'd push
        // a zero L3 nexthop into the FIB and VPP wouldn't know
        // what to ARP for. This is the case that broke the first
        // jt-router-style test against an FRR upstream peer.
        let mut rib = Rib::new();
        let connected_prefix = p4(172, 30, 0, 0, 24);
        let connected_route = Route {
            prefix: connected_prefix,
            source: Source::Connected,
            next_hops: vec![NextHop {
                kind: NextHopKind::Direct,
                addr: [0u8; 16],
                sw_if_index: 1,
            }],
            metric: 0,
            tag: 0,
            admin_distance: None,
        };
        rib.upsert(&connected_route);

        // BGP route via 172.30.0.1 (a peer on the connected /24).
        let bgp_prefix = p4(10, 99, 0, 0, 24);
        let deltas = rib.upsert(&r_recursive(
            bgp_prefix,
            Source::Bgp,
            Ipv4Addr::new(172, 30, 0, 1),
        ));
        assert_eq!(deltas.len(), 1);
        let inst = deltas[0].new.as_ref().unwrap();
        assert_eq!(inst.next_hops.len(), 1);
        assert_eq!(
            &inst.next_hops[0].addr[..4],
            &[172, 30, 0, 1],
            "recursive via connected route must keep the BGP nexthop IP, not zero"
        );
        assert_eq!(inst.next_hops[0].sw_if_index, 1);
    }

    #[test]
    fn test_nexthop_sharing_one_resolution_many_dependents() {
        // A single underlying route change should re-resolve once
        // (not per-dependent) and cascade to every dependent.
        let mut rib = Rib::new();
        let igp_prefix = p4(10, 0, 0, 0, 24);
        rib.upsert(&r(igp_prefix, Source::OspfIntra, 10, 1));

        // Push 5 BGP routes all recursive through the same nexthop.
        for i in 0..5 {
            let bp = p4(192, 0, 2, i, 32);
            rib.upsert(&r_recursive(bp, Source::Bgp, Ipv4Addr::new(10, 0, 0, 5)));
        }
        assert_eq!(rib.installed_count(), 6);

        // Tracker should have ONE entry for 10.0.0.5 with 5 dependents.
        let mut shared_addr = [0u8; 16];
        shared_addr[..4].copy_from_slice(&[10, 0, 0, 5]);
        let tracker_entry = rib.nh_tracker.entries.get(&(Af::V4, shared_addr)).unwrap();
        assert_eq!(tracker_entry.len(), 5);

        // Replace IGP route with a different egress.
        let mut new_igp = r(igp_prefix, Source::OspfIntra, 10, 9);
        new_igp.next_hops = vec![NextHop::v4(Ipv4Addr::new(10, 0, 0, 9), 7)];
        let deltas = rib.upsert(&new_igp);
        // 1 delta for the IGP route + 5 cascade deltas for the BGP routes.
        assert_eq!(deltas.len(), 6);

        // Verify all 5 BGP routes now resolve via the new egress.
        // The L3 destination stays the original recursive IP
        // (10.0.0.5), only the egress sw_if_index changes.
        for d in &deltas {
            if let Some(inst) = &d.new {
                if inst.source == Source::Bgp {
                    assert_eq!(inst.next_hops[0].sw_if_index, 7);
                    assert_eq!(&inst.next_hops[0].addr[..4], &[10, 0, 0, 5]);
                }
            }
        }
    }

    #[test]
    fn test_lpm_picks_longest_match() {
        let mut rib = Rib::new();
        // Two covering prefixes: /16 and /24. /24 should win.
        let p_short = p4(10, 0, 0, 0, 16);
        let p_long = p4(10, 0, 0, 0, 24);
        let mut short_route = r(p_short, Source::OspfIntra, 10, 1);
        short_route.next_hops = vec![NextHop::v4(Ipv4Addr::new(10, 99, 99, 1), 99)];
        rib.upsert(&short_route);
        rib.upsert(&r(p_long, Source::OspfIntra, 10, 1));

        let bgp_prefix = p4(192, 0, 2, 0, 24);
        let deltas = rib.upsert(&r_recursive(
            bgp_prefix,
            Source::Bgp,
            Ipv4Addr::new(10, 0, 0, 5),
        ));
        let inst = deltas[0].new.as_ref().unwrap();
        assert_eq!(inst.resolved_via.as_ref().unwrap().through_prefix, p_long);
        // Verify the resolved path came from the /24, not the /16.
        assert_eq!(inst.next_hops[0].sw_if_index, 1);
    }

    #[test]
    fn test_remove_clears_tracker_dependent() {
        let mut rib = Rib::new();
        let igp_prefix = p4(10, 0, 0, 0, 24);
        let bgp_prefix = p4(192, 0, 2, 0, 24);
        rib.upsert(&r(igp_prefix, Source::OspfIntra, 10, 1));
        rib.upsert(&r_recursive(bgp_prefix, Source::Bgp, Ipv4Addr::new(10, 0, 0, 5)));

        // Remove the BGP route.
        rib.remove(bgp_prefix, Source::Bgp);

        // Tracker should be empty (no dependents → entry removed).
        let mut shared_addr = [0u8; 16];
        shared_addr[..4].copy_from_slice(&[10, 0, 0, 5]);
        assert!(rib.nh_tracker.entries.get(&(Af::V4, shared_addr)).is_none());
    }
}
