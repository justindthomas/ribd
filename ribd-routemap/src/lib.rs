//! Route-map shared types and universal evaluator.
//!
//! Producers (bgpd, ospfd, future routing daemons) use this crate
//! to share a YAML schema and an evaluator for route-maps. The
//! universal clauses — prefix-list, prefix-length, source, tag,
//! metric, next-hop — live here. Daemon-specific clauses (BGP
//! communities, OSPF route-type, etc.) plug in via the generic
//! `M` (match) and `S` (set) extra parameters using serde's
//! `flatten`, so daemon-specific keys appear at the same YAML
//! indentation as the universal ones.
//!
//! # YAML shape
//!
//! ```yaml
//! route_maps:
//!   - name: my-prefixes-only
//!     statements:
//!       - seq: 10
//!         action: permit
//!         match:
//!           prefix_list: [23.177.24.0/24, 2602:f90e::/32]
//!         set:
//!           tag: 42
//!       - seq: 20
//!         action: deny
//! ```
//!
//! Empty-or-missing match/set blocks are valid: a statement with
//! no match clauses always matches; a statement with no set
//! clauses leaves the route untouched.
//!
//! # Default-deny
//!
//! A route that matches no statement falls off the end of the
//! map and is treated as **denied** — Cisco/FRR convention. An
//! empty map (zero statements) denies everything for the same
//! reason: a referenced map always reflects operator intent.
//!
//! # Evaluation
//!
//! Daemons own the per-route loop. They walk `RouteMap::statements`
//! in seq order, run [`Match::evaluate_universal`] (and any
//! daemon-specific match extras) against a [`MatchContext`] view of
//! the route, and on the first matching `Permit` apply
//! [`Set::apply_universal`] (and daemon-specific set extras) via a
//! [`SetContext`].

use std::net::IpAddr;

use ipnet::IpNet;
use ribd_proto::{Prefix, Source};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---- on-disk YAML types ----

/// Route-map statement action. `Permit` means the route is accepted
/// and any `set` clauses are applied; `Deny` means the route is
/// dropped (subsequent statements are not consulted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Permit,
    Deny,
}

/// On-disk shape of one entry in `route_maps:`. Use the default
/// `NoExtras` for `M`/`S` if the daemon doesn't need any extras
/// beyond the universal clauses.
#[derive(Debug, Clone, Deserialize)]
pub struct RouteMapYaml<M = NoExtras, S = NoExtras> {
    pub name: String,
    #[serde(default)]
    pub statements: Vec<StatementYaml<M, S>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatementYaml<M = NoExtras, S = NoExtras> {
    pub seq: u32,
    pub action: Action,
    #[serde(default, rename = "match")]
    pub match_: MatchYaml<M>,
    #[serde(default)]
    pub set: SetYaml<S>,
}

/// Universal match clauses + a daemon-specific extra block.
///
/// The `extra: E` field is `#[serde(flatten)]`, which lets daemon-
/// specific keys (like `as_path:` for bgpd or `route_type:` for
/// ospfd) sit at the same indentation as the universal clauses in
/// the on-disk YAML.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MatchYaml<E = NoExtras> {
    /// Exact-match prefix list. A route's prefix must equal one of
    /// these CIDRs to satisfy the clause. Use `prefix_length` for
    /// range-based filtering. Empty list = no constraint.
    #[serde(default)]
    pub prefix_list: Vec<String>,
    /// Acceptable prefix-length range, inclusive on both ends.
    #[serde(default)]
    pub prefix_length: Option<PrefixLengthRange>,
    /// Match against the route's ribd `Source`. Aliases are
    /// expanded at compile time: `ospf` matches all four OSPFv2
    /// subtypes, `ospf6` matches the four OSPFv3 subtypes, `bgp`
    /// matches both eBGP and iBGP. Empty list = no constraint.
    #[serde(default)]
    pub source: Vec<String>,
    /// Exact tag match. `None` = no constraint.
    #[serde(default)]
    pub tag: Option<u32>,
    /// Exact metric match (BGP MED, OSPF cost, etc.).
    #[serde(default)]
    pub metric: Option<u32>,
    /// Inclusive metric range. Mutually informative with `metric`;
    /// if both are set, both must hold.
    #[serde(default)]
    pub metric_range: Option<MetricRange>,
    /// Exact next-hop IP match.
    #[serde(default)]
    pub next_hop: Option<String>,
    /// Next-hop must fall within one of these CIDRs.
    #[serde(default)]
    pub next_hop_in: Vec<String>,
    /// Daemon-specific match extras. Flattened so daemon keys
    /// appear at the same level as the universal ones.
    #[serde(flatten)]
    pub extra: E,
}

/// Universal set clauses + a daemon-specific extra block.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SetYaml<E = NoExtras> {
    /// Replace the route's metric with this value.
    #[serde(default)]
    pub metric: Option<u32>,
    /// Add this delta to the route's metric (signed). Applied
    /// after `metric` if both are present.
    #[serde(default)]
    pub metric_add: Option<i32>,
    /// Replace the route's tag.
    #[serde(default)]
    pub tag: Option<u32>,
    /// Override the next-hop.
    #[serde(default)]
    pub next_hop: Option<String>,
    #[serde(flatten)]
    pub extra: E,
}

/// Inclusive prefix-length range for the `prefix_length:` match.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PrefixLengthRange {
    pub min: u8,
    pub max: u8,
}

/// Inclusive metric range for the `metric_range:` match.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MetricRange {
    pub min: u32,
    pub max: u32,
}

/// Default empty-extras marker used when a daemon doesn't add any
/// match/set clauses beyond the universal subset. Empty struct so
/// serde's `flatten` consumes zero fields.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct NoExtras {}

// ---- compiled / runtime form ----

/// A route-map ready for evaluation. Statements are sorted by
/// `seq` ascending; the daemon walks them in order until one
/// matches.
#[derive(Debug, Clone)]
pub struct RouteMap<M = NoExtras, S = NoExtras> {
    pub name: String,
    pub statements: Vec<Statement<M, S>>,
}

#[derive(Debug, Clone)]
pub struct Statement<M = NoExtras, S = NoExtras> {
    pub seq: u32,
    pub action: Action,
    pub match_: Match<M>,
    pub set: Set<S>,
}

#[derive(Debug, Clone, Default)]
pub struct Match<E = NoExtras> {
    pub prefix_list: Vec<Prefix>,
    pub prefix_length: Option<(u8, u8)>,
    pub source: Vec<Source>,
    pub tag: Option<u32>,
    pub metric: Option<u32>,
    pub metric_range: Option<(u32, u32)>,
    pub next_hop: Option<IpAddr>,
    pub next_hop_in: Vec<Prefix>,
    pub extra: E,
}

#[derive(Debug, Clone, Default)]
pub struct Set<E = NoExtras> {
    pub metric: Option<u32>,
    pub metric_add: Option<i32>,
    pub tag: Option<u32>,
    pub next_hop: Option<IpAddr>,
    pub extra: E,
}

// ---- compile errors ----

#[derive(Debug, Error)]
pub enum CompileError {
    #[error("invalid CIDR prefix: {0}")]
    BadPrefix(String),
    #[error("invalid IP address: {0}")]
    BadIp(String),
    #[error("unknown source name: {0}")]
    BadSource(String),
    #[error("invalid prefix-length range {min}..={max}")]
    BadPrefixLengthRange { min: u8, max: u8 },
    #[error("invalid metric range {min}..={max}")]
    BadMetricRange { min: u32, max: u32 },
}

// ---- compile impls ----

impl<M, S> RouteMapYaml<M, S> {
    /// Compile the YAML form into the runtime form. Statements are
    /// sorted by `seq` ascending. Errors on unparseable prefixes,
    /// IPs, sources, or invalid ranges. Daemon extras are passed
    /// through unchanged — daemons compile their own extras
    /// separately if they need to.
    pub fn compile(self) -> Result<RouteMap<M, S>, CompileError> {
        let mut statements = Vec::with_capacity(self.statements.len());
        for s in self.statements {
            statements.push(s.compile()?);
        }
        statements.sort_by_key(|s| s.seq);
        Ok(RouteMap {
            name: self.name,
            statements,
        })
    }
}

impl<M, S> StatementYaml<M, S> {
    pub fn compile(self) -> Result<Statement<M, S>, CompileError> {
        Ok(Statement {
            seq: self.seq,
            action: self.action,
            match_: self.match_.compile()?,
            set: self.set.compile()?,
        })
    }
}

impl<E> MatchYaml<E> {
    pub fn compile(self) -> Result<Match<E>, CompileError> {
        let prefix_list = self
            .prefix_list
            .iter()
            .map(|s| parse_prefix(s))
            .collect::<Result<Vec<_>, _>>()?;
        let prefix_length = self
            .prefix_length
            .map(|r| {
                if r.min > r.max || r.max > 128 {
                    Err(CompileError::BadPrefixLengthRange {
                        min: r.min,
                        max: r.max,
                    })
                } else {
                    Ok((r.min, r.max))
                }
            })
            .transpose()?;
        let mut source = Vec::new();
        for s in &self.source {
            source.extend(parse_source(s)?);
        }
        let metric_range = self
            .metric_range
            .map(|r| {
                if r.min > r.max {
                    Err(CompileError::BadMetricRange {
                        min: r.min,
                        max: r.max,
                    })
                } else {
                    Ok((r.min, r.max))
                }
            })
            .transpose()?;
        let next_hop = self
            .next_hop
            .as_deref()
            .map(parse_ip)
            .transpose()?;
        let next_hop_in = self
            .next_hop_in
            .iter()
            .map(|s| parse_prefix(s))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Match {
            prefix_list,
            prefix_length,
            source,
            tag: self.tag,
            metric: self.metric,
            metric_range,
            next_hop,
            next_hop_in,
            extra: self.extra,
        })
    }
}

impl<E> SetYaml<E> {
    pub fn compile(self) -> Result<Set<E>, CompileError> {
        let next_hop = self
            .next_hop
            .as_deref()
            .map(parse_ip)
            .transpose()?;
        Ok(Set {
            metric: self.metric,
            metric_add: self.metric_add,
            tag: self.tag,
            next_hop,
            extra: self.extra,
        })
    }
}

// ---- match / set context traits ----

/// Read-side adapter implemented by daemons for their native route
/// type. The universal evaluator calls these to extract the fields
/// it needs.
pub trait MatchContext {
    fn prefix(&self) -> Prefix;
    fn source(&self) -> Source;
    fn tag(&self) -> Option<u32> {
        None
    }
    fn metric(&self) -> Option<u32> {
        None
    }
    fn next_hop(&self) -> Option<IpAddr> {
        None
    }
}

/// Write-side adapter for daemons. The universal applier calls
/// these to push set-clause changes into the route. Default impls
/// no-op so daemons can implement only the fields they care about.
pub trait SetContext {
    fn set_metric(&mut self, _m: u32) {}
    fn add_metric(&mut self, _delta: i32) {}
    fn set_tag(&mut self, _t: u32) {}
    fn set_next_hop(&mut self, _nh: IpAddr) {}
}

// ---- evaluators ----

impl<E> Match<E> {
    /// Evaluate the universal clauses against `ctx`. Returns true
    /// iff every populated clause is satisfied. Daemons must AND
    /// this with their own evaluation of `self.extra` to get the
    /// full match decision.
    pub fn evaluate_universal<C: MatchContext>(&self, ctx: &C) -> bool {
        if !self.prefix_list.is_empty() {
            let p = ctx.prefix();
            if !self.prefix_list.iter().any(|q| prefix_eq(q, &p)) {
                return false;
            }
        }
        if let Some((min, max)) = self.prefix_length {
            let len = ctx.prefix().len;
            if len < min || len > max {
                return false;
            }
        }
        if !self.source.is_empty() && !self.source.contains(&ctx.source()) {
            return false;
        }
        if let Some(t) = self.tag {
            if ctx.tag() != Some(t) {
                return false;
            }
        }
        if let Some(m) = self.metric {
            if ctx.metric() != Some(m) {
                return false;
            }
        }
        if let Some((min, max)) = self.metric_range {
            let met = ctx.metric().unwrap_or(0);
            if met < min || met > max {
                return false;
            }
        }
        if let Some(nh) = self.next_hop {
            if ctx.next_hop() != Some(nh) {
                return false;
            }
        }
        if !self.next_hop_in.is_empty() {
            let Some(nh) = ctx.next_hop() else {
                return false;
            };
            if !self.next_hop_in.iter().any(|p| ip_in_prefix(p, nh)) {
                return false;
            }
        }
        true
    }
}

impl<E> Set<E> {
    /// Apply the universal set clauses to `ctx`. Order:
    /// `metric` (replace) before `metric_add` (delta), then
    /// `tag`, then `next_hop`. Daemon extras run separately.
    pub fn apply_universal<C: SetContext>(&self, ctx: &mut C) {
        if let Some(m) = self.metric {
            ctx.set_metric(m);
        }
        if let Some(d) = self.metric_add {
            ctx.add_metric(d);
        }
        if let Some(t) = self.tag {
            ctx.set_tag(t);
        }
        if let Some(nh) = self.next_hop {
            ctx.set_next_hop(nh);
        }
    }
}

// ---- helpers ----

/// Two prefixes are equal if AF, address bytes within the prefix
/// length, and length all agree. Bytes outside the prefix length
/// are ignored — callers that pass canonicalized prefixes get the
/// same answer either way.
fn prefix_eq(a: &Prefix, b: &Prefix) -> bool {
    if a.af != b.af || a.len != b.len {
        return false;
    }
    let bits = a.len as usize;
    let full_bytes = bits / 8;
    let extra_bits = bits % 8;
    if a.addr[..full_bytes] != b.addr[..full_bytes] {
        return false;
    }
    if extra_bits == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - extra_bits);
    (a.addr[full_bytes] & mask) == (b.addr[full_bytes] & mask)
}

/// Whether `ip` falls inside `prefix`. AF must agree.
fn ip_in_prefix(prefix: &Prefix, ip: IpAddr) -> bool {
    match (prefix.af, ip) {
        (ribd_proto::Af::V4, IpAddr::V4(v)) => {
            let octets = v.octets();
            byte_match(&prefix.addr[..4], &octets, prefix.len)
        }
        (ribd_proto::Af::V6, IpAddr::V6(v)) => {
            let octets = v.octets();
            byte_match(&prefix.addr, &octets, prefix.len)
        }
        _ => false,
    }
}

fn byte_match(prefix_bytes: &[u8], addr_bytes: &[u8], len: u8) -> bool {
    let bits = len as usize;
    let full_bytes = bits / 8;
    let extra_bits = bits % 8;
    if prefix_bytes[..full_bytes] != addr_bytes[..full_bytes] {
        return false;
    }
    if extra_bits == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - extra_bits);
    (prefix_bytes[full_bytes] & mask) == (addr_bytes[full_bytes] & mask)
}

fn parse_prefix(s: &str) -> Result<Prefix, CompileError> {
    let net: IpNet = s.parse().map_err(|_| CompileError::BadPrefix(s.into()))?;
    Ok(match net {
        IpNet::V4(v) => Prefix::v4(v.network(), v.prefix_len()),
        IpNet::V6(v) => Prefix::v6(v.network(), v.prefix_len()),
    })
}

fn parse_ip(s: &str) -> Result<IpAddr, CompileError> {
    s.parse::<IpAddr>().map_err(|_| CompileError::BadIp(s.into()))
}

/// Resolve a `source:` string to one or more ribd `Source` values.
/// Supports umbrella aliases (`ospf`, `ospf6`, `bgp`) that expand
/// to all subtypes; also accepts the canonical names from
/// [`Source::as_str`].
fn parse_source(s: &str) -> Result<Vec<Source>, CompileError> {
    Ok(match s {
        "connected" => vec![Source::Connected],
        "static" => vec![Source::Static],
        "dhcp-pd" => vec![Source::DhcpPd],
        "ospf" => vec![
            Source::OspfIntra,
            Source::OspfInter,
            Source::OspfExt1,
            Source::OspfExt2,
        ],
        "ospf-intra" => vec![Source::OspfIntra],
        "ospf-inter" => vec![Source::OspfInter],
        "ospf-ext1" => vec![Source::OspfExt1],
        "ospf-ext2" => vec![Source::OspfExt2],
        "ospf6" => vec![
            Source::Ospf6Intra,
            Source::Ospf6Inter,
            Source::Ospf6Ext1,
            Source::Ospf6Ext2,
        ],
        "ospf6-intra" => vec![Source::Ospf6Intra],
        "ospf6-inter" => vec![Source::Ospf6Inter],
        "ospf6-ext1" => vec![Source::Ospf6Ext1],
        "ospf6-ext2" => vec![Source::Ospf6Ext2],
        "bgp" => vec![Source::Bgp, Source::BgpInternal],
        "bgp-external" => vec![Source::Bgp],
        "bgp-internal" => vec![Source::BgpInternal],
        other => return Err(CompileError::BadSource(other.into())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ribd_proto::{Af, Prefix, Source};
    use std::net::{Ipv4Addr, Ipv6Addr};

    struct TestRoute {
        prefix: Prefix,
        source: Source,
        tag: Option<u32>,
        metric: Option<u32>,
        next_hop: Option<IpAddr>,
    }

    impl MatchContext for TestRoute {
        fn prefix(&self) -> Prefix {
            self.prefix
        }
        fn source(&self) -> Source {
            self.source
        }
        fn tag(&self) -> Option<u32> {
            self.tag
        }
        fn metric(&self) -> Option<u32> {
            self.metric
        }
        fn next_hop(&self) -> Option<IpAddr> {
            self.next_hop
        }
    }

    impl SetContext for TestRoute {
        fn set_metric(&mut self, m: u32) {
            self.metric = Some(m);
        }
        fn add_metric(&mut self, d: i32) {
            let cur = self.metric.unwrap_or(0) as i64;
            self.metric = Some((cur + d as i64).max(0) as u32);
        }
        fn set_tag(&mut self, t: u32) {
            self.tag = Some(t);
        }
        fn set_next_hop(&mut self, nh: IpAddr) {
            self.next_hop = Some(nh);
        }
    }

    fn route_v4(addr: [u8; 4], len: u8, source: Source) -> TestRoute {
        TestRoute {
            prefix: Prefix::v4(Ipv4Addr::from(addr), len),
            source,
            tag: None,
            metric: None,
            next_hop: None,
        }
    }

    #[test]
    fn yaml_round_trip_universal_only() {
        let blob = r#"
name: my-prefixes-only
statements:
  - seq: 10
    action: permit
    match:
      prefix_list:
        - "23.177.24.0/24"
        - "2602:f90e::/32"
    set:
      tag: 42
  - seq: 20
    action: deny
"#;
        let yaml: RouteMapYaml = serde_yaml::from_str(blob).unwrap();
        let map = yaml.compile().unwrap();
        assert_eq!(map.name, "my-prefixes-only");
        assert_eq!(map.statements.len(), 2);
        assert_eq!(map.statements[0].seq, 10);
        assert_eq!(map.statements[0].action, Action::Permit);
        assert_eq!(map.statements[0].match_.prefix_list.len(), 2);
        assert_eq!(map.statements[0].set.tag, Some(42));
        assert_eq!(map.statements[1].action, Action::Deny);
    }

    #[test]
    fn statements_sorted_by_seq_after_compile() {
        let yaml: RouteMapYaml = serde_yaml::from_str(
            r#"
name: out-of-order
statements:
  - { seq: 30, action: deny }
  - { seq: 10, action: permit }
  - { seq: 20, action: deny }
"#,
        )
        .unwrap();
        let map = yaml.compile().unwrap();
        let seqs: Vec<u32> = map.statements.iter().map(|s| s.seq).collect();
        assert_eq!(seqs, vec![10, 20, 30]);
    }

    #[test]
    fn empty_match_block_matches_anything() {
        let m = Match::<NoExtras>::default();
        let r = route_v4([10, 0, 0, 0], 8, Source::Connected);
        assert!(m.evaluate_universal(&r));
    }

    #[test]
    fn prefix_list_exact_match() {
        let m = Match::<NoExtras> {
            prefix_list: vec![Prefix::v4(Ipv4Addr::new(10, 0, 0, 0), 8)],
            ..Default::default()
        };
        assert!(m.evaluate_universal(&route_v4([10, 0, 0, 0], 8, Source::Static)));
        assert!(!m.evaluate_universal(&route_v4([10, 0, 0, 0], 16, Source::Static)));
        assert!(!m.evaluate_universal(&route_v4([192, 168, 0, 0], 16, Source::Static)));
    }

    #[test]
    fn prefix_length_range_inclusive() {
        let m = Match::<NoExtras> {
            prefix_length: Some((24, 32)),
            ..Default::default()
        };
        assert!(m.evaluate_universal(&route_v4([10, 0, 0, 0], 24, Source::Connected)));
        assert!(m.evaluate_universal(&route_v4([10, 0, 0, 0], 32, Source::Connected)));
        assert!(!m.evaluate_universal(&route_v4([10, 0, 0, 0], 16, Source::Connected)));
    }

    #[test]
    fn source_alias_ospf_expands_at_compile() {
        let yaml: RouteMapYaml = serde_yaml::from_str(
            r#"
name: ospf-only
statements:
  - seq: 10
    action: permit
    match:
      source: [ospf]
"#,
        )
        .unwrap();
        let map = yaml.compile().unwrap();
        let s = &map.statements[0].match_.source;
        assert_eq!(s.len(), 4);
        assert!(s.contains(&Source::OspfIntra));
        assert!(s.contains(&Source::OspfExt2));
    }

    #[test]
    fn source_alias_bgp_covers_external_and_internal() {
        let v = parse_source("bgp").unwrap();
        assert!(v.contains(&Source::Bgp));
        assert!(v.contains(&Source::BgpInternal));
    }

    #[test]
    fn source_unknown_errors() {
        assert!(matches!(
            parse_source("isis"),
            Err(CompileError::BadSource(_))
        ));
    }

    #[test]
    fn next_hop_in_v4_match() {
        let m = Match::<NoExtras> {
            next_hop_in: vec![Prefix::v4(Ipv4Addr::new(10, 0, 0, 0), 8)],
            ..Default::default()
        };
        let mut r = route_v4([192, 0, 2, 0], 24, Source::Connected);
        r.next_hop = Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(m.evaluate_universal(&r));

        r.next_hop = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!m.evaluate_universal(&r));

        r.next_hop = None;
        assert!(!m.evaluate_universal(&r));
    }

    #[test]
    fn next_hop_in_v6_match() {
        let m = Match::<NoExtras> {
            next_hop_in: vec![Prefix::v6("2001:db8::".parse().unwrap(), 32)],
            ..Default::default()
        };
        let mut r = TestRoute {
            prefix: Prefix::v6("2001:db8::1".parse::<Ipv6Addr>().unwrap(), 128),
            source: Source::Connected,
            tag: None,
            metric: None,
            next_hop: Some(IpAddr::V6("2001:db8:1::1".parse().unwrap())),
        };
        assert!(m.evaluate_universal(&r));
        r.next_hop = Some(IpAddr::V6("2001:db9::1".parse().unwrap()));
        assert!(!m.evaluate_universal(&r));
    }

    #[test]
    fn metric_range_bounds() {
        let m = Match::<NoExtras> {
            metric_range: Some((100, 200)),
            ..Default::default()
        };
        let mut r = route_v4([10, 0, 0, 0], 8, Source::Connected);
        r.metric = Some(150);
        assert!(m.evaluate_universal(&r));
        r.metric = Some(99);
        assert!(!m.evaluate_universal(&r));
        r.metric = Some(201);
        assert!(!m.evaluate_universal(&r));
    }

    #[test]
    fn apply_universal_set_clauses() {
        let s = Set::<NoExtras> {
            metric: Some(100),
            metric_add: Some(50),
            tag: Some(7),
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            ..Default::default()
        };
        let mut r = route_v4([10, 0, 0, 0], 8, Source::Connected);
        s.apply_universal(&mut r);
        assert_eq!(r.metric, Some(150));
        assert_eq!(r.tag, Some(7));
        assert_eq!(r.next_hop, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    }

    #[test]
    fn compile_rejects_bad_prefix() {
        let yaml: RouteMapYaml = serde_yaml::from_str(
            r#"
name: bad
statements:
  - seq: 10
    action: permit
    match:
      prefix_list: ["not-a-cidr"]
"#,
        )
        .unwrap();
        assert!(matches!(yaml.compile(), Err(CompileError::BadPrefix(_))));
    }

    #[test]
    fn compile_rejects_inverted_prefix_length() {
        let yaml: RouteMapYaml = serde_yaml::from_str(
            r#"
name: bad
statements:
  - seq: 10
    action: permit
    match:
      prefix_length:
        min: 30
        max: 20
"#,
        )
        .unwrap();
        assert!(matches!(
            yaml.compile(),
            Err(CompileError::BadPrefixLengthRange { .. })
        ));
    }

    #[test]
    fn daemon_extras_flatten_into_match() {
        #[derive(Debug, Default, Clone, Deserialize)]
        struct DaemonMatch {
            #[serde(default)]
            community: Vec<String>,
        }

        let yaml: RouteMapYaml<DaemonMatch> = serde_yaml::from_str(
            r#"
name: with-extras
statements:
  - seq: 10
    action: permit
    match:
      prefix_list: ["10.0.0.0/8"]
      community: ["65000:100", "65000:200"]
"#,
        )
        .unwrap();
        let map = yaml.compile().unwrap();
        assert_eq!(
            map.statements[0].match_.extra.community,
            vec!["65000:100".to_string(), "65000:200".to_string()]
        );
        assert_eq!(map.statements[0].match_.prefix_list.len(), 1);
    }

    #[test]
    fn prefix_eq_matches_canonical_only_within_len() {
        // Two prefixes with same len but different bytes outside
        // the masked region should compare equal, so callers don't
        // need to canonicalize before lookup.
        let a = Prefix {
            af: Af::V4,
            addr: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            len: 8,
        };
        let b = Prefix {
            af: Af::V4,
            addr: [10, 99, 99, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            len: 8,
        };
        assert!(prefix_eq(&a, &b));
    }
}
