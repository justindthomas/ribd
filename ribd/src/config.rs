//! Router.yaml reader — the subset ribd cares about.
//!
//! ribd owns Source::Static (from `routes:`) and the config side of
//! Source::Connected (from `interfaces:` IPs) directly, so it can
//! resolve recursive next-hops without depending on impd having
//! already programmed VPP. That fixes a chicken-and-egg at startup
//! where VPP's ip_address_dump returns nothing until impd's live
//! apply runs, leaving ribd's connected table empty and any
//! recursive next-hop unresolvable.
//!
//! This parser is intentionally lenient — unknown fields on the
//! interface/subinterface/route schemas are ignored (serde default
//! behavior without `deny_unknown_fields`). impd owns the canonical
//! schema; ribd just skims what it needs and ignores the rest so we
//! don't have to keep the two schemas in lockstep.
//!
//! If the file is missing or fails to parse, ribd logs and returns
//! an empty config. The existing VPP-dump seeding path still runs,
//! so ribd degrades to its prior behavior rather than crashing.

use std::path::Path;

use serde::Deserialize;

pub const DEFAULT_CONFIG_PATH: &str = "/persistent/config/router.yaml";

/// Top-level file shape — only the sections ribd needs. Other keys
/// (hostname, management, dhcp_server, sfw, bgp, ospf, etc.) are
/// silently ignored.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RouterConfig {
    #[serde(default)]
    pub interfaces: Vec<Interface>,
    #[serde(default)]
    pub routes: Vec<StaticRoute>,
    #[serde(default)]
    pub loopbacks: Vec<Loopback>,
    #[serde(default)]
    pub bvi_domains: Vec<BviDomain>,
    #[serde(default)]
    pub tunnels: Vec<Tunnel>,
    /// Declared VRFs. impd's apply path is the only thing that
    /// validates this list; ribd just consumes it to translate
    /// `routes[].vrf` (a name) into a table-id at static-build
    /// time. Default-VRF entries (vrf empty / "default") never
    /// reach this list — they pass through with table_id 0.
    #[serde(default)]
    pub vrfs: Vec<Vrf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Vrf {
    pub name: String,
    pub table_id_v4: u32,
    pub table_id_v6: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Interface {
    pub name: String,
    #[serde(default)]
    pub ipv4: Vec<IpAddress>,
    #[serde(default)]
    pub ipv6: Vec<IpAddress>,
    #[serde(default)]
    pub subinterfaces: Vec<SubInterface>,
    /// VRF this interface is placed in. Empty / absent / "default"
    /// means the implicit default VRF (table 0). Otherwise must
    /// match a declared VRF name in `cfg.vrfs`; callers pull
    /// `table_id_v4` / `table_id_v6` from there when building
    /// Source::Connected entries so per-VRF and default-VRF
    /// interfaces don't collide on prefix.
    #[serde(default)]
    pub vrf: Option<String>,
}

/// An IP address on an interface. impd writes a CIDR string today;
/// the legacy `{address, prefix}` map is also accepted via the
/// untagged enum so existing yaml round-trips during the schema
/// migration. Mirrors the same pattern ospfd's `Ipv4AddressConfig`
/// and dhcpd's `Ipv4AddressConfig` use — keeping daemon-side schemas
/// aligned so any impd serializer shape lands cleanly across the
/// routing stack.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum IpAddress {
    Cidr(String),
    Split { address: String, prefix: u8 },
}

impl IpAddress {
    /// Parse into (address, prefix). Returns None when a CIDR
    /// variant doesn't carry a numeric prefix.
    pub fn as_pair(&self) -> Option<(&str, u8)> {
        match self {
            IpAddress::Cidr(s) => {
                let (a, p) = s.split_once('/')?;
                let plen: u8 = p.parse().ok()?;
                Some((a, plen))
            }
            IpAddress::Split { address, prefix } => Some((address.as_str(), *prefix)),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubInterface {
    pub vlan_id: i32,
    #[serde(default)]
    pub ipv4: Option<String>,
    #[serde(default)]
    pub ipv4_prefix: Option<u8>,
    #[serde(default)]
    pub ipv6: Option<String>,
    #[serde(default)]
    pub ipv6_prefix: Option<u8>,
    /// VRF the sub-interface lives in; same semantics as
    /// `Interface.vrf`. A sub may sit in a different VRF from its
    /// parent (that's the whole point of sub-interface VRFs), so we
    /// can't just inherit.
    #[serde(default)]
    pub vrf: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StaticRoute {
    pub destination: String,
    #[serde(default)]
    pub via: String,
    #[serde(default)]
    pub interface: Option<String>,
    /// VRF the route belongs to. Empty / absent / "default" means
    /// the implicit default VRF (table 0). Otherwise must match a
    /// declared VRF name; ribd looks up the matching `Vrf` and
    /// pulls `table_id_v4` / `table_id_v6` based on the prefix's
    /// address family.
    #[serde(default)]
    pub vrf: Option<String>,
}

/// Loopback interface yaml shape. Minimal — only the fields needed
/// to emit a connected route. VPP names these `loop<instance>`.
#[derive(Debug, Clone, Deserialize)]
pub struct Loopback {
    pub instance: u32,
    #[serde(default)]
    pub ipv4: Option<String>,
    #[serde(default)]
    pub ipv4_prefix: Option<u8>,
    #[serde(default)]
    pub ipv6: Option<String>,
    #[serde(default)]
    pub ipv6_prefix: Option<u8>,
    /// Same semantics as `Interface.vrf`.
    #[serde(default)]
    pub vrf: Option<String>,
}

/// BVI yaml shape. VPP names these `bvi<bridge_id>`.
#[derive(Debug, Clone, Deserialize)]
pub struct BviDomain {
    pub bridge_id: u32,
    #[serde(default)]
    pub ipv4: Option<String>,
    #[serde(default)]
    pub ipv4_prefix: Option<u8>,
    #[serde(default)]
    pub ipv6: Option<String>,
    #[serde(default)]
    pub ipv6_prefix: Option<u8>,
    /// Same semantics as `Interface.vrf`.
    #[serde(default)]
    pub vrf: Option<String>,
}

/// GRE tunnel yaml shape. VPP names these `gre<instance>`. impd
/// writes `tunnel_ip` / `tunnel_prefix` (no `_v4` suffix); accept
/// both so a future impd schema rename doesn't quietly hide tunnel
/// addresses from ribd's connected-build.
#[derive(Debug, Clone, Deserialize)]
pub struct Tunnel {
    pub name: String,
    /// Inner v4 address(es). ecrd writes `tunnel_ip` as a list of
    /// `{address, prefix}` (the same untagged `IpAddress` shape interfaces
    /// use); a bare CIDR string in the list is also accepted. `tunnel_ipv4`
    /// is kept as a back-compat alias. ribd builds a Connected route per entry.
    #[serde(default, alias = "tunnel_ipv4")]
    pub tunnel_ip: Vec<IpAddress>,
    /// Inner v6 address(es), same shape.
    #[serde(default)]
    pub tunnel_ipv6: Vec<IpAddress>,
    /// Inner / L3 endpoint VRF (which FIB the tunnel address lives
    /// in). Same semantics as `Interface.vrf`.
    #[serde(default)]
    pub vrf: Option<String>,
    /// Outer / source VRF — which FIB the encapsulated GRE traffic
    /// is forwarded through. Carried here for schema parity with
    /// impd; ribd itself only cares about the inner VRF because
    /// that's where the connected route for the tunnel address
    /// lands. Storing it lets a future ribd feature surface it
    /// without needing another schema bump.
    #[serde(default)]
    pub source_vrf: Option<String>,
}

impl RouterConfig {
    /// Resolve a (possibly empty / "default") vrf name to its
    /// (v4_id, v6_id) table pair. Returns `(0, 0)` for the implicit
    /// default VRF and for any name that doesn't appear in
    /// `cfg.vrfs` — same lenient fallback the rest of the
    /// connected-build path uses (a typo'd VRF name shouldn't
    /// vanish the Connected route, just keep it in default).
    pub fn vrf_tables(&self, vrf: Option<&str>) -> (u32, u32) {
        let name = match vrf {
            Some(n) if !n.is_empty() && n != "default" => n,
            _ => return (0, 0),
        };
        match self.vrfs.iter().find(|v| v.name == name) {
            Some(v) => (v.table_id_v4, v.table_id_v6),
            None => (0, 0),
        }
    }
}

/// Load `/persistent/config/router.yaml` (or `path`). Returns an
/// empty config if the file is missing or malformed, after logging.
pub fn load(path: impl AsRef<Path>) -> RouterConfig {
    let path = path.as_ref();
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(path = %path.display(), "config: read failed: {}", e);
            return RouterConfig::default();
        }
    };
    match serde_yaml::from_str::<RouterConfig>(&text) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!(path = %path.display(), "config: parse failed: {}", e);
            RouterConfig::default()
        }
    }
}

/// Walk configured interfaces looking for one whose connected
/// subnet contains `via`. Returns the interface's VPP-side name,
/// which callers pair with the sw_if_index resolver.
///
/// Subinterfaces are checked after their parents so a gateway that
/// sits inside a VLAN doesn't accidentally match the parent's
/// unrelated address. Same semantics as the impd-side helper this
/// replaces (intentional — keeps operator-visible behavior stable).
pub fn resolve_via_interface(
    via: std::net::IpAddr,
    interfaces: &[Interface],
) -> Option<String> {
    use std::net::IpAddr;

    for iface in interfaces {
        match via {
            IpAddr::V4(v4) => {
                for a in &iface.ipv4 {
                    let Some((addr, prefix)) = a.as_pair() else { continue };
                    if let Ok(net) =
                        format!("{}/{}", addr, prefix).parse::<ipnet::Ipv4Net>()
                    {
                        if net.contains(&v4) {
                            return Some(iface.name.clone());
                        }
                    }
                }
            }
            IpAddr::V6(v6) => {
                for a in &iface.ipv6 {
                    let Some((addr, prefix)) = a.as_pair() else { continue };
                    if let Ok(net) =
                        format!("{}/{}", addr, prefix).parse::<ipnet::Ipv6Net>()
                    {
                        if net.contains(&v6) {
                            return Some(iface.name.clone());
                        }
                    }
                }
            }
        }

        for sub in &iface.subinterfaces {
            let sub_name = format!("{}.{}", iface.name, sub.vlan_id);
            match via {
                IpAddr::V4(v4) => {
                    if let (Some(addr), Some(prefix)) = (&sub.ipv4, sub.ipv4_prefix) {
                        if let Ok(net) =
                            format!("{}/{}", addr, prefix).parse::<ipnet::Ipv4Net>()
                        {
                            if net.contains(&v4) {
                                return Some(sub_name);
                            }
                        }
                    }
                }
                IpAddr::V6(v6) => {
                    if let (Some(addr), Some(prefix)) = (&sub.ipv6, sub.ipv6_prefix) {
                        if let Ok(net) =
                            format!("{}/{}", addr, prefix).parse::<ipnet::Ipv6Net>()
                        {
                            if net.contains(&v6) {
                                return Some(sub_name);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let yaml = r#"
hostname: router
interfaces:
  - name: wan
    ipv4:
      - address: 23.177.24.9
        prefix: 31
    subinterfaces:
      - vlan_id: 110
        ipv4: 192.168.37.4
        ipv4_prefix: 24
routes:
  - destination: 0.0.0.0/0
    via: 23.177.24.8
dhcp_server:
  enabled: true
"#;
        let cfg: RouterConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.interfaces.len(), 1);
        assert_eq!(cfg.interfaces[0].name, "wan");
        assert_eq!(
            cfg.interfaces[0].ipv4[0].as_pair(),
            Some(("23.177.24.9", 31u8)),
        );
        assert_eq!(cfg.interfaces[0].subinterfaces.len(), 1);
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.routes[0].via, "23.177.24.8");
    }

    #[test]
    fn resolve_parent_interface() {
        let ifaces = vec![Interface {
            name: "wan".into(),
            ipv4: vec![IpAddress::Split {
                address: "23.177.24.9".into(),
                prefix: 31,
            }],
            ipv6: vec![],
            subinterfaces: vec![],
            vrf: None,
        }];
        let via: std::net::IpAddr = "23.177.24.8".parse().unwrap();
        assert_eq!(resolve_via_interface(via, &ifaces).as_deref(), Some("wan"));
    }

    #[test]
    fn resolve_subinterface() {
        let ifaces = vec![Interface {
            name: "lan".into(),
            ipv4: vec![],
            ipv6: vec![],
            subinterfaces: vec![SubInterface {
                vlan_id: 110,
                ipv4: Some("192.168.37.4".into()),
                ipv4_prefix: Some(24),
                ipv6: None,
                ipv6_prefix: None,
                vrf: None,
            }],
            vrf: None,
        }];
        let via: std::net::IpAddr = "192.168.37.1".parse().unwrap();
        assert_eq!(
            resolve_via_interface(via, &ifaces).as_deref(),
            Some("lan.110")
        );
    }

    #[test]
    fn parses_vrfs_and_per_route_vrf() {
        let yaml = r#"
vrfs:
  - name: customer_vrf
    table_id_v4: 10
    table_id_v6: 10
routes:
  - destination: 0.0.0.0/0
    via: 192.168.37.1
    vrf: customer_vrf
  - destination: 10.50.0.0/24
    via: 23.177.24.8
"#;
        let cfg: RouterConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.vrfs.len(), 1);
        assert_eq!(cfg.vrfs[0].name, "customer_vrf");
        assert_eq!(cfg.vrfs[0].table_id_v4, 10);
        assert_eq!(cfg.routes.len(), 2);
        assert_eq!(cfg.routes[0].vrf.as_deref(), Some("customer_vrf"));
        assert_eq!(cfg.routes[1].vrf, None);
    }

    #[test]
    fn resolve_misses_nonmatching_subnet() {
        let ifaces = vec![Interface {
            name: "wan".into(),
            ipv4: vec![IpAddress::Split {
                address: "23.177.24.9".into(),
                prefix: 31,
            }],
            ipv6: vec![],
            subinterfaces: vec![],
            vrf: None,
        }];
        let via: std::net::IpAddr = "8.8.8.8".parse().unwrap();
        assert!(resolve_via_interface(via, &ifaces).is_none());
    }

    /// Lock in that both wire shapes deserialise — CIDR string (what
    /// the current impd serializer emits) and split-map (the legacy
    /// form). Either should yield the same `(addr, prefix)` pair via
    /// `as_pair()` so downstream consumers stay schema-agnostic.
    #[test]
    fn ip_address_accepts_both_cidr_and_split() {
        let yaml = r#"
interfaces:
- name: wan
  ipv4:
  - 23.177.24.9/31
  - address: 10.0.0.1
    prefix: 24
  ipv6:
  - 2602:f90e::101/127
"#;
        let cfg: RouterConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.interfaces[0].ipv4.len(), 2);
        assert_eq!(
            cfg.interfaces[0].ipv4[0].as_pair(),
            Some(("23.177.24.9", 31u8)),
        );
        assert_eq!(
            cfg.interfaces[0].ipv4[1].as_pair(),
            Some(("10.0.0.1", 24u8)),
        );
        assert_eq!(
            cfg.interfaces[0].ipv6[0].as_pair(),
            Some(("2602:f90e::101", 127u8)),
        );
    }
}
