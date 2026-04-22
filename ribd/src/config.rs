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
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpAddress {
    pub address: String,
    pub prefix: u8,
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct StaticRoute {
    pub destination: String,
    #[serde(default)]
    pub via: String,
    #[serde(default)]
    pub interface: Option<String>,
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
                    if let Ok(net) = format!("{}/{}", a.address, a.prefix)
                        .parse::<ipnet::Ipv4Net>()
                    {
                        if net.contains(&v4) {
                            return Some(iface.name.clone());
                        }
                    }
                }
            }
            IpAddr::V6(v6) => {
                for a in &iface.ipv6 {
                    if let Ok(net) = format!("{}/{}", a.address, a.prefix)
                        .parse::<ipnet::Ipv6Net>()
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
        assert_eq!(cfg.interfaces[0].ipv4[0].address, "23.177.24.9");
        assert_eq!(cfg.interfaces[0].ipv4[0].prefix, 31);
        assert_eq!(cfg.interfaces[0].subinterfaces.len(), 1);
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.routes[0].via, "23.177.24.8");
    }

    #[test]
    fn resolve_parent_interface() {
        let ifaces = vec![Interface {
            name: "wan".into(),
            ipv4: vec![IpAddress {
                address: "23.177.24.9".into(),
                prefix: 31,
            }],
            ipv6: vec![],
            subinterfaces: vec![],
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
            }],
        }];
        let via: std::net::IpAddr = "192.168.37.1".parse().unwrap();
        assert_eq!(
            resolve_via_interface(via, &ifaces).as_deref(),
            Some("lan.110")
        );
    }

    #[test]
    fn resolve_misses_nonmatching_subnet() {
        let ifaces = vec![Interface {
            name: "wan".into(),
            ipv4: vec![IpAddress {
                address: "23.177.24.9".into(),
                prefix: 31,
            }],
            ipv6: vec![],
            subinterfaces: vec![],
        }];
        let via: std::net::IpAddr = "8.8.8.8".parse().unwrap();
        assert!(resolve_via_interface(via, &ifaces).is_none());
    }
}
