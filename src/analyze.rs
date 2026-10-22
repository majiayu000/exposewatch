//! Exposure levels, matching against the feed, and scoring.

use crate::catalog::{self, Catalog};
use crate::feed::{Feed, Kev};
use crate::model::{Binding, Service};
use crate::version;
use serde::Serialize;
use std::collections::BTreeSet;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Exposure {
    None,
    Loopback,
    Lan,
    AllInterfaces,
    Proxied,
    Internet,
}

impl Exposure {
    pub fn weight(self) -> f64 {
        match self {
            Exposure::Internet => 1.0,
            Exposure::Proxied => 0.9,
            Exposure::AllInterfaces => 0.7,
            Exposure::Lan => 0.3,
            Exposure::Loopback => 0.1,
            Exposure::None => 0.05,
        }
    }

    /// The "open to the internet" condition of the main list.
    pub fn is_public(self) -> bool {
        self >= Exposure::AllInterfaces
    }

    pub fn label(self) -> &'static str {
        match self {
            Exposure::Internet => "internet (confirmed)",
            Exposure::Proxied => "via reverse proxy",
            Exposure::AllInterfaces => "all interfaces",
            Exposure::Lan => "LAN only",
            Exposure::Loopback => "loopback only",
            Exposure::None => "not published",
        }
    }
}

const INTERNAL_SUFFIXES: [&str; 6] = [
    ".local",
    ".lan",
    ".home.arpa",
    ".internal",
    ".localhost",
    ".test",
];

pub fn binding_exposure(b: &Binding, external_ports: &BTreeSet<u16>) -> Exposure {
    if b.listening == Some(false) {
        return Exposure::None;
    }
    let port_seen = b
        .host_port
        .as_deref()
        .and_then(|p| p.parse::<u16>().ok())
        .is_some_and(|p| external_ports.contains(&p));
    if b.host_ip.is_empty() {
        return if port_seen {
            Exposure::Internet
        } else {
            Exposure::AllInterfaces
        };
    }
    match b.host_ip.parse::<IpAddr>() {
        Ok(ip) if ip.is_loopback() => Exposure::Loopback,
        Ok(ip) if is_private(&ip) => Exposure::Lan,
        Ok(_) if port_seen => Exposure::Internet,
        // A specific public address, or a name/variable we cannot resolve offline.
        _ => Exposure::AllInterfaces,
    }
}

pub fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Hostnames routed to this service by Traefik or caddy-docker-proxy labels.
pub fn routed_hosts(s: &Service) -> Vec<String> {
    if s.labels.get("traefik.enable").map(String::as_str) == Some("false") {
        return Vec::new();
    }
    let mut hosts = Vec::new();
    for (k, v) in &s.labels {
        if k.starts_with("traefik.http.routers.") && k.ends_with(".rule") {
            // Host(`a.example.com`) || Host(`b.example.com`, `c.example.com`)
            for part in v.split("Host(").skip(1) {
                let inner = part.split(')').next().unwrap_or("");
                hosts.extend(
                    inner
                        .split(',')
                        .map(|h| h.trim().trim_matches(['`', '"', '\'']).to_string()),
                );
            }
        } else if k == "caddy"
            || k.strip_prefix("caddy_")
                .is_some_and(|n| n.chars().all(|c| c.is_ascii_digit()))
        {
            hosts.extend(v.split([' ', ',']).filter(|h| !h.is_empty()).map(|h| {
                h.trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .to_string()
            }));
        }
    }
    hosts.retain(|h| !h.is_empty());
    hosts
}

pub fn is_internal_host(h: &str) -> bool {
    let h = h.to_ascii_lowercase();
    !h.contains('.')
        || h.parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback() || is_private(&ip))
        || INTERNAL_SUFFIXES.iter().any(|s| h.ends_with(s))
}

#[derive(Debug, Serialize)]
pub struct Hit {
    pub cve: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kev: Option<Kev>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
    pub range_source: String,
}

#[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    /// Public + vulnerable version + exploited: the main list.
    Act,
    /// Vulnerable and exploited, but not published to all interfaces.
    NotExposed,
    /// Cannot decide: unknown version, or a KEV entry without ranges.
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub category: Category,
    pub score: f64,
    pub service: String,
    pub source: String,
    pub image: String,
    pub product: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub exposure: Exposure,
    pub exposure_detail: Vec<String>,
    pub privilege: Vec<String>,
    pub hits: Vec<Hit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade_to: Option<String>,
    pub fix: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub feed_source: String,
    pub kev_catalog_version: String,
    pub epss_date: String,
    pub epss_min: f64,
    pub services_scanned: usize,
    pub findings: Vec<Finding>,
    /// Services whose image is not in the catalog (not checked).
    pub unrecognized: Vec<String>,
}

fn privilege(s: &Service) -> Vec<String> {
    let mut p = Vec::new();
    if s.privileged {
        p.push("privileged".to_string());
    }
    if s.docker_socket {
        p.push("docker socket mounted".to_string());
    }
    if s.host_network {
        p.push("host network".to_string());
    }
    if s.root == Some(true) {
        p.push("runs as root".to_string());
    }
    for c in &s.cap_add {
        if ["SYS_ADMIN", "NET_ADMIN", "ALL"].contains(&c.trim_start_matches("CAP_")) {
            p.push(format!("cap_add {c}"));
        }
    }
    p
}

fn exposure_of(
    s: &Service,
    all: &[Service],
    catalog: &Catalog,
    external: &BTreeSet<u16>,
) -> (Exposure, Vec<String>) {
    let mut level = Exposure::None;
    let mut detail = Vec::new();
    if s.host_network {
        level = Exposure::AllInterfaces;
        detail.push("network_mode: host (every listening port is on the host)".into());
    }
    for b in &s.ports {
        let e = binding_exposure(b, external);
        level = level.max(e);
        let ip = if b.host_ip.is_empty() {
            "0.0.0.0"
        } else {
            &b.host_ip
        };
        let hp = b.host_port.as_deref().unwrap_or("random");
        let probe = match b.listening {
            Some(true) => " (probe: open)",
            Some(false) => " (probe: closed)",
            None => "",
        };
        detail.push(format!(
            "{ip}:{hp}->{}/{}{probe}",
            b.container_port, b.proto
        ));
    }
    let hosts = routed_hosts(s);
    if !hosts.is_empty() && !catalog.is_proxy(&s.image) {
        // Best proxy published in the same scan source.
        let proxy = all
            .iter()
            .filter(|p| p.source == s.source && catalog.is_proxy(&p.image))
            .map(|p| exposure_of(p, &[], catalog, external).0)
            .max();
        let public: Vec<&String> = hosts.iter().filter(|h| !is_internal_host(h)).collect();
        match proxy {
            Some(pe) if pe.is_public() && !public.is_empty() => {
                level = level.max(if pe == Exposure::Internet {
                    Exposure::Internet
                } else {
                    Exposure::Proxied
                });
                detail.push(format!(
                    "routed by reverse proxy as {}",
                    public
                        .iter()
                        .map(|h| h.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            Some(pe) if pe.is_public() => {
                level = level.max(Exposure::Lan);
                detail.push(format!(
                    "routed by reverse proxy as internal name {}",
                    hosts.join(", ")
                ));
            }
            Some(pe) => detail.push(format!(
                "routed as {} by a reverse proxy that is {}",
                hosts.join(", "),
                pe.label()
            )),
            None => detail.push(format!(
                "has proxy route {} but no reverse proxy found in {}",
                hosts.join(", "),
                s.source
            )),
        }
    }
    (level, detail)
}

pub fn analyze(
    services: &[Service],
    catalog: &Catalog,
    feed: &Feed,
    feed_source: String,
    external: &BTreeSet<u16>,
) -> Report {
    let mut findings = Vec::new();
    let mut unrecognized = Vec::new();
    for s in services {
        let Some(product) = catalog.product_for(&s.image) else {
            unrecognized.push(format!(
                "{} ({})",
                s.name,
                if s.image.is_empty() {
                    "no image"
                } else {
                    &s.image
                }
            ));
            continue;
        };
        let version = catalog::tag(&s.image)
            .and_then(version::extract)
            .or_else(|| s.label_version.clone());
        let (exposure, exposure_detail) = exposure_of(s, services, catalog, external);
        let privilege = privilege(s);
        let vulns = feed
            .products
            .get(&product.key)
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        let mut hits = Vec::new();
        let mut unknown_ranges = Vec::new();
        if let Some(v) = &version {
            for vuln in vulns {
                if vuln.ranges.is_empty() {
                    if vuln.kev.is_some() {
                        unknown_ranges.push(vuln.cve.clone());
                    }
                    continue;
                }
                if let Some(r) = vuln.ranges.iter().find(|r| r.contains(v)) {
                    hits.push(Hit {
                        cve: vuln.cve.clone(),
                        kev: vuln.kev.clone(),
                        epss: vuln.epss,
                        fixed: r.fix(),
                        range_source: vuln.range_source.clone(),
                    });
                }
            }
        }
        hits.sort_by(|a, b| {
            (
                b.kev.as_ref().map(|k| k.date_added.clone()),
                b.epss.map(|e| (e * 1e6) as i64),
            )
                .cmp(&(
                    a.kev.as_ref().map(|k| k.date_added.clone()),
                    a.epss.map(|e| (e * 1e6) as i64),
                ))
        });

        let (category, note) = if version.is_none() {
            let why = if s.source == "docker" {
                "the tag has no version and the image has no version label"
            } else {
                "the tag has no version (compose files carry no image labels; scan the running container instead)"
            };
            (
                Category::Unknown,
                Some(format!("version unknown: {why}; pin a versioned tag")),
            )
        } else if hits.is_empty() && !unknown_ranges.is_empty() {
            (
                Category::Unknown,
                Some(format!(
                    "no machine-readable affected range yet for KEV {}; check the vendor advisory",
                    unknown_ranges.join(", ")
                )),
            )
        } else if hits.is_empty() {
            continue;
        } else if exposure.is_public() {
            (Category::Act, None)
        } else {
            (Category::NotExposed, None)
        };

        let threat = if hits.iter().any(|h| h.kev.is_some()) {
            1.0
        } else {
            hits.iter().filter_map(|h| h.epss).fold(0.0, f64::max)
        };
        let priv_factor = (1.0 + 0.15 * privilege.len() as f64).min(1.5);
        let score = (100.0 * threat * exposure.weight() * priv_factor * 10.0).round() / 10.0;

        let upgrade_to = hits.iter().filter_map(|h| h.fixed.clone()).max_by(|a, b| {
            version::compare(a.trim_start_matches("> "), b.trim_start_matches("> "))
        });
        let fix = fixes(s, product, exposure, &privilege, upgrade_to.as_deref());
        findings.push(Finding {
            category,
            score,
            service: s.name.clone(),
            source: s.source.clone(),
            image: s.image.clone(),
            product: product.name.clone(),
            version,
            exposure,
            exposure_detail,
            privilege,
            hits,
            upgrade_to,
            fix,
            note,
        });
    }
    findings.sort_by(|a, b| {
        a.category
            .cmp(&b.category)
            .then(b.score.total_cmp(&a.score))
            .then(a.service.cmp(&b.service))
    });
    Report {
        feed_source,
        kev_catalog_version: feed.kev_catalog_version.clone(),
        epss_date: feed.epss_date.clone(),
        epss_min: feed.epss_min,
        services_scanned: services.len(),
        findings,
        unrecognized,
    }
}

fn fixes(
    s: &Service,
    product: &crate::catalog::Product,
    exposure: Exposure,
    privilege: &[String],
    upgrade: Option<&str>,
) -> Vec<String> {
    let mut f = Vec::new();
    if let Some(u) = upgrade {
        let target = u.strip_prefix("> ").map_or_else(
            || format!("{u} or later"),
            |v| format!("a release newer than {v}"),
        );
        f.push(format!("Upgrade {} to {target}.", product.name));
    }
    match exposure {
        Exposure::Internet | Exposure::AllInterfaces => {
            for b in s.ports.iter().filter(|b| b.host_ip.is_empty() && b.host_port.is_some()) {
                let hp = b.host_port.as_deref().unwrap_or_default();
                f.push(format!(
                    "Bind {hp} to loopback (\"127.0.0.1:{hp}:{}\") and reach it through a reverse proxy with authentication; remove any router port-forward for {hp} you do not need.",
                    b.container_port
                ));
            }
            if s.host_network {
                f.push("Drop network_mode: host and publish only the ports you need on 127.0.0.1.".into());
            }
        }
        Exposure::Proxied => f.push(
            "Put authentication (forward-auth / basic auth) or an IP allow-list in front of this route on the reverse proxy."
                .into(),
        ),
        _ => {}
    }
    if let Some(a) = &product.advice {
        f.push(a.clone());
    }
    if !privilege.is_empty() && privilege.iter().any(|p| p != "runs as root") {
        f.push(format!("Reduce privileges: {}.", privilege.join(", ")));
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose;
    use crate::feed::Vuln;
    use crate::version::Range;
    use std::collections::BTreeMap;

    fn feed() -> Feed {
        let mut products = BTreeMap::new();
        products.insert(
            "plex".into(),
            vec![Vuln {
                cve: "CVE-2026-96656".into(),
                kev: Some(Kev {
                    date_added: "2026-10-20".into(),
                    due_date: "2026-10-23".into(),
                    ransomware: false,
                }),
                epss: Some(0.00758),
                cvss: Some(8.6),
                ranges: vec![Range {
                    end_excluding: Some("1.43.3.10861".into()),
                    ..Default::default()
                }],
                range_source: "nvd".into(),
            }],
        );
        products.insert(
            "gitea".into(),
            vec![Vuln {
                cve: "CVE-2026-60004".into(),
                kev: Some(Kev {
                    date_added: "2026-08-25".into(),
                    due_date: "2026-08-28".into(),
                    ransomware: false,
                }),
                epss: None,
                cvss: None,
                ranges: vec![Range {
                    start_including: Some("1.17.0".into()),
                    end_excluding: Some("1.27.1".into()),
                    ..Default::default()
                }],
                range_source: "nvd".into(),
            }],
        );
        products.insert(
            "grafana".into(),
            vec![Vuln {
                cve: "CVE-2099-0001".into(),
                kev: Some(Kev {
                    date_added: "2099-01-01".into(),
                    due_date: String::new(),
                    ransomware: false,
                }),
                epss: None,
                cvss: None,
                ranges: vec![],
                range_source: "none".into(),
            }],
        );
        Feed {
            generated: String::new(),
            kev_catalog_version: "test".into(),
            epss_date: "test".into(),
            epss_min: 0.1,
            products,
        }
    }

    const COMPOSE: &str = r#"
services:
  plex:
    image: plexinc/pms-docker:1.43.2.10687-563d026ea
    ports: ["32400:32400"]
  plex-new:
    image: plexinc/pms-docker:1.43.3.10861-07dfddaeb
    ports: ["32401:32400"]
  plex-local:
    image: plexinc/pms-docker:1.43.2.10687-563d026ea
    ports: ["127.0.0.1:32402:32400"]
  traefik:
    image: traefik:v3.7.16
    ports: ["443:443"]
  gitea:
    image: gitea/gitea:1.26.4
    labels:
      traefik.http.routers.git.rule: Host(`git.example.com`)
  gitea-internal:
    image: gitea/gitea:1.26.4
    labels:
      traefik.http.routers.gi.rule: Host(`git.home.arpa`)
  grafana:
    image: grafana/grafana:8.2.6
  jelly:
    image: jellyfin/jellyfin:latest
  app:
    build: .
"#;

    #[test]
    fn ranks_public_exploited_first() {
        let services = compose::parse(COMPOSE, "c.yml").unwrap();
        let r = analyze(
            &services,
            &Catalog::load(None).unwrap(),
            &feed(),
            "test".into(),
            &BTreeSet::new(),
        );
        let got: Vec<(&str, Category, Exposure)> = r
            .findings
            .iter()
            .map(|f| (f.service.as_str(), f.category, f.exposure))
            .collect();
        assert_eq!(
            got,
            vec![
                ("gitea", Category::Act, Exposure::Proxied),
                ("plex", Category::Act, Exposure::AllInterfaces),
                ("gitea-internal", Category::NotExposed, Exposure::Lan),
                ("plex-local", Category::NotExposed, Exposure::Loopback),
                ("grafana", Category::Unknown, Exposure::None),
                ("jelly", Category::Unknown, Exposure::None),
            ]
        );
        let plex = &r.findings[1];
        assert_eq!(plex.upgrade_to.as_deref(), Some("1.43.3.10861"));
        assert!(plex.fix.iter().any(|f| f.contains("127.0.0.1:32400:32400")));
        assert_eq!(plex.score, 70.0);
        assert_eq!(r.unrecognized, vec!["app (no image)".to_string()]);
    }

    #[test]
    fn external_view_upgrades_to_internet() {
        let services = compose::parse(COMPOSE, "c.yml").unwrap();
        let ext: BTreeSet<u16> = [32400].into();
        let r = analyze(
            &services,
            &Catalog::load(None).unwrap(),
            &feed(),
            "test".into(),
            &ext,
        );
        let plex = r.findings.iter().find(|f| f.service == "plex").unwrap();
        assert_eq!(plex.exposure, Exposure::Internet);
        assert_eq!(plex.score, 100.0);
    }

    #[test]
    fn closed_probe_is_not_exposed() {
        let b = Binding {
            host_ip: String::new(),
            host_port: Some("1".into()),
            container_port: "1".into(),
            proto: "tcp".into(),
            listening: Some(false),
        };
        assert_eq!(binding_exposure(&b, &BTreeSet::new()), Exposure::None);
    }

    #[test]
    fn internal_hosts() {
        assert!(is_internal_host("git.home.arpa"));
        assert!(is_internal_host("nas"));
        assert!(is_internal_host("192.168.1.2"));
        assert!(!is_internal_host("git.example.com"));
    }
}
