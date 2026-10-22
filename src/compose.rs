//! Static analysis of docker compose files. Nothing is started.

use crate::model::{Binding, Service, is_root_user, is_socket_path};
use anyhow::{Context, Result, bail};
use serde_yaml_ng::Value;
use std::collections::BTreeMap;
use std::path::Path;

pub fn load(path: &Path) -> Result<Vec<Service>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse(&text, &path.display().to_string())
}

pub fn parse(text: &str, source: &str) -> Result<Vec<Service>> {
    let doc: Value = serde_yaml_ng::from_str(text).with_context(|| format!("parsing {source}"))?;
    let Some(services) = doc.get("services").and_then(Value::as_mapping) else {
        bail!("{source}: no `services:` section");
    };
    let mut out = Vec::new();
    for (name, svc) in services {
        let name = scalar(name).unwrap_or_default();
        let mut s = Service {
            name: svc.get("container_name").and_then(scalar).unwrap_or(name),
            source: source.to_string(),
            image: svc.get("image").and_then(scalar).unwrap_or_default(),
            labels: labels(svc.get("labels")),
            host_network: svc.get("network_mode").and_then(scalar).as_deref() == Some("host"),
            privileged: svc
                .get("privileged")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            root: svc.get("user").and_then(scalar).map(|u| is_root_user(&u)),
            cap_add: seq(svc.get("cap_add")),
            ..Default::default()
        };
        if let Some(ports) = svc.get("ports").and_then(Value::as_sequence) {
            for p in ports {
                s.ports
                    .push(port(p).with_context(|| {
                        format!("{source}: service {}: bad port {p:?}", s.name)
                    })?);
            }
        }
        s.docker_socket = svc
            .get("volumes")
            .and_then(Value::as_sequence)
            .is_some_and(|v| {
                v.iter()
                    .any(|m| volume_source(m).is_some_and(|src| is_socket_path(&src)))
            });
        out.push(s);
    }
    Ok(out)
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn seq(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_sequence)
        .map(|s| s.iter().filter_map(scalar).collect())
        .unwrap_or_default()
}

fn labels(v: Option<&Value>) -> BTreeMap<String, String> {
    match v {
        Some(Value::Mapping(m)) => m
            .iter()
            .filter_map(|(k, v)| Some((scalar(k)?, scalar(v).unwrap_or_default())))
            .collect(),
        Some(Value::Sequence(s)) => s
            .iter()
            .filter_map(scalar)
            .map(|l| match l.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (l, String::new()),
            })
            .collect(),
        _ => BTreeMap::new(),
    }
}

fn volume_source(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => s.split(':').next().map(str::to_string),
        Value::Mapping(_) => v.get("source").and_then(scalar),
        _ => None,
    }
}

/// Parse compose short (`[ip:]host:container[/proto]`, `container`) or long port syntax.
fn port(v: &Value) -> Result<Binding> {
    if let Value::Mapping(_) = v {
        let target = v
            .get("target")
            .and_then(scalar)
            .context("long syntax without target")?;
        return Ok(Binding {
            host_ip: v.get("host_ip").and_then(scalar).unwrap_or_default(),
            host_port: v.get("published").and_then(scalar),
            container_port: target,
            proto: v
                .get("protocol")
                .and_then(scalar)
                .unwrap_or_else(|| "tcp".into()),
            listening: None,
        });
    }
    let spec = scalar(v).context("port is not a string or number")?;
    let (spec, proto) = match spec.split_once('/') {
        Some((s, p)) => (s.to_string(), p.to_string()),
        None => (spec, "tcp".to_string()),
    };
    let (rest, container) = match spec.rsplit_once(':') {
        Some((r, c)) => (Some(r), c.to_string()),
        None => (None, spec.clone()),
    };
    let (host_ip, host_port) = match rest {
        None => (String::new(), None),
        Some(r) => match r.rsplit_once(':') {
            Some((ip, hp)) => (
                ip.trim_matches(['[', ']']).to_string(),
                Some(hp.to_string()),
            ),
            None => (String::new(), Some(r.to_string())),
        },
    };
    Ok(Binding {
        host_ip,
        host_port,
        container_port: container,
        proto,
        listening: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"
services:
  plex:
    image: plexinc/pms-docker:1.43.2.10687-563d026ea
    ports:
      - "32400:32400/tcp"
      - "127.0.0.1:8324:8324"
      - "[::1]:9000:9000"
      - 1900
      - target: 80
        published: "8080"
        host_ip: 192.168.1.10
    user: "1000:1000"
  traefik:
    image: traefik:v3.7.16
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    labels:
      - traefik.enable=true
  gitea:
    image: gitea/gitea:1.26.4
    privileged: true
    labels:
      traefik.http.routers.git.rule: Host(`git.example.com`)
"#;

    #[test]
    fn parses_services_and_ports() {
        let s = parse(DOC, "test.yml").unwrap();
        assert_eq!(s.len(), 3);
        let plex = &s[0];
        assert_eq!(plex.root, Some(false));
        let p: Vec<_> = plex
            .ports
            .iter()
            .map(|b| {
                (
                    b.host_ip.as_str(),
                    b.host_port.as_deref(),
                    b.container_port.as_str(),
                )
            })
            .collect();
        assert_eq!(
            p,
            vec![
                ("", Some("32400"), "32400"),
                ("127.0.0.1", Some("8324"), "8324"),
                ("::1", Some("9000"), "9000"),
                ("", None, "1900"),
                ("192.168.1.10", Some("8080"), "80"),
            ]
        );
        assert!(s[1].host_network && s[1].docker_socket);
        assert_eq!(s[1].labels["traefik.enable"], "true");
        assert!(s[2].privileged && s[2].root.is_none());
        assert_eq!(
            s[2].labels["traefik.http.routers.git.rule"],
            "Host(`git.example.com`)"
        );
    }

    #[test]
    fn rejects_files_without_services() {
        assert!(parse("version: '3'\n", "x").is_err());
    }
}
