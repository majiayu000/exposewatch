//! Read-only Docker Engine API client over a unix socket (works for Podman's
//! Docker-compatible socket too). Only GET requests are ever sent.

use crate::model::{Binding, Service, is_root_user, is_socket_path};
use crate::version;
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn find_socket(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    let mut candidates = Vec::new();
    if let Ok(h) = std::env::var("DOCKER_HOST") {
        match h.strip_prefix("unix://") {
            Some(p) => candidates.push(PathBuf::from(p)),
            None => bail!("DOCKER_HOST={h} is not a unix socket; pass --socket"),
        }
    }
    candidates.push("/var/run/docker.sock".into());
    if let Ok(home) = std::env::var("HOME") {
        for p in [
            ".docker/run/docker.sock",
            ".orbstack/run/docker.sock",
            ".colima/default/docker.sock",
        ] {
            candidates.push(Path::new(&home).join(p));
        }
    }
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        candidates.push(Path::new(&xdg).join("podman/podman.sock"));
    }
    candidates.push("/run/podman/podman.sock".into());
    candidates
        .iter()
        .find(|p| p.exists())
        .cloned()
        .with_context(|| format!("no docker/podman socket found (tried {candidates:?}); pass --socket or use --compose"))
}

fn get(socket: &Path, path: &str) -> Result<Value> {
    let mut s = UnixStream::connect(socket)
        .with_context(|| format!("connecting to {}", socket.display()))?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    // HTTP/1.0 avoids chunked bodies; some daemons (OrbStack) still keep the
    // connection open, so the body is read by Content-Length.
    write!(
        s,
        "GET {path} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )?;
    let mut r = BufReader::new(s);
    let mut status = String::new();
    r.read_line(&mut status)?;
    let (mut len, mut chunked) = (None, false);
    loop {
        let mut line = String::new();
        if r.read_line(&mut line)? == 0 || line == "\r\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                len = Some(v.trim().parse::<usize>().context("bad Content-Length")?);
            } else if k.eq_ignore_ascii_case("transfer-encoding")
                && v.trim().eq_ignore_ascii_case("chunked")
            {
                chunked = true;
            }
        }
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            let mut size = String::new();
            r.read_line(&mut size)?;
            let n = usize::from_str_radix(size.trim().split(';').next().unwrap_or(""), 16)
                .context("bad chunk size")?;
            let mut chunk = vec![0; n + 2];
            r.read_exact(&mut chunk)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    } else {
        match len {
            Some(n) => {
                body.resize(n, 0);
                r.read_exact(&mut body)?;
            }
            None => {
                r.read_to_end(&mut body)?;
            }
        }
    }
    if !status.contains(" 200 ") {
        bail!("GET {path}: {}", status.trim());
    }
    serde_json::from_slice(&body).with_context(|| format!("GET {path}: bad JSON"))
}

pub fn collect(socket: &Path) -> Result<Vec<Service>> {
    let list = get(socket, "/containers/json")?;
    let mut out = Vec::new();
    for c in list.as_array().context("container list is not an array")? {
        let id = c["Id"].as_str().context("container without Id")?;
        let inspect = get(socket, &format!("/containers/{id}/json"))?;
        let image = get(
            socket,
            &format!(
                "/images/{}/json",
                inspect["Image"].as_str().unwrap_or_default()
            ),
        )?;
        out.push(from_inspect(&inspect, &image));
    }
    Ok(out)
}

fn str_of(v: &Value) -> String {
    v.as_str().unwrap_or_default().to_string()
}

pub fn from_inspect(c: &Value, image: &Value) -> Service {
    let cfg = &c["Config"];
    let host = &c["HostConfig"];
    let mut image_ref = str_of(&cfg["Image"]);
    if image_ref.starts_with("sha256:")
        && let Some(t) = image["RepoTags"].as_array().and_then(|t| t.first())
    {
        image_ref = str_of(t);
    }
    let labels = cfg["Labels"]
        .as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), str_of(v))).collect())
        .unwrap_or_default();
    let image_labels = &image["Config"]["Labels"];
    let label_version = ["org.opencontainers.image.version", "build_version"]
        .iter()
        .find_map(|k| image_labels[*k].as_str().and_then(label_version));

    let mut ports = Vec::new();
    if let Some(map) = c["NetworkSettings"]["Ports"].as_object() {
        for (spec, binds) in map {
            let (container_port, proto) = spec.split_once('/').unwrap_or((spec, "tcp"));
            for b in binds.as_array().into_iter().flatten() {
                let ip = str_of(&b["HostIp"]);
                ports.push(Binding {
                    host_ip: if ip == "0.0.0.0" || ip == "::" {
                        String::new()
                    } else {
                        ip
                    },
                    host_port: b["HostPort"].as_str().map(str::to_string),
                    container_port: container_port.to_string(),
                    proto: proto.to_string(),
                    listening: None,
                });
            }
        }
    }
    // Docker lists 0.0.0.0 and :: separately; one entry is enough.
    ports.sort_by(|a, b| (&a.host_port, &a.host_ip).cmp(&(&b.host_port, &b.host_ip)));
    ports.dedup();

    Service {
        name: str_of(&c["Name"]).trim_start_matches('/').to_string(),
        source: "docker".into(),
        image: image_ref,
        label_version,
        labels,
        ports,
        host_network: host["NetworkMode"].as_str() == Some("host"),
        privileged: host["Privileged"].as_bool().unwrap_or(false),
        docker_socket: c["Mounts"].as_array().is_some_and(|m| {
            m.iter()
                .any(|m| is_socket_path(m["Source"].as_str().unwrap_or_default()))
        }),
        root: Some(is_root_user(cfg["User"].as_str().unwrap_or_default())),
        cap_add: host["CapAdd"]
            .as_array()
            .map(|a| a.iter().map(str_of).collect())
            .unwrap_or_default(),
    }
}

/// linuxserver's `build_version` reads "Linuxserver.io version:- 1.43.5... Build-date:- ...".
fn label_version(v: &str) -> Option<String> {
    v.split_whitespace().find_map(version::extract)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_inspect_output() {
        let c = json!({
            "Name": "/plex",
            "Config": {"Image": "plexinc/pms-docker:latest", "User": "", "Labels": {"a": "b"}},
            "HostConfig": {"NetworkMode": "bridge", "Privileged": true, "CapAdd": ["NET_ADMIN"]},
            "Mounts": [{"Source": "/var/run/docker.sock"}],
            "NetworkSettings": {"Ports": {
                "32400/tcp": [{"HostIp": "0.0.0.0", "HostPort": "32400"}, {"HostIp": "::", "HostPort": "32400"}],
                "1900/udp": null,
                "8324/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8324"}]
            }}
        });
        let img = json!({"Config": {"Labels": {"build_version": "Linuxserver.io version:- 1.43.2.10687-563d026ea Build-date:- 2026-08-01"}}});
        let s = from_inspect(&c, &img);
        assert_eq!(s.name, "plex");
        assert_eq!(s.label_version.as_deref(), Some("1.43.2.10687"));
        assert_eq!(s.ports.len(), 2);
        assert!(
            s.ports
                .iter()
                .any(|p| p.host_ip.is_empty() && p.host_port.as_deref() == Some("32400"))
        );
        assert!(s.privileged && s.docker_socket && s.root == Some(true));
    }
}
