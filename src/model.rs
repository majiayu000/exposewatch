//! Service inventory shared by the docker and compose collectors.

use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Binding {
    /// Empty means "all interfaces" (compose default, docker `0.0.0.0`/`::`).
    pub host_ip: String,
    /// `None` when docker picks a random host port (compose `ports: ["80"]`).
    pub host_port: Option<String>,
    pub container_port: String,
    pub proto: String,
    /// Set by `--probe`: whether a TCP connect succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listening: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Service {
    pub name: String,
    /// Where it came from: `docker` or a compose file path.
    pub source: String,
    pub image: String,
    /// Version from image labels (docker only), used when the tag has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label_version: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub ports: Vec<Binding>,
    pub host_network: bool,
    pub privileged: bool,
    pub docker_socket: bool,
    /// `None` when the user is unknown (compose without `user:`).
    pub root: Option<bool>,
    pub cap_add: Vec<String>,
}

pub fn is_root_user(user: &str) -> bool {
    let u = user.split(':').next().unwrap_or("");
    u.is_empty() || u == "0" || u == "root"
}

pub fn is_socket_path(path: &str) -> bool {
    path.ends_with("docker.sock") || path.ends_with("podman.sock")
}
