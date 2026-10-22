//! Image name -> product (NVD CPE) mapping.

use anyhow::{Context, Result};
use serde::Deserialize;

const BUILTIN: &str = include_str!("../data/catalog.json");

#[derive(Debug, Clone, Deserialize)]
pub struct Product {
    pub key: String,
    pub name: String,
    /// `vendor:product` part of a CPE 2.3 name.
    pub cpe: String,
    pub images: Vec<String>,
    #[serde(default)]
    pub advice: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Catalog {
    pub proxies: Vec<String>,
    pub products: Vec<Product>,
}

impl Catalog {
    pub fn load(path: Option<&std::path::Path>) -> Result<Self> {
        let text = match path {
            Some(p) => {
                std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?
            }
            None => BUILTIN.to_string(),
        };
        serde_json::from_str(&text).context("parsing catalog")
    }

    pub fn product_for(&self, image: &str) -> Option<&Product> {
        let repo = repository(image);
        self.products
            .iter()
            .find(|p| p.images.iter().any(|i| repository(i) == repo))
    }

    pub fn is_proxy(&self, image: &str) -> bool {
        let repo = repository(image);
        self.proxies.iter().any(|p| repository(p) == repo)
    }
}

/// Normalize an image reference to its repository path:
/// `docker.io/library/traefik:v3@sha256:..` -> `traefik`.
pub fn repository(image: &str) -> String {
    let no_digest = image.split('@').next().unwrap_or(image);
    // A tag is a ':' after the last '/', so registry ports survive.
    let slash = no_digest.rfind('/').map_or(0, |i| i + 1);
    let no_tag = match no_digest[slash..].find(':') {
        Some(i) => &no_digest[..slash + i],
        None => no_digest,
    };
    let mut r = no_tag.to_ascii_lowercase();
    for prefix in ["docker.io/", "index.docker.io/", "registry-1.docker.io/"] {
        if let Some(rest) = r.strip_prefix(prefix) {
            r = rest.to_string();
        }
    }
    r.strip_prefix("library/").map(str::to_string).unwrap_or(r)
}

/// The tag part of an image reference, if any.
pub fn tag(image: &str) -> Option<&str> {
    let no_digest = image.split('@').next().unwrap_or(image);
    let slash = no_digest.rfind('/').map_or(0, |i| i + 1);
    no_digest[slash..].split_once(':').map(|(_, t)| t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_repositories() {
        assert_eq!(repository("docker.io/library/traefik:v3.7.16"), "traefik");
        assert_eq!(
            repository("plexinc/pms-docker:1.43.2.10687-563d026ea"),
            "plexinc/pms-docker"
        );
        assert_eq!(
            repository("lscr.io/linuxserver/plex:latest"),
            "lscr.io/linuxserver/plex"
        );
        assert_eq!(
            repository("registry.local:5000/gitea/gitea:1.26.4"),
            "registry.local:5000/gitea/gitea"
        );
        assert_eq!(repository("grafana/grafana@sha256:abc"), "grafana/grafana");
        assert_eq!(
            tag("registry.local:5000/gitea/gitea:1.26.4"),
            Some("1.26.4")
        );
        assert_eq!(tag("registry.local:5000/gitea/gitea"), None);
    }

    #[test]
    fn builtin_catalog_matches_images() {
        let c = Catalog::load(None).unwrap();
        assert_eq!(
            c.product_for("lscr.io/linuxserver/plex:1.43.2")
                .unwrap()
                .key,
            "plex"
        );
        assert_eq!(
            c.product_for("docker.io/gitea/gitea:1.26.4").unwrap().key,
            "gitea"
        );
        assert!(c.product_for("someone/gitea:1.26.4").is_none());
        assert!(c.is_proxy("traefik:v3.7.16"));
        assert!(!c.is_proxy("gitea/gitea"));
    }
}
