mod analyze;
mod catalog;
mod compose;
mod docker;
mod feed;
mod model;
mod output;
mod version;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

/// Find containers that are open to the network, run a vulnerable version,
/// and have a vulnerability that is being exploited, ranked by danger.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Table,
    Json,
    Markdown,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan running containers (docker/podman socket) or compose files. Offline unless --external.
    Scan {
        /// Analyze these compose files instead of the container socket (repeatable).
        #[arg(long)]
        compose: Vec<PathBuf>,
        /// Docker or Podman API socket. Default: DOCKER_HOST, then the usual paths.
        #[arg(long)]
        socket: Option<PathBuf>,
        /// TCP-connect to each published port on this host (loopback / private addresses only).
        #[arg(long)]
        probe: bool,
        /// YOUR public IP: look it up in Shodan InternetDB to see which ports the internet sees.
        /// Sends this IP to internetdb.shodan.io.
        #[arg(long, value_name = "IP")]
        external: Option<IpAddr>,
        #[arg(long, value_enum, default_value = "table")]
        format: Format,
        /// Feed file. Default: the `update` cache, else the built-in snapshot.
        #[arg(long)]
        feed: Option<PathBuf>,
        /// Catalog file mapping images to products. Default: built-in.
        #[arg(long)]
        catalog: Option<PathBuf>,
    },
    /// Rebuild the vulnerability feed from CISA KEV, FIRST EPSS, NVD and OSV.
    Update {
        /// Output file. Default: ~/.cache/exposewatch/feed.json
        #[arg(long)]
        out: Option<PathBuf>,
        /// Keep non-KEV CVEs whose EPSS is at least this.
        #[arg(long, default_value_t = 0.1)]
        epss_min: f64,
        #[arg(long)]
        catalog: Option<PathBuf>,
    },
}

fn probe(services: &mut [model::Service]) {
    for s in services {
        for b in &mut s.ports {
            let Some(port) = b.host_port.as_deref().and_then(|p| p.parse::<u16>().ok()) else {
                continue;
            };
            if b.proto != "tcp" {
                continue;
            }
            let ip: IpAddr = if b.host_ip.is_empty() {
                IpAddr::from([127, 0, 0, 1])
            } else {
                match b.host_ip.parse::<IpAddr>() {
                    Ok(ip) if ip.is_loopback() || analyze::is_private(&ip) => ip,
                    // Never connect to anything but this host or private addresses.
                    _ => continue,
                }
            };
            b.listening = Some(
                TcpStream::connect_timeout(&SocketAddr::new(ip, port), Duration::from_millis(800))
                    .is_ok(),
            );
        }
    }
}

fn internetdb(ip: IpAddr) -> Result<BTreeSet<u16>> {
    let url = format!("https://internetdb.shodan.io/{ip}");
    match ureq::get(&url).call() {
        Ok(mut r) => {
            let v: serde_json::Value = r.body_mut().read_json().context("InternetDB: bad JSON")?;
            Ok(v["ports"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|p| p.as_u64())
                .map(|p| p as u16)
                .collect())
        }
        // 404 means InternetDB has never seen an open port on this IP.
        Err(ureq::Error::StatusCode(404)) => Ok(BTreeSet::new()),
        Err(e) => Err(e).context("InternetDB lookup failed"),
    }
}

fn run() -> Result<i32> {
    match Cli::parse().cmd {
        Cmd::Update {
            out,
            epss_min,
            catalog,
        } => {
            let catalog = catalog::Catalog::load(catalog.as_deref())?;
            let out = match out {
                Some(o) => o,
                None => feed::default_cache().context("no HOME; pass --out")?,
            };
            let f = feed::update(&catalog, &out, epss_min)?;
            let n: usize = f.products.values().map(Vec::len).sum();
            let kev = f
                .products
                .values()
                .flatten()
                .filter(|v| v.kev.is_some())
                .count();
            eprintln!(
                "wrote {} ({n} CVEs, {kev} in KEV, KEV {}, EPSS {})",
                out.display(),
                f.kev_catalog_version,
                f.epss_date
            );
            Ok(0)
        }
        Cmd::Scan {
            compose,
            socket,
            probe: do_probe,
            external,
            format,
            feed,
            catalog,
        } => {
            let catalog = catalog::Catalog::load(catalog.as_deref())?;
            let (feed, feed_source) = feed::Feed::load(feed.as_deref())?;
            let mut services = Vec::new();
            if compose.is_empty() {
                let sock = docker::find_socket(socket.as_deref())?;
                services = docker::collect(&sock)?;
            } else {
                if socket.is_some() {
                    bail!("--socket and --compose are mutually exclusive");
                }
                for c in &compose {
                    services.extend(compose::load(c)?);
                }
            }
            if do_probe {
                probe(&mut services);
            }
            let ext = match external {
                Some(ip) => {
                    let ports = internetdb(ip)?;
                    eprintln!(
                        "InternetDB sees {} open port(s) on {ip}: {ports:?}",
                        ports.len()
                    );
                    ports
                }
                None => BTreeSet::new(),
            };
            let report = analyze::analyze(&services, &catalog, &feed, feed_source, &ext);
            print!(
                "{}",
                match format {
                    Format::Table => output::table(&report),
                    Format::Json => output::json(&report)?,
                    Format::Markdown => output::markdown(&report),
                }
            );
            Ok(
                if report
                    .findings
                    .iter()
                    .any(|f| f.category == analyze::Category::Act)
                {
                    2
                } else {
                    0
                },
            )
        }
    }
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    }
}
