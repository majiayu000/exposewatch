mod analyze;
mod catalog;
mod compose;
mod docker;
mod feed;
mod model;
mod output;
mod version;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

/// Find containers that are open to the network, run a vulnerable version,
/// and have a vulnerability that is being exploited, ranked by danger.
/// Running `exposewatch` with no subcommand is the same as `exposewatch scan`.
#[derive(Parser)]
#[command(version, args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    #[command(flatten)]
    scan: ScanArgs,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Table,
    Json,
    Markdown,
}

#[derive(Args)]
struct ScanArgs {
    /// Analyze these compose files instead of the container socket (repeatable).
    #[arg(long)]
    compose: Vec<PathBuf>,
    /// Docker or Podman API socket. Default: DOCKER_HOST, then the usual paths.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Only containers of these compose projects (label com.docker.compose.project; repeatable).
    #[arg(long)]
    project: Vec<String>,
    /// TCP-connect to each published port on this host (loopback / private addresses only).
    #[arg(long)]
    probe: bool,
    /// Experimental. YOUR public IP: look it up in Shodan InternetDB to see which ports
    /// internet scanners have seen open. Sends this IP to internetdb.shodan.io.
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
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan running containers (docker/podman socket) or compose files. Offline unless --external.
    Scan(ScanArgs),
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

/// Only globally routable addresses make sense for an outside view: InternetDB
/// returns unrelated data for 127.0.0.1 or RFC 1918 space.
fn check_public(ip: IpAddr) -> Result<()> {
    let ok = match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || (a == 100 && (64..128).contains(&b)))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || analyze::is_private(&ip))
        }
    };
    if !ok {
        bail!("--external needs your public IP; {ip} is loopback, private, CGNAT or reserved");
    }
    Ok(())
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
    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Cmd::Scan(cli.scan)) {
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
        Cmd::Scan(ScanArgs {
            compose,
            socket,
            project,
            probe: do_probe,
            external,
            format,
            feed,
            catalog,
        }) => {
            if let Some(ip) = external {
                check_public(ip)?;
            }
            let catalog = catalog::Catalog::load(catalog.as_deref())?;
            let (feed, feed_source) = feed::Feed::load(feed.as_deref())?;
            let mut services = Vec::new();
            if compose.is_empty() {
                let sock = docker::find_socket(socket.as_deref())?;
                services = docker::collect(&sock)?;
                if !project.is_empty() {
                    services.retain(|s| {
                        s.labels
                            .get("com.docker.compose.project")
                            .is_some_and(|p| project.contains(p))
                    });
                }
            } else {
                if socket.is_some() || !project.is_empty() {
                    bail!(
                        "--socket and --project only apply to the container socket, not --compose"
                    );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_requires_public_ip() {
        for bad in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.2",
            "100.64.1.1",
            "169.254.1.1",
            "203.0.113.7",
            "::1",
            "fd00::1",
        ] {
            assert!(check_public(bad.parse().unwrap()).is_err(), "{bad}");
        }
        for good in ["8.8.8.8", "2001:4860:4860::8888"] {
            assert!(check_public(good.parse().unwrap()).is_ok(), "{good}");
        }
    }

    #[test]
    fn bare_invocation_scans() {
        let cli = Cli::try_parse_from(["exposewatch", "--compose", "a.yml"]).unwrap();
        assert!(cli.cmd.is_none());
        assert_eq!(cli.scan.compose, vec![PathBuf::from("a.yml")]);
        let cli = Cli::try_parse_from(["exposewatch", "scan", "--project", "media"]).unwrap();
        assert!(
            matches!(cli.cmd, Some(Cmd::Scan(ScanArgs { ref project, .. })) if project == &["media"])
        );
    }
}
