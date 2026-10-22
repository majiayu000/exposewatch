# exposewatch

[![CI](https://github.com/majiayu000/exposewatch/actions/workflows/ci.yml/badge.svg)](https://github.com/majiayu000/exposewatch/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/majiayu000/exposewatch)](https://github.com/majiayu000/exposewatch/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**exposewatch finds the exposed containers on your homelab or self-hosted server that run a vulnerable version with an actively exploited vulnerability (CISA KEV, EPSS)**: Docker and Podman containers or compose stacks, ranked by danger, each with the exact fix. Built for cases like Plex2Shell, the Plex Media Server exploit chain added to CISA KEV on 2026-10-20.

Image scanners say an image has 300 CVEs. Update notifiers say a new tag exists. Neither says that your Plex is on `0.0.0.0:32400`, still on 1.43.2, and that this exact setup is being used to drop crypto miners. exposewatch checks three things together (open to the network, vulnerable version, exploited in the wild) and prints only what passes all three.

## Quick start

```bash
# macOS (Apple silicon); see Releases for macOS x86_64 and Linux x86_64
curl -sL https://github.com/majiayu000/exposewatch/releases/latest/download/exposewatch-aarch64-apple-darwin.tar.gz | tar xz
./exposewatch                     # scan running containers via the Docker/Podman socket
```

Or build from source (Rust 1.88+): `cargo install --git https://github.com/majiayu000/exposewatch`

```bash
exposewatch --compose docker-compose.yml   # static check of a compose file, starts nothing
exposewatch --project media                # only one compose project
exposewatch --probe                        # also TCP-connect to your published ports on this host
exposewatch --format json                  # or markdown
exposewatch update                         # refresh CISA KEV + EPSS + NVD + OSV data
```

Exit code 2 means something matched all three conditions, so it works from cron.

## Example output

`exposewatch --compose examples/homelab-compose.yml` (first section; full output in [examples/homelab-compose.txt](examples/homelab-compose.txt)):

```text
exposewatch: 7 services scanned; data: KEV 2026.10.21 / EPSS 2026-10-21 (min 0.1) from built-in snapshot

== ACT NOW: published to the network, vulnerable version, exploited in the wild (2)

 1. [ 90.0] gitea  Gitea 1.26.4
    image:    gitea/gitea:1.26.4  (examples/homelab-compose.yml)
    exposure: via reverse proxy: routed by reverse proxy as git.example.com
    vuln:     CVE-2026-60004 KEV 2026-08-25 EPSS 24.0% (fixed: 1.27.1)
    fix:      Upgrade Gitea to 1.27.1 or later.
    fix:      Put authentication (forward-auth / basic auth) or an IP allow-list in front of this route on the reverse proxy.

 2. [ 70.0] plex  Plex Media Server 1.43.2.10687
    image:    plexinc/pms-docker:1.43.2.10687-563d026ea  (examples/homelab-compose.yml)
    exposure: all interfaces: 0.0.0.0:32400->32400/tcp
    vuln:     CVE-2026-96656 KEV 2026-10-20 EPSS 0.8% (fixed: 1.43.3.10861)
    vuln:     CVE-2026-96654 KEV 2026-10-20 EPSS 0.4% (fixed: 1.43.3.10861)
    vuln:     CVE-2026-96652 KEV 2026-10-20 EPSS 0.4% (fixed: 1.43.3.10861)
    vuln:     CVE-2026-96655 KEV 2026-10-20 EPSS 0.4% (fixed: 1.43.3.10861)
    fix:      Upgrade Plex Media Server to 1.43.3.10861 or later.
    fix:      Bind 32400 to loopback ("127.0.0.1:32400:32400") and reach it through a reverse proxy with authentication; remove any router port-forward for 32400 you do not need.
    fix:      Disable Remote Access if you do not need it and do not forward port 32400 directly. Plex says servers older than 1.43.3.10861 that were reachable from the internet should be presumed compromised: check the Codecs folder for unknown .so/.dll files and rebuild from a clean install if in doubt.
...
```

Live run against the Docker socket with the same old images, all bound to 127.0.0.1 ([examples/live-demo-compose.yml](examples/live-demo-compose.yml)): Plex 1.43.2, Gitea 1.26.4 and Grafana 8.2.6 are found and correctly placed in the "not published" section, and the patched Gitea 1.27.3 and Traefik 3.7.16 are not flagged. See [examples/live-docker.txt](examples/live-docker.txt); JSON and Markdown versions are in [examples/](examples/).

## How it compares

| | trivy / grype / docker scout | Watchtower / diun / WUD / cup | CrowdSec | **exposewatch** |
|---|---|---|---|---|
| Knows a port is on 0.0.0.0 vs 127.0.0.1, follows Traefik/Caddy routes | ✗ | ✗ | ✗ | ✓ |
| Version of closed-source apps such as Plex | ✗ (package-based) | ✗ | ✗ | ✓ NVD CPE ranges |
| CISA KEV / EPSS | grype, scout ✓ | ✗ | ✗ | ✓ KEV outranks EPSS |
| Ranks by exposure × exploitation × privilege | ✗ | ✗ | ✗ | ✓ |
| Tells you how to close the exposure | ✗ | ✗ | blocks IPs | ✓ |
| OS package CVEs, new-image alerts | ✓ / ✗ | ✗ / ✓ | ✗ | ✗ (use them for that) |

Full feature-by-feature table with star counts and sources: [docs/comparison.md](docs/comparison.md).

## How it works

- **Discovery**: reads the Docker or Podman socket (GET requests only; Docker Desktop, OrbStack, Colima and rootless Podman paths are found automatically) or parses compose files. Starts nothing, changes nothing.
- **Exposure**: port bindings (`0.0.0.0` / LAN / loopback), `network_mode: host`, and Traefik or caddy-docker-proxy routes whose hostname is public and whose proxy is published.
- **Version → CVE**: image tag or OCI version label, matched against NVD CPE ranges for 20 popular self-hosted apps (Plex, Jellyfin, Nextcloud, Gitea, GitLab, Grafana, n8n, Langflow, Roundcube, Vaultwarden, Home Assistant, WordPress and more; see [data/catalog.json](data/catalog.json)), with OSV as a fallback.
- **Exploited**: CISA KEV, or EPSS ≥ 0.1. KEV always wins because EPSS lags: the Plex2Shell CVEs were in KEV while their EPSS was under 1%.
- **Score**: `100 × threat × exposure × privilege`. Threat is 1.0 for KEV, otherwise the EPSS score. Exposure ranges from 1.0 (internet) down to 0.05 (not published). Privilege rises with privileged mode, a mounted docker.sock, host network or root.
- **Offline by default**: a data snapshot is built in; only `update` and `--external` use the network.

Design notes: [docs/design.md](docs/design.md). Research on Plex2Shell and other exploited self-hosted apps: [docs/research.md](docs/research.md).

## Experimental: outside view

`exposewatch --external <your public IP>` asks [Shodan InternetDB](https://internetdb.shodan.io/) which ports internet scanners have already seen open on that IP. Bindings on those ports are then marked "internet (confirmed)" instead of "all interfaces". It sends only that IP to Shodan and refuses loopback, private, CGNAT and reserved addresses, because InternetDB returns unrelated data for them. It has not yet been tested against a real public IP.

## Limits

- Only apps in the catalog are checked; everything else is listed as "not in catalog".
- A `latest` tag without a version label is reported as "version unknown", not guessed.
- "All interfaces" behind NAT is not proof of internet exposure; use `--external` to confirm.
- Nginx Proxy Manager, Caddyfile and nginx.conf routes are not parsed yet.

## Safety

exposewatch never sends exploit traffic and never scans other people's addresses. `--probe` only opens a TCP connection to loopback or private addresses your own containers publish.

## License

MIT
