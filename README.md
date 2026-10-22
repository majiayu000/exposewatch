# exposewatch

One command that lists the containers on your homelab or small server that are **open to the network, running a vulnerable version, and affected by a vulnerability that is being exploited right now** — ranked, with the fix.

Image scanners tell you an image has 300 CVEs. Update notifiers tell you a new tag exists. Neither tells you that your Plex is on `0.0.0.0:32400`, still on 1.43.2, and that Plex2Shell (CISA KEV, 2026-10-20) is being used to drop miners on exactly that setup. exposewatch multiplies those three facts and prints only what matters.

- Reads the Docker / Podman socket (GET only) or your compose files. Starts nothing, changes nothing.
- Exposure from port bindings (`0.0.0.0` vs `127.0.0.1` vs LAN), `network_mode: host`, and Traefik / caddy-docker-proxy routes with public hostnames.
- Application versions (not OS packages) matched against NVD CPE ranges, with OSV as fallback. This is how it catches Plex, which package scanners and OSV do not cover.
- "Exploited" means CISA KEV, or EPSS ≥ 0.1. KEV always wins because EPSS lags: the Plex2Shell CVEs were in KEV while their EPSS was under 1%.
- Scans are offline. Only `exposewatch update` (refresh data) and the opt-in `--external <your IP>` touch the network.

## Install

```bash
cargo install --path .
```

Single static binary, no database download. A data snapshot is built in; refresh it with:

```bash
exposewatch update
```

`update` pulls CISA KEV, FIRST EPSS, NVD (one query per catalog product; set `NVD_API_KEY` to go faster) and OSV, and writes `~/.cache/exposewatch/feed.json`.

## Use

```bash
exposewatch scan                          # running containers via the docker/podman socket
exposewatch scan --compose docker-compose.yml
exposewatch scan --probe                  # also TCP-connect to published ports on this host
exposewatch scan --external 203.0.113.7   # YOUR public IP: ask Shodan InternetDB what the internet sees
exposewatch scan --format json            # or markdown
```

Exit code is 2 when something matches all three conditions, so it can run from cron.

## Example output

`exposewatch scan --compose examples/homelab-compose.yml` (first section; full output in [examples/homelab-compose.txt](examples/homelab-compose.txt)):

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

Live run against the Docker socket, with the same old images started from [examples/live-demo-compose.yml](examples/live-demo-compose.yml) bound to 127.0.0.1 only: all three vulnerable containers are found but land in the "not published" section, and the patched Gitea 1.27.3 and Traefik are not flagged. See [examples/live-docker.txt](examples/live-docker.txt). JSON and Markdown variants are in [examples/](examples/).

## How it ranks

```
score = 100 × threat × exposure × privilege
threat    = 1.0 if any matched CVE is in KEV, else the highest EPSS
exposure  = internet 1.0 · via reverse proxy 0.9 · all interfaces 0.7 · LAN 0.3 · loopback 0.1 · not published 0.05
privilege = 1 + 0.15 per: privileged, docker socket, host network, root, SYS_ADMIN/NET_ADMIN (max 1.5)
```

Only findings that are public (all interfaces or above), in an affected version range, and exploited go into the top section. Everything else is listed separately, including services whose version cannot be determined, so nothing disappears silently.

Details: [docs/design.md](docs/design.md). Research and comparison with trivy, grype, docker scout, Watchtower, diun, CrowdSec and others: [docs/research.md](docs/research.md).

## Limits

- Only products in [data/catalog.json](data/catalog.json) are checked (20 common self-hosted apps); others are listed as "not in catalog".
- Version comes from the image tag or the image's version label. `latest` without a version label is reported as "version unknown".
- `all interfaces` is not proof of internet exposure behind NAT; use `--external` to confirm.
- Nginx Proxy Manager databases, Caddyfiles and nginx.conf are not parsed yet.

## Safety

exposewatch never sends exploit traffic. `--probe` only opens a TCP connection to loopback or private addresses that your own containers publish. `--external` sends only the IP you give it to internetdb.shodan.io, which answers from its existing scan database.
