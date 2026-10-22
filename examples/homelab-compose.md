# exposewatch report

exposewatch: 7 services scanned; data: KEV 2026.10.21 / EPSS 2026-10-21 (min 0.1) from built-in snapshot

## ACT NOW: published to the network, vulnerable version, exploited in the wild (2)

| # | Score | Service | Product / version | Exposure | Vulnerabilities | Fix |
|---|---|---|---|---|---|---|
| 1 | 90.0 | `gitea` | Gitea 1.26.4 | via reverse proxy `routed by reverse proxy as git.example.com` | CVE-2026-60004 KEV 2026-08-25 EPSS 24.0% | Upgrade Gitea to 1.27.1 or later.<br>Put authentication (forward-auth / basic auth) or an IP allow-list in front of this route on the reverse proxy. |
| 2 | 70.0 | `plex` | Plex Media Server 1.43.2.10687 | all interfaces `0.0.0.0:32400->32400/tcp` | CVE-2026-96656 KEV 2026-10-20 EPSS 0.8%<br>CVE-2026-96654 KEV 2026-10-20 EPSS 0.4%<br>CVE-2026-96652 KEV 2026-10-20 EPSS 0.4%<br>CVE-2026-96655 KEV 2026-10-20 EPSS 0.4% | Upgrade Plex Media Server to 1.43.3.10861 or later.<br>Bind 32400 to loopback ("127.0.0.1:32400:32400") and reach it through a reverse proxy with authentication; remove any router port-forward for 32400 you do not need.<br>Disable Remote Access if you do not need it and do not forward port 32400 directly. Plex says servers older than 1.43.3.10861 that were reachable from the internet should be presumed compromised: check the Codecs folder for unknown .so/.dll files and rebuild from a clean install if in doubt. |

## Vulnerable and exploited, but not published beyond this host / LAN (2)

| # | Score | Service | Product / version | Exposure | Vulnerabilities | Fix |
|---|---|---|---|---|---|---|
| 1 | 30.0 | `n8n` | n8n 1.120.0 | LAN only `routed by reverse proxy as internal name n8n.home.arpa` | CVE-2025-68613 KEV 2026-03-11 EPSS 99.0%<br>CVE-2026-21858 EPSS 78.2%<br>CVE-2026-1470 EPSS 20.7%<br>CVE-2025-68668 EPSS 13.2% | Upgrade n8n to 2.0.0 or later. |
| 2 | 10.0 | `grafana` | Grafana 8.2.6 | loopback only `127.0.0.1:3001->3000/tcp` | CVE-2021-43798 KEV 2025-10-09 EPSS 88.5%<br>CVE-2025-4123 EPSS 97.1%<br>CVE-2022-31097 EPSS 70.1%<br>CVE-2021-43813 EPSS 57.1%<br>CVE-2023-0507 EPSS 15.5% | Upgrade Grafana to 10.4.18 or later. |

## Could not decide (1)

| # | Score | Service | Product / version | Exposure | Vulnerabilities | Fix |
|---|---|---|---|---|---|---|
| 1 | 0.0 | `jellyfin` | Jellyfin ? | all interfaces `network_mode: host (every listening port is on the host)` |  | version unknown: the tag has no version (compose files carry no image labels; scan the running container instead); pin a versioned tag<br>Drop network_mode: host and publish only the ports you need on 127.0.0.1.<br>Reduce privileges: host network. |
