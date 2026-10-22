# exposewatch vs. other tools

Stars, license and last push were checked with `gh api repos/<owner>/<repo>` on 2026-10-22. Feature cells come from each project's docs or README unless marked. "inferred" means reasoned from how the tool works, not tested; "unverified" means we could not confirm it.

## The question each tool answers

| Tool | Stars | License | Answers |
|---|---|---|---|
| [trivy](https://github.com/aquasecurity/trivy) | 38,600 | Apache-2.0 | Which packages in this image have CVEs? |
| [grype](https://github.com/anchore/grype) | 13,069 | Apache-2.0 | Same, with a KEV/EPSS-based risk column |
| [docker scout](https://github.com/docker/scout-cli) | 457 | not stated | Same, plus base-image upgrade advice (needs Docker login) |
| [osv-scanner](https://github.com/google/osv-scanner) | 11,231 | Apache-2.0 | Which dependencies have OSV advisories? |
| [sieve](https://github.com/casareanderson/sieve) | 12 | AGPL-3.0 | Which installed packages on this box have CVEs that matter (KEV/EPSS)? |
| [Watchtower](https://github.com/containrrr/watchtower) (archived) / [fork](https://github.com/nicholas-fedor/watchtower) | 24,612 / 4,673 | Apache-2.0 | Is there a newer image? Pull it and restart. |
| [diun](https://github.com/crazy-max/diun) | 4,988 | MIT | Is there a newer image? Notify me. |
| [WUD](https://github.com/getwud/wud) | 4,054 | MIT | Same, with a web UI |
| [cup](https://github.com/sergi0g/cup) | 1,357 | AGPL-3.0 | Same, fast and small |
| [CrowdSec](https://github.com/crowdsecurity/crowdsec) | 15,249 | MIT | Is this IP attacking me right now? Block it. |
| [scanopy](https://github.com/scanopy/scanopy) | 5,893 | AGPL-3.0 | What is on my network? (topology map) |
| [nuclei](https://github.com/projectdiscovery/nuclei) | 32,211 | MIT | Does this target respond like a vulnerable service? (active probing) |
| **exposewatch** | new | MIT | **Which of my containers are reachable, on a version in an exploited CVE's range, and how do I fix it?** |

## Feature by feature

✓ yes · ✗ no · ~ partly · ? unverified

| Feature | trivy | grype | scout | osv-scanner | sieve | Watchtower / diun / WUD / cup | CrowdSec | nuclei | exposewatch |
|---|---|---|---|---|---|---|---|---|---|
| Lists running containers | ~ image scan | ~ image scan | ~ image scan | ✗ | ✓ | ✓ | ✗ | ✗ | ✓ socket, GET only |
| Reads compose files without running them | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Knows if a port is on 0.0.0.0, LAN or loopback | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Follows reverse-proxy routes (Traefik / caddy-docker-proxy labels) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Optional outside view of your own IP | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ active | ~ InternetDB lookup (experimental) |
| Application version of closed-source apps (Plex) | ✗ inferred | ✗ inferred | ✗ inferred | ✗ OSV has no Plex | ✗ OSV has no Plex | ✗ | ✗ | ✓ templates | ✓ NVD CPE ranges |
| OS / language package CVEs | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ (use trivy/grype for that) |
| CISA KEV | ? | ✓ "(kev)" marker | ✓ `--only-cisa-kev` | ✗ | ✓ | ✗ | ✗ | ~ template tags | ✓ always outranks EPSS |
| EPSS | ? | ✓ | ✓ `--epss` | ✗ | ✓ | ✗ | ✗ | ✗ | ✓ |
| Ranks by exposure × exploitation × privilege | ✗ | ~ risk = threat × impact | ✗ | ✗ | ~ KEV/EPSS | ✗ | ✗ | ✗ | ✓ |
| Says which version fixes it | ✓ | ✓ | ✓ | ✓ | ~ | ~ shows newest tag | ✗ | ✗ | ✓ |
| Says how to close the exposure (bind to 127.0.0.1, add auth, drop host network) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ~ blocks IPs | ✗ | ✓ |
| Flags privileged / docker.sock / host network | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Notifies when a new image exists | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ (use diun / cup) |
| Scans offline after a data refresh | ✓ with DB | ✓ with DB | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ built-in snapshot |
| Sends traffic to services | ✗ | ✗ | ✗ | ✗ | ✗ | registry only | ✗ | ✓ attack-like requests | ✗ (`--probe` is a TCP connect to your own ports) |
| Single binary, no server or database | ✓ | ✓ | ✓ plugin | ✓ | ✗ Python | ~ | ✗ agent + LAPI | ✓ | ✓ |

Sources for KEV/EPSS cells: grype's "Understanding Grype results" guide (oss.anchore.com), Docker's `docker scout cves` reference (docs.docker.com). Trivy: we only found a closed issue (#11108) mentioning KEV and could not confirm built-in support. sieve: its README.

## Where exposewatch fits

It is not a replacement for an image scanner or an update notifier. It sits on top of the question those tools leave open: of everything that is outdated or vulnerable, what is reachable and actively exploited **today**. Plex2Shell is the case in point: the four CVEs were in CISA KEV on 2026-10-20 with EPSS under 1%, and Plex is not in OSV, so package scanners and EPSS-only ranking would both have missed or buried it.

Not covered yet: Nginx Proxy Manager / Caddyfile / nginx.conf routes, UPnP port-forward discovery, apps outside the 20-entry catalog.
