# exposewatch 调研（2026-10-22）

本文所有数字都在 2026-10-22 实查。查不到或没有亲手验证的写“未核实”或“未实测”。

## 1. 近期被大规模利用的自托管漏洞

### 1.1 Plex2Shell（Plex Media Server）

| 项 | 内容 | 来源 |
|---|---|---|
| CVE | CVE-2026-96652（未授权 SSRF）、CVE-2026-96654（编码 URI 处理不当，用于偷 admin token）、CVE-2026-96655（已授权 SSRF，`/video/:/transcode/universal`）、CVE-2026-96656（任意文件写，落在 Codecs 目录，加载时执行） | CISA KEV JSON（catalogVersion 2026.10.21） |
| 受影响版本 | `< 1.43.3.10861`（NVD CPE `cpe:2.3:a:plex:media_server`，`versionEndExcluding: 1.43.3.10861`）；Plex 公告标题写的是 “v1.43.2 and earlier” | NVD API 2.0；[Plex 论坛公告](https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319) |
| 修复版本 | 1.43.3.10861（Docker Hub `plexinc/pms-docker:1.43.3.10861-07dfddaeb`） | Plex 公告、Docker Hub tags API |
| 时间线 | 2026-09-01 Plex 发首个安全更新公告；2026-09-23 NVD 发布 CVE；2026-10-16 研究者公开 PoC；2026-10-17 蜜罐首次看到在野利用；2026-10-19 Plex 更新公告，确认在野利用，称“1.43.3.10861 之前且可从公网访问的服务器应视为已被入侵”；2026-10-20 进入 CISA KEV | Plex 公告、[SecurityWeek](https://www.securityweek.com/plex2shell-exploit-chain-weaponized-against-plex-servers-hours-after-disclosure/)、KEV `dateAdded` |
| KEV 截止日 | CVE-2026-96654、-96656：2026-10-23；CVE-2026-96652、-96655：2026-11-03 | KEV `dueDate` |
| 载荷 | 基于 XMRig 的挖矿程序、名为 myawesomeproxy 的代理程序；蜜罐是 Docker 里的 Linux Plex | SecurityWeek |
| CVSS | NVD 给出两组分数：96652 为 5.3 / 4.3，96656 为 8.6 / 7.2（不同评分方） | NVD API |
| EPSS | 2026-10-21：96656 = 0.00758（第 54.7 百分位），其余三个约 0.0042–0.0043 | FIRST EPSS API |
| 官方缓解 | 升级到 1.43.3.10861+；不需要时关掉 Remote Access；不要直接转发 32400 端口；检查 Codecs 目录里陌生的 .so/.dll、到 proxystream.st 的外连 | Plex 公告 |
| CrowdSec 没拦住 | 只有 r/selfhosted 楼主的自述，**未核实** | 选题 README 信号 #16 |

**结论 1：EPSS 严重滞后。** Plex2Shell 已在 KEV、已被批量利用，但 EPSS 全部低于 1%。排序不能只看 EPSS，KEV 必须是一票优先。

**结论 2：OSV 没有 Plex。** `api.osv.dev/v1/vulns/CVE-2026-96652` 返回 “not found”。Plex 是闭源二进制，不在任何包生态里，所以基于包清单的扫描器（trivy、grype、osv-scanner、sieve）原理上匹配不到它（推断，**未实测**）。应用级版本只能靠 NVD 的 CPE 区间。

### 1.2 其他近期进入 KEV 的自托管应用（2025-01 起，KEV + NVD CPE 实查）

| 产品 | CVE | 进 KEV | 受影响区间（NVD CPE） |
|---|---|---|---|
| Zammad | CVE-2026-102489（会话固定 → RCE）、-102490（本地提权） | 2026-10-02 | 102489：6.3.0 ≤ v ≤ 6.5.4 |
| Gitea | CVE-2026-60004（diffpatch API 代码注入） | 2026-08-25 | 1.17.0 ≤ v < 1.27.1；OSV 别名 GHSA-rcr6-4jqh-j84m、GO-2026-6433 |
| GitLab CE/EE | CVE-2026-85706（路径穿越） | 2026-09-11 | 18.7.0–18.11.11、19.0.0–19.0.8、19.1.0–19.1.7、19.2.0–19.2.5、19.3.0–19.3.1 |
| WordPress（wp2shell） | CVE-2026-60137、CVE-2026-63030 | 2026-07-21 | 6.9.0–6.9.4、7.0.0–7.0.1，修复 6.9.5 / 7.0.2（来自二手报道，NVD 区间未逐条核对） |
| n8n | CVE-2025-68613 | 2026-03-11 | 0.211.0 ≤ v < 1.120.4（以及 1.121.0） |
| Langflow | CVE-2026-33017 等 6 条 | 2025-05 至 2026-08 | 33017：v < 1.8.2 |
| Roundcube | CVE-2025-49113 等 | 2026-02-20 | v < 1.5.10；1.6.0 ≤ v < 1.6.11 |
| ownCloud | CVE-2023-49105 | 2026-08-27 | 10.6.0 ≤ v < 10.13.1 |
| Grafana | CVE-2021-43798（路径穿越） | 2025-10-09 | 8.0.1–8.0.6、8.1.0–8.1.7、8.2.0–8.2.6 等 |
| Strapi / ONLYOFFICE Docs | CVE-2023-22894 / CVE-2021-3199 | 2026-10-08 | 未逐条核对 |

**“PHP2Shell”**：选题 README 提到 r/selfhosted 有 PHP2Shell 预警帖，但检索只找到 **wp2shell**（WordPress Core，见上表）。PHP2Shell 本身的 CVE **未核实**。

**附带发现**：KEV 里有 CVE-2026-33634（Aqua Security Trivy “Embedded Malicious Code”，2026-03-26 进 KEV）。sieve 的 README 说 trivy v0.69.4 发布和 v0.69.5/v0.69.6 镜像被投毒。因此 exposewatch 不调用、不打包任何外部扫描器。

## 2. 数据源（全部可自动更新）

| 数据源 | 用途 | 接口 | 实测 |
|---|---|---|---|
| CISA KEV | 是否被在野利用（一票优先）、进 KEV 日期、截止日、勒索软件使用 | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 2026-10-21 版，1754 条；字段含 `dateAdded`、`dueDate`、`knownRansomwareCampaignUse` |
| FIRST EPSS | 未来 30 天被利用概率，补 KEV 之外的“可能被利用” | `https://api.first.org/data/v1/epss?cve=a,b,...`（批量） | 可用，返回 `epss`、`percentile`、`date` |
| NVD API 2.0 | 应用级 CPE → 受影响版本区间、CVSS | `/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:<vendor>:<product>`，每个产品一次请求 | Plex 19 条、Gitea 81 条；无 key 限速 5 次 / 30 秒，可设 `NVD_API_KEY` |
| OSV（含 GHSA 别名） | NVD 没有 CPE 区间时的兜底（开源应用，如 Gitea 的 GO/GHSA 记录） | `https://api.osv.dev/v1/vulns/<CVE>` | Gitea 有、Plex 无 |
| Shodan InternetDB | 可选的“外部视角”：某个 IP 被互联网扫描器看到开着哪些端口；免 key、只查库不扫描 | `https://internetdb.shodan.io/<ip>` | 可用，返回 `ports`、`vulns` 等 |

GHSA 没有单独接：OSV 已经同步 GHSA（别名里直接给出 GHSA id），再调 GitHub API 需要 token 且有限速，收益很小。

## 3. 竞品

### 3.1 查重（GitHub search，按 star 排序，2026-10-22）

| 关键词组 | total | 最高结果 |
|---|---|---|
| homelab exposure scan | 4 | marctheshark3/cyber-posture 2★ |
| exposed docker containers vulnerability | 9 | Arcane-MCP-Server 21★（无关）；vtino17/docker-security-scanner 0★ |
| known exploited vulnerabilities docker | 4 | 5★ 教学靶场（无关） |
| kev docker scanner | 7 | cybersecify/OpenEASD 30★（外部攻击面：子域名、接管）；casareanderson/sieve 12★ |
| cisa kev container | 12 | sieve 12★；heretix-management 2★；vultriage 0★（给 trivy 输出补 EPSS/KEV） |
| selfhosted attack surface | 1 | 0★ |
| internet exposed services cve homelab | 0 | — |

选题 README 另查过：“homelab inventory docker map” → GravityLAN 6★。

最接近的是 **sieve**（12★，AGPL-3.0，Python）：读主机和容器里的包清单，问 OSV，再按 KEV/EPSS 排序。它是包级的，不判断暴露面，也匹配不到 Plex 这种闭源应用（OSV 没有）。

### 3.2 相邻大项目（`gh api repos/...` 实查 star）

trivy 38,592★；grype 13,067★；docker/scout-cli 457★；containrrr/watchtower 24,611★（**已归档**），活跃分支 nicholas-fedor/watchtower 4,671★；diun 4,987★；getwud/wud 4,056★；cup 1,357★；CrowdSec 15,247★；scanopy 5,892★；nuclei 32,206★；osv-scanner 11,227★。

### 3.3 功能矩阵

✓ = 有；✗ = 没有；~ = 部分；? = 未核实

| 工具 | 读运行中容器 | 判断公网暴露 | 应用级版本（闭源如 Plex） | KEV | EPSS | 新版本提醒 | 按风险排序 | 给修法 | 只读、默认不出网 |
|---|---|---|---|---|---|---|---|---|---|
| trivy | ~（扫镜像） | ✗ | ✗（推断，未实测） | ?（只搜到已关闭的 #11108，未核实是否内置） | ? | ✗ | ✗（按严重度） | ~（fixed version） | ✗（下载 DB） |
| grype | ~（扫镜像） | ✗ | ✗（推断，未实测） | ✓（“(kev)” 标注） | ✓ | ✗ | ✓（RISK 列，0–10） | ~ | ✗（下载 DB） |
| docker scout | ~（扫镜像） | ✗ | ✗（推断） | ✓（`--only-cisa-kev`，1.11.0 起） | ✓（`--epss`） | ~（base image 建议） | ✗ | ✓（base image 建议） | ✗（需登录、出网） |
| osv-scanner | ~（扫镜像/锁文件） | ✗ | ✗（OSV 无 Plex） | ✗ | ✗ | ✗ | ✗ | ~ | ✗ |
| sieve | ✓（/proc） | ✗ | ✗（OSV 无 Plex） | ✓ | ✓ | ✗ | ✓ | ~ | ✗（查 OSV） |
| Watchtower | ✓ | ✗ | ✗ | ✗ | ✗ | ✓（自动更新） | ✗ | ✗ | ✗ |
| diun / WUD / cup | ✓ | ✗ | ✗ | ✗ | ✗ | ✓ | ✗（不分轻重） | ✗ | ✗ |
| CrowdSec | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | 运行时拦截，非清点 |
| scanopy | ✓（网络拓扑） | ~（画图） | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ? |
| nuclei | ✗ | 主动探测 | ✓（模板） | ~ | ✗ | ✗ | ✗ | ✗ | ✗（主动发攻击性请求） |
| **exposewatch** | ✓（socket 只读） | ✓（端口绑定 + 反代路由 + 可选外部视角） | ✓（NVD CPE 区间） | ✓ | ✓ | ✗（只看“修复版本”） | ✓ | ✓（升到哪版、关端口/加认证） | ✓（只有 `update` 出网） |

**空白**：没有工具同时回答“哪个容器现在对公网开着、它的应用版本在被利用的区间里”。镜像扫描器只看包，更新提醒工具不分轻重，CrowdSec 是事后拦截。

## 4. 风险

- NVD 有积压，新 CVE 可能长时间没有 CPE 区间（Plex 的在 2026-09-23 就有了）。没有区间时 exposewatch 报“版本区间未知，请人工确认”，不静默跳过。
- 镜像名 → 产品的映射需要人工维护，MVP 内置一份常见自托管应用的目录。
- 窗口短：Plex2Shell 的 KEV 截止日是 10-23 / 11-03。
