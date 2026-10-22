# exposewatch 设计

目标：一条命令列出同时满足三个条件的容器或服务，按危险程度排序并给修法：

1. **对公网开放**（或很可能开放）
2. **版本落在漏洞的受影响区间里**（比修复版本旧）
3. **该漏洞正在被利用**（CISA KEV，或 EPSS 超过阈值）

原则：只读；扫描时默认不出网；不发任何攻击性请求；数据缺失时明确报出来，不静默跳过。

## 1. 命令

```
exposewatch scan                     # 读 docker/podman socket
exposewatch scan --compose a.yml     # 只分析 compose 文件（可多次给）
exposewatch scan --probe             # 额外对已发布端口做 TCP connect（只连本机）
exposewatch scan --external 203.0.113.7   # 显式开启外部视角（Shodan InternetDB）
exposewatch scan --format json|markdown|table
exposewatch update                   # 唯一会出网的命令：重建漏洞数据
```

## 2. 发现

| 来源 | 做法 |
|---|---|
| Docker / Podman socket | 只发 `GET /containers/json`、`GET /containers/{id}/json`、`GET /images/{id}/json`。socket 路径按顺序找：`--socket`、`DOCKER_HOST=unix://…`、`/var/run/docker.sock`、`~/.docker/run/docker.sock`（Docker Desktop）、`~/.orbstack/run/docker.sock`、`~/.colima/default/docker.sock`、`$XDG_RUNTIME_DIR/podman/podman.sock`、`/run/podman/podman.sock`。Podman 走 Docker 兼容 API。找不到 socket 时报错退出，不假装“没有容器” |
| compose 文件 | 解析 `services.*.image / ports / network_mode / labels / privileged / volumes / user / cap_add`。只做静态分析，不启动任何东西 |
| 端口探测（可选，`--probe`） | 对每个已发布的 host 端口做 TCP connect，目标固定为 `127.0.0.1`（绑定在指定 IP 上时用该 IP，且只允许 loopback / 私网地址）。只确认“在监听”，不发任何应用层数据 |

## 3. 是否暴露在公网

暴露等级（从高到低）：

| 等级 | 判定 | 系数 |
|---|---|---|
| `internet` | 用户开了 `--external <自己的公网 IP>`，InternetDB 显示该端口开着 | 1.0 |
| `proxied` | 服务没直接发布端口，但带反代路由标签（Traefik `traefik.http.routers.*.rule=Host(...)`、caddy-docker-proxy `caddy=...`），域名不是内网后缀（`.local .lan .home.arpa .internal .localhost .test`），且同一扫描里有反代容器在所有网卡上发布 80/443 | 0.9 |
| `all-interfaces` | 端口绑定在 `0.0.0.0` / `::` / 未写 host_ip；或 `network_mode: host`。家庭 NAT 后面不一定是公网，但只要路由器做了端口转发或 UPnP 就是 | 0.7 |
| `lan` | 绑定在私网地址（10/8、172.16/12、192.168/16、fc00::/7） | 0.3 |
| `loopback` | 只绑定 127.0.0.1 / ::1 | 0.1 |
| `none` | 没有发布端口，也没有反代路由 | 0.05 |

外部视角必须由用户显式给出自己的 IP 才会启用，因为它会把这个 IP 发给 Shodan。exposewatch 不自动探测公网 IP，也不扫描任何别人的地址。

## 4. 镜像 → 产品 → CVE

1. **镜像 → 产品**：内置目录 `data/catalog.json`，每项是 `{key, name, cpe: "vendor:product", images: [...], advice}`。镜像名先规范化（去掉 `docker.io/`、`library/`、tag、digest），`lscr.io/linuxserver/plex`、`ghcr.io/linuxserver/plex`、`linuxserver/plex` 都算同一个。
2. **版本**：依次取 ① tag 开头的版本号（`1.43.2.10687-563d026ea` → `1.43.2.10687`，`v3.7.16` → `3.7.16`）；② 镜像 label `org.opencontainers.image.version`；③ linuxserver 的 `build_version` label。`latest` 这类 tag 走 ②③。都拿不到时报 “version unknown”，不丢弃。
3. **CVE**：`exposewatch update` 对目录里每个 CPE 调一次 NVD `virtualMatchString`，取全部 CVE 和它们的版本区间；再拉 KEV 全量和这些 CVE 的 EPSS；只保留 “在 KEV 中” 或 “EPSS ≥ 0.1” 的 CVE。NVD 没有区间的 KEV 条目，用 OSV `vulns/<CVE>` 的 `affected.ranges` 兜底；还没有就标记 “区间未知”。结果写进 `data/feed.json`（仓库内置一份快照，`update` 默认写到 `~/.cache/exposewatch/feed.json`，扫描时优先读缓存）。
4. **版本比较**：按 `.`、`-`、`+` 切段，数字段按数值比较，非数字段按字符串比较。区间语义与 NVD 一致：`versionStartIncluding/Excluding`、`versionEndIncluding/Excluding`；没有区间只有具体版本的 CPE 做精确匹配。

## 5. 排序

```
score = 100 × threat × exposure × privilege
threat    = 1.0                      若命中的 CVE 中有 KEV
          = EPSS 最大值              否则（需 ≥ --epss-min，默认 0.1）
exposure  = 第 3 节的系数（多个端口取最高）
privilege = 1.0，以下每项 +0.15，上限 1.5：
            privileged、挂载 docker.sock、network_mode host、以 root 运行（User 为空或 0/root）、cap_add 含 SYS_ADMIN/NET_ADMIN/ALL
```

KEV 一票优先是因为 EPSS 滞后：Plex2Shell 进 KEV 时 EPSS 不到 1%。同分时按 KEV `dateAdded` 新的在前，再按 EPSS。

**主清单**只放三个条件都满足的（exposure ≥ `all-interfaces`、版本在区间内、threat 来自 KEV 或 EPSS 达标）。其余命中项放在 “已存在漏洞但未暴露” 和 “无法判断” 两节，不混进主清单。

## 6. 修法

每条结果给出：

- **升级**：目标版本 = 所有命中 CVE 的修复版本里最高的那个（`versionEndExcluding`；只有 `versionEndIncluding` 时写 “高于 X”）。
- **暴露面**：直接发布在所有网卡上 → “改为 `127.0.0.1:PORT:PORT`，经反代加认证访问；不需要外网访问就关掉路由器上的端口转发”；经反代暴露 → “在反代上加认证（forward-auth / basic auth）或限制来源 IP”。
- **产品专属建议**：来自目录的 `advice`，例如 Plex：“关闭 Remote Access，不要直接转发 32400；版本早于 1.43.3.10861 且曾暴露在公网的，按 Plex 公告检查 Codecs 目录并重建”。
- **权限**：有 privileged / docker.sock 等时提示去掉。

## 7. 输出

- `table`（默认）：一行一个服务，列出分数、服务、产品与版本、暴露、CVE（KEV 标记）、修法。表头写数据日期（KEV catalogVersion、EPSS 日期），让用户看得出数据有多旧。
- `json`：完整结构，供脚本和 ntfy 等推送使用。
- `markdown`：可直接贴进 issue 或笔记。
- 退出码：主清单非空时返回 2，方便放进 cron。

## 8. 误报控制

| 来源 | 处理 |
|---|---|
| 镜像名撞名（同名但不是该产品） | 目录只收精确镜像名，不做模糊匹配 |
| tag 不是应用版本（如 `28.2` 这种 gitea 新版本号、`-ls329` 构建号） | 只取 tag 开头的数字段；版本取不到时报 “version unknown”，不猜 |
| 0.0.0.0 但在 NAT 后面 | 等级定为 `all-interfaces`（0.7），不说成 “internet”；需要确认时用 `--external` |
| NVD 区间缺失或有误 | 显示数据来源（NVD / OSV）和区间，便于人工核对 |
| 数据过期 | 输出数据日期；`update` 失败时报错退出，不回落到旧数据假装成功 |

## 9. 不做（MVP）

注册表 “最新版本” 查询（diun/cup 已经做了）、Nginx Proxy Manager 数据库和 Caddyfile/nginx.conf 解析、UPnP 端口转发查询、通知推送。都可以后加，不影响主流程。
