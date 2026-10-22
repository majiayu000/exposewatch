//! Vulnerability feed: built by `exposewatch update` from CISA KEV, FIRST EPSS,
//! NVD (CPE ranges) and OSV (fallback ranges). Scans read it offline.

use crate::catalog::Catalog;
use crate::version::Range;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

const BUILTIN: &str = include_str!("../data/feed.json");
const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const NVD_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const EPSS_URL: &str = "https://api.first.org/data/v1/epss";
const OSV_URL: &str = "https://api.osv.dev/v1/vulns";
const BODY_LIMIT: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Kev {
    pub date_added: String,
    pub due_date: String,
    pub ransomware: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vuln {
    pub cve: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kev: Option<Kev>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss: Option<f64>,
    /// Empty when neither NVD nor OSV has machine-readable ranges yet.
    pub ranges: Vec<Range>,
    /// `nvd`, `osv` or `none`.
    pub range_source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feed {
    pub generated: String,
    pub kev_catalog_version: String,
    pub epss_date: String,
    pub epss_min: f64,
    /// Product key -> exploited (KEV) or likely exploited (EPSS >= epss_min) vulns.
    pub products: BTreeMap<String, Vec<Vuln>>,
}

pub fn default_cache() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".cache")))?;
    Some(base.join("exposewatch/feed.json"))
}

impl Feed {
    /// Explicit path, else the update cache, else the snapshot built into the binary.
    pub fn load(path: Option<&Path>) -> Result<(Self, String)> {
        let path = path
            .map(Path::to_path_buf)
            .or_else(|| default_cache().filter(|p| p.exists()));
        match path {
            Some(p) => {
                let text = std::fs::read_to_string(&p)
                    .with_context(|| format!("reading {}", p.display()))?;
                Ok((
                    serde_json::from_str(&text).context("parsing feed")?,
                    p.display().to_string(),
                ))
            }
            None => Ok((
                serde_json::from_str(BUILTIN).context("parsing built-in feed")?,
                "built-in snapshot".into(),
            )),
        }
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(300)))
        .user_agent(concat!("exposewatch/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

fn get_json_once(agent: &ureq::Agent, url: &str, headers: &[(&str, &str)]) -> Result<Value> {
    let mut req = agent.get(url);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let mut resp = req.call().with_context(|| format!("GET {url}"))?;
    resp.body_mut()
        .with_config()
        .limit(BODY_LIMIT)
        .read_json()
        .with_context(|| format!("GET {url}: bad JSON"))
}

/// NVD drops connections on large pages now and then; retry before failing.
fn get_json(agent: &ureq::Agent, url: &str, headers: &[(&str, &str)]) -> Result<Value> {
    const ATTEMPTS: u64 = 3;
    for attempt in 1..ATTEMPTS {
        match get_json_once(agent, url, headers) {
            Ok(v) => return Ok(v),
            Err(e) => {
                eprintln!("  retry {attempt}/{}: {e:#}", ATTEMPTS - 1);
                std::thread::sleep(Duration::from_secs(10 * attempt));
            }
        }
    }
    get_json_once(agent, url, headers)
}

/// Parse NVD configurations into ranges for one `vendor:product`.
pub fn nvd_ranges(cve: &Value, cpe: &str) -> Vec<Range> {
    let prefix = format!("cpe:2.3:a:{cpe}:");
    let mut out = Vec::new();
    for cfg in cve["configurations"].as_array().into_iter().flatten() {
        for node in cfg["nodes"].as_array().into_iter().flatten() {
            for m in node["cpeMatch"].as_array().into_iter().flatten() {
                let crit = m["criteria"].as_str().unwrap_or_default();
                if m["vulnerable"].as_bool() != Some(true) || !crit.starts_with(&prefix) {
                    continue;
                }
                let s = |k: &str| m[k].as_str().map(str::to_string);
                let ver = crit.split(':').nth(5).unwrap_or("*");
                let r = Range {
                    exact: (ver != "*" && ver != "-").then(|| ver.to_string()),
                    start_including: s("versionStartIncluding"),
                    start_excluding: s("versionStartExcluding"),
                    end_including: s("versionEndIncluding"),
                    end_excluding: s("versionEndExcluding"),
                };
                if r != Range::default() && !out.contains(&r) {
                    out.push(r);
                }
            }
        }
    }
    out
}

fn has_configurations(cve: &Value) -> bool {
    cve["configurations"]
        .as_array()
        .is_some_and(|c| !c.is_empty())
}

/// Whether any *vulnerable* CPE in the record is this product.
fn names_product(cve: &Value, cpe: &str) -> bool {
    let prefix = format!("cpe:2.3:a:{cpe}:");
    cve["configurations"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|c| c["nodes"].as_array().into_iter().flatten())
        .flat_map(|n| n["cpeMatch"].as_array().into_iter().flatten())
        .any(|m| {
            m["vulnerable"].as_bool() == Some(true)
                && m["criteria"]
                    .as_str()
                    .is_some_and(|c| c.starts_with(&prefix))
        })
}

/// OSV `affected[].ranges[]` (SEMVER/ECOSYSTEM) -> ranges.
pub fn osv_ranges(osv: &Value) -> Vec<Range> {
    let mut out = Vec::new();
    for a in osv["affected"].as_array().into_iter().flatten() {
        for r in a["ranges"].as_array().into_iter().flatten() {
            if r["type"].as_str() == Some("GIT") {
                continue;
            }
            let mut cur = Range::default();
            for e in r["events"].as_array().into_iter().flatten() {
                if let Some(v) = e["introduced"].as_str() {
                    cur.start_including = (v != "0").then(|| v.to_string());
                } else if let Some(v) = e["fixed"].as_str() {
                    cur.end_excluding = Some(v.to_string());
                    out.push(std::mem::take(&mut cur));
                } else if let Some(v) = e["last_affected"].as_str() {
                    cur.end_including = Some(v.to_string());
                    out.push(std::mem::take(&mut cur));
                }
            }
        }
    }
    out.retain(|r| *r != Range::default());
    out
}

fn cvss(cve: &Value) -> Option<f64> {
    ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30"]
        .iter()
        .find_map(|k| cve["metrics"][*k][0]["cvssData"]["baseScore"].as_f64())
}

pub fn update(catalog: &Catalog, out: &Path, epss_min: f64) -> Result<Feed> {
    let agent = agent();
    let api_key = std::env::var("NVD_API_KEY").ok();
    let pause = Duration::from_millis(if api_key.is_some() { 700 } else { 6500 });
    let headers: Vec<(&str, &str)> = api_key
        .as_deref()
        .map(|k| vec![("apiKey", k)])
        .unwrap_or_default();

    eprintln!("fetching CISA KEV");
    let kev_doc = get_json(&agent, KEV_URL, &[])?;
    let kev: HashMap<String, Kev> = kev_doc["vulnerabilities"]
        .as_array()
        .context("KEV: no vulnerabilities array")?
        .iter()
        .filter_map(|v| {
            Some((
                v["cveID"].as_str()?.to_string(),
                Kev {
                    date_added: v["dateAdded"].as_str()?.to_string(),
                    due_date: v["dueDate"].as_str().unwrap_or_default().to_string(),
                    ransomware: v["knownRansomwareCampaignUse"].as_str() == Some("Known"),
                },
            ))
        })
        .collect();
    eprintln!(
        "  {} KEV entries, catalog {}",
        kev.len(),
        kev_doc["catalogVersion"]
    );

    // product key -> (cve id, nvd record)
    let mut nvd: BTreeMap<String, Vec<(String, Value)>> = BTreeMap::new();
    for (i, p) in catalog.products.iter().enumerate() {
        if i > 0 {
            std::thread::sleep(pause);
        }
        let mut start = 0;
        let list = nvd.entry(p.key.clone()).or_default();
        loop {
            let url = format!(
                "{NVD_URL}?virtualMatchString=cpe:2.3:a:{}&resultsPerPage=500&startIndex={start}",
                p.cpe
            );
            let page = get_json(&agent, &url, &headers)?;
            let vulns = page["vulnerabilities"]
                .as_array()
                .context("NVD: no vulnerabilities array")?;
            for v in vulns {
                let cve = &v["cve"];
                list.push((
                    cve["id"].as_str().unwrap_or_default().to_string(),
                    cve.clone(),
                ));
            }
            let total = page["totalResults"].as_u64().unwrap_or(0) as usize;
            start += vulns.len();
            if vulns.is_empty() || start >= total {
                break;
            }
            std::thread::sleep(pause);
        }
        eprintln!("  NVD {:<16} {} CVEs", p.key, list.len());
    }

    let all: Vec<&String> = nvd.values().flatten().map(|(id, _)| id).collect();
    let mut epss: HashMap<String, f64> = HashMap::new();
    let mut epss_date = String::new();
    eprintln!("fetching EPSS for {} CVEs", all.len());
    for chunk in all.chunks(100) {
        let ids: Vec<&str> = chunk.iter().map(|s| s.as_str()).collect();
        let url = format!("{EPSS_URL}?cve={}&limit=100", ids.join(","));
        let page = get_json(&agent, &url, &[])?;
        for d in page["data"].as_array().context("EPSS: no data array")? {
            if let (Some(c), Some(e)) = (
                d["cve"].as_str(),
                d["epss"].as_str().and_then(|e| e.parse().ok()),
            ) {
                epss.insert(c.to_string(), e);
            }
            if let Some(date) = d["date"].as_str() {
                epss_date = date.to_string();
            }
        }
    }

    let mut products = BTreeMap::new();
    for p in &catalog.products {
        let mut keep = Vec::new();
        for (id, cve) in &nvd[&p.key] {
            let k = kev.get(id).cloned();
            let e = epss.get(id).copied();
            if k.is_none() && e.is_none_or(|e| e < epss_min) {
                continue;
            }
            let mut ranges = nvd_ranges(cve, &p.cpe);
            let mut range_source = "nvd";
            if ranges.is_empty() && has_configurations(cve) && !names_product(cve, &p.cpe) {
                // The product is only the platform (e.g. a WordPress plugin CVE).
                continue;
            }
            if ranges.is_empty() {
                let osv = agent.get(&format!("{OSV_URL}/{id}")).call();
                ranges = match osv {
                    Ok(mut r) => osv_ranges(&r.body_mut().read_json()?),
                    Err(ureq::Error::StatusCode(404)) => Vec::new(),
                    Err(e) => return Err(e).with_context(|| format!("OSV {id}")),
                };
                range_source = if ranges.is_empty() { "none" } else { "osv" };
            }
            keep.push(Vuln {
                cve: id.clone(),
                kev: k,
                epss: e,
                cvss: cvss(cve),
                ranges,
                range_source: range_source.into(),
            });
        }
        keep.sort_by(|a, b| a.cve.cmp(&b.cve));
        products.insert(p.key.clone(), keep);
    }
    if epss_date.is_empty() {
        bail!("EPSS returned no data");
    }

    let feed = Feed {
        generated: now_utc(),
        kev_catalog_version: kev_doc["catalogVersion"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        epss_date,
        epss_min,
        products,
    };
    if let Some(dir) = out.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(out, serde_json::to_string_pretty(&feed)? + "\n")?;
    Ok(feed)
}

fn now_utc() -> String {
    // Days-from-civil inverse (Howard Hinnant), avoids a time crate for one timestamp.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (days, rem) = ((secs / 86400) as i64, secs % 86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_nvd_configurations() {
        let cve = json!({"configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": true, "criteria": "cpe:2.3:a:n8n:n8n:*:*:*:*:*:node.js:*:*", "versionStartIncluding": "0.211.0", "versionEndExcluding": "1.120.4"},
            {"vulnerable": true, "criteria": "cpe:2.3:a:n8n:n8n:1.121.0:*:*:*:*:node.js:*:*"},
            {"vulnerable": true, "criteria": "cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*"},
            {"vulnerable": false, "criteria": "cpe:2.3:a:n8n:n8n:*:*:*:*:*:*:*:*", "versionEndExcluding": "9"}
        ]}]}]});
        let r = nvd_ranges(&cve, "n8n:n8n");
        assert_eq!(r.len(), 2);
        assert!(r[0].contains("1.120.0") && !r[0].contains("1.120.4"));
        assert!(r[1].contains("1.121.0"));
        assert!(names_product(&cve, "n8n:n8n"));
        let plugin = json!({"configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": true, "criteria": "cpe:2.3:a:acme:gallery:*:*:*:*:*:wordpress:*:*"},
            {"vulnerable": false, "criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"}
        ]}]}]});
        assert!(has_configurations(&plugin) && !names_product(&plugin, "wordpress:wordpress"));
    }

    #[test]
    fn parses_osv_ranges() {
        let osv = json!({"affected": [{"ranges": [
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.27.1"}]},
            {"type": "GIT", "events": [{"introduced": "abc"}, {"fixed": "def"}]}
        ]}]});
        let r = osv_ranges(&osv);
        assert_eq!(r.len(), 1);
        assert!(r[0].contains("1.26.4") && !r[0].contains("1.27.1"));
    }

    #[test]
    fn builtin_feed_parses() {
        let f: Feed = serde_json::from_str(BUILTIN).unwrap();
        assert!(f.products.contains_key("plex"));
    }
}
