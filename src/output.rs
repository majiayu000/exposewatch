//! Terminal table, Markdown and JSON renderers.

use crate::analyze::{Category, Finding, Hit, Report};
use std::fmt::Write;

fn hit_label(h: &Hit) -> String {
    let mut s = h.cve.clone();
    if let Some(k) = &h.kev {
        s += &format!(" KEV {}", k.date_added);
        if k.ransomware {
            s += " ransomware";
        }
    }
    if let Some(e) = h.epss {
        s += &format!(" EPSS {:.1}%", e * 100.0);
    }
    s
}

fn section(c: Category) -> &'static str {
    match c {
        Category::Act => {
            "ACT NOW: published to the network, vulnerable version, exploited in the wild"
        }
        Category::NotExposed => {
            "Vulnerable and exploited, but not published beyond this host / LAN"
        }
        Category::Unknown => "Could not decide",
    }
}

fn header(r: &Report) -> String {
    format!(
        "exposewatch: {} services scanned; data: KEV {} / EPSS {} (min {}) from {}",
        r.services_scanned, r.kev_catalog_version, r.epss_date, r.epss_min, r.feed_source
    )
}

pub fn table(r: &Report) -> String {
    let mut out = header(r) + "\n";
    for c in [Category::Act, Category::NotExposed, Category::Unknown] {
        let items: Vec<&Finding> = r.findings.iter().filter(|f| f.category == c).collect();
        if items.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\n== {} ({})", section(c), items.len());
        for (i, f) in items.iter().enumerate() {
            let _ = writeln!(
                out,
                "\n{:>2}. [{:>5.1}] {}  {} {}",
                i + 1,
                f.score,
                f.service,
                f.product,
                f.version.as_deref().unwrap_or("(version unknown)")
            );
            let _ = writeln!(out, "    image:    {}  ({})", f.image, f.source);
            let detail = if f.exposure_detail.is_empty() {
                String::new()
            } else {
                format!(": {}", f.exposure_detail.join("; "))
            };
            let _ = writeln!(out, "    exposure: {}{}", f.exposure.label(), detail);
            if !f.privilege.is_empty() {
                let _ = writeln!(out, "    privilege: {}", f.privilege.join(", "));
            }
            for h in &f.hits {
                let fixed = h
                    .fixed
                    .as_deref()
                    .map(|v| format!(" (fixed: {v})"))
                    .unwrap_or_default();
                let _ = writeln!(out, "    vuln:     {}{}", hit_label(h), fixed);
            }
            if let Some(n) = &f.note {
                let _ = writeln!(out, "    note:     {n}");
            }
            for x in &f.fix {
                let _ = writeln!(out, "    fix:      {x}");
            }
        }
    }
    if r.findings.iter().all(|f| f.category != Category::Act) {
        out += "\nNothing matches all three conditions (public + vulnerable + exploited).\n";
    }
    if !r.unrecognized.is_empty() {
        let _ = writeln!(
            out,
            "\nNot in catalog, not checked ({}): {}",
            r.unrecognized.len(),
            r.unrecognized.join(", ")
        );
    }
    out
}

pub fn markdown(r: &Report) -> String {
    let mut out = format!("# exposewatch report\n\n{}\n", header(r));
    for c in [Category::Act, Category::NotExposed, Category::Unknown] {
        let items: Vec<&Finding> = r.findings.iter().filter(|f| f.category == c).collect();
        if items.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\n## {} ({})\n", section(c), items.len());
        out += "| # | Score | Service | Product / version | Exposure | Vulnerabilities | Fix |\n|---|---|---|---|---|---|---|\n";
        for (i, f) in items.iter().enumerate() {
            let vulns: Vec<String> = f.hits.iter().map(hit_label).collect();
            let mut fix = f.fix.clone();
            if let Some(n) = &f.note {
                fix.insert(0, n.clone());
            }
            let _ = writeln!(
                out,
                "| {} | {:.1} | `{}` | {} {} | {} {} | {} | {} |",
                i + 1,
                f.score,
                f.service,
                f.product,
                f.version.as_deref().unwrap_or("?"),
                f.exposure.label(),
                f.exposure_detail
                    .iter()
                    .map(|d| format!("`{d}`"))
                    .collect::<Vec<_>>()
                    .join(" "),
                vulns.join("<br>"),
                fix.join("<br>").replace('|', "\\|")
            );
        }
    }
    if !r.unrecognized.is_empty() {
        let _ = writeln!(
            out,
            "\nNot in catalog, not checked: {}",
            r.unrecognized.join(", ")
        );
    }
    out
}

pub fn json(r: &Report) -> serde_json::Result<String> {
    Ok(serde_json::to_string_pretty(r)? + "\n")
}
