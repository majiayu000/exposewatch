//! Version parsing and NVD-style range matching.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Num(u64),
    Text(String),
}

fn tokens(v: &str) -> Vec<Tok> {
    v.split(['.', '-', '+', '_'])
        .filter(|s| !s.is_empty())
        .map(|s| match s.parse::<u64>() {
            Ok(n) => Tok::Num(n),
            Err(_) => Tok::Text(s.to_ascii_lowercase()),
        })
        .collect()
}

/// Compare dotted versions numerically. A missing numeric part sorts lower
/// (`1.2 < 1.2.1`); a trailing text part is a pre-release (`1.2-beta < 1.2`).
pub fn compare(a: &str, b: &str) -> Ordering {
    let (ta, tb) = (tokens(a), tokens(b));
    for i in 0..ta.len().max(tb.len()) {
        let ord = match (ta.get(i), tb.get(i)) {
            (Some(Tok::Num(x)), Some(Tok::Num(y))) => x.cmp(y),
            (Some(Tok::Text(x)), Some(Tok::Text(y))) => x.cmp(y),
            (Some(Tok::Num(_)), Some(Tok::Text(_))) => Ordering::Greater,
            (Some(Tok::Text(_)), Some(Tok::Num(_))) => Ordering::Less,
            (Some(Tok::Num(_)), None) => Ordering::Greater,
            (None, Some(Tok::Num(_))) => Ordering::Less,
            (Some(Tok::Text(_)), None) => Ordering::Less,
            (None, Some(Tok::Text(_))) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

/// Pull an application version out of an image tag or label value.
/// Requires at least one dot so floating tags like `2` or `latest` are rejected.
pub fn extract(s: &str) -> Option<String> {
    let mut s = s.trim();
    for prefix in ["amd64-", "arm64v8-", "arm64-", "version-", "release-"] {
        s = s.strip_prefix(prefix).unwrap_or(s);
    }
    let start = s.find(|c: char| c.is_ascii_digit())?;
    // Only skip a leading "v" (v3.7.16), not arbitrary text.
    if start > 0 && &s[..start] != "v" && !s[..start].ends_with(' ') {
        return None;
    }
    let ver: String = s[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let ver = ver.trim_end_matches('.');
    ver.contains('.').then(|| ver.to_string())
}

/// One affected range, using NVD cpeMatch semantics. `exact` is set for CPEs
/// that name a single version instead of a range.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Range {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_including: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_excluding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_including: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_excluding: Option<String>,
}

impl Range {
    pub fn contains(&self, v: &str) -> bool {
        if let Some(e) = &self.exact {
            return compare(v, e) == Ordering::Equal;
        }
        if self.start_including.is_none()
            && self.start_excluding.is_none()
            && self.end_including.is_none()
            && self.end_excluding.is_none()
        {
            // "every version" CPEs are too broad to act on.
            return false;
        }
        let ge = |b: &Option<String>| b.as_ref().is_none_or(|b| compare(v, b) != Ordering::Less);
        let gt = |b: &Option<String>| {
            b.as_ref()
                .is_none_or(|b| compare(v, b) == Ordering::Greater)
        };
        let le = |b: &Option<String>| {
            b.as_ref()
                .is_none_or(|b| compare(v, b) != Ordering::Greater)
        };
        let lt = |b: &Option<String>| b.as_ref().is_none_or(|b| compare(v, b) == Ordering::Less);
        ge(&self.start_including)
            && gt(&self.start_excluding)
            && le(&self.end_including)
            && lt(&self.end_excluding)
    }

    /// Human-readable fix target: the first version outside this range.
    pub fn fix(&self) -> Option<String> {
        if let Some(e) = &self.end_excluding {
            Some(e.clone())
        } else {
            self.end_including.as_ref().map(|e| format!("> {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_numeric_parts() {
        assert_eq!(compare("1.43.2.10687", "1.43.3.10861"), Ordering::Less);
        assert_eq!(compare("1.27.10", "1.27.9"), Ordering::Greater);
        assert_eq!(compare("1.2", "1.2.0.1"), Ordering::Less);
        assert_eq!(compare("8.0.0-beta1", "8.0.0"), Ordering::Less);
        assert_eq!(compare("6.5.4", "6.5.4"), Ordering::Equal);
    }

    #[test]
    fn extracts_versions_from_tags() {
        assert_eq!(
            extract("1.43.2.10687-563d026ea").as_deref(),
            Some("1.43.2.10687")
        );
        assert_eq!(
            extract("1.43.4.10903-e5521bd8c-ls328").as_deref(),
            Some("1.43.4.10903")
        );
        assert_eq!(
            extract("version-1.43.5.11029-6bf8af3f0").as_deref(),
            Some("1.43.5.11029")
        );
        assert_eq!(extract("amd64-1.43.5").as_deref(), Some("1.43.5"));
        assert_eq!(extract("v3.7.16").as_deref(), Some("3.7.16"));
        assert_eq!(extract("1.26.4-rootless").as_deref(), Some("1.26.4"));
        assert_eq!(extract("18.7.0-ce.0").as_deref(), Some("18.7.0"));
        assert_eq!(extract("latest"), None);
        assert_eq!(extract("2"), None);
        assert_eq!(extract("nightly-58f11bf"), None);
        assert_eq!(extract("RELEASE.2025-01-01T00-00-00Z"), None);
    }

    #[test]
    fn range_semantics() {
        let plex = Range {
            end_excluding: Some("1.43.3.10861".into()),
            ..Default::default()
        };
        assert!(plex.contains("1.43.2.10687"));
        assert!(!plex.contains("1.43.3.10861"));
        assert_eq!(plex.fix().as_deref(), Some("1.43.3.10861"));

        let zammad = Range {
            start_including: Some("6.3.0".into()),
            end_including: Some("6.5.4".into()),
            ..Default::default()
        };
        assert!(zammad.contains("6.5.4"));
        assert!(!zammad.contains("6.2.9"));
        assert!(!zammad.contains("6.5.5"));
        assert_eq!(zammad.fix().as_deref(), Some("> 6.5.4"));

        let exact = Range {
            exact: Some("1.121.0".into()),
            ..Default::default()
        };
        assert!(exact.contains("1.121.0"));
        assert!(!exact.contains("1.121.1"));

        assert!(!Range::default().contains("1.0"));
    }
}
