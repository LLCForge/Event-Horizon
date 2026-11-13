//! Per-sink routing filters and the small glob matcher shared with silences.

use serde::{Deserialize, Serialize};

use crate::alert::{Alert, Severity};

/// Maximum accepted glob pattern length (config and API input).
pub const MAX_GLOB: usize = 256;

/// Routing filter. Empty lists match everything; non-empty lists are OR-ed
/// glob patterns; the four criteria are AND-ed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filter {
    pub min_severity: Severity,
    pub tools: Vec<String>,
    pub kinds: Vec<String>,
    pub resources: Vec<String>,
}

impl Filter {
    pub fn matches(&self, a: &Alert) -> bool {
        a.severity >= self.min_severity
            && any_glob(&self.tools, &a.tool)
            && any_glob(&self.kinds, &a.kind)
            && (self.resources.is_empty()
                || a.resource
                    .as_deref()
                    .is_some_and(|r| any_glob(&self.resources, r)))
    }

    pub fn validate(&self) -> Result<(), String> {
        for p in self.tools.iter().chain(&self.kinds).chain(&self.resources) {
            validate_glob(p)?;
        }
        Ok(())
    }
}

fn any_glob(patterns: &[String], text: &str) -> bool {
    patterns.is_empty() || patterns.iter().any(|p| glob_match(p, text))
}

pub(crate) fn validate_glob(p: &str) -> Result<(), String> {
    if p.is_empty() || p.len() > MAX_GLOB {
        return Err(format!("glob pattern must be 1..={MAX_GLOB} bytes"));
    }
    if p.chars().any(char::is_control) {
        return Err("glob pattern contains control characters".into());
    }
    Ok(())
}

/// Case-insensitive glob: `*` matches any run (including empty), `?` one char.
/// Linear-time two-pointer algorithm, no backtracking blow-up.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().flat_map(char::to_lowercase).collect();
    let t: Vec<char> = text.chars().flat_map(char::to_lowercase).collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_basics() {
        assert!(glob_match("*", ""));
        assert!(glob_match("192.0.2.*", "192.0.2.0/24"));
        assert!(!glob_match("192.0.2.*", "198.51.100.0/24"));
        assert!(glob_match("*.EXAMPLE.org", "www.example.org"));
        assert!(!glob_match("*.example.org", "example.org"));
        assert!(glob_match("a?c", "abc"));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("a*b*c", "axxbyy"));
        assert!(glob_match(&"*a".repeat(50), &"a".repeat(200)));
    }

    #[test]
    fn filter_matching() {
        let f = Filter {
            min_severity: Severity::Warning,
            tools: vec!["vigil".into()],
            kinds: vec![],
            resources: vec!["2001:db8:*".into()],
        };
        let a = Alert::new("vigil", "hijack", Severity::Critical, "t").resource("2001:db8::/32");
        assert!(f.matches(&a));
        assert!(!f.matches(&a.clone().resource("192.0.2.0/24")));
        let mut low = a.clone();
        low.severity = Severity::Info;
        assert!(!f.matches(&low));
        let mut no_res = a.clone();
        no_res.resource = None;
        assert!(!f.matches(&no_res));
        assert!(Filter::default().matches(&no_res));
    }
}
