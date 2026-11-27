use crate::parser::Entry;
use regex::Regex;

/// One filter token. Tokens are AND-combined.
#[derive(Debug, Clone)]
enum Term {
    /// 2xx / 4xx / 5xx class, exact code, "0", or ">=500" / "<400".
    Status(String),
    Method(String),
    /// Case-insensitive substring match.
    Host(String),
    Router(String),
    Service(String),
    Client(String),
    Path(String),
    /// Bare term: regex over a compact "method host path router service ip"
    /// haystack.
    Regex(Regex),
}

#[derive(Debug, Clone, Default)]
pub struct Filter {
    raw: String,
    terms: Vec<Term>,
    /// Compile error from the last attempt (shown in the footer).
    pub error: Option<String>,
}

impl Filter {
    pub fn parse(raw: &str) -> Filter {
        let mut terms = Vec::new();
        let mut error = None;
        for tok in raw.split_whitespace() {
            if let Some(v) = tok.strip_prefix("status:").or_else(|| tok.strip_prefix("s:")) {
                terms.push(Term::Status(v.to_string()));
            } else if let Some(v) = tok
                .strip_prefix("method:")
                .or_else(|| tok.strip_prefix("m:"))
            {
                terms.push(Term::Method(v.to_uppercase()));
            } else if let Some(v) = tok.strip_prefix("host:").or_else(|| tok.strip_prefix("h:")) {
                terms.push(Term::Host(v.to_lowercase()));
            } else if let Some(v) = tok
                .strip_prefix("router:")
                .or_else(|| tok.strip_prefix("r:"))
            {
                terms.push(Term::Router(v.to_lowercase()));
            } else if let Some(v) = tok
                .strip_prefix("service:")
                .or_else(|| tok.strip_prefix("svc:"))
            {
                terms.push(Term::Service(v.to_lowercase()));
            } else if let Some(v) = tok
                .strip_prefix("ip:")
                .or_else(|| tok.strip_prefix("client:"))
            {
                terms.push(Term::Client(v.to_string()));
            } else if let Some(v) = tok.strip_prefix("path:").or_else(|| tok.strip_prefix("p:")) {
                terms.push(Term::Path(v.to_lowercase()));
            } else if tok == "errors" || tok == "err" {
                terms.push(Term::Status("5xx".to_string()));
            } else {
                match Regex::new(tok) {
                    Ok(re) => terms.push(Term::Regex(re)),
                    Err(e) => {
                        error = Some(format!("{tok}: {e}"));
                        break;
                    }
                }
            }
        }
        Filter {
            raw: raw.to_string(),
            terms,
            error,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn matches(&self, e: &Entry) -> bool {
        for term in &self.terms {
            let ok = match term {
                Term::Status(pat) => status_matches(e.status, pat),
                Term::Method(m) => e.method.as_deref().is_some_and(|v| v.eq_ignore_ascii_case(m)),
                Term::Host(s) => e.host.as_deref().is_some_and(|v| v.to_lowercase().contains(s)),
                Term::Router(s) => e
                    .router
                    .as_deref()
                    .is_some_and(|v| v.to_lowercase().contains(s)),
                Term::Service(s) => e
                    .service
                    .as_deref()
                    .is_some_and(|v| v.to_lowercase().contains(s)),
                Term::Client(s) => e.client_ip().is_some_and(|v| v.contains(s)),
                Term::Path(s) => e.path.as_deref().is_some_and(|v| v.to_lowercase().contains(s)),
                Term::Regex(re) => re.is_match(&e.haystack()),
            };
            if !ok {
                return false;
            }
        }
        true
    }
}

fn status_matches(status: Option<i64>, pat: &str) -> bool {
    let Some(s) = status else {
        return false;
    };
    if let Some(rest) = pat.strip_prefix(">=") {
        return rest.parse::<i64>().map(|n| s >= n).unwrap_or(false);
    }
    if let Some(rest) = pat.strip_prefix("<") {
        return rest.parse::<i64>().map(|n| s < n).unwrap_or(false);
    }
    if let Some(cls) = pat.strip_suffix("xx") {
        return cls.parse::<u8>().map(|c| s / 100 == c as i64).unwrap_or(false);
    }
    pat.parse::<i64>().map(|n| s == n).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_line;

    fn entry(json: &str) -> Entry {
        parse_line(json).unwrap()
    }

    #[test]
    fn empty_matches_everything() {
        let f = Filter::parse("");
        assert!(f.matches(&entry(r#"{"DownstreamStatus":500}"#)));
    }

    #[test]
    fn status_class() {
        let f = Filter::parse("status:5xx");
        assert!(f.matches(&entry(r#"{"DownstreamStatus":502}"#)));
        assert!(!f.matches(&entry(r#"{"DownstreamStatus":404}"#)));

        let f = Filter::parse("status:404");
        assert!(f.matches(&entry(r#"{"DownstreamStatus":404}"#)));
        assert!(!f.matches(&entry(r#"{"DownstreamStatus":401}"#)));

        let f = Filter::parse("status:>=500");
        assert!(f.matches(&entry(r#"{"DownstreamStatus":500}"#)));
        assert!(!f.matches(&entry(r#"{"DownstreamStatus":499}"#)));

        let f = Filter::parse("status:0");
        assert!(f.matches(&entry(r#"{"DownstreamStatus":0}"#)));
    }

    #[test]
    fn errors_keyword() {
        let f = Filter::parse("errors");
        assert!(f.matches(&entry(r#"{"DownstreamStatus":503}"#)));
        assert!(!f.matches(&entry(r#"{"DownstreamStatus":200}"#)));
    }

    #[test]
    fn field_tokens() {
        let e = entry(r#"{"RequestHost":"bao.valicek.de","RequestPath":"/v1/auth/login","RequestMethod":"PUT","RouterName":"bao-api@docker","ClientHost":"91.33.28.80"}"#);
        assert!(Filter::parse("host:bao").matches(&e));
        assert!(Filter::parse("path:/v1/auth").matches(&e));
        assert!(Filter::parse("method:put").matches(&e));
        assert!(Filter::parse("ip:91.33").matches(&e));
        assert!(Filter::parse("router:bao-api").matches(&e));
        assert!(!Filter::parse("host:git").matches(&e));
    }

    #[test]
    fn bare_regex_and_combination() {
        let e = entry(r#"{"RequestHost":"bao.valicek.de","RequestPath":"/v1/talos/outline.tc1","DownstreamStatus":200}"#);
        assert!(Filter::parse("talos").matches(&e));
        assert!(Filter::parse("bao\\.valicek status:2xx").matches(&e));
        assert!(!Filter::parse("talos status:4xx").matches(&e));
    }

    #[test]
    fn bad_regex_reports_error() {
        let f = Filter::parse("foo(");
        assert!(f.error.is_some());
    }
}
