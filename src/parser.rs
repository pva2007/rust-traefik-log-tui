use chrono::{DateTime, Utc};
use serde::Deserialize;

/// One Traefik access-log request, decoded from the default JSON format.
///
/// All fields are optional because Traefik omits keys depending on the
/// request (no router yet, plain HTTP without TLS, aborted connections
/// report status 0, ...). Unknown keys are ignored.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Entry {
    #[serde(rename = "StartUTC")]
    pub start_utc: Option<DateTime<Utc>>,
    #[serde(rename = "ClientAddr")]
    pub client_addr: Option<String>,
    #[serde(rename = "ClientHost")]
    pub client_host: Option<String>,
    #[serde(rename = "ClientPort")]
    pub client_port: Option<String>,
    #[serde(rename = "ClientUsername")]
    pub client_username: Option<String>,
    #[serde(rename = "DownstreamStatus")]
    pub status: Option<i64>,
    #[serde(rename = "OriginStatus")]
    pub origin_status: Option<i64>,
    #[serde(rename = "Duration")]
    pub duration_ns: Option<i64>,
    #[serde(rename = "OriginDuration")]
    pub origin_duration_ns: Option<i64>,
    #[serde(rename = "Overhead")]
    pub overhead_ns: Option<i64>,
    #[serde(rename = "RequestContentSize")]
    pub request_size: Option<i64>,
    #[serde(rename = "DownstreamContentSize")]
    pub response_size: Option<i64>,
    #[serde(rename = "RequestHost")]
    pub host: Option<String>,
    #[serde(rename = "RequestMethod")]
    pub method: Option<String>,
    #[serde(rename = "RequestPath")]
    pub path: Option<String>,
    #[serde(rename = "RequestProtocol")]
    pub protocol: Option<String>,
    #[serde(rename = "RequestScheme")]
    pub scheme: Option<String>,
    #[serde(rename = "RetryAttempts")]
    pub retries: Option<u32>,
    #[serde(rename = "RouterName")]
    pub router: Option<String>,
    #[serde(rename = "ServiceName")]
    pub service: Option<String>,
    #[serde(rename = "ServiceAddr")]
    pub service_addr: Option<String>,
    #[serde(rename = "entryPointName")]
    pub entry_point: Option<String>,
    #[serde(rename = "TLSVersion")]
    pub tls_version: Option<String>,
    #[serde(rename = "TLSCipher")]
    pub tls_cipher: Option<String>,
}

/// Parse one JSON access-log line. Returns an error for anything that is
/// not valid JSON (half-written trailing lines are handled by the watcher
/// and should never reach here).
pub fn parse_line(line: &str) -> Result<Entry, serde_json::Error> {
    serde_json::from_str(line)
}

impl Entry {
    /// The upstream-facing client IP (what Traefik sees as the TCP peer,
    /// or the trusted forwarded client when behind a proxy).
    pub fn client_ip(&self) -> Option<&str> {
        self.client_host.as_deref().or_else(|| {
            self.client_addr
                .as_deref()
                .and_then(|a| a.rsplit_once(':').map(|(ip, _)| ip))
        })
    }

    /// Status class bucket: 2, 3, 4, 5 or 0 for unknown/aborted.
    pub fn status_class(&self) -> u8 {
        match self.status {
            Some(s) if (200..300).contains(&s) => 2,
            Some(s) if (300..400).contains(&s) => 3,
            Some(s) if (400..500).contains(&s) => 4,
            Some(s) if s >= 500 => 5,
            _ => 0,
        }
    }

    pub fn is_error(&self) -> bool {
        self.status_class() >= 5
    }

    /// Duration in milliseconds.
    pub fn duration_ms(&self) -> Option<f64> {
        self.duration_ns.map(|ns| ns as f64 / 1_000_000.0)
    }

    /// Compact one-line summary, used as the haystack for bare filter terms.
    pub fn haystack(&self) -> String {
        format!(
            "{} {} {} {} {} {} {}",
            self.method.as_deref().unwrap_or("-"),
            self.host.as_deref().unwrap_or("-"),
            self.path.as_deref().unwrap_or("-"),
            self.router.as_deref().unwrap_or("-"),
            self.service.as_deref().unwrap_or("-"),
            self.client_ip().unwrap_or("-"),
            self.status.map(|s| s.to_string()).unwrap_or_default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"ClientAddr":"172.69.109.100:10726","ClientHost":"91.33.28.80","ClientPort":"10726","ClientUsername":"-","DownstreamContentSize":534,"DownstreamStatus":200,"Duration":19670025,"OriginContentSize":534,"OriginStatus":200,"Overhead":565804,"RequestAddr":"bao.valicek.de","RequestContentSize":101,"RequestCount":2059914,"RequestHost":"bao.valicek.de","RequestMethod":"PUT","RequestPath":"/v1/auth/approle/login","RequestPort":"-","RequestProtocol":"HTTP/2.0","RequestScheme":"https","RetryAttempts":0,"RouterName":"de_valicek-bao-bao-api@docker","ServiceAddr":"de_valicek-bao:8200","ServiceName":"de_valicek-bao-bao-api@docker","ServiceURL":"http://de_valicek-bao:8200","StartLocal":"2026-11-25T00:00:29.069855019+01:00","StartUTC":"2026-11-24T23:00:29.069855019Z","TLSCipher":"TLS_AES_128_GCM_SHA256","TLSVersion":"1.3","entryPointName":"websecure","level":"info","msg":"","time":"2026-11-25T00:00:29+01:00"}"#;

    #[test]
    fn parses_sample_line() {
        let e = parse_line(SAMPLE).unwrap();
        assert_eq!(e.status, Some(200));
        assert_eq!(e.status_class(), 2);
        assert_eq!(e.client_host.as_deref(), Some("91.33.28.80"));
        assert_eq!(e.host.as_deref(), Some("bao.valicek.de"));
        assert_eq!(e.method.as_deref(), Some("PUT"));
        assert_eq!(e.duration_ms(), Some(19.670025));
        assert_eq!(e.router.as_deref(), Some("de_valicek-bao-bao-api@docker"));
        assert_eq!(e.tls_version.as_deref(), Some("1.3"));
    }

    #[test]
    fn parses_minimal_line() {
        let e = parse_line(r#"{"DownstreamStatus":0,"Duration":100}"#).unwrap();
        assert_eq!(e.status, Some(0));
        assert_eq!(e.status_class(), 0);
        assert!(e.host.is_none());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_line("not json").is_err());
    }

    #[test]
    fn error_classes() {
        for (code, class) in [(204u32, 2u8), (207, 2), (307, 3), (404, 4), (401, 4), (502, 5)] {
            let e = parse_line(&format!(r#"{{"DownstreamStatus":{code}}}"#)).unwrap();
            assert_eq!(e.status_class(), class, "status {code}");
        }
    }
}
