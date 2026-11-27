use crate::parser::Entry;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

/// Aggregates for one key (an IP, host, router, service or path).
#[derive(Debug, Clone, Default)]
pub struct Agg {
    pub key: String,
    pub count: u64,
    pub errors: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub duration_sum_ns: u128,
    pub max_duration_ns: u64,
}

impl Agg {
    pub fn avg_ms(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.duration_sum_ns as f64 / self.count as f64 / 1_000_000.0
        }
    }

    pub fn max_ms(&self) -> f64 {
        self.max_duration_ns as f64 / 1_000_000.0
    }

    pub fn error_rate(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.errors as f64 / self.count as f64
        }
    }
}

/// Per-second request volume bucket.
#[derive(Debug, Clone, Copy, Default)]
pub struct Bucket {
    /// Seconds since the Unix epoch, bucket start.
    pub ts: i64,
    pub count: u64,
    /// 5xx responses.
    pub errors: u64,
    /// 4xx responses.
    pub client_errors: u64,
}

#[derive(Debug, Clone, Default)]
pub struct Latency {
    pub avg_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// Window length the snapshot covers.
    pub window_secs: i64,
    /// Newest entry time inside the window (or session start fallback).
    pub window_end: Option<DateTime<Utc>>,
    /// Actual span of data inside the window, seconds (0 if empty).
    pub span_secs: i64,
    pub count: u64,
    pub errors: u64,
    pub client_errors: u64,
    pub rps: f64,
    pub buckets: Vec<Bucket>,
    /// Index 0 = unknown/aborted (0), then 2xx..5xx at 2..=5.
    pub status_classes: [u64; 6],
    pub statuses: Vec<(i64, u64)>,
    pub top_clients: Vec<Agg>,
    pub top_hosts: Vec<Agg>,
    pub top_routers: Vec<Agg>,
    pub top_services: Vec<Agg>,
    pub top_paths: Vec<Agg>,
    pub latency: Latency,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// RetryAttempts sum: re-routed requests hint at unhealthy backends.
    pub retries: u64,
}

/// Build a snapshot over `[window_end - window, window_end]` from `entries`
/// (must be sorted by time ascending, which the ingest path guarantees).
pub fn snapshot(entries: &[Entry], window: Duration, now: DateTime<Utc>, top_n: usize) -> Snapshot {
    let window_secs = window.num_seconds().max(1);
    let mut snap = Snapshot {
        window_secs,
        ..Default::default()
    };

    // The data may lag behind wall-clock (replayed logs): anchor the window
    // at the newest entry, not at `now`.
    let end = entries
        .last()
        .and_then(|e| e.start_utc)
        .unwrap_or(now)
        .min(now);
    let start = end - window;
    snap.window_end = Some(end);

    let start_ts = start.timestamp();
    let end_ts = end.timestamp();

    // One bucket per second targets ~360 buckets; for long windows (or a
    // whole-file snapshot) the granularity coarsens automatically.
    let bucket_secs = (window_secs / 360).max(1);
    let nbuckets = ((window_secs / bucket_secs) + 1).max(1) as usize;
    let mut buckets: Vec<Bucket> = vec![Bucket::default(); nbuckets];
    for (i, b) in buckets.iter_mut().enumerate() {
        b.ts = start_ts + (i as i64) * bucket_secs;
    }

    let mut clients: HashMap<String, Agg> = HashMap::new();
    let mut hosts: HashMap<String, Agg> = HashMap::new();
    let mut routers: HashMap<String, Agg> = HashMap::new();
    let mut services: HashMap<String, Agg> = HashMap::new();
    let mut paths: HashMap<String, Agg> = HashMap::new();
    let mut status_counts: HashMap<i64, u64> = HashMap::new();
    let mut durations: Vec<u64> = Vec::new();

    for e in entries {
        let Some(ts) = e.start_utc.map(|t| t.timestamp()) else {
            continue;
        };
        if ts < start_ts || ts > end_ts {
            continue;
        }
        snap.count += 1;
        match e.status_class() {
            0 => snap.status_classes[0] += 1,
            c => {
                snap.status_classes[c as usize] += 1;
                if c == 5 {
                    snap.errors += 1;
                } else if c == 4 {
                    snap.client_errors += 1;
                }
            }
        }
        if let Some(s) = e.status {
            *status_counts.entry(s).or_default() += 1;
        }
        let idx = ((ts - start_ts) / bucket_secs) as usize;
        if let Some(b) = buckets.get_mut(idx) {
            b.count += 1;
            if e.status_class() == 5 {
                b.errors += 1;
            } else if e.status_class() == 4 {
                b.client_errors += 1;
            }
        }
        snap.bytes_in += e.request_size.unwrap_or(0).max(0) as u64;
        snap.bytes_out += e.response_size.unwrap_or(0).max(0) as u64;
        snap.retries += e.retries.unwrap_or(0) as u64;
        if let Some(d) = e.duration_ns
            && d >= 0 {
                durations.push(d as u64);
            }

        let dur = e.duration_ns.unwrap_or(0).max(0) as u128;
        let bytes_in = e.request_size.unwrap_or(0).max(0) as u64;
        let bytes_out = e.response_size.unwrap_or(0).max(0) as u64;
        let is_err = e.is_error();
        let bump = |map: &mut HashMap<String, Agg>, key: Option<&str>| {
            if let Some(k) = key {
                let a = map.entry(k.to_string()).or_default();
                a.key = k.to_string();
                a.count += 1;
                a.errors += is_err as u64;
                a.bytes_in += bytes_in;
                a.bytes_out += bytes_out;
                a.duration_sum_ns += dur;
                a.max_duration_ns = a.max_duration_ns.max(dur as u64);
            }
        };
        bump(&mut clients, e.client_ip());
        bump(&mut hosts, e.host.as_deref());
        bump(&mut routers, e.router.as_deref());
        bump(&mut services, e.service.as_deref());
        // paths: keep the raw path (no per-path templating) but cap stored
        // length so query-heavy endpoints don't blow up memory
        bump(&mut paths, e.path.as_deref().map(|p| {
            let cut = p.find(['?', ';']).unwrap_or(p.len()).min(120);
            &p[..cut]
        }));
    }

    // first/last timestamp inside the window for a truthful rps
    let span = entries
        .iter()
        .filter(|e| {
            e.start_utc
                .map(|t| t.timestamp() >= start_ts && t.timestamp() <= end_ts)
                .unwrap_or(false)
        })
        .fold(None, |acc: Option<(i64, i64)>, e| {
            let ts = e.start_utc.unwrap().timestamp();
            Some(acc.map_or((ts, ts), |(lo, hi)| (lo.min(ts), hi.max(ts))))
        });
    if let Some((lo, hi)) = span {
        snap.span_secs = (hi - lo + 1).max(1);
    } else {
        snap.span_secs = 1;
    }
    snap.rps = snap.count as f64 / snap.span_secs as f64;

    // trim leading/trailing empty buckets so the chart starts at first traffic
    while buckets.first().is_some_and(|b| b.count == 0) && buckets.len() > 2 {
        buckets.remove(0);
    }
    while buckets.last().is_some_and(|b| b.count == 0) && buckets.len() > 2 {
        buckets.pop();
    }
    snap.buckets = buckets;

    snap.statuses = {
        let mut v: Vec<(i64, u64)> = status_counts.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    };
    let sort_top = |mut v: Vec<Agg>| {
        v.sort_by(|a, b| b.count.cmp(&a.count).then(a.key.cmp(&b.key)));
        v.truncate(top_n);
        v
    };
    snap.top_clients = sort_top(clients.into_values().collect());
    snap.top_hosts = sort_top(hosts.into_values().collect());
    snap.top_routers = sort_top(routers.into_values().collect());
    snap.top_services = sort_top(services.into_values().collect());
    snap.top_paths = sort_top(paths.into_values().collect());

    snap.latency = percentiles(&durations);
    snap
}

fn percentiles(durations: &[u64]) -> Latency {
    if durations.is_empty() {
        return Latency::default();
    }
    let mut v = durations.to_vec();
    v.sort_unstable();
    let pick = |p: usize| v[(v.len() - 1).min(v.len() * p / 100)] as f64 / 1_000_000.0;
    let sum: u128 = v.iter().map(|&d| d as u128).sum();
    Latency {
        avg_ms: sum as f64 / v.len() as f64 / 1_000_000.0,
        p50_ms: pick(50),
        p95_ms: pick(95),
        p99_ms: pick(99),
        max_ms: *v.last().unwrap() as f64 / 1_000_000.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_line;

    fn e(ts: i64, status: i64, dur_ns: i64, ip: &str, host: &str) -> Entry {
        let mut e = parse_line(&format!(
            r#"{{"DownstreamStatus":{status},"Duration":{dur_ns},"ClientHost":"{ip}","RequestHost":"{host}"}}"#
        ))
        .unwrap();
        e.start_utc = DateTime::from_timestamp(ts, 0);
        e
    }

    #[test]
    fn window_and_rps() {
        let now = DateTime::from_timestamp(1_700_000_100, 0).unwrap();
        let entries = vec![
            e(1_700_000_000 - 3600, 200, 1_000_000, "3.3.3.3", "c.test"), // outside
            e(1_700_000_000, 200, 1_000_000, "1.1.1.1", "a.test"),
            e(1_700_000_005, 500, 2_000_000, "1.1.1.1", "a.test"),
            e(1_700_000_005, 404, 3_000_000, "2.2.2.2", "b.test"),
        ];
        let s = snapshot(&entries, Duration::seconds(120), now, 10);
        assert_eq!(s.count, 3);
        assert_eq!(s.errors, 1);
        assert_eq!(s.client_errors, 1);
        assert_eq!(s.status_classes[2], 1);
        assert_eq!(s.rps, 3.0 / 6.0);
        assert_eq!(s.top_clients[0].key, "1.1.1.1");
        assert_eq!(s.top_clients[0].errors, 1);
        assert_eq!(s.top_hosts.len(), 2);
        assert!((s.latency.p50_ms - 2.0).abs() < 1e-9);
        assert_eq!(s.latency.max_ms, 3.0);
    }

    #[test]
    fn buckets_trimmed() {
        let now = DateTime::from_timestamp(1_700_000_010, 0).unwrap();
        let entries = vec![e(1_700_000_005, 200, 1, "1.1.1.1", "a")];
        let s = snapshot(&entries, Duration::seconds(60), now, 5);
        // window is 60s, but only the bucket around ts=...005 has traffic
        assert!(s.buckets.len() < 61);
        assert!(s.buckets.iter().any(|b| b.count == 1));
    }

    #[test]
    fn empty_entries() {
        let now = Utc::now();
        let s = snapshot(&[], Duration::seconds(60), now, 5);
        assert_eq!(s.count, 0);
        assert_eq!(s.rps, 0.0);
        assert!(s.top_clients.is_empty());
    }
}
