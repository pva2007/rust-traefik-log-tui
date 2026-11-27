use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::mpsc;

/// A resolved (or definitely-unresolvable) hostname for one IP.
#[derive(Debug, Clone)]
pub struct DnsEntry {
    pub name: Option<String>,
    pub resolved_at: DateTime<Utc>,
}

/// Cache of reverse-DNS results. Requests are handed to a background worker
/// thread; [`DnsCache::drain`] collects finished answers on the UI tick.
pub struct DnsCache {
    entries: HashMap<IpAddr, DnsEntry>,
    pending: HashSet<IpAddr>,
    ttl: Duration,
    request_tx: mpsc::Sender<IpAddr>,
    answer_rx: mpsc::Receiver<(IpAddr, Option<String>)>,
}

impl DnsCache {
    pub fn new(ttl_hours: u64) -> DnsCache {
        let (request_tx, request_rx) = mpsc::channel::<IpAddr>();
        let (answer_tx, answer_rx) = mpsc::channel::<(IpAddr, Option<String>)>();
        spawn_worker(request_rx, answer_tx);
        DnsCache {
            entries: HashMap::new(),
            pending: HashSet::new(),
            ttl: Duration::hours(ttl_hours.clamp(1, 720) as i64),
            request_tx,
            answer_rx,
        }
    }

    /// Queue an IP for resolution if it is neither cached nor pending.
    pub fn ensure(&mut self, ip: IpAddr) {
        if self.entries.contains_key(&ip) || self.pending.contains(&ip) {
            return;
        }
        self.pending.insert(ip);
        // if the worker is backed up the channel just fills
        let _ = self.request_tx.send(ip);
    }

    /// Collect finished answers from the worker.
    pub fn drain(&mut self) {
        while let Ok((ip, name)) = self.answer_rx.try_recv() {
            self.pending.remove(&ip);
            self.entries.insert(
                ip,
                DnsEntry {
                    name,
                    resolved_at: Utc::now(),
                },
            );
        }
    }

    /// The display name for an IP when one was resolved, else None.
    pub fn get(&self, ip: IpAddr, now: DateTime<Utc>) -> Option<&str> {
        match self.entries.get(&ip) {
            Some(entry) if now - entry.resolved_at < self.ttl => entry.name.as_deref(),
            Some(entry) => entry.name.as_deref(),
            _ => None,
        }
    }

    pub fn invalidate(&mut self) {
        self.entries.clear();
        self.pending.clear();
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

/// Reverse PTR lookup for `ip` via the system DNS configuration. The
/// hickory sync `Resolver` runs its own internal runtime and blocks here;
/// this function only ever runs on the worker thread.
fn reverse_lookup(resolver: &hickory_resolver::Resolver, ip: IpAddr) -> Option<String> {
    let lookup = resolver.reverse_lookup(ip).ok()?;
    lookup
        .iter()
        .next()
        .map(|name| name.to_string().trim_end_matches('.').to_string())
}

fn build_resolver() -> Option<hickory_resolver::Resolver> {
    use hickory_resolver::Resolver;
    use hickory_resolver::system_conf::read_system_conf;
    let (config, mut opts) = match read_system_conf() {
        Ok(c) => c,
        // no resolv.conf (or unsupported platform): default config
        Err(_) => return Resolver::default().ok(),
    };
    opts.timeout = std::time::Duration::from_secs(2);
    Resolver::new(config, opts).ok()
}

fn spawn_worker(
    requests: mpsc::Receiver<IpAddr>,
    answers: mpsc::Sender<(IpAddr, Option<String>)>,
) {
    std::thread::Builder::new()
        .name("dns".into())
        .spawn(move || {
            let Some(resolver) = build_resolver() else { return };
            while let Ok(ip) = requests.recv() {
                let name = reverse_lookup(&resolver, ip);
                if answers.send((ip, name)).is_err() {
                    break;
                }
            }
        })
        .expect("spawn dns worker");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: Option<&str>) -> DnsEntry {
        DnsEntry {
            name: name.map(String::from),
            resolved_at: Utc::now(),
        }
    }

    #[test]
    fn get_returns_cached_name() {
        let mut c = DnsCache::new(1);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(c.get(ip, Utc::now()), None);
        c.entries.insert(ip, entry(Some("one.example")));
        assert_eq!(c.get(ip, Utc::now()), Some("one.example"));
    }

    #[test]
    fn ensure_skips_pending() {
        let mut c = DnsCache::new(1);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        c.ensure(ip);
        c.ensure(ip);
        assert_eq!(c.pending_count(), 1);
        c.drain();
        assert_eq!(c.pending_count(), 1); // worker has not answered yet
    }
}
