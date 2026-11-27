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

#[derive(Debug)]
enum Request {
    Ptr(IpAddr),
    Host(String),
}

#[derive(Debug)]
enum Answer {
    Ptr(IpAddr, Option<String>),
    Host(String, Vec<IpAddr>),
}

/// Cache of reverse-DNS results and self-IP detection. Requests are handed
/// to a background worker thread; [`DnsCache::drain`] collects finished
/// answers on the UI tick.
///
/// PTR names are only kept when forward-confirmed (the name resolves back
/// to the same IP): a machine with several virtual hosts has a single PTR
/// record, so an unconfirmed PTR is too weak a claim to show as identity.
pub struct DnsCache {
    entries: HashMap<IpAddr, DnsEntry>,
    pending: HashSet<IpAddr>,
    hosts_pending: HashSet<String>,
    /// Hosts already resolved (possibly to zero addresses) - never re-queried
    /// unless invalidated, so unresolvable names don't loop.
    hosts_done: HashSet<String>,
    ttl: Duration,
    /// IPs of the observed virtual hosts (RequestHost): traffic from these
    /// is the server talking to itself.
    self_ips: HashSet<IpAddr>,
    request_tx: mpsc::Sender<Request>,
    answer_rx: mpsc::Receiver<Answer>,
}

impl DnsCache {
    pub fn new(ttl_hours: u64) -> DnsCache {
        let (request_tx, request_rx) = mpsc::channel::<Request>();
        let (answer_tx, answer_rx) = mpsc::channel::<Answer>();
        spawn_worker(request_rx, answer_tx);
        DnsCache {
            entries: HashMap::new(),
            pending: HashSet::new(),
            hosts_pending: HashSet::new(),
            hosts_done: HashSet::new(),
            ttl: Duration::hours(ttl_hours.clamp(1, 720) as i64),
            self_ips: HashSet::new(),
            request_tx,
            answer_rx,
        }
    }

    /// Queue an IP for reverse resolution if neither cached nor pending.
    pub fn ensure(&mut self, ip: IpAddr) {
        if self.entries.contains_key(&ip) || self.pending.contains(&ip) {
            return;
        }
        self.pending.insert(ip);
        // if the worker is backed up the channel just fills
        let _ = self.request_tx.send(Request::Ptr(ip));
    }

    /// Queue a virtual host name for forward resolution (self-IP discovery).
    pub fn ensure_host(&mut self, host: &str) {
        if self.hosts_pending.contains(host) || self.hosts_done.contains(host) {
            return;
        }
        self.hosts_pending.insert(host.to_string());
        let _ = self.request_tx.send(Request::Host(host.to_string()));
    }

    /// Collect finished answers from the worker.
    pub fn drain(&mut self) {
        while let Ok(answer) = self.answer_rx.try_recv() {
            match answer {
                Answer::Ptr(ip, name) => {
                    self.pending.remove(&ip);
                    self.entries.insert(
                        ip,
                        DnsEntry {
                            name,
                            resolved_at: Utc::now(),
                        },
                    );
                }
                Answer::Host(host, ips) => {
                    self.hosts_pending.remove(&host);
                    self.hosts_done.insert(host);
                    self.self_ips.extend(ips);
                }
            }
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

    /// True if `ip` is one of the addresses the observed virtual hosts
    /// resolve to: a client whose address equals the address of the host
    /// it requested is the server itself (or shares that address).
    /// No other inference is made — a PTR name, however similar, is not
    /// evidence of co-location.
    pub fn is_self(&self, ip: IpAddr) -> bool {
        self.self_ips.contains(&ip)
    }

    pub fn invalidate(&mut self) {
        self.entries.clear();
        self.pending.clear();
        self.self_ips.clear();
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

/// Non-global single-host addresses: loopback, RFC1918, link-local, docker
/// bridges and such. Clients from these are the machine itself or its LAN.
pub fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 link local
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Reverse PTR lookup for `ip` via the system DNS configuration. The
/// hickory sync `Resolver` runs its own internal runtime and blocks here;
/// these functions only ever run on the worker thread.
fn reverse_lookup(resolver: &hickory_resolver::Resolver, ip: IpAddr) -> Option<String> {
    let lookup = resolver.reverse_lookup(ip).ok()?;
    lookup
        .iter()
        .next()
        .map(|name| name.to_string().trim_end_matches('.').to_string())
}

fn lookup_host(resolver: &hickory_resolver::Resolver, name: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Ok(lookup) = resolver.ipv4_lookup(name) {
        out.extend(lookup.iter().map(|a| IpAddr::V4(a.0)));
    }
    if let Ok(lookup) = resolver.ipv6_lookup(name) {
        out.extend(lookup.iter().map(|a| IpAddr::V6(a.0)));
    }
    out
}

/// Forward-confirm the PTR name: it must resolve back to `ip` (FCrDNS).
fn forward_confirmed(resolver: &hickory_resolver::Resolver, name: &str, ip: IpAddr) -> bool {
    lookup_host(resolver, name).contains(&ip)
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

fn spawn_worker(requests: mpsc::Receiver<Request>, answers: mpsc::Sender<Answer>) {
    std::thread::Builder::new()
        .name("dns".into())
        .spawn(move || {
            let Some(resolver) = build_resolver() else { return };
            while let Ok(req) = requests.recv() {
                let answer = match req {
                    Request::Ptr(ip) => {
                        let name = reverse_lookup(&resolver, ip)
                            .filter(|name| forward_confirmed(&resolver, name, ip));
                        Answer::Ptr(ip, name)
                    }
                    Request::Host(host) => {
                        let ips = lookup_host(&resolver, &host);
                        Answer::Host(host, ips)
                    }
                };
                if answers.send(answer).is_err() {
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

    #[test]
    fn self_ips_detected() {
        let mut c = DnsCache::new(1);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(!c.is_self(ip));
        c.drain(); // worker answered nothing
        c.self_ips.insert(ip);
        assert!(c.is_self(ip));
        c.invalidate();
        assert!(!c.is_self(ip));
    }

    #[test]
    fn ensure_host_deduplicates() {
        let mut c = DnsCache::new(1);
        c.ensure_host("mail.example");
        c.ensure_host("mail.example");
        assert_eq!(c.hosts_pending.len(), 1);
        // answered (even with zero addresses): never re-queried
        c.drain(); // worker has no resolver in test env; simulate manually
        c.hosts_pending.remove("mail.example");
        c.hosts_done.insert("mail.example".to_string());
        c.ensure_host("mail.example");
        assert!(c.hosts_pending.is_empty());
    }

    #[test]
    fn local_addresses() {
        for ip in ["127.0.0.1", "10.0.0.5", "192.168.1.10", "172.18.0.1", "169.254.3.3", "::1", "fe80::1", "fd00::5"] {
            assert!(is_local_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "91.107.197.42", "2606:4700::1"] {
            assert!(!is_local_ip(ip.parse().unwrap()), "{ip}");
        }
    }
}
