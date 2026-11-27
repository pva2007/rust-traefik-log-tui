use crate::dns::DnsCache;
use crate::filter::Filter;
use crate::parser::{parse_line, Entry};
use crate::stats::{snapshot, Snapshot};
use chrono::{DateTime, Duration, Local, Utc};
use ratatui::widgets::TableState;
use std::collections::VecDeque;
use std::path::PathBuf;

pub const N_TABS: usize = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Logs,
    Clients,
    Hosts,
    Routers,
    Services,
    Paths,
    Status,
}

pub const TAB_NAMES: [&str; N_TABS] = [
    "Logs", "Clients", "Hosts", "Routers", "Services", "Paths", "Status",
];

impl Tab {
    pub fn index(self) -> usize {
        self as usize
    }

    pub fn from_index(i: usize) -> Tab {
        match i {
            0 => Tab::Logs,
            1 => Tab::Clients,
            2 => Tab::Hosts,
            3 => Tab::Routers,
            4 => Tab::Services,
            5 => Tab::Paths,
            _ => Tab::Status,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Popup {
    None,
    Detail,
    FilterInput,
    Help,
}

pub const WINDOWS_SECS: [i64; 4] = [60, 300, 900, 3600];

#[derive(Default)]
pub struct SessionTotals {
    pub lines_seen: u64,
    pub parse_errors: u64,
    pub status_classes: [u64; 6],
    pub errors: u64,
    pub first_entry: Option<DateTime<Utc>>,
}


pub struct App {
    pub max_entries: usize,
    pub entries: VecDeque<Entry>,
    pub filter: Filter,
    /// Indices into `entries` that pass the filter (ascending).
    pub filtered: Vec<usize>,
    pub tab: Tab,
    pub table_states: [TableState; N_TABS],
    pub paused: bool,
    pub paused_dropped: u64,
    pub window_idx: usize,
    pub dns: Option<DnsCache>,
    pub snapshot: Option<Snapshot>,
    last_snapshot: Option<DateTime<Utc>>,
    pub popup: Popup,
    pub filter_input: String,
    pub filter_error: Option<String>,
    pub detail_scroll: u16,
    pub totals: SessionTotals,
    pub active_file: Option<PathBuf>,
    pub files_seen: usize,
    pub should_quit: bool,
}

impl App {
    pub fn new(max_entries: usize, initial_filter: &str, use_dns: bool, window_secs: i64) -> App {
        let window_idx = WINDOWS_SECS
            .iter()
            .position(|&w| w == window_secs)
            .unwrap_or(1);
        App {
            max_entries,
            entries: VecDeque::new(),
            filter: Filter::parse(initial_filter),
            filtered: Vec::new(),
            tab: Tab::Logs,
            table_states: Default::default(),
            paused: false,
            paused_dropped: 0,
            window_idx,
            dns: if use_dns { Some(DnsCache::new(24)) } else { None },
            snapshot: None,
            last_snapshot: None,
            popup: Popup::None,
            filter_input: String::new(),
            filter_error: None,
            detail_scroll: 0,
            totals: SessionTotals::default(),
            active_file: None,
            files_seen: 0,
            should_quit: false,
        }
    }

    pub fn window_secs(&self) -> i64 {
        WINDOWS_SECS[self.window_idx]
    }

    /// Ingest raw lines: parse, buffer, filter, keep the tail pinned.
    pub fn ingest(&mut self, lines: &[String]) {
        if self.paused {
            self.paused_dropped += lines.len() as u64;
            return;
        }
        if lines.is_empty() {
            return;
        }
        let sel = self.selected(Tab::Logs);
        let was_at_tail = match sel {
            None => true,
            Some(i) => Some(i) == self.filtered.last().copied(),
        };

        let mut base = self.entries.len();
        for line in lines {
            self.totals.lines_seen += 1;
            match parse_line(line) {
                Ok(e) => {
                    if let Some(t) = e.start_utc {
                        self.totals.first_entry =
                            Some(self.totals.first_entry.map_or(t, |f| f.min(t)));
                    }
                    let class = e.status_class() as usize;
                    self.totals.status_classes[class] += 1;
                    if class == 5 {
                        self.totals.errors += 1;
                    }
                    if self.filter.matches(&e) {
                        self.filtered.push(base);
                    }
                    self.entries.push_back(e);
                    base += 1;
                }
                Err(_) => {
                    self.totals.parse_errors += 1;
                }
            }
        }

        // evict from the front, shift filter indices accordingly
        if self.entries.len() > self.max_entries {
            let k = self.entries.len() - self.max_entries;
            self.entries.drain(..k);
            self.filtered = self
                .filtered
                .iter()
                .filter_map(|i| i.checked_sub(k))
                .collect();
        }

        if was_at_tail {
            self.select_last(Tab::Logs);
        }
        self.clamp_selections();
    }

    pub fn note_files(&mut self, active: Option<PathBuf>, files_seen: usize) {
        self.active_file = active;
        self.files_seen = files_seen;
    }

    pub fn rebuild_filtered(&mut self) {
        self.filtered = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| self.filter.matches(e))
            .map(|(i, _)| i)
            .collect();
        self.clamp_selections();
        self.select_last(Tab::Logs);
    }

    pub fn apply_filter_input(&mut self) {
        self.filter = Filter::parse(&self.filter_input);
        self.filter_error = self.filter.error.clone();
        self.rebuild_filtered();
    }

    /// Refresh the stats snapshot at most twice per second.
    pub fn refresh_snapshot(&mut self) {
        let now = Utc::now();
        if let Some(t) = self.last_snapshot
            && (now - t).num_milliseconds() < 500 {
                return;
            }
        self.last_snapshot = Some(now);
        let entries: Vec<Entry> = self.entries.iter().cloned().collect();
        let window = Duration::seconds(self.window_secs());
        let dns_keys: Vec<String> = if let Some(s) = &self.snapshot {
            s.top_clients.iter().take(40).map(|a| a.key.clone()).collect()
        } else {
            Vec::new()
        };
        let snap = snapshot(&entries, window, now, 100);
        // warm up DNS for the top talkers (and keep the previous set warm)
        if let Some(dns) = &mut self.dns {
            for key in dns_keys {
                if let Ok(ip) = key.parse() {
                    dns.ensure(ip);
                }
            }
            for a in &snap.top_clients {
                if let Ok(ip) = a.key.parse() {
                    dns.ensure(ip);
                }
            }
            dns.drain();
        }
        self.snapshot = Some(snap);
    }

    pub fn display_name(&self, ip: &str) -> String {
        if let Some(dns) = &self.dns
            && let Ok(addr) = ip.parse::<std::net::IpAddr>()
                && let Some(name) = dns.get(addr, Utc::now()) {
                    return format!("{name} ({ip})");
                }
        ip.to_string()
    }

    /// Short form for table cells: resolved name if known, else the IP.
    pub fn display_short(&self, ip: &str) -> String {
        if let Some(dns) = &self.dns
            && let Ok(addr) = ip.parse::<std::net::IpAddr>()
                && let Some(name) = dns.get(addr, Utc::now()) {
                    return name.to_string();
                }
        ip.to_string()
    }

    fn selected(&self, tab: Tab) -> Option<usize> {
        self.table_states[tab.index()].selected()
    }

    fn select_last(&mut self, tab: Tab) {
        let len = self.row_count(tab);
        let sel = if len == 0 { None } else { Some(len - 1) };
        self.table_states[tab.index()].select(sel);
    }

    pub fn row_count(&self, tab: Tab) -> usize {
        match tab {
            Tab::Logs => self.filtered.len(),
            _ => self
                .snapshot
                .as_ref()
                .map(|s| match tab {
                    Tab::Clients => s.top_clients.len(),
                    Tab::Hosts => s.top_hosts.len(),
                    Tab::Routers => s.top_routers.len(),
                    Tab::Services => s.top_services.len(),
                    Tab::Paths => s.top_paths.len(),
                    Tab::Status => s.statuses.len(),
                    _ => 0,
                })
                .unwrap_or(0),
        }
    }

    fn clamp_selections(&mut self) {
        for tab in [
            Tab::Logs,
            Tab::Clients,
            Tab::Hosts,
            Tab::Routers,
            Tab::Services,
            Tab::Paths,
            Tab::Status,
        ] {
            let len = self.row_count(tab);
            let st = &mut self.table_states[tab.index()];
            match st.selected() {
                Some(i) if i >= len => st.select(if len == 0 { None } else { Some(len - 1) }),
                None if len > 0 && tab == Tab::Logs => st.select(Some(0)),
                _ => {}
            }
        }
    }

    pub fn move_selection(&mut self, delta: isize) {
        let tab = self.tab;
        let len = self.row_count(tab);
        if len == 0 {
            return;
        }
        let cur = self.selected(tab).unwrap_or(0) as isize;
        let next = (cur + delta).clamp(0, len as isize - 1);
        self.table_states[tab.index()].select(Some(next as usize));
        self.detail_scroll = 0;
    }

    pub fn page(&mut self, dir: isize, height: usize) {
        let step = height.max(1) as isize * dir;
        self.move_selection(step);
    }

    pub fn select_first(&mut self) {
        let len = self.row_count(self.tab);
        if len > 0 {
            self.table_states[self.tab.index()].select(Some(0));
        }
    }

    pub fn select_last_visible(&mut self) {
        self.select_last(self.tab);
    }

    /// The entry currently selected in the Logs tab.
    pub fn selected_entry(&self) -> Option<&Entry> {
        let i = self.selected(Tab::Logs)?;
        let idx = *self.filtered.get(i)?;
        self.entries.get(idx)
    }

    /// Filter token that drills into the selected aggregate row.
    pub fn drill_filter(&self) -> Option<String> {
        let idx = self.selected(self.tab)?;
        let snap = self.snapshot.as_ref()?;
        let token = match self.tab {
            Tab::Clients => snap
                .top_clients
                .get(idx)
                .map(|a| format!("ip:{}", a.key)),
            Tab::Hosts => snap.top_hosts.get(idx).map(|a| format!("host:{}", a.key)),
            Tab::Routers => snap
                .top_routers
                .get(idx)
                .map(|a| format!("router:{}", a.key)),
            Tab::Services => snap
                .top_services
                .get(idx)
                .map(|a| format!("service:{}", a.key)),
            Tab::Paths => snap.top_paths.get(idx).map(|a| format!("path:{}", a.key)),
            Tab::Status => snap
                .statuses
                .get(idx)
                .map(|(code, _)| format!("status:{code}")),
            Tab::Logs => None,
        }?;
        Some(format!("{} {}", self.filter.as_str(), token.trim()))
    }

    pub fn toggle_tab(&mut self, forward: bool) {
        let i = self.tab.index();
        let next = if forward {
            (i + 1) % N_TABS
        } else {
            (i + N_TABS - 1) % N_TABS
        };
        self.tab = Tab::from_index(next);
        self.detail_scroll = 0;
    }

    pub fn local_time_str(t: DateTime<Utc>) -> String {
        t.with_timezone(&Local).format("%H:%M:%S").to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        let mut a = App::new(10, "", false, 300);
        a.refresh_snapshot();
        a
    }

    #[test]
    fn ingest_and_evict() {
        let mut a = app();
        let lines: Vec<String> = (0..15)
            .map(|i| {
                serde_json::json!({"DownstreamStatus": 200, "StartUTC": format!("2026-01-01T00:00:{:02}Z", i)})
                    .to_string()
            })
            .collect();
        a.ingest(&lines);
        assert_eq!(a.entries.len(), 10); // capped
        assert_eq!(a.totals.lines_seen, 15);
        assert_eq!(a.filtered.len(), 10);
        // filter indices were shifted with the eviction
        assert_eq!(a.filtered[0], 0);
        assert_eq!(a.entries[0].status, Some(200));
    }

    #[test]
    fn filtered_view_tracks_filter() {
        let mut a = app();
        let lines = vec![
            r#"{"DownstreamStatus":200}"#.to_string(),
            r#"{"DownstreamStatus":500}"#.to_string(),
        ];
        a.ingest(&lines);
        assert_eq!(a.filtered.len(), 2);

        a.filter_input = "status:5xx".into();
        a.apply_filter_input();
        assert_eq!(a.filtered.len(), 1);
        assert_eq!(a.entries[a.filtered[0]].status, Some(500));

        a.filter_input = String::new();
        a.apply_filter_input();
        assert_eq!(a.filtered.len(), 2);
    }

    #[test]
    fn tail_pinned_while_following() {
        let mut a = app();
        a.ingest(&[r#"{"DownstreamStatus":200}"#.to_string()]);
        assert_eq!(a.selected(Tab::Logs), Some(0));
        a.ingest(&[
            r#"{"DownstreamStatus":200}"#.to_string(),
            r#"{"DownstreamStatus":200}"#.to_string(),
        ]);
        assert_eq!(a.selected(Tab::Logs), Some(2));
    }

    #[test]
    fn paused_drops_lines() {
        let mut a = app();
        a.paused = true;
        a.ingest(&[r#"{"DownstreamStatus":200}"#.to_string()]);
        assert!(a.entries.is_empty());
        assert_eq!(a.paused_dropped, 1);
    }

    #[test]
    fn parse_errors_counted() {
        let mut a = app();
        a.ingest(&["garbage".to_string(), "{}".to_string()]);
        assert_eq!(a.totals.parse_errors, 1);
        assert_eq!(a.entries.len(), 1);
    }

    #[test]
    fn selection_clamped_after_filter() {
        let mut a = app();
        let lines: Vec<String> = (0..5)
            .map(|_| r#"{"DownstreamStatus":200}"#.to_string())
            .collect();
        a.ingest(&lines);
        a.select_last_visible();
        assert_eq!(a.selected(Tab::Logs), Some(4));
        a.filter_input = "status:5xx".into();
        a.apply_filter_input();
        assert_eq!(a.selected(Tab::Logs), None);
    }
}
