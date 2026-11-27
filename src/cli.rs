use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "traefik-logs",
    about = "Terminal UI for live Traefik access log observation",
    long_about = "Tails Traefik JSON access logs and shows live traffic: requests/sec, \
status codes, latency percentiles, top clients (with reverse DNS), hosts, \
routers, services and paths. Watches a file or a directory of rotated files \
and follows rotation automatically."
)]
pub struct Cli {
    /// Log file or directory. Repeatable. Directories are scanned for files
    /// whose name starts with the pattern below. Default: current directory.
    pub paths: Vec<PathBuf>,

    /// File-name prefix to match when a directory is given.
    #[arg(short, long, default_value = "access.log")]
    pub pattern: String,

    /// Poll interval in milliseconds.
    #[arg(short = 'i', long, default_value_t = 250)]
    pub interval_ms: u64,

    /// On startup, read only the last N lines of the newest file
    /// (approximate byte window). 0 = read everything.
    #[arg(short = 'n', long, default_value_t = 0)]
    pub lines: usize,

    /// Initial filter, same syntax as the in-app filter prompt.
    #[arg(short = 'F', long)]
    pub filter: Option<String>,

    /// Stats window in seconds (60, 300, 900 or 3600).
    #[arg(short = 'w', long, default_value_t = 300)]
    pub window: i64,

    /// In-memory entry buffer size (oldest entries are evicted).
    #[arg(long, default_value_t = 100_000)]
    pub max_entries: usize,

    /// Disable reverse DNS lookups for client IPs.
    #[arg(long)]
    pub no_dns: bool,

    /// Parse the given inputs, print the stats snapshot and exit (no TUI).
    /// Useful to sanity-check parsing against a log file.
    #[arg(long, conflicts_with_all = ["lines", "interval_ms"])]
    pub print_stats: bool,

    /// Window for --print-stats, in seconds; negative = whole file.
    #[arg(long)]
    pub stats_window: Option<i64>,
}
