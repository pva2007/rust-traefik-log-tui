use crate::app::{App, Popup, Tab, TAB_NAMES};
use crate::parser::Entry;
use crate::stats::Agg;
use chrono::{DateTime, Utc};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    symbols,
    text::{Line, Span},
    widgets::{
        Axis, Block, Borders, Cell, Chart, Clear, Dataset, Paragraph, Row, Table, Wrap,
    },
    Frame,
};

pub fn status_color(status: Option<i64>) -> Color {
    match status {
        Some(s) if (200..300).contains(&s) => Color::Green,
        Some(s) if (300..400).contains(&s) => Color::Cyan,
        Some(s) if (400..500).contains(&s) => Color::Yellow,
        Some(s) if s >= 500 => Color::Red,
        _ => Color::DarkGray,
    }
}

fn dur_color(ms: f64) -> Color {
    if ms >= 1000.0 {
        Color::Red
    } else if ms >= 200.0 {
        Color::Yellow
    } else {
        Color::Reset
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let keep = max.saturating_sub(1);
        format!("{}…", s.chars().take(keep).collect::<String>())
    }
}

fn fmt_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{b} {}", UNITS[0])
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn fmt_dur(ms: f64) -> String {
    if ms >= 10_000.0 {
        format!("{:.1}s", ms / 1000.0)
    } else {
        format!("{ms:.1}ms")
    }
}

fn fmt_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 10_000 {
        format!("{:.0}k", n as f64 / 1_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

pub fn draw(f: &mut Frame, app: &mut App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(f.area());

    render_header(f, app, header);

    let [main, side] = Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)])
        .areas(body);
    let [tabs_bar, table_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(main);
    let [chart_area, latency_area, status_area] = Layout::vertical([
        Constraint::Min(8),
        Constraint::Length(6),
        Constraint::Min(4),
    ])
    .areas(side);

    render_tabs(f, app, tabs_bar);
    render_table(f, app, table_area);
    render_chart(f, app, chart_area);
    render_latency(f, app, latency_area);
    render_status_dist(f, app, status_area);
    render_footer(f, app, footer);

    match app.popup {
        Popup::None => {}
        Popup::Detail => render_detail(f, app),
        Popup::FilterInput => render_filter_input(f, app, table_area),
        Popup::Help => render_help(f),
    }
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let mode = if app.paused {
        Span::styled(" PAUSED ", Style::new().bg(Color::Yellow).fg(Color::Black).bold())
    } else {
        Span::styled(" LIVE ", Style::new().bg(Color::Green).fg(Color::Black).bold())
    };
    let mut spans = vec![
        Span::styled("traefik-logs", Style::new().bold()),
        Span::raw("  "),
        mode,
    ];
    if app.paused && app.paused_dropped > 0 {
        spans.push(Span::styled(
            format!(" (dropped {})", fmt_count(app.paused_dropped)),
            Style::new().fg(Color::Yellow),
        ));
    }
    if let Some(file) = &app.active_file {
        spans.push(Span::raw("  file: "));
        spans.push(Span::raw(
            file.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default(),
        ));
    }
    spans.push(Span::raw(format!(
        "  buffered {}/{}",
        fmt_count(app.entries.len() as u64),
        fmt_count(app.max_entries as u64)
    )));
    spans.push(Span::raw(format!(
        "  shown {}",
        fmt_count(app.filtered.len() as u64)
    )));
    if app.totals.parse_errors > 0 {
        spans.push(Span::styled(
            format!("  unparsed {}", fmt_count(app.totals.parse_errors)),
            Style::new().fg(Color::Red),
        ));
    }
    if let Some(dns) = &app.dns {
        spans.push(Span::styled(
            format!("  dns:{}", dns.pending_count()),
            Style::new().fg(Color::DarkGray),
        ));
    }
    let line = Line::from(spans);
    f.render_widget(Paragraph::new(line), area);
}

fn render_tabs(f: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![Span::raw(" ")];
    for (i, name) in TAB_NAMES.iter().enumerate() {
        let tab = Tab::from_index(i);
        if tab == app.tab {
            spans.push(Span::styled(
                format!(" {name} "),
                Style::new()
                    .fg(Color::Black)
                    .bg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::styled(
                format!(" {name} "),
                Style::new().fg(Color::Gray),
            ));
        }
    }
    spans.push(Span::styled(
        format!("  window {}s", app.window_secs()),
        Style::new().fg(Color::DarkGray),
    ));
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn log_row(e: &Entry, app: &App) -> Row<'static> {
    let time = e
        .start_utc
        .map(App::local_time_str)
        .unwrap_or_else(|| "--:--:--".into());
    let status = e
        .status
        .map(|s| s.to_string())
        .unwrap_or_else(|| "?".into());
    let dur = e.duration_ms().unwrap_or(0.0);
    let client = app.display_short(e.client_ip().unwrap_or("-"));
    let path = e.path.as_deref().unwrap_or("-");
    let service = e
        .service
        .as_deref()
        .map(|s| s.split('@').next().unwrap_or(s))
        .unwrap_or("-");
    Row::new(vec![
        Cell::from(time).style(Style::new().fg(Color::DarkGray)),
        Cell::from(status).style(Style::new().fg(status_color(e.status)).bold()),
        Cell::from(fmt_dur(dur)).style(Style::new().fg(dur_color(dur))),
        Cell::from(truncate(&client, 20)),
        Cell::from(e.method.as_deref().unwrap_or("-").to_string()),
        Cell::from(truncate(e.host.as_deref().unwrap_or("-"), 18)),
        Cell::from(truncate(path, 48)),
        Cell::from(truncate(service, 20)).style(Style::new().fg(Color::DarkGray)),
    ])
}

fn render_table(f: &mut Frame, app: &mut App, area: Rect) {
    let tab = app.tab;
    let header_style = Style::new().fg(Color::Blue).add_modifier(Modifier::BOLD);

    match tab {
        Tab::Logs => {
            let widths = [
                Constraint::Length(8),
                Constraint::Length(4),
                Constraint::Length(7),
                Constraint::Length(20),
                Constraint::Length(7),
                Constraint::Length(18),
                Constraint::Min(16),
                Constraint::Length(20),
            ];
            let header = Row::new(["time", "st", "dur", "client", "method", "host", "path", "service"])
                .style(header_style);

            // Render only a window of rows around the selection (the buffer
            // can hold 100k+ entries); remap the selection onto the slice.
            let selected = app.table_states[0].selected().unwrap_or(0);
            let visible = area.height.saturating_sub(3) as usize;
            let len = app.filtered.len();
            let start = selected
                .saturating_sub(visible / 2)
                .min(len.saturating_sub(1));
            let end = (start + visible + 1).min(len);
            let rows: Vec<Row<'static>> = app.filtered[start..end]
                .iter()
                .filter_map(|&idx| app.entries.get(idx).map(|e| log_row(e, app)))
                .collect();

            let local_sel = selected.saturating_sub(start).min(rows.len().saturating_sub(1));
            let st = &mut app.table_states[0];
            *st.offset_mut() = 0;
            st.select(Some(local_sel));
            let table = Table::new(rows, widths)
                .header(header)
                .block(block_with_title(" requests (filtered) "))
                .row_highlight_style(Style::new().bg(Color::DarkGray).add_modifier(Modifier::BOLD));
            f.render_stateful_widget(table, area, st);
            st.select(Some(selected));
        }
        _ => {
            let widths = [
                Constraint::Length(4),
                Constraint::Min(24),
                Constraint::Length(9),
                Constraint::Length(6),
                Constraint::Length(6),
                Constraint::Length(9),
                Constraint::Length(9),
            ];
            let header = Row::new(["#", "key", "count", "%", "err%", "avg", "max"]).style(header_style);
            let (rows, title) = agg_rows(app, tab);
            let ti = tab.index();
            let table = Table::new(rows, widths)
                .header(header)
                .block(block_with_title(&title))
                .row_highlight_style(Style::new().bg(Color::DarkGray).add_modifier(Modifier::BOLD));
            f.render_stateful_widget(table, area, &mut app.table_states[ti]);
        }
    }
}

fn agg_rows(app: &App, tab: Tab) -> (Vec<Row<'static>>, String) {
    let Some(snap) = app.snapshot.as_ref() else {
        return (Vec::new(), " aggregates ".into());
    };
    let total = snap.count.max(1) as f64;
    let list: (&Vec<Agg>, &str) = match tab {
        Tab::Clients => (&snap.top_clients, " clients (top talkers) "),
        Tab::Hosts => (&snap.top_hosts, " hosts (virtual hosts) "),
        Tab::Routers => (&snap.top_routers, " routers "),
        Tab::Services => (&snap.top_services, " services (backends) "),
        Tab::Paths => (&snap.top_paths, " paths "),
        _ => (&snap.top_clients, " clients "),
    };
    let rows = list
        .0
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let err_style = if a.error_rate() > 0.1 {
                Style::new().fg(Color::Red)
            } else {
                Style::new()
            };
            Row::new(vec![
                Cell::from(format!("{}", i + 1)).style(Style::new().fg(Color::DarkGray)),
                Cell::from(truncate(&app.display_name(&a.key), 40)),
                Cell::from(fmt_count(a.count)),
                Cell::from(format!("{:.1}%", a.count as f64 / total * 100.0)),
                Cell::from(format!("{:.1}", a.error_rate() * 100.0)).style(err_style),
                Cell::from(fmt_dur(a.avg_ms())),
                Cell::from(fmt_dur(a.max_ms())).style(Style::new().fg(dur_color(a.max_ms()))),
            ])
        })
        .collect();
    (rows, list.1.to_string())
}

fn render_chart(f: &mut Frame, app: &App, area: Rect) {
    let Some(snap) = app.snapshot.as_ref() else {
        f.render_widget(block_with_title(" traffic "), area);
        return;
    };
    if snap.buckets.is_empty() {
        f.render_widget(
            block_with_title(&format!(" traffic  {}s window ", snap.window_secs)),
            area,
        );
        return;
    }
    let n = snap.buckets.len() as f64;
    let max_count = snap.buckets.iter().map(|b| b.count).max().unwrap_or(1) as f64;
    let y_max = (max_count * 1.1).max(1.0);

    let req_data: Vec<(f64, f64)> = snap
        .buckets
        .iter()
        .enumerate()
        .map(|(i, b)| (i as f64, b.count as f64))
        .collect();
    let err_data: Vec<(f64, f64)> = snap
        .buckets
        .iter()
        .enumerate()
        .map(|(i, b)| (i as f64, b.errors as f64))
        .collect();

    let t0 = DateTime::from_timestamp(snap.buckets[0].ts, 0).unwrap_or(Utc::now());
    let t1 = DateTime::from_timestamp(
        snap.buckets[snap.buckets.len() - 1].ts,
        0,
    )
    .unwrap_or(Utc::now());
    let labels = [
        Span::raw(App::local_time_str(t0)),
        Span::raw(String::new()),
        Span::raw(App::local_time_str(t1)),
    ];

    let datasets = vec![
        Dataset::default()
            .name("req/s")
            .marker(symbols::Marker::Braille)
            .graph_type(ratatui::widgets::GraphType::Bar)
            .style(Style::new().fg(Color::Blue))
            .data(&req_data),
        Dataset::default()
            .name("5xx/s")
            .marker(symbols::Marker::Braille)
            .graph_type(ratatui::widgets::GraphType::Line)
            .style(Style::new().fg(Color::Red))
            .data(&err_data),
    ];
    let title = format!(
        " traffic  {:.1} req/s over {}s  ({}) ",
        snap.rps,
        snap.window_secs,
        fmt_count(snap.count)
    );
    let chart = Chart::new(datasets)
        .block(block_with_title(&title))
        .x_axis(
            Axis::default()
                .labels(labels)
                .bounds([0.0, n - 1.0])
                .labels_alignment(Alignment::Left)
                .style(Style::new().fg(Color::DarkGray)),
        )
        .y_axis(
            Axis::default()
                .labels([
                    Span::raw("0"),
                    Span::raw(format!("{}", max_count as i64)),
                ])
                .bounds([0.0, y_max])
                .style(Style::new().fg(Color::DarkGray)),
        )
        .legend_position(Some(ratatui::widgets::LegendPosition::TopRight));
    f.render_widget(chart, area);
}

fn render_latency(f: &mut Frame, app: &App, area: Rect) {
    let Some(snap) = app.snapshot.as_ref() else {
        f.render_widget(block_with_title(" latency "), area);
        return;
    };
    let l = &snap.latency;
    let bar = |v: f64, max: f64| -> String {
        let w = if max <= 0.0 {
            0
        } else {
            ((v / max) * 20.0).round() as usize
        };
        format!("{:<20}", "█".repeat(w.min(20)))
    };
    let max = l.max_ms.max(0.001);
    let line = |label: &str, v: f64| -> Line<'static> {
        Line::from(vec![
            Span::styled(format!("{:>4} ", label), Style::new().fg(Color::Blue)),
            Span::styled(bar(v, max), Style::new().fg(dur_color(v))),
            Span::raw(fmt_dur(v)),
        ])
    };
    let text = vec![
        line("avg", l.avg_ms),
        line("p50", l.p50_ms),
        line("p95", l.p95_ms),
        line("p99", l.p99_ms),
        line("max", l.max_ms),
    ];
    let title = format!(
        " latency  in {} out {}  retries {} ",
        fmt_bytes(snap.bytes_in),
        fmt_bytes(snap.bytes_out),
        snap.retries
    );
    let mut lines = text;
    lines.push(Line::from(vec![Span::styled(
        format!(" window {}s", snap.window_secs),
        Style::new().fg(Color::DarkGray),
    )]));
    f.render_widget(
        Paragraph::new(lines).block(block_with_title(&title)),
        area,
    );
}

fn render_status_dist(f: &mut Frame, app: &App, area: Rect) {
    let Some(snap) = app.snapshot.as_ref() else {
        f.render_widget(block_with_title(" status codes "), area);
        return;
    };
    let total = snap.count.max(1) as f64;
    let mut lines = Vec::new();
    let classes: [(usize, &str, Color); 5] = [
        (2, "2xx", Color::Green),
        (3, "3xx", Color::Cyan),
        (4, "4xx", Color::Yellow),
        (5, "5xx", Color::Red),
        (0, "0/unk", Color::DarkGray),
    ];
    for (idx, label, color) in classes {
        let n = snap.status_classes[idx];
        let pct = n as f64 / total * 100.0;
        let w = (pct / 100.0 * 30.0).round() as usize;
        lines.push(Line::from(vec![
            Span::styled(format!("{:>6} ", label), Style::new().fg(color)),
            Span::styled(format!("{:>7} ", fmt_count(n)), Style::new()),
            Span::styled(
                format!("{:5.1}% ", pct),
                Style::new().fg(Color::DarkGray),
            ),
            Span::styled("▮".repeat(w), Style::new().fg(color)),
        ]));
    }
    f.render_widget(
        Paragraph::new(lines).block(block_with_title(" status classes ")),
        area,
    );
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let filter_part = if app.filter.is_empty() {
        Span::styled(" no filter", Style::new().fg(Color::DarkGray))
    } else {
        Span::styled(
            format!(" /{}", truncate(app.filter.as_str(), 60)),
            Style::new().fg(Color::Magenta),
        )
    };
    if let Some(err) = &app.filter_error {
        let line = Line::from(vec![
            Span::styled(" filter error: ", Style::new().fg(Color::Black).bg(Color::Red)),
            Span::styled(
                truncate(err, area.width as usize),
                Style::new().fg(Color::Red),
            ),
        ]);
        f.render_widget(Paragraph::new(line), area);
        return;
    }
    let line = Line::from(vec![
        filter_part,
        Span::styled(
            "  [f]ilter [Tab]panel [Enter]detail/dig [w]indow [d]ns [Space]pause [q]uit [?]help",
            Style::new().fg(Color::DarkGray),
        ),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn render_detail(f: &mut Frame, app: &mut App) {
    let Some(e) = app.selected_entry().cloned() else {
        return;
    };
    let area = centered_rect(70, 80, f.area());
    let dash = || "-".to_string();
    let rows: Vec<(&str, String)> = vec![
        (
            "time (UTC)",
            e.start_utc.map(|t| t.to_string()).unwrap_or_else(dash),
        ),
        ("client", e.client_addr.clone().unwrap_or_else(dash)),
        ("client ip", e.client_ip().unwrap_or("-").to_string()),
        ("dns name", {
            let ip = e.client_ip().unwrap_or("-").to_string();
            app.display_name(&ip)
        }),
        ("username", e.client_username.clone().unwrap_or_else(dash)),
        (
            "status",
            format!(
                "downstream {} / origin {}",
                e.status.map(|s| s.to_string()).unwrap_or_else(|| "?".into()),
                e.origin_status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "?".into())
            ),
        ),
        (
            "duration",
            format!(
                "total {}  origin {}  overhead {}",
                e.duration_ms().map(fmt_dur).unwrap_or_else(|| "-".into()),
                e.origin_duration_ns
                    .map(|ns| fmt_dur(ns as f64 / 1e6))
                    .unwrap_or_else(|| "-".into()),
                e.overhead_ns
                    .map(|ns| fmt_dur(ns as f64 / 1e6))
                    .unwrap_or_else(|| "-".into())
            ),
        ),
        (
            "request",
            format!(
                "{} {}://{}{} {}",
                e.method.as_deref().unwrap_or("-"),
                e.scheme.as_deref().unwrap_or("http"),
                e.host.as_deref().unwrap_or("-"),
                e.path.as_deref().unwrap_or("/"),
                e.protocol.as_deref().unwrap_or("")
            ),
        ),
        (
            "sizes",
            format!(
                "in {}  out {}",
                fmt_bytes(e.request_size.unwrap_or(0).max(0) as u64),
                fmt_bytes(e.response_size.unwrap_or(0).max(0) as u64)
            ),
        ),
        ("router", e.router.clone().unwrap_or_else(dash)),
        ("service", e.service.clone().unwrap_or_else(dash)),
        ("backend", e.service_addr.clone().unwrap_or_else(dash)),
        ("entrypoint", e.entry_point.clone().unwrap_or_else(dash)),
        (
            "tls",
            format!(
                "{} {}",
                e.tls_version.as_deref().unwrap_or("-"),
                e.tls_cipher.as_deref().unwrap_or("")
            ),
        ),
        ("retries", e.retries.unwrap_or(0).to_string()),
    ];

    let text: Vec<Line> = rows
        .iter()
        .map(|(k, v)| {
            Line::from(vec![
                Span::styled(format!("{:>12}  ", k), Style::new().fg(Color::Blue)),
                Span::raw(v.clone()),
            ])
        })
        .collect();
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(text)
            .block(
                Block::new()
                    .borders(Borders::ALL)
                    .title(" request detail (Esc to close, ↑↓ scroll) ")
                    .border_style(Style::new().fg(Color::Blue)),
            )
            .wrap(Wrap { trim: false })
            .scroll((app.detail_scroll, 0)),
        area,
    );
}

fn render_filter_input(f: &mut Frame, app: &App, base: Rect) {
    let w = (base.width as usize).min(80);
    let area = Rect {
        x: base.x + 1,
        y: base.bottom().saturating_sub(3),
        width: w.saturating_sub(2) as u16,
        height: 3,
    };
    let hint = " tokens: status:5xx method:GET host:x ip:x path:x router:x service:x, bare term = regex, space = AND";
    let text = vec![
        Line::from(Span::styled(
            truncate(hint, w.saturating_sub(2)),
            Style::new().fg(Color::DarkGray),
        )),
        Line::from(vec![
            Span::styled("/ ", Style::new().fg(Color::Magenta)),
            Span::raw(app.filter_input.clone()),
            Span::styled("▏", Style::new().slow_blink().fg(Color::Magenta)),
        ]),
    ];
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(text).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" filter (Enter apply, Esc cancel) ")
                .border_style(Style::new().fg(Color::Magenta)),
        ),
        area,
    );
}

const HELP: &[&str] = &[
    "traefik-logs - live view of Traefik JSON access logs",
    "",
    "Navigation",
    "  ↑/k ↓/j      move selection          PgUp/PgDn  page",
    "  g / G        first / last row",
    "  Tab, 1-7     switch panel (Logs, Clients, Hosts, Routers, Services, Paths, Status)",
    "  Enter        Logs: request detail;  other panels: drill into row (adds filter)",
    "",
    "Filters (space = AND)",
    "  status:5xx / status:404 / status:>=500     method:GET",
    "  host:x  ip:x  path:x  router:x  service:x   bare term = regex on the whole line",
    "  errors                                     shorthand for status:5xx",
    "  f /        open filter prompt, Enter applies, x clears",
    "",
    "View",
    "  w            stats window 1m → 5m → 15m → 1h",
    "  d            toggle reverse DNS for client IPs",
    "  Space        pause live feed (new lines are dropped, not buffered)",
    "  r            clear buffer and session totals",
    "  q / Esc      quit / close popup",
    "",
    "The right side shows traffic (req/s + 5xx/s), latency percentiles and",
    "status classes, all over the selected window ending at the newest log line.",
    "",
    "Red flags to watch for: 5xx spikes in the chart, high error% for a single",
    "service or router, p95/p99 far above avg, high Overhead in details (Traefik",
    "itself slow, not the backend), retries > 0 (failed backend attempts).",
];

fn render_help(f: &mut Frame) {
    let area = centered_rect(80, 80, f.area());
    let lines: Vec<Line> = HELP.iter().map(|l| Line::raw(l.to_string())).collect();
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(lines).block(
            Block::new()
                .borders(Borders::ALL)
                .title(" help (Esc to close) ")
                .border_style(Style::new().fg(Color::Blue)),
        ),
        area,
    );
}

fn block_with_title(title: &str) -> Block<'_> {
    Block::new()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::new().fg(Color::DarkGray))
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup = ratatui::layout::Rect {
        width: r.width * percent_x / 100,
        height: r.height * percent_y / 100,
        x: r.x + (r.width - r.width * percent_x / 100) / 2,
        y: r.y + (r.height - r.height * percent_y / 100) / 2,
    };
    popup.clamp(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;

    fn app_with_entries(n: usize) -> App {
        let mut app = App::new(1000, "", false, 300);
        // newest entry at "now" so the stats window has data
        let newest = Utc::now().timestamp();
        let lines: Vec<String> = (0..n)
            .map(|i| {
                let ts = newest - (n as i64 - i as i64);
                format!(
                    r#"{{"DownstreamStatus":{},"Duration":{}00000,"ClientHost":"10.0.0.{}","RequestHost":"test.local","RequestMethod":"GET","RequestPath":"/p/{i}","RouterName":"r@docker","ServiceName":"s@docker","StartUTC":"{}"}}"#,
                    if i % 97 == 0 { 502 } else { 200 },
                    i,
                    i % 3,
                    chrono::DateTime::from_timestamp(ts, 0)
                        .unwrap()
                        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
                )
            })
            .collect();
        app.ingest(&lines);
        app.refresh_snapshot();
        app
    }

    #[test]
    fn draws_all_tabs_without_panic() {
        let mut app = app_with_entries(200);
        for tab in [
            Tab::Logs,
            Tab::Clients,
            Tab::Hosts,
            Tab::Routers,
            Tab::Services,
            Tab::Paths,
            Tab::Status,
        ] {
            app.tab = tab;
            let term = ratatui::backend::TestBackend::new(120, 40);
            terminal_draw(term, &mut app);
        }
    }

    #[test]
    fn draws_small_terminal_and_popups() {
        let mut app = app_with_entries(5);
        for popup in [Popup::None, Popup::Detail, Popup::FilterInput, Popup::Help] {
            app.popup = popup;
            let term = ratatui::backend::TestBackend::new(60, 14);
            terminal_draw(term, &mut app);
        }
    }

    #[test]
    fn draws_empty_state() {
        let mut app = App::new(100, "", false, 300);
        app.refresh_snapshot();
        let term = ratatui::backend::TestBackend::new(80, 24);
        terminal_draw(term, &mut app);
    }

    fn terminal_draw(term: ratatui::backend::TestBackend, app: &mut App) {
        let mut t = ratatui::Terminal::new(term).unwrap();
        t.draw(|f| draw(f, app)).unwrap();
    }
}
