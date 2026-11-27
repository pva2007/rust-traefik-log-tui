mod app;
mod cli;
mod dns;
mod filter;
mod parser;
mod stats;
mod ui;
mod watcher;

use anyhow::{Context, Result};
use app::{App, Popup};
use chrono::Utc;
use clap::Parser;
use cli::Cli;
use crossterm::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEvent, MouseEventKind,
};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use watcher::LogWatcher;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let inputs = if cli.paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        cli.paths.clone()
    };

    if cli.print_stats {
        return print_stats(&cli, &inputs);
    }

    let mut watcher =
        LogWatcher::new(&inputs, cli.pattern.clone(), cli.lines).context("setting up log watch")?;

    // initial load before entering the TUI so the first frame is useful
    eprint!("loading logs ...");
    std::io::stderr().flush().ok();
    let mut app = App::new(
        cli.max_entries,
        cli.filter.as_deref().unwrap_or(""),
        !cli.no_dns,
        cli.window,
    );
    let r = watcher.poll()?;
    app.note_files(r.active.clone(), r.files_seen);
    app.ingest(&r.lines);
    eprintln!(" {} entries", app.entries.len());

    let terminal = ratatui::init();
    let result = run_loop(terminal, &mut app, &mut watcher, &cli);
    ratatui::restore();
    result
}

fn run_loop(
    mut terminal: ratatui::DefaultTerminal,
    app: &mut App,
    watcher: &mut LogWatcher,
    cli: &Cli,
) -> Result<()> {
    let poll = Duration::from_millis(cli.interval_ms.clamp(50, 5000));
    loop {
        if app.should_quit {
            return Ok(());
        }

        // poll for new log lines
        match watcher.poll() {
            Ok(r) => {
                app.note_files(r.active, r.files_seen);
                app.ingest(&r.lines);
            }
            Err(e) => {
                // transient IO errors (file vanished mid-read) are reported
                // in the header area on the next draw; keep going
                app.filter_error = Some(format!("watch: {e}"));
            }
        }
        app.refresh_snapshot();

        terminal
            .draw(|f| ui::draw(f, app))
            .context("terminal draw")?;

        // wait for input up to the poll interval
        if crossterm::event::poll(poll)? {
            match crossterm::event::read()? {
                Event::Key(key) => on_key(app, key),
                Event::Mouse(mouse) => on_mouse(app, mouse),
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }
}

fn on_key(app: &mut App, key: KeyEvent) {
    // ignore key release events (some terminals report them)
    if key.kind != KeyEventKind::Press {
        return;
    }
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        app.should_quit = true;
        return;
    }

    // filter input mode swallows everything except Enter/Esc/editing
    if app.popup == Popup::FilterInput {
        match key.code {
            KeyCode::Enter => {
                app.popup = Popup::None;
                app.apply_filter_input();
            }
            KeyCode::Esc => {
                app.popup = Popup::None;
                app.filter_input.clear();
                app.filter_error = None;
            }
            KeyCode::Backspace => {
                app.filter_input.pop();
            }
            KeyCode::Char(c) => app.filter_input.push(c),
            _ => {}
        }
        return;
    }

    // close popups first
    if app.popup != Popup::None {
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => app.popup = Popup::None,
            KeyCode::Down => app.detail_scroll = app.detail_scroll.saturating_add(1),
            KeyCode::Up => app.detail_scroll = app.detail_scroll.saturating_sub(1),
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Char('?') | KeyCode::F(1) => app.popup = Popup::Help,
        KeyCode::Esc => {
            if !app.filter.is_empty() {
                app.filter_input.clear();
                app.filter = filter::Filter::parse("");
                app.filter_error = None;
                app.rebuild_filtered();
            }
        }
        KeyCode::Char('f') | KeyCode::Char('/') => {
            app.filter_input = app.filter.as_str().to_string();
            app.popup = Popup::FilterInput;
        }
        KeyCode::Char('x') => {
            app.filter_input.clear();
            app.filter = filter::Filter::parse("");
            app.filter_error = None;
            app.rebuild_filtered();
        }
        KeyCode::Tab => app.toggle_tab(true),
        KeyCode::BackTab => app.toggle_tab(false),
        KeyCode::Char(c @ '1'..='7') => {
            app.tab = app::Tab::from_index(c as usize - '1' as usize);
        }
        KeyCode::Char('w') => app.window_idx = (app.window_idx + 1) % app::WINDOWS_SECS.len(),
        KeyCode::Char('d') => {
            if let Some(dns) = &mut app.dns {
                dns.invalidate();
                app.dns = None;
            } else {
                app.dns = Some(dns::DnsCache::new(24));
            }
        }
        KeyCode::Char(' ') => {
            app.paused = !app.paused;
            if !app.paused {
                app.paused_dropped = 0;
            }
        }
        KeyCode::Char('r') => {
            app.entries.clear();
            app.filtered.clear();
            app.totals = app::SessionTotals::default();
            app.snapshot = None;
            app.refresh_snapshot();
        }
        KeyCode::Char('j') | KeyCode::Down => app.move_selection(1),
        KeyCode::Char('k') | KeyCode::Up => app.move_selection(-1),
        KeyCode::PageDown => app.page(1, 20),
        KeyCode::PageUp => app.page(-1, 20),
        KeyCode::Char('g') | KeyCode::Home => app.select_first(),
        KeyCode::Char('G') | KeyCode::End => app.select_last_visible(),
        KeyCode::Enter => {
            if app.tab == app::Tab::Logs {
                if app.selected_entry().is_some() {
                    app.detail_scroll = 0;
                    app.popup = Popup::Detail;
                }
            } else if let Some(f) = app.drill_filter() {
                app.filter_input = f;
                app.apply_filter_input();
                app.tab = app::Tab::Logs;
            }
        }
        _ => {}
    }
}

fn on_mouse(app: &mut App, mouse: MouseEvent) {
    match mouse.kind {
        MouseEventKind::ScrollDown => app.move_selection(3),
        MouseEventKind::ScrollUp => app.move_selection(-3),
        _ => {}
    }
}

/// Headless mode: parse the inputs once and dump the snapshot as text.
fn print_stats(cli: &Cli, inputs: &[PathBuf]) -> Result<()> {
    let mut watcher = LogWatcher::new(inputs, cli.pattern.clone(), 0)?;
    let mut app = App::new(
        usize::MAX,
        cli.filter.as_deref().unwrap_or(""),
        false,
        cli.window,
    );
    let r = watcher.poll()?;
    app.note_files(r.active, r.files_seen);
    app.ingest(&r.lines);

    let window = cli
        .stats_window
        .map(chrono::Duration::seconds)
        .unwrap_or_else(|| chrono::Duration::seconds(86_400 * 3650));
    let snap = stats::snapshot(
        &app.entries.iter().cloned().collect::<Vec<_>>(),
        window,
        Utc::now(),
        15,
    );
    println!(
        "lines: {} parsed, {} unparsed; entries buffered: {}",
        app.totals.lines_seen, app.totals.parse_errors, app.entries.len()
    );
    println!(
        "window {}s: {} requests, {:.2} req/s, {} errors (5xx), {} client errors (4xx)",
        snap.window_secs,
        snap.count,
        snap.rps,
        snap.errors,
        snap.client_errors
    );
    println!(
        "latency: avg {:.1}ms p50 {:.1}ms p95 {:.1}ms p99 {:.1}ms max {:.1}ms",
        snap.latency.avg_ms,
        snap.latency.p50_ms,
        snap.latency.p95_ms,
        snap.latency.p99_ms,
        snap.latency.max_ms
    );
    let dump = |name: &str, list: &Vec<stats::Agg>| {
        println!("--- top {name} ---");
        for a in list.iter().take(10) {
            println!(
                "{:>8}  {:<40} err {:>5.1}%  avg {:>9.1}ms  max {:>9.1}ms",
                a.count,
                a.key,
                a.error_rate() * 100.0,
                a.avg_ms(),
                a.max_ms()
            );
        }
    };
    dump("clients", &snap.top_clients);
    dump("hosts", &snap.top_hosts);
    dump("routers", &snap.top_routers);
    dump("services", &snap.top_services);
    dump("paths", &snap.top_paths);
    println!("--- status codes ---");
    for (code, n) in snap.statuses.iter().take(15) {
        println!("{code:>4}  {n}");
    }
    Ok(())
}
