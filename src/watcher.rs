use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Watches log files by polling: reads appended data from known files,
/// picks up newly created (rotated) files, and handles truncation. No
/// external watch dependency; a 250 ms poll is plenty for access logs.
#[derive(Debug)]
pub struct LogWatcher {
    /// Explicit files given on the command line (may be empty).
    explicit: Vec<PathBuf>,
    /// Directory to scan for matching files, if any.
    dir: Option<PathBuf>,
    /// File-name prefix a scanned file must have.
    pattern: String,
    offsets: HashMap<PathBuf, u64>,
    /// Trailing bytes of a file whose last line has no newline yet.
    partial: HashMap<PathBuf, String>,
    /// Whether the initial poll already happened (tail logic applies once).
    initialized: bool,
    /// On first poll of the newest file, skip back this many lines (0 = all).
    tail_lines: usize,
}

#[derive(Debug, Default)]
pub struct PollResult {
    pub lines: Vec<String>,
    /// The file that will receive appended data (the newest match).
    pub active: Option<PathBuf>,
    pub files_seen: usize,
}

impl LogWatcher {
    /// `inputs` may be files, directories or a mix. For directories only
    /// file names starting with `pattern` are followed.
    pub fn new(inputs: &[PathBuf], pattern: String, tail_lines: usize) -> Result<LogWatcher> {
        let mut explicit = Vec::new();
        let mut dir = None;
        for p in inputs {
            if p.is_dir() {
                dir = Some(p.clone());
            } else if p.exists() {
                explicit.push(p.clone());
            } else {
                anyhow::bail!("input does not exist: {}", p.display());
            }
        }
        if dir.is_none() && explicit.is_empty() {
            anyhow::bail!("no readable log file or directory given");
        }
        Ok(LogWatcher {
            explicit,
            dir,
            pattern,
            offsets: HashMap::new(),
            partial: HashMap::new(),
            initialized: false,
            tail_lines,
        })
    }

    /// Convenience: `pattern` defaults to "access.log".
    #[allow(dead_code)]
    pub fn with_defaults(inputs: &[PathBuf]) -> Result<LogWatcher> {
        Self::new(inputs, "access.log".to_string(), 0)
    }

    pub fn poll(&mut self) -> Result<PollResult> {
        let mut result = PollResult::default();

        let mut seen: Vec<PathBuf> = self.explicit.clone();
        if let Some(dir) = &self.dir {
            let entries = fs::read_dir(dir)
                .with_context(|| format!("reading folder {}", dir.display()))?;
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with('.') || !name.starts_with(&self.pattern) {
                        continue;
                    }
                    seen.push(path);
                }
            }
        }

        // Rotation order = lexicographic name order (access.log-YYYYMMDD).
        seen.sort();
        seen.dedup();
        result.files_seen = seen.len();
        result.active = seen.last().cloned();

        // Drop tracking for files that disappeared.
        self.offsets.retain(|p, _| seen.contains(p));
        self.partial.retain(|p, _| seen.contains(p));

        for (i, path) in seen.iter().enumerate() {
            let is_newest = i + 1 == seen.len();
            let tail = if !self.initialized && is_newest {
                self.tail_lines
            } else {
                0
            };
            match self.read_appends(path, tail) {
                Ok(lines) => result.lines.extend(lines),
                Err(e) => {
                    // never fail the whole poll because one file vanished
                    eprintln!("watcher: skipping {}: {e}", path.display());
                }
            }
        }
        self.initialized = true;
        Ok(result)
    }

    fn read_appends(&mut self, path: &Path, tail_lines: usize) -> Result<Vec<String>> {
        let meta = fs::metadata(path)
            .with_context(|| format!("stat {}", path.display()))?;
        let size = meta.len();

        let mut offset = *self.offsets.get(path).unwrap_or(&0);
        if size < offset {
            // truncated or rotated in place: start over
            offset = 0;
            self.partial.remove(path);
        }

        let mut file = fs::File::open(path)
            .with_context(|| format!("open {}", path.display()))?;

        let tail_back = if offset == 0 && tail_lines > 0 {
            // approximate byte window: 800 bytes per requested line, never
            // more than the file itself; the first (partial) line is dropped
            Some(size.saturating_sub(tail_lines as u64 * 800).min(size))
        } else {
            None
        };
        let read_from = tail_back.unwrap_or(offset);

        file.seek(SeekFrom::Start(read_from))?;
        let mut buf = String::new();
        file.read_to_string(&mut buf)
            .with_context(|| format!("read {}", path.display()))?;

        let mut text = if let Some(prev) = self.partial.get(path) {
            format!("{prev}{buf}")
        } else {
            buf
        };

        // split at the last newline: everything before is complete lines,
        // the tail stays pending until the next poll
        let mut lines = Vec::new();
        match text.rfind('\n') {
            Some(pos) => {
                let rest = text.split_off(pos + 1);
                for line in text.lines() {
                    let line = line.trim_end_matches('\r');
                    if !line.is_empty() {
                        lines.push(line.to_string());
                    }
                }
                if rest.is_empty() {
                    self.partial.remove(path);
                } else {
                    self.partial.insert(path.to_path_buf(), rest);
                }
            }
            None => {
                if text.is_empty() {
                    self.partial.remove(path);
                } else {
                    self.partial.insert(path.to_path_buf(), text);
                }
            }
        }
        // the byte window may over-read (short lines); trim to the last N
        if tail_back.is_some() && lines.len() > tail_lines {
            lines.drain(..lines.len() - tail_lines);
        }
        self.offsets.insert(path.to_path_buf(), size);
        Ok(lines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn reads_new_file_and_appends() {
        let dir = tmpdir();
        let log = dir.path().join("access.log");
        std::fs::write(&log, "{\"a\":1}\n{\"a\":2}\n").unwrap();
        let mut w = LogWatcher::with_defaults(&[dir.path().to_path_buf()]).unwrap();

        let r = w.poll().unwrap();
        assert_eq!(r.lines.len(), 2);
        assert_eq!(r.active.as_deref(), Some(log.as_path()));

        // no new data
        assert!(w.poll().unwrap().lines.is_empty());

        // appended data
        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        writeln!(f, "{{\"a\":3}}").unwrap();
        let r = w.poll().unwrap();
        assert_eq!(r.lines, vec!["{\"a\":3}"]);
    }

    #[test]
    fn picks_up_rotated_file() {
        let dir = tmpdir();
        std::fs::write(dir.path().join("access.log-20261124"), "{}\n").unwrap();
        let mut w = LogWatcher::with_defaults(&[dir.path().to_path_buf()]).unwrap();
        let r = w.poll().unwrap();
        assert_eq!(r.lines.len(), 1);
        assert_eq!(r.files_seen, 1);

        // logrotate creates the next day's file
        std::fs::write(dir.path().join("access.log-20261125"), "{}\n{}\n").unwrap();
        let r = w.poll().unwrap();
        assert_eq!(r.lines.len(), 2);
        assert_eq!(r.files_seen, 2);
        assert!(r.active.unwrap().ends_with("access.log-20261125"));
    }

    #[test]
    fn keeps_partial_line() {
        let dir = tmpdir();
        let log = dir.path().join("access.log");
        std::fs::write(&log, "{\"a\":1}\n{\"b").unwrap();
        let mut w = LogWatcher::with_defaults(&[dir.path().to_path_buf()]).unwrap();
        let r = w.poll().unwrap();
        assert_eq!(r.lines.len(), 1);

        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        writeln!(f, "\":2}}").unwrap();
        let r = w.poll().unwrap();
        assert_eq!(r.lines, vec!["{\"b\":2}"]);
    }

    #[test]
    fn handles_truncation() {
        let dir = tmpdir();
        let log = dir.path().join("access.log");
        std::fs::write(&log, "{\"a\":1}\n{\"a\":2}\n").unwrap();
        let mut w = LogWatcher::with_defaults(&[dir.path().to_path_buf()]).unwrap();
        assert_eq!(w.poll().unwrap().lines.len(), 2);

        // truncated in place (logrotate copytruncate)
        std::fs::write(&log, "{\"a\":9}\n").unwrap();
        let r = w.poll().unwrap();
        assert_eq!(r.lines, vec!["{\"a\":9}"]);
    }

    #[test]
    fn explicit_files_and_tail() {
        let dir = tmpdir();
        let log = dir.path().join("access.log");
        let body: String = (0..100)
            .map(|i| format!("{{\"n\":{i}}}\n"))
            .collect();
        std::fs::write(&log, &body).unwrap();
        let mut w = LogWatcher::new(std::slice::from_ref(&log), "access.log".into(), 10).unwrap();
        let r = w.poll().unwrap();
        assert_eq!(r.lines.len(), 10);
        assert_eq!(r.lines.last().unwrap(), "{\"n\":99}");
        // subsequent polls return only new lines
        assert!(w.poll().unwrap().lines.is_empty());
    }

    #[test]
    fn ignores_foreign_files() {
        let dir = tmpdir();
        std::fs::write(dir.path().join("access.log-1"), "{}\n").unwrap();
        std::fs::write(dir.path().join("traefik.log"), "{}\n").unwrap();
        let mut w = LogWatcher::with_defaults(&[dir.path().to_path_buf()]).unwrap();
        let r = w.poll().unwrap();
        assert_eq!(r.files_seen, 1);
    }
}
