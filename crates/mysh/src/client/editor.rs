//! The prompt's line editor (docs/05-meta-shell.md "The prompt"): one line,
//! cursor, history navigation, `Ctrl-R` reverse incremental search and Tab
//! completion of local paths, plus the persisted [`History`].
//!
//! The editor is deliberately tiny: the terminal is in raw mode for the
//! whole run and one task owns stdin, so a readline crate would have to be
//! driven byte by byte anyway. Every keystroke redraws the line
//! (`\r`, clear to end of line, prompt, buffer, cursor move), which is
//! correct for lines shorter than the terminal width and good enough here.

use std::{
    fmt::Write as _,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use crate::config::expand_tilde;

/// Lines kept in the history file.
pub const HISTORY_CAP: usize = 1000;

/// Commands whose arguments are local paths (every argument).
const LOCAL_PATH_COMMANDS: &[&str] = &["put", "lcd", "log", "authorize"];

// ---------------------------------------------------------------------------
// History

/// Prompt history, persisted to `paths.history`.
#[derive(Debug)]
pub struct History {
    path: Option<PathBuf>,
    entries: Vec<String>,
    /// Entries added this run (appended on save).
    added: usize,
}

impl History {
    /// Load the last [`HISTORY_CAP`] lines; a missing file is empty history.
    pub fn load(path: &Path) -> Self {
        let text = fs::read_to_string(path).unwrap_or_default();
        Self {
            path: Some(path.to_path_buf()),
            entries: trim_history(text.lines().map(str::to_owned).collect()),
            added: 0,
        }
    }

    /// In-memory only (tests, scripted mode).
    pub fn empty() -> Self {
        Self {
            path: None,
            entries: Vec::new(),
            added: 0,
        }
    }

    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// Remember `line` unless blank or identical to the previous entry.
    pub fn push(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() || self.entries.last().is_some_and(|l| l == line) {
            return;
        }
        self.entries.push(line.to_owned());
        self.added += 1;
    }

    /// Append this run's lines, then trim the file to [`HISTORY_CAP`].
    /// Creates the parent directory `0700`.
    pub fn save(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if self.added == 0 {
            return Ok(());
        }
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            create_private_dir(dir)?;
        }
        let existing = fs::read_to_string(path).unwrap_or_default();
        let mut all: Vec<String> = existing.lines().map(str::to_owned).collect();
        all.extend(
            self.entries[self.entries.len() - self.added..]
                .iter()
                .cloned(),
        );
        let all = trim_history(all);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        }
        for line in &all {
            writeln!(file, "{line}")?;
        }
        Ok(())
    }
}

fn trim_history(mut lines: Vec<String>) -> Vec<String> {
    lines.retain(|l| !l.trim().is_empty());
    if lines.len() > HISTORY_CAP {
        lines.drain(..lines.len() - HISTORY_CAP);
    }
    lines
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

// ---------------------------------------------------------------------------
// Path completion

/// Candidates for the local path `word` (`~` expanded against `home`,
/// relative paths against `cwd`). Each candidate is the whole word to
/// substitute, keeping the directory part as typed (`~/Doc` → `~/Documents/`);
/// directories end in `/`. Dot files are offered only when the name part
/// starts with `.`. Sorted; empty when the directory cannot be read.
pub fn complete_path(word: &str, cwd: &Path, home: &Path) -> Vec<String> {
    if word == "~" {
        return vec!["~/".to_owned()];
    }
    let split = word.rfind('/').map_or(0, |i| i + 1);
    let (dir_part, prefix) = word.split_at(split);
    let dir = if dir_part.is_empty() {
        cwd.to_path_buf()
    } else {
        let p = expand_tilde(dir_part, home);
        if p.is_absolute() { p } else { cwd.join(p) }
    };
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.starts_with(prefix) || (name.starts_with('.') && !prefix.starts_with('.')) {
                return None;
            }
            let is_dir = e.path().is_dir();
            let mut word = String::with_capacity(dir_part.len() + name.len() + 1);
            word.push_str(dir_part);
            word.push_str(&name);
            if is_dir {
                word.push('/');
            }
            Some(word)
        })
        .collect();
    out.sort();
    out
}

/// Longest common prefix of `words` (by `char`).
fn common_prefix(words: &[String]) -> String {
    let Some(first) = words.first() else {
        return String::new();
    };
    let mut prefix: Vec<char> = first.chars().collect();
    for w in &words[1..] {
        let common = prefix
            .iter()
            .zip(w.chars())
            .take_while(|(a, b)| *a == b)
            .count();
        prefix.truncate(common);
    }
    prefix.into_iter().collect()
}

/// Lay `items` out in columns that fit `width` cells, one row per line,
/// `\r\n` terminated.
pub fn format_columns(items: &[String], width: usize) -> String {
    let Some(longest) = items.iter().map(|s| s.chars().count()).max() else {
        return String::new();
    };
    let cell = longest + 2;
    let cols = (width / cell).max(1);
    let rows = items.len().div_ceil(cols);
    let mut out = String::new();
    for r in 0..rows {
        for c in 0..cols {
            let Some(item) = items.get(c * rows + r) else {
                break;
            };
            out.push_str(item);
            if c + 1 < cols && (c + 1) * rows + r < items.len() {
                out.extend(std::iter::repeat_n(' ', cell - item.chars().count()));
            }
        }
        out.push_str("\r\n");
    }
    out
}

// ---------------------------------------------------------------------------
// Line editor

/// What a batch of keystrokes produced besides edits to the buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    /// Enter: the finished line.
    Line(String),
    /// `Ctrl-C`: the line was cleared.
    Cancel,
    /// `Ctrl-D` on an empty line.
    Eof,
    /// `Ctrl-Z`.
    Suspend,
    /// `Ctrl-L`.
    ClearScreen,
    /// Second Tab with several completions: print these, then redraw.
    ShowCandidates(Vec<String>),
}

/// A decoded key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    Char(char),
    Ctrl(u8),
    Enter,
    Tab,
    Backspace,
    Delete,
    Left,
    Right,
    Home,
    End,
    Up,
    Down,
}

/// `Ctrl-R` state: the query so far and the history entry it matched.
#[derive(Debug)]
struct Search {
    query: Vec<char>,
    /// History index of the current match; `None` until something matched.
    pos: Option<usize>,
    /// The last refinement or `Ctrl-R` found nothing.
    failed: bool,
    /// Line and cursor to restore on cancel.
    saved: Vec<char>,
    saved_cursor: usize,
}

/// Minimal readline: one line, cursor, history navigation, `Ctrl-R`
/// search and local path completion.
#[derive(Debug)]
pub struct LineEditor {
    prompt: String,
    buf: Vec<char>,
    cursor: usize,
    history: Vec<String>,
    /// Index into `history` while browsing; `None` = editing a new line.
    hist_pos: Option<usize>,
    /// The new line stashed while browsing history.
    stash: Vec<char>,
    esc: Vec<u8>,
    utf8: Vec<u8>,
    home: PathBuf,
    cwd: PathBuf,
    /// The previous key was a Tab that left several candidates.
    tab_pending: bool,
    search: Option<Search>,
}

impl LineEditor {
    /// `home` expands `~` and `cwd` anchors relative paths for completion.
    pub fn new(prompt: &str, history: Vec<String>, home: PathBuf, cwd: PathBuf) -> Self {
        Self {
            prompt: prompt.to_owned(),
            buf: Vec::new(),
            cursor: 0,
            history,
            hist_pos: None,
            stash: Vec::new(),
            esc: Vec::new(),
            utf8: Vec::new(),
            home,
            cwd,
            tab_pending: false,
            search: None,
        }
    }

    /// Completion base for relative paths (follows `lcd`).
    pub fn set_cwd(&mut self, cwd: PathBuf) {
        self.cwd = cwd;
    }

    pub fn line(&self) -> String {
        self.buf.iter().collect()
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// `Ctrl-R` search in progress.
    pub fn searching(&self) -> bool {
        self.search.is_some()
    }

    pub fn push_history(&mut self, line: &str) {
        if !line.trim().is_empty() && self.history.last().is_none_or(|l| l != line) {
            self.history.push(line.to_owned());
        }
    }

    /// Terminal bytes that redraw the prompt and line with the cursor placed.
    /// While searching the prompt is `(reverse-i-search)'query': `.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(self.prompt.len() + self.buf.len() + 32);
        out.push_str("\r\x1b[K");
        match &self.search {
            Some(s) => {
                let _ = write!(
                    out,
                    "({}reverse-i-search)'{}': ",
                    if s.failed { "failed " } else { "" },
                    s.query.iter().collect::<String>()
                );
            }
            None => out.push_str(&self.prompt),
        }
        out.extend(self.buf.iter());
        let back = self.buf.len() - self.cursor;
        if back > 0 {
            let _ = write!(out, "\x1b[{back}D");
        }
        out
    }

    /// Decode `bytes` (possibly a partial escape or UTF-8 sequence) and apply
    /// the keys; returns the non-edit results in order.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Edit> {
        let mut out = Vec::new();
        for &b in bytes {
            if let Some(key) = self.decode(b)
                && let Some(edit) = self.apply(key)
            {
                out.push(edit);
            }
        }
        // A chunk ending in a lone ESC while searching is the Esc key, not
        // the start of a split sequence: terminals send sequences whole.
        if self.search.is_some() && self.esc.as_slice() == [0x1b] {
            self.esc.clear();
            self.search_cancel();
        }
        out
    }

    fn decode(&mut self, b: u8) -> Option<Key> {
        if !self.esc.is_empty() {
            return self.decode_escape(b);
        }
        if !self.utf8.is_empty() || b >= 0x80 {
            self.utf8.push(b);
            return match std::str::from_utf8(&self.utf8) {
                Ok(s) => {
                    let c = s.chars().next();
                    self.utf8.clear();
                    c.map(Key::Char)
                }
                Err(e) if e.error_len().is_none() && self.utf8.len() < 4 => None,
                Err(_) => {
                    self.utf8.clear();
                    None
                }
            };
        }
        Some(match b {
            0x1b => {
                self.esc.push(b);
                return None;
            }
            b'\r' | b'\n' => Key::Enter,
            b'\t' => Key::Tab,
            0x7f | 0x08 => Key::Backspace,
            0x01..=0x1a => Key::Ctrl(b + 0x40),
            0x20..=0x7e => Key::Char(char::from(b)),
            _ => return None,
        })
    }

    fn decode_escape(&mut self, b: u8) -> Option<Key> {
        match self.esc.as_slice() {
            [0x1b] => {
                if b == b'[' || b == b'O' {
                    self.esc.push(b);
                } else {
                    // Alt+key or a bare ESC: ignored.
                    self.esc.clear();
                }
                None
            }
            [0x1b, b'O'] => {
                self.esc.clear();
                match b {
                    b'A' => Some(Key::Up),
                    b'B' => Some(Key::Down),
                    b'C' => Some(Key::Right),
                    b'D' => Some(Key::Left),
                    b'H' => Some(Key::Home),
                    b'F' => Some(Key::End),
                    _ => None,
                }
            }
            _ => {
                // CSI: parameters until a final byte in 0x40..=0x7e.
                if (0x40..=0x7e).contains(&b) {
                    let params: String = self.esc[2..].iter().map(|&p| char::from(p)).collect();
                    self.esc.clear();
                    match b {
                        b'A' => Some(Key::Up),
                        b'B' => Some(Key::Down),
                        b'C' => Some(Key::Right),
                        b'D' => Some(Key::Left),
                        b'H' => Some(Key::Home),
                        b'F' => Some(Key::End),
                        b'~' => match params.as_str() {
                            "1" | "7" => Some(Key::Home),
                            "4" | "8" => Some(Key::End),
                            "3" => Some(Key::Delete),
                            _ => None,
                        },
                        _ => None,
                    }
                } else {
                    self.esc.push(b);
                    if self.esc.len() > 16 {
                        self.esc.clear();
                    }
                    None
                }
            }
        }
    }

    fn apply(&mut self, key: Key) -> Option<Edit> {
        if self.search.is_some() {
            match key {
                Key::Char(c) => {
                    self.search_refine(Some(c));
                    return None;
                }
                Key::Backspace => {
                    self.search_refine(None);
                    return None;
                }
                Key::Ctrl(b'R') => {
                    self.search_older();
                    return None;
                }
                Key::Ctrl(b'G') => {
                    self.search_cancel();
                    return None;
                }
                // Everything else accepts the match and then applies.
                _ => self.search = None,
            }
        }
        let tab_pending = std::mem::replace(&mut self.tab_pending, false);
        match key {
            Key::Char(c) => {
                self.buf.insert(self.cursor, c);
                self.cursor += 1;
            }
            Key::Enter => {
                let line = self.line();
                self.buf.clear();
                self.cursor = 0;
                self.hist_pos = None;
                self.stash.clear();
                return Some(Edit::Line(line));
            }
            Key::Tab => return self.complete(tab_pending),
            Key::Backspace | Key::Ctrl(b'H') => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.buf.remove(self.cursor);
                }
            }
            Key::Delete => {
                if self.cursor < self.buf.len() {
                    self.buf.remove(self.cursor);
                }
            }
            Key::Left | Key::Ctrl(b'B') => self.cursor = self.cursor.saturating_sub(1),
            Key::Right | Key::Ctrl(b'F') => self.cursor = (self.cursor + 1).min(self.buf.len()),
            Key::Home | Key::Ctrl(b'A') => self.cursor = 0,
            Key::End | Key::Ctrl(b'E') => self.cursor = self.buf.len(),
            Key::Up | Key::Ctrl(b'P') => self.history_move(-1),
            Key::Down | Key::Ctrl(b'N') => self.history_move(1),
            Key::Ctrl(b'U') => {
                self.buf.drain(..self.cursor);
                self.cursor = 0;
            }
            Key::Ctrl(b'K') => self.buf.truncate(self.cursor),
            Key::Ctrl(b'W') => {
                let mut start = self.cursor;
                while start > 0 && self.buf[start - 1] == ' ' {
                    start -= 1;
                }
                while start > 0 && self.buf[start - 1] != ' ' {
                    start -= 1;
                }
                self.buf.drain(start..self.cursor);
                self.cursor = start;
            }
            Key::Ctrl(b'D') => {
                if self.buf.is_empty() {
                    return Some(Edit::Eof);
                }
                if self.cursor < self.buf.len() {
                    self.buf.remove(self.cursor);
                }
            }
            Key::Ctrl(b'C') => {
                self.buf.clear();
                self.cursor = 0;
                self.hist_pos = None;
                return Some(Edit::Cancel);
            }
            Key::Ctrl(b'L') => return Some(Edit::ClearScreen),
            Key::Ctrl(b'Z') => return Some(Edit::Suspend),
            Key::Ctrl(b'R') => {
                self.search = Some(Search {
                    query: Vec::new(),
                    pos: None,
                    failed: false,
                    saved: self.buf.clone(),
                    saved_cursor: self.cursor,
                });
            }
            Key::Ctrl(_) => {}
        }
        None
    }

    fn history_move(&mut self, delta: i32) {
        if self.history.is_empty() {
            return;
        }
        let next = match (self.hist_pos, delta) {
            (None, d) if d < 0 => Some(self.history.len() - 1),
            (None, _) => return,
            (Some(0), d) if d < 0 => return,
            (Some(i), d) if d < 0 => Some(i - 1),
            (Some(i), _) if i + 1 >= self.history.len() => None,
            (Some(i), _) => Some(i + 1),
        };
        if self.hist_pos.is_none() {
            self.stash = self.buf.clone();
        }
        self.hist_pos = next;
        self.buf = match next {
            Some(i) => self.history[i].chars().collect(),
            None => self.stash.clone(),
        };
        self.cursor = self.buf.len();
    }

    // -- Ctrl-R -------------------------------------------------------------

    /// Add a char to the query (or drop the last one) and search again from
    /// the current match, so a longer query keeps the match when it still
    /// fits.
    fn search_refine(&mut self, c: Option<char>) {
        let Some(s) = &mut self.search else {
            return;
        };
        match c {
            Some(c) => s.query.push(c),
            None => {
                s.query.pop();
            }
        }
        if s.query.is_empty() {
            s.pos = None;
            s.failed = false;
            self.buf = s.saved.clone();
            self.cursor = s.saved_cursor;
            return;
        }
        let from = s.pos.unwrap_or(self.history.len().saturating_sub(1));
        self.search_from(from);
    }

    /// `Ctrl-R` again: the next older match.
    fn search_older(&mut self) {
        let Some((pos, empty)) = self.search.as_ref().map(|s| (s.pos, s.query.is_empty())) else {
            return;
        };
        if empty {
            return;
        }
        match pos {
            Some(0) => self.set_failed(true),
            Some(p) => self.search_from(p - 1),
            None if self.history.is_empty() => self.set_failed(true),
            None => self.search_from(self.history.len() - 1),
        }
    }

    /// Search `history[..=from]` backwards for the query.
    fn search_from(&mut self, from: usize) {
        let Some(s) = &self.search else {
            return;
        };
        let query: String = s.query.iter().collect();
        let found = self.history[..=from.min(self.history.len().saturating_sub(1))]
            .iter()
            .enumerate()
            .rev()
            .find_map(|(i, h)| h.find(&query).map(|at| (i, at)));
        match found {
            Some((i, at)) => {
                let line = &self.history[i];
                self.buf = line.chars().collect();
                self.cursor = line[..at].chars().count();
                if let Some(s) = &mut self.search {
                    s.pos = Some(i);
                    s.failed = false;
                }
            }
            None => self.set_failed(true),
        }
    }

    fn set_failed(&mut self, failed: bool) {
        if let Some(s) = &mut self.search {
            s.failed = failed;
        }
    }

    /// `Esc` / `Ctrl-G`: back to the line as it was.
    fn search_cancel(&mut self) {
        if let Some(s) = self.search.take() {
            self.buf = s.saved;
            self.cursor = s.saved_cursor;
        }
    }

    // -- Tab ----------------------------------------------------------------

    /// Complete the word under the cursor when the command takes a local
    /// path there. `again` is a second Tab on the same word.
    fn complete(&mut self, again: bool) -> Option<Edit> {
        let start = self.buf[..self.cursor]
            .iter()
            .rposition(|&c| c == ' ')
            .map_or(0, |i| i + 1);
        if !self.local_path_here(start) {
            return None;
        }
        let word: String = self.buf[start..self.cursor].iter().collect();
        let candidates = complete_path(&word, &self.cwd, &self.home);
        match candidates.as_slice() {
            [] => None,
            [one] => {
                self.replace_word(start, one);
                None
            }
            many => {
                let prefix = common_prefix(many);
                if prefix.chars().count() > word.chars().count() {
                    self.replace_word(start, &prefix);
                }
                self.tab_pending = true;
                again.then(|| {
                    let dir_len = word.rfind('/').map_or(0, |i| i + 1);
                    Edit::ShowCandidates(
                        many.iter()
                            .map(|c| c.get(dir_len..).unwrap_or(c).to_owned())
                            .collect(),
                    )
                })
            }
        }
    }

    /// Whether the word starting at `start` is a local path argument: any
    /// argument of `put`/`lcd`/`log`/`authorize`, or an argument of `get`
    /// after the first path.
    fn local_path_here(&self, start: usize) -> bool {
        if start == 0 {
            return false;
        }
        let before: String = self.buf[..start].iter().collect();
        let mut words = before.split_whitespace();
        let Some(cmd) = words.next() else {
            return false;
        };
        if LOCAL_PATH_COMMANDS.contains(&cmd) {
            return true;
        }
        cmd == "get" && words.any(|w| !w.starts_with('-'))
    }

    fn replace_word(&mut self, start: usize, with: &str) {
        self.buf.splice(start..self.cursor, with.chars());
        self.cursor = start + with.chars().count();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn editor() -> LineEditor {
        LineEditor::new(
            "p> ",
            vec!["first".to_owned(), "second".to_owned()],
            PathBuf::from("/nonexistent-home"),
            PathBuf::from("/nonexistent-cwd"),
        )
    }

    #[test]
    fn insert_and_enter() {
        let mut e = editor();
        assert_eq!(e.feed(b"hel").len(), 0);
        assert_eq!(e.line(), "hel");
        assert_eq!(e.feed(b"lo\r"), vec![Edit::Line("hello".to_owned())]);
        assert_eq!(e.line(), "");
        assert_eq!(e.cursor(), 0);
    }

    #[test]
    fn backspace_and_cursor_moves() {
        let mut e = editor();
        e.feed(b"abcd");
        e.feed(b"\x7f");
        assert_eq!(e.line(), "abc");
        e.feed(b"\x1b[D\x1b[D"); // left twice
        assert_eq!(e.cursor(), 1);
        e.feed(b"X");
        assert_eq!(e.line(), "aXbc");
        e.feed(b"\x01"); // Ctrl-A
        assert_eq!(e.cursor(), 0);
        e.feed(b"\x05"); // Ctrl-E
        assert_eq!(e.cursor(), 4);
        e.feed(b"\x1b[H");
        assert_eq!(e.cursor(), 0);
        e.feed(b"\x1b[3~"); // Delete
        assert_eq!(e.line(), "Xbc");
        e.feed(b"\x1bOF"); // End
        assert_eq!(e.cursor(), 3);
    }

    #[test]
    fn kill_keys() {
        let mut e = editor();
        e.feed(b"one two three");
        e.feed(b"\x17"); // Ctrl-W
        assert_eq!(e.line(), "one two ");
        e.feed(b"\x1b[D\x1b[D");
        e.feed(b"\x0b"); // Ctrl-K
        assert_eq!(e.line(), "one tw");
        e.feed(b"\x15"); // Ctrl-U
        assert_eq!(e.line(), "");
        assert_eq!(e.cursor(), 0);
    }

    #[test]
    fn history_navigation() {
        let mut e = editor();
        e.feed(b"new");
        e.feed(b"\x1b[A");
        assert_eq!(e.line(), "second");
        e.feed(b"\x1b[A");
        assert_eq!(e.line(), "first");
        e.feed(b"\x1b[A");
        assert_eq!(e.line(), "first");
        e.feed(b"\x1b[B\x1b[B");
        assert_eq!(e.line(), "new");
        e.push_history("new");
        e.push_history("new");
        assert_eq!(e.history.len(), 3);
    }

    #[test]
    fn control_edits() {
        let mut e = editor();
        assert_eq!(e.feed(b"\x04"), vec![Edit::Eof]);
        e.feed(b"abc");
        assert_eq!(e.feed(b"\x03"), vec![Edit::Cancel]);
        assert_eq!(e.line(), "");
        assert_eq!(e.feed(b"\x0c"), vec![Edit::ClearScreen]);
        assert_eq!(e.feed(b"\x1a"), vec![Edit::Suspend]);
    }

    #[test]
    fn split_escape_and_utf8() {
        let mut e = editor();
        e.feed(b"ab");
        e.feed(b"\x1b");
        e.feed(b"[");
        e.feed(b"D");
        assert_eq!(e.cursor(), 1);
        let euro = "€".as_bytes();
        e.feed(&euro[..1]);
        e.feed(&euro[1..]);
        assert_eq!(e.line(), "a€b");
    }

    #[test]
    fn render_places_cursor() {
        let mut e = editor();
        e.feed(b"abc\x1b[D");
        assert_eq!(e.render(), "\r\x1b[Kp> abc\x1b[1D");
        e.feed(b"\x05");
        assert_eq!(e.render(), "\r\x1b[Kp> abc");
    }

    #[test]
    fn history_push_and_trim() {
        let mut h = History::empty();
        h.push("a");
        h.push("a");
        h.push("  ");
        h.push("b");
        assert_eq!(h.entries(), ["a", "b"]);
        let many: Vec<String> = (0..HISTORY_CAP + 5).map(|i| i.to_string()).collect();
        let trimmed = trim_history(many);
        assert_eq!(trimmed.len(), HISTORY_CAP);
        assert_eq!(trimmed[0], "5");
    }

    #[test]
    fn history_save_round_trip() {
        let dir = std::env::temp_dir().join(format!("mysh-hist-{}", std::process::id()));
        let path = dir.join("history");
        let mut h = History::load(&path);
        assert_eq!(h.entries().len(), 0);
        h.push("ls -l");
        h.push("exit");
        h.save().expect("save history");
        let again = History::load(&path);
        assert_eq!(again.entries(), ["ls -l", "exit"]);
        let _ = fs::remove_dir_all(&dir);
    }

    // -- completion ----------------------------------------------------------

    /// `root/{alpha.txt, alps/, beta, .hidden, sub/{one, two/}}`.
    fn tree(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("mysh-cmpl-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("alps")).expect("mkdir");
        fs::create_dir_all(root.join("sub/two")).expect("mkdir");
        for f in ["alpha.txt", "beta", ".hidden", "sub/one"] {
            fs::write(root.join(f), b"x").expect("write");
        }
        root
    }

    #[test]
    fn complete_path_lists_matches() {
        let root = tree("list");
        let home = root.join("sub");
        assert_eq!(complete_path("al", &root, &home), ["alpha.txt", "alps/"]);
        assert_eq!(complete_path("alph", &root, &home), ["alpha.txt"]);
        assert_eq!(
            complete_path("", &root, &home),
            ["alpha.txt", "alps/", "beta", "sub/"]
        );
        assert_eq!(complete_path(".", &root, &home), [".hidden"]);
        assert_eq!(complete_path("sub/", &root, &home), ["sub/one", "sub/two/"]);
        assert_eq!(complete_path("sub/t", &root, &home), ["sub/two/"]);
        assert_eq!(complete_path("zzz", &root, &home), Vec::<String>::new());
        assert_eq!(
            complete_path("missing/x", &root, &home),
            Vec::<String>::new()
        );
        // Absolute and `~`-relative directory parts are kept as typed.
        let abs = format!("{}/al", root.display());
        assert_eq!(
            complete_path(&abs, Path::new("/"), &home),
            [
                format!("{}/alpha.txt", root.display()),
                format!("{}/alps/", root.display())
            ]
        );
        assert_eq!(complete_path("~/t", &root, &home), ["~/two/"]);
        assert_eq!(complete_path("~", &root, &home), ["~/"]);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn tab_completes_tilde_word() {
        let root = tree("tilde");
        let mut e = LineEditor::new("p> ", Vec::new(), root.join("sub"), root.clone());
        e.feed(b"put ~/o\t");
        assert_eq!(e.line(), "put ~/one");
        assert_eq!(e.cursor(), 9);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn tab_common_prefix_then_candidates() {
        let root = tree("prefix");
        let mut e = LineEditor::new("p> ", Vec::new(), root.join("sub"), root.clone());
        e.feed(b"lcd a");
        assert_eq!(e.feed(b"\t"), vec![]);
        assert_eq!(e.line(), "lcd alp");
        assert_eq!(
            e.feed(b"\t"),
            vec![Edit::ShowCandidates(vec![
                "alpha.txt".to_owned(),
                "alps/".to_owned()
            ])]
        );
        assert_eq!(e.line(), "lcd alp");
        // Typing resets the "second Tab" state; a single match completes
        // outright and a directory gets its slash.
        e.feed(b"s");
        assert_eq!(e.feed(b"\t"), vec![]);
        assert_eq!(e.line(), "lcd alps/");
        // Candidates inside a directory are shown without the directory part.
        e.feed(b"\x15put sub/\t");
        assert_eq!(e.line(), "put sub/");
        assert_eq!(
            e.feed(b"\t"),
            vec![Edit::ShowCandidates(vec![
                "one".to_owned(),
                "two/".to_owned()
            ])]
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn tab_only_for_local_path_arguments() {
        let root = tree("cmds");
        let mut e = LineEditor::new("p> ", Vec::new(), root.join("sub"), root.clone());
        for line in ["ls al", "al", "get al", "get -r al", "shell al"] {
            e.feed(b"\x15");
            e.feed(line.as_bytes());
            assert_eq!(e.feed(b"\t"), vec![], "{line}");
            assert_eq!(e.line(), line, "{line}");
        }
        for (line, want) in [
            ("get remote al", "get remote alp"),
            ("get -r remote al", "get -r remote alp"),
            ("put x y al", "put x y alp"),
            ("log al", "log alp"),
            ("authorize al", "authorize alp"),
        ] {
            e.feed(b"\x15");
            e.feed(line.as_bytes());
            e.feed(b"\t");
            assert_eq!(e.line(), want, "{line}");
        }
        // Tab in the middle of a word completes the part before the cursor.
        e.feed(b"\x15lcd bX\x1b[D\t");
        assert_eq!(e.line(), "lcd betaX");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn columns_layout() {
        let items: Vec<String> = ["a", "bb", "ccc", "d", "e"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(format_columns(&items, 12), "a    d\r\nbb   e\r\nccc\r\n");
        assert_eq!(format_columns(&items, 3), "a\r\nbb\r\nccc\r\nd\r\ne\r\n");
        assert_eq!(format_columns(&[], 80), "");
    }

    // -- Ctrl-R --------------------------------------------------------------

    fn searcher() -> LineEditor {
        LineEditor::new(
            "p> ",
            ["put a.txt", "ls -l", "put b.txt", "shell"]
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            PathBuf::from("/nonexistent-home"),
            PathBuf::from("/nonexistent-cwd"),
        )
    }

    #[test]
    fn search_refines_and_cycles_older() {
        let mut e = searcher();
        e.feed(b"typed");
        e.feed(b"\x12");
        assert!(e.searching());
        assert_eq!(e.render(), "\r\x1b[K(reverse-i-search)'': typed");
        e.feed(b"p");
        assert_eq!(e.line(), "put b.txt");
        assert_eq!(e.cursor(), 0);
        assert_eq!(
            e.render(),
            "\r\x1b[K(reverse-i-search)'p': put b.txt\x1b[9D"
        );
        e.feed(b"ut a");
        assert_eq!(e.line(), "put a.txt");
        assert_eq!(
            e.render(),
            "\r\x1b[K(reverse-i-search)'put a': put a.txt\x1b[9D"
        );
        // Backspace shortens the query and keeps the current match.
        e.feed(b"\x7f");
        assert_eq!(e.line(), "put a.txt");
        e.feed(b"\x7f\x7f\x7f");
        assert_eq!(e.line(), "put a.txt");
        // Ctrl-R cycles to the older match; past the oldest it fails.
        e.feed(b"\x7fs");
        assert_eq!(e.line(), "shell");
        e.feed(b"\x12");
        assert_eq!(e.line(), "ls -l");
        e.feed(b"\x12");
        assert_eq!(e.line(), "ls -l");
        assert_eq!(
            e.render(),
            "\r\x1b[K(failed reverse-i-search)'s': ls -l\x1b[4D"
        );
        // A query nothing matches keeps the line and reports failure.
        e.feed(b"zz");
        assert_eq!(e.line(), "ls -l");
        assert!(
            e.render()
                .starts_with("\r\x1b[K(failed reverse-i-search)'szz': ")
        );
        e.feed(b"\x7f\x7f");
        assert!(e.render().starts_with("\r\x1b[K(reverse-i-search)'s': "));
    }

    #[test]
    fn search_accepts_with_enter() {
        let mut e = searcher();
        e.feed(b"\x12ls");
        assert_eq!(e.feed(b"\r"), vec![Edit::Line("ls -l".to_owned())]);
        assert!(!e.searching());
        assert_eq!(e.line(), "");
        assert_eq!(e.render(), "\r\x1b[Kp> ");
    }

    #[test]
    fn search_cancels_with_esc_and_ctrl_g() {
        let mut e = searcher();
        e.feed(b"keep");
        e.feed(b"\x12sh");
        assert_eq!(e.line(), "shell");
        e.feed(b"\x1b");
        assert!(!e.searching());
        assert_eq!(e.line(), "keep");
        assert_eq!(e.cursor(), 4);
        assert_eq!(e.render(), "\r\x1b[Kp> keep");
        e.feed(b"\x12sh\x07");
        assert!(!e.searching());
        assert_eq!(e.line(), "keep");
        // Outside a search a lone ESC still waits for the rest of a sequence.
        e.feed(b"\x1b");
        e.feed(b"[D");
        assert_eq!(e.cursor(), 3);
    }

    #[test]
    fn search_other_key_accepts_then_applies() {
        let mut e = searcher();
        e.feed(b"\x12b.t");
        assert_eq!(e.line(), "put b.txt");
        assert_eq!(e.cursor(), 4);
        e.feed(b"\x05"); // Ctrl-E
        assert!(!e.searching());
        assert_eq!(e.cursor(), 9);
        e.feed(b"\x12b.t\x1b[C"); // Right
        assert!(!e.searching());
        assert_eq!(e.cursor(), 5);
        e.feed(b"\x12sh\x03");
        assert!(!e.searching());
        assert_eq!(e.line(), "");
    }
}
