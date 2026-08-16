//! The thin interactive shell: raw-mode via `stty` (std has no termios),
//! alternate-screen ANSI drawing, and a `/dev/tty` key reader.
//!
//! Safety contract (M5 acceptance): the terminal is restored on every path —
//! normal exit, engine error, and panic (a panic hook chains the restore).
//! Everything interesting lives in `render.rs`, which is pure.

use std::fs::File;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

use sipr_stats::Snapshot;

use crate::render::{Screen, render_with};
use crate::style::Palette;

const ENTER_ALT: &str = "\x1b[?1049h\x1b[?25l";
const LEAVE_ALT: &str = "\x1b[?1049l\x1b[?25h";

/// Run `stty` with the controlling terminal as stdin.
fn stty(args: &[&str]) -> Option<String> {
    let tty = File::open("/dev/tty").ok()?;
    let out = Command::new("stty")
        .args(args)
        .stdin(Stdio::from(tty))
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Raw-mode guard: restores the saved terminal state on drop.
struct RawGuard {
    saved: Option<String>,
}

impl RawGuard {
    fn enter() -> Self {
        let saved = stty(&["-g"]);
        // -icanon: byte-at-a-time reads; -echo: keys don't print.
        let _ = stty(&["-icanon", "-echo", "min", "1", "time", "0"]);
        print!("{ENTER_ALT}");
        let _ = std::io::stdout().flush();
        Self { saved }
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        print!("{LEAVE_ALT}");
        let _ = std::io::stdout().flush();
        match self.saved.take() {
            Some(state) => {
                let _ = stty(&[&state]);
            }
            None => {
                let _ = stty(&["sane"]);
            }
        }
    }
}

/// Restore the terminal even when some thread panics mid-run.
fn install_panic_restore() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        print!("{LEAVE_ALT}");
        let _ = std::io::stdout().flush();
        let _ = stty(&["sane"]);
        previous(info);
    }));
}

/// Draw a full frame: home the cursor and repaint, clearing each line.
fn draw(lines: &[String]) {
    let mut frame = String::with_capacity(4096);
    frame.push_str("\x1b[H");
    for line in lines {
        frame.push_str(line);
        frame.push_str("\x1b[K\r\n");
    }
    frame.push_str("\x1b[J"); // clear everything below the frame
    print!("{frame}");
    let _ = std::io::stdout().flush();
}

/// Run the TUI until the snapshot channel closes (engine finished).
///
/// `snapshots`: engine → UI. `keys_out`: UI → engine (rate/pause/quit keys;
/// `s` is consumed locally to switch screens).
pub fn run(snapshots: &Receiver<Snapshot>, keys_out: &Sender<char>) {
    install_panic_restore();
    let _guard = RawGuard::enter();
    // Key reader: /dev/tty bytes, forwarded as chars.
    let (key_tx, key_rx) = std::sync::mpsc::channel::<char>();
    let _keys = std::thread::Builder::new()
        .name("sipr-tty-keys".into())
        .spawn(move || {
            let Ok(tty) = File::open("/dev/tty") else {
                return;
            };
            // One byte at a time is the point here (keystrokes), but clippy
            // rightly wants the reads buffered.
            for byte in std::io::BufReader::new(tty).bytes() {
                match byte {
                    Ok(b) => {
                        if key_tx.send(char::from(b)).is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
    // Ferrous colors, unless the user set NO_COLOR (https://no-color.org).
    let pal = if std::env::var_os("NO_COLOR").is_some() {
        Palette::PLAIN
    } else {
        Palette::COLOR
    };
    let mut screen = Screen::Main;
    let mut last: Option<Snapshot> = None;
    loop {
        // Drain any pending keys.
        while let Ok(key) = key_rx.try_recv() {
            if key == 's' {
                screen = screen.next();
                if let Some(snap) = &last {
                    draw(&render_with(snap, screen, &pal));
                }
            } else if keys_out.send(key).is_err() {
                return;
            }
        }
        // Wait briefly for the next snapshot; redraw when one arrives.
        match snapshots.recv_timeout(Duration::from_millis(100)) {
            Ok(snap) => {
                draw(&render_with(&snap, screen, &pal));
                last = Some(snap);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}
