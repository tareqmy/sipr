//! `exec command=`: SIPp's external-command hook. SIPp double-forks and runs
//! the rendered text with `system()`, never waiting for it and never seeing
//! its status. sipr keeps that contract — fire-and-forget, a shell, inherited
//! stdio so `>> file` works — but spawns from one runner thread that also
//! reaps the children it started, so the engine thread never forks or blocks
//! and no zombies accumulate under load. When the run ends the queue is
//! drained (every command still gets started) but running commands are left
//! to finish on their own, as SIPp's grandchildren are.

use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::Duration;

/// How often the runner checks its children while waiting for commands.
const REAP_INTERVAL: Duration = Duration::from_millis(100);

/// Handle to the runner thread; dropping it drains the queue and ends the
/// thread (running children are not waited for).
#[derive(Debug)]
pub struct ExecRunner {
    tx: Option<Sender<String>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ExecRunner {
    /// Start the runner thread.
    #[must_use]
    pub fn start() -> Self {
        let (tx, rx) = channel();
        let thread = std::thread::Builder::new()
            .name("sipr-exec".into())
            .spawn(move || run(&rx))
            .ok();
        Self {
            tx: Some(tx),
            thread,
        }
    }

    /// Queue a rendered command; returns false when the runner is gone.
    pub fn run(&self, command: String) -> bool {
        self.tx.as_ref().is_some_and(|tx| tx.send(command).is_ok())
    }
}

impl Drop for ExecRunner {
    fn drop(&mut self) {
        // Closing the channel lets the thread spawn what is still queued
        // and return; joining makes sure that happens before the process
        // exits.
        self.tx.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run(rx: &Receiver<String>) {
    let mut children: Vec<(Child, String)> = Vec::new();
    loop {
        match rx.recv_timeout(REAP_INTERVAL) {
            Ok(command) => match spawn_shell(&command) {
                Ok(child) => children.push((child, command)),
                // SIPp's grandchild prints this when `system()` fails.
                Err(e) => eprintln!("sipr: warning: system call error for {command}: {e}"),
            },
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        children.retain_mut(|(child, _)| !matches!(child.try_wait(), Ok(Some(_))));
    }
}

/// `sh -c` (SIPp's `system()`), stdin closed, stdout/stderr inherited.
fn spawn_shell(command: &str) -> std::io::Result<Child> {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(command);
        c
    } else {
        let mut c = Command::new("sh");
        c.arg("-c").arg(command);
        c
    };
    cmd.stdin(Stdio::null()).spawn()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_run_through_a_shell_and_are_reaped() {
        let dir = std::env::temp_dir().join(format!("sipr-exec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("out.txt");
        let runner = ExecRunner::start();
        // A shell feature (redirection) and two commands in a row.
        assert!(runner.run(format!("echo one >> {}", out.display())));
        assert!(runner.run(format!("echo two >> {}", out.display())));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut text = String::new();
        while std::time::Instant::now() < deadline {
            text = std::fs::read_to_string(&out).unwrap_or_default();
            if text.lines().count() == 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(text, "one\ntwo\n");
        drop(runner);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
