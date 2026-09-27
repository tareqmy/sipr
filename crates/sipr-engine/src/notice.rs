//! What the engine has to say outside its statistics: the lines the binary
//! prints as `sipr: ...`, `sipr: warning: ...` and `sipr: error: ...`. An
//! embedder chooses where they go with [`NoticeSink`]; the engine itself
//! never prints (the crate denies `print_stderr`/`print_stdout`).

use std::io::Write;
use std::sync::mpsc::Sender;

/// One line the engine would otherwise have printed to stderr.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// Progress and bindings: where a socket bound, that the control API
    /// is up, a pcap's packet count, the `-bg` statistics line.
    Info(String),
    /// Something unexpected the run survives: a failed reconnection, a
    /// rejected message, a flag without effect.
    Warning(String),
    /// Something fatal: the run is ending because of it.
    Error(String),
}

impl Notice {
    /// The text without its level prefix.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Info(m) | Self::Warning(m) | Self::Error(m) => m,
        }
    }
}

impl std::fmt::Display for Notice {
    /// The binary's stderr wording: `sipr: `, `sipr: warning: `,
    /// `sipr: error: ` before the message.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info(m) => write!(f, "sipr: {m}"),
            Self::Warning(m) => write!(f, "sipr: warning: {m}"),
            Self::Error(m) => write!(f, "sipr: error: {m}"),
        }
    }
}

/// Where the engine's [`Notice`]s go. The default prints them to stderr
/// exactly as the binary always has; an embedder passes a channel to read
/// them as values, or discards them on purpose. Silence is never the
/// default.
#[derive(Debug, Clone, Default)]
pub enum NoticeSink {
    /// Print each notice to stderr, one line each, with its prefix.
    #[default]
    Stderr,
    /// Send each notice down this channel. A dropped receiver drops the
    /// notices from then on.
    Channel(Sender<Notice>),
    /// Drop every notice.
    Discard,
}

impl PartialEq for NoticeSink {
    /// Sinks compare by kind: two `Channel`s are equal whatever they lead
    /// to, since a sender cannot be compared. This is enough for a
    /// configuration to be comparable.
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl NoticeSink {
    /// Emit an [`Notice::Info`].
    pub(crate) fn info(&self, message: impl std::fmt::Display) {
        self.emit(Notice::Info(message.to_string()));
    }

    /// Emit a [`Notice::Warning`].
    pub(crate) fn warning(&self, message: impl std::fmt::Display) {
        self.emit(Notice::Warning(message.to_string()));
    }

    /// Emit a [`Notice::Error`].
    pub(crate) fn error(&self, message: impl std::fmt::Display) {
        self.emit(Notice::Error(message.to_string()));
    }

    fn emit(&self, notice: Notice) {
        match self {
            Self::Stderr => {
                // A closed stderr is nothing the engine can act on.
                let _ = writeln!(std::io::stderr().lock(), "{notice}");
            }
            Self::Channel(tx) => {
                let _ = tx.send(notice);
            }
            Self::Discard => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_the_binary_wording() {
        assert_eq!(
            Notice::Info("bound to x".into()).to_string(),
            "sipr: bound to x"
        );
        assert_eq!(
            Notice::Warning("odd".into()).to_string(),
            "sipr: warning: odd"
        );
        assert_eq!(Notice::Error("bad".into()).to_string(), "sipr: error: bad");
    }

    #[test]
    fn channel_receives_and_discard_drops() {
        let (tx, rx) = std::sync::mpsc::channel();
        let sink = NoticeSink::Channel(tx);
        sink.warning("w");
        sink.info(format!("{} packets", 3));
        assert_eq!(rx.recv().unwrap(), Notice::Warning("w".into()));
        assert_eq!(rx.recv().unwrap(), Notice::Info("3 packets".into()));
        NoticeSink::Discard.error("nobody hears this");
        assert_eq!(NoticeSink::Discard, NoticeSink::Discard);
        assert_ne!(NoticeSink::Discard, NoticeSink::Stderr);
    }
}
