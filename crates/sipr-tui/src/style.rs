//! The "Ferrous" brand palette, mapped to terminal ANSI colors.
//!
//! From `brand/README.md`: rust → 208, sage → green (65), taupe → bright
//! black. Each field is either an ANSI escape or an empty string; a
//! [`Palette::PLAIN`] with all-empty fields renders byte-identically to the
//! uncolored screens, which is what the pure-render unit tests assert against.

/// Semantic ANSI colors for the dashboard.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    /// Product name / headline (rust, bold).
    pub title: &'static str,
    /// Rules, separators, secondary labels (taupe / bright black).
    pub label: &'static str,
    /// Good news — successful calls (sage green).
    pub ok: &'static str,
    /// Bad news — failures (rust/orange).
    pub bad: &'static str,
    /// Interactive hints — footer key letters (rust bright).
    pub key: &'static str,
    /// Reset back to default.
    pub reset: &'static str,
}

impl Palette {
    /// The Ferrous color palette (256-color ANSI).
    pub const COLOR: Self = Self {
        title: "\x1b[1;38;5;208m", // rust, bold
        label: "\x1b[38;5;244m",   // taupe / dim grey
        ok: "\x1b[38;5;65m",       // sage green
        bad: "\x1b[38;5;208m",     // rust/orange
        key: "\x1b[1;38;5;208m",   // rust bright, bold
        reset: "\x1b[0m",
    };

    /// No color — every field empty. Output matches the plain screens.
    pub const PLAIN: Self = Self {
        title: "",
        label: "",
        ok: "",
        bad: "",
        key: "",
        reset: "",
    };

    /// True when this palette emits no escape codes.
    #[must_use]
    pub fn is_plain(&self) -> bool {
        self.reset.is_empty()
    }

    /// Wrap `s` in `color` (a field of this palette). No-op when plain.
    #[must_use]
    pub fn paint(&self, color: &str, s: &str) -> String {
        if color.is_empty() {
            s.to_owned()
        } else {
            format!("{color}{s}{}", self.reset)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_paint_is_identity() {
        assert_eq!(Palette::PLAIN.paint(Palette::PLAIN.ok, "5 ok"), "5 ok");
        assert!(Palette::PLAIN.is_plain());
    }

    #[test]
    fn color_paint_wraps_and_resets() {
        let p = Palette::COLOR;
        let painted = p.paint(p.ok, "5 ok");
        assert!(painted.starts_with("\x1b[38;5;65m"));
        assert!(painted.ends_with("\x1b[0m"));
        assert!(painted.contains("5 ok"));
        assert!(!p.is_plain());
    }
}
