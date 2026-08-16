//! A small POSIX-ERE-flavored regex engine for `ereg` (milestone M6).
//!
//! In-tree because the `regex` crate is unreachable from the build
//! environment, and SIPp scenario patterns are modest: literals, `.`,
//! classes (incl. `[[:alpha:]]`), anchors, alternation, `* + ? {m,n}`, and
//! capture groups. Semantics divergence, recorded in docs/SIPP_COMPAT.md §6:
//! this is a leftmost-first greedy backtracker (PCRE-style), not POSIX
//! leftmost-longest — identical on the patterns real scenarios use. A step
//! budget bounds pathological backtracking: over-budget matches fail.
//!
//! Operates on bytes: SIP messages may carry non-UTF-8 bodies.

/// Compile error with a human-readable message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegexError(pub String);

impl std::fmt::Display for RegexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Backtracking step budget per match attempt (all start offsets combined).
const STEP_BUDGET: u64 = 1_000_000;

#[derive(Debug, Clone, PartialEq)]
enum Node {
    Literal(u8),
    Any,
    Class {
        negated: bool,
        items: Vec<ClassItem>,
    },
    Start,
    End,
    Group(usize, Box<Node>),
    Seq(Vec<Node>),
    Alt(Vec<Node>),
    Repeat {
        node: Box<Node>,
        min: u32,
        max: Option<u32>,
    },
}

#[derive(Debug, Clone, PartialEq)]
enum ClassItem {
    Byte(u8),
    Range(u8, u8),
    Posix(Posix),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Posix {
    Alnum,
    Alpha,
    Digit,
    Lower,
    Upper,
    Space,
    Punct,
    Xdigit,
    Blank,
    Cntrl,
    Graph,
    Print,
}

impl Posix {
    fn matches(self, b: u8) -> bool {
        match self {
            Self::Alnum => b.is_ascii_alphanumeric(),
            Self::Alpha => b.is_ascii_alphabetic(),
            Self::Digit => b.is_ascii_digit(),
            Self::Lower => b.is_ascii_lowercase(),
            Self::Upper => b.is_ascii_uppercase(),
            Self::Space => b.is_ascii_whitespace(),
            Self::Punct => b.is_ascii_punctuation(),
            Self::Xdigit => b.is_ascii_hexdigit(),
            Self::Blank => b == b' ' || b == b'\t',
            Self::Cntrl => b.is_ascii_control(),
            Self::Graph => b.is_ascii_graphic(),
            Self::Print => b.is_ascii_graphic() || b == b' ',
        }
    }
}

/// A compiled expression.
#[derive(Debug, Clone, PartialEq)]
pub struct Regex {
    root: Node,
    /// Number of capture groups (not counting group 0 = whole match).
    ngroups: usize,
    /// Original pattern text.
    pub raw: String,
}

/// Byte ranges of the whole match (index 0) and each capture group.
pub type Captures = Vec<Option<(usize, usize)>>;

impl Regex {
    /// Compile a pattern.
    ///
    /// # Errors
    ///
    /// [`RegexError`] on syntax errors (unbalanced parens, bad class, ...).
    pub fn compile(pattern: &str) -> Result<Self, RegexError> {
        let bytes: Vec<u8> = pattern.bytes().collect();
        let mut p = Parser {
            b: &bytes,
            pos: 0,
            ngroups: 0,
        };
        let root = p.parse_alt()?;
        if p.pos != p.b.len() {
            return Err(RegexError(format!(
                "unexpected '{}' at offset {}",
                char::from(p.b[p.pos]),
                p.pos
            )));
        }
        Ok(Self {
            root,
            ngroups: p.ngroups,
            raw: pattern.to_owned(),
        })
    }

    /// Number of capture groups.
    #[must_use]
    pub fn group_count(&self) -> usize {
        self.ngroups
    }

    /// Leftmost match with captures, or `None`.
    #[must_use]
    pub fn find(&self, text: &[u8]) -> Option<Captures> {
        let mut budget = STEP_BUDGET;
        for start in 0..=text.len() {
            let mut caps: Captures = vec![None; self.ngroups + 1];
            if let Some(end) = match_node(&self.root, text, start, &mut caps, &mut budget) {
                caps[0] = Some((start, end));
                return Some(caps);
            }
            if budget == 0 {
                return None; // pathological pattern: fail loudly-by-not-matching
            }
            // `^` can only match at offset 0.
            if starts_with_anchor(&self.root) {
                break;
            }
        }
        None
    }

    /// Convenience: captured slices as lossy strings (group 0 first).
    #[must_use]
    pub fn find_strings(&self, text: &[u8]) -> Option<Vec<Option<String>>> {
        self.find(text).map(|caps| {
            caps.iter()
                .map(|c| c.map(|(s, e)| String::from_utf8_lossy(&text[s..e]).into_owned()))
                .collect()
        })
    }
}

fn starts_with_anchor(node: &Node) -> bool {
    match node {
        Node::Start => true,
        Node::Seq(nodes) => nodes.first().is_some_and(starts_with_anchor),
        Node::Group(_, inner) => starts_with_anchor(inner),
        Node::Alt(branches) => branches.iter().all(starts_with_anchor),
        _ => false,
    }
}

// ---- parser ------------------------------------------------------------

struct Parser<'a> {
    b: &'a [u8],
    pos: usize,
    ngroups: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn parse_alt(&mut self) -> Result<Node, RegexError> {
        let mut branches = vec![self.parse_seq()?];
        while self.peek() == Some(b'|') {
            self.bump();
            branches.push(self.parse_seq()?);
        }
        Ok(if branches.len() == 1 {
            branches.remove(0)
        } else {
            Node::Alt(branches)
        })
    }

    fn parse_seq(&mut self) -> Result<Node, RegexError> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == b'|' || c == b')' {
                break;
            }
            let atom = self.parse_atom()?;
            items.push(self.parse_postfix(atom)?);
        }
        Ok(if items.len() == 1 {
            items.remove(0)
        } else {
            Node::Seq(items)
        })
    }

    fn parse_postfix(&mut self, atom: Node) -> Result<Node, RegexError> {
        let (min, max) = match self.peek() {
            Some(b'*') => (0, None),
            Some(b'+') => (1, None),
            Some(b'?') => (0, Some(1)),
            Some(b'{') => {
                self.bump();
                return self.parse_bound(atom);
            }
            _ => return Ok(atom),
        };
        self.bump();
        Ok(Node::Repeat {
            node: Box::new(atom),
            min,
            max,
        })
    }

    fn parse_bound(&mut self, atom: Node) -> Result<Node, RegexError> {
        let mut min_s = String::new();
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                min_s.push(char::from(c));
                self.bump();
            } else {
                break;
            }
        }
        let min: u32 = min_s
            .parse()
            .map_err(|_| RegexError("bad {m,n} bound".into()))?;
        let max = match self.bump() {
            Some(b'}') => Some(min),
            Some(b',') => {
                let mut max_s = String::new();
                while let Some(c) = self.peek() {
                    if c.is_ascii_digit() {
                        max_s.push(char::from(c));
                        self.bump();
                    } else {
                        break;
                    }
                }
                if self.bump() != Some(b'}') {
                    return Err(RegexError("unterminated {m,n}".into()));
                }
                if max_s.is_empty() {
                    None
                } else {
                    Some(
                        max_s
                            .parse()
                            .map_err(|_| RegexError("bad {m,n} bound".into()))?,
                    )
                }
            }
            _ => return Err(RegexError("unterminated {m,n}".into())),
        };
        if let Some(m) = max {
            if m < min {
                return Err(RegexError("{m,n} with n < m".into()));
            }
        }
        Ok(Node::Repeat {
            node: Box::new(atom),
            min,
            max,
        })
    }

    fn parse_atom(&mut self) -> Result<Node, RegexError> {
        match self.bump() {
            Some(b'(') => {
                self.ngroups += 1;
                let idx = self.ngroups;
                let inner = self.parse_alt()?;
                if self.bump() != Some(b')') {
                    return Err(RegexError("unbalanced '('".into()));
                }
                Ok(Node::Group(idx, Box::new(inner)))
            }
            Some(b'[') => self.parse_class(),
            Some(b'.') => Ok(Node::Any),
            Some(b'^') => Ok(Node::Start),
            Some(b'$') => Ok(Node::End),
            Some(b'\\') => {
                let c = self
                    .bump()
                    .ok_or_else(|| RegexError("trailing backslash".into()))?;
                Ok(match c {
                    b'n' => Node::Literal(b'\n'),
                    b'r' => Node::Literal(b'\r'),
                    b't' => Node::Literal(b'\t'),
                    other => Node::Literal(other),
                })
            }
            Some(b'*' | b'+' | b'?') => Err(RegexError("repetition with nothing to repeat".into())),
            Some(c) => Ok(Node::Literal(c)),
            None => Err(RegexError("unexpected end of pattern".into())),
        }
    }

    fn parse_class(&mut self) -> Result<Node, RegexError> {
        let negated = if self.peek() == Some(b'^') {
            self.bump();
            true
        } else {
            false
        };
        let mut items = Vec::new();
        // A ']' immediately after '[' (or '[^') is a literal.
        if self.peek() == Some(b']') {
            self.bump();
            items.push(ClassItem::Byte(b']'));
        }
        loop {
            match self.peek() {
                None => return Err(RegexError("unterminated character class".into())),
                Some(b']') => {
                    self.bump();
                    break;
                }
                Some(b'[') if self.b.get(self.pos + 1) == Some(&b':') => {
                    items.push(self.parse_posix_class()?);
                }
                Some(c) => {
                    self.bump();
                    let c = if c == b'\\' {
                        self.bump()
                            .ok_or_else(|| RegexError("trailing backslash in class".into()))?
                    } else {
                        c
                    };
                    // Range c-d (unless '-' is last before ']').
                    if self.peek() == Some(b'-') && self.b.get(self.pos + 1) != Some(&b']') {
                        self.bump();
                        let d = self
                            .bump()
                            .ok_or_else(|| RegexError("unterminated range".into()))?;
                        if d < c {
                            return Err(RegexError("reversed range in class".into()));
                        }
                        items.push(ClassItem::Range(c, d));
                    } else {
                        items.push(ClassItem::Byte(c));
                    }
                }
            }
        }
        Ok(Node::Class { negated, items })
    }

    fn parse_posix_class(&mut self) -> Result<ClassItem, RegexError> {
        // Consumes "[:name:]".
        self.bump();
        self.bump();
        let mut name = String::new();
        while let Some(c) = self.peek() {
            if c == b':' {
                break;
            }
            name.push(char::from(c));
            self.bump();
        }
        if self.bump() != Some(b':') || self.bump() != Some(b']') {
            return Err(RegexError("malformed [[:class:]]".into()));
        }
        let class = match name.as_str() {
            "alnum" => Posix::Alnum,
            "alpha" => Posix::Alpha,
            "digit" => Posix::Digit,
            "lower" => Posix::Lower,
            "upper" => Posix::Upper,
            "space" => Posix::Space,
            "punct" => Posix::Punct,
            "xdigit" => Posix::Xdigit,
            "blank" => Posix::Blank,
            "cntrl" => Posix::Cntrl,
            "graph" => Posix::Graph,
            "print" => Posix::Print,
            other => return Err(RegexError(format!("unknown POSIX class [[:{other}:]]"))),
        };
        Ok(ClassItem::Posix(class))
    }
}

// ---- matcher -----------------------------------------------------------

/// Match `node` at `pos`; returns the end position of the match.
fn match_node(
    node: &Node,
    text: &[u8],
    pos: usize,
    caps: &mut Captures,
    budget: &mut u64,
) -> Option<usize> {
    if *budget == 0 {
        return None;
    }
    *budget -= 1;
    match node {
        Node::Literal(c) => (text.get(pos) == Some(c)).then(|| pos + 1),
        Node::Any => (pos < text.len() && text[pos] != b'\n').then(|| pos + 1),
        Node::Class { negated, items } => {
            let b = *text.get(pos)?;
            let hit = items.iter().any(|i| match i {
                ClassItem::Byte(c) => b == *c,
                ClassItem::Range(a, z) => (*a..=*z).contains(&b),
                ClassItem::Posix(p) => p.matches(b),
            });
            (hit != *negated).then(|| pos + 1)
        }
        Node::Start => (pos == 0).then_some(pos),
        Node::End => (pos == text.len()).then_some(pos),
        Node::Group(idx, inner) => {
            let saved = caps[*idx];
            match match_node(inner, text, pos, caps, budget) {
                Some(end) => {
                    caps[*idx] = Some((pos, end));
                    Some(end)
                }
                None => {
                    caps[*idx] = saved;
                    None
                }
            }
        }
        Node::Seq(nodes) => match_seq(nodes, text, pos, caps, budget),
        Node::Alt(branches) => {
            for branch in branches {
                let saved = caps.clone();
                if let Some(end) = match_node(branch, text, pos, caps, budget) {
                    return Some(end);
                }
                *caps = saved;
            }
            None
        }
        Node::Repeat { node, min, max } => {
            match_repeat_then(node, *min, *max, &[], text, pos, caps, budget)
        }
    }
}

fn match_seq(
    nodes: &[Node],
    text: &[u8],
    pos: usize,
    caps: &mut Captures,
    budget: &mut u64,
) -> Option<usize> {
    let Some((first, rest)) = nodes.split_first() else {
        return Some(pos);
    };
    if let Node::Repeat { node, min, max } = first {
        return match_repeat_then(node, *min, *max, rest, text, pos, caps, budget);
    }
    let saved = caps.clone();
    if let Some(mid) = match_node(first, text, pos, caps, budget) {
        if let Some(end) = match_seq(rest, text, mid, caps, budget) {
            return Some(end);
        }
    }
    *caps = saved;
    None
}

/// Greedy repetition with backtracking into the continuation `rest`.
#[allow(clippy::too_many_arguments)]
fn match_repeat_then(
    node: &Node,
    min: u32,
    max: Option<u32>,
    rest: &[Node],
    text: &[u8],
    pos: usize,
    caps: &mut Captures,
    budget: &mut u64,
) -> Option<usize> {
    // Collect greedy end positions: pos after 0,1,2,... repetitions.
    let mut ends = vec![pos];
    let mut cur = pos;
    let limit = max.unwrap_or(u32::MAX);
    while (ends.len() as u64) <= u64::from(limit) {
        match match_node(node, text, cur, caps, budget) {
            Some(next) if next > cur || ends.len() <= min as usize => {
                if next == cur {
                    break; // empty-width repetition: stop expanding
                }
                ends.push(next);
                cur = next;
            }
            _ => break,
        }
    }
    if (ends.len() as u64) <= u64::from(min) {
        return None; // could not reach the minimum
    }
    // Try longest first (greedy), backtracking down to min.
    for &end in ends.iter().skip(min as usize).rev() {
        let saved = caps.clone();
        if let Some(final_end) = match_seq(rest, text, end, caps, budget) {
            return Some(final_end);
        }
        *caps = saved;
        if *budget == 0 {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(pattern: &str, text: &str) -> Option<Vec<Option<String>>> {
        Regex::compile(pattern)
            .expect("compiles")
            .find_strings(text.as_bytes())
    }

    fn whole(pattern: &str, text: &str) -> Option<String> {
        cap(pattern, text).and_then(|c| c[0].clone())
    }

    #[test]
    fn literals_and_dot_and_anchors() {
        assert_eq!(whole("abc", "xxabcxx").as_deref(), Some("abc"));
        assert_eq!(whole("a.c", "abc").as_deref(), Some("abc"));
        assert_eq!(whole("^abc$", "abc").as_deref(), Some("abc"));
        assert!(whole("^abc", "xabc").is_none());
        assert!(whole("abc$", "abcx").is_none());
        assert!(whole("a.c", "a\nc").is_none(), "dot must not match newline");
    }

    #[test]
    fn repetitions_are_greedy_with_backtracking() {
        assert_eq!(whole("a*", "aaab").as_deref(), Some("aaa"));
        assert_eq!(whole("a+b", "caaab").as_deref(), Some("aaab"));
        assert_eq!(whole("ab?c", "ac").as_deref(), Some("ac"));
        assert_eq!(whole("a{2,3}", "aaaa").as_deref(), Some("aaa"));
        assert_eq!(whole("a{3}", "aaaa").as_deref(), Some("aaa"));
        assert!(whole("a{4}", "aaa").is_none());
        assert_eq!(whole(".*b", "aababc").as_deref(), Some("aabab"));
    }

    #[test]
    fn classes_ranges_and_negation() {
        assert_eq!(whole("[0-9]+", "abc4711def").as_deref(), Some("4711"));
        assert_eq!(whole("[^0-9]+", "471abc1").as_deref(), Some("abc"));
        assert_eq!(whole("[]a]+", "]a]").as_deref(), Some("]a]"));
        assert_eq!(whole("[a-c-]+", "a-b-c").as_deref(), Some("a-b-c"));
    }

    #[test]
    fn posix_classes() {
        assert_eq!(whole("[[:digit:]]+", "ab123").as_deref(), Some("123"));
        assert_eq!(whole("[[:alnum:]]+", "!!x9y!!").as_deref(), Some("x9y"));
        assert!(Regex::compile("[[:nope:]]").is_err());
    }

    #[test]
    fn captures_and_alternation() {
        let caps = cap("(INVITE|BYE) sip:([a-z]+)", "xx BYE sip:carol yy").expect("match");
        assert_eq!(caps[0].as_deref(), Some("BYE sip:carol"));
        assert_eq!(caps[1].as_deref(), Some("BYE"));
        assert_eq!(caps[2].as_deref(), Some("carol"));
    }

    #[test]
    fn unmatched_optional_group_is_none() {
        let caps = cap("a(b)?c", "ac").expect("match");
        assert_eq!(caps[0].as_deref(), Some("ac"));
        assert!(caps[1].is_none());
    }

    #[test]
    fn sipp_corpus_patterns_work() {
        // The exact patterns from SIPp's default regexp scenario.
        let ip = cap(
            "[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[:][0-9]{1,5}",
            "Contact: <sip:10.0.0.2:5060>",
        )
        .expect("match");
        assert_eq!(ip[0].as_deref(), Some("10.0.0.2:5060"));
        let o = cap(
            "o=([[:alnum:]]*) ([[:alnum:]]*) ([[:alnum:]]*)",
            "v=0\r\no=user1 53655765 2353687637 IN IP4 x\r\n",
        )
        .expect("match");
        assert_eq!(o[1].as_deref(), Some("user1"));
        assert_eq!(o[2].as_deref(), Some("53655765"));
        assert_eq!(o[3].as_deref(), Some("2353687637"));
        // Status code capture from our corpus.
        let code = cap("([0-9]{3})", "SIP/2.0 200 OK").expect("match");
        assert_eq!(code[1].as_deref(), Some("200"));
    }

    #[test]
    fn escapes_and_error_cases() {
        assert_eq!(whole(r"a\.b", "a.b").as_deref(), Some("a.b"));
        assert!(whole(r"a\.b", "axb").is_none());
        assert_eq!(whole(r"\[len\]", "x[len]y").as_deref(), Some("[len]"));
        assert!(Regex::compile("(a").is_err());
        assert!(Regex::compile("a)").is_err());
        assert!(Regex::compile("*a").is_err());
        assert!(Regex::compile("[a").is_err());
        assert!(Regex::compile("a{2,1}").is_err());
    }

    #[test]
    fn pathological_pattern_fails_within_budget_not_forever() {
        // (a+)+b against many a's and no b: classic exponential blowup.
        let re = Regex::compile("(a+)+b").expect("compiles");
        let text = vec![b'a'; 64];
        let start = std::time::Instant::now();
        assert!(re.find(&text).is_none());
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "budget must bound runtime"
        );
    }

    #[test]
    fn empty_repetition_terminates() {
        assert_eq!(whole("(x?)*y", "y").as_deref(), Some("y"));
    }
}
