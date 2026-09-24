//! A deliberately small XML parser for SIPp scenario files.
//!
//! Hand-rolled on purpose (like SIPp's own `xp_parser.cpp`): the scenario
//! grammar needs only elements, attributes, text, CDATA, comments, the XML
//! declaration, and a DOCTYPE line — no namespaces, processing instructions,
//! or external entities. In exchange we get zero dependencies and exact
//! line numbers on every node and every parse error.
//!
//! Supported entity references: `&lt;` `&gt;` `&amp;` `&quot;` `&apos;`.

/// A parsed element: name, attributes in document order, children, line.
#[derive(Debug, Clone)]
pub struct Element {
    /// Tag name, e.g. `scenario`, `send`.
    pub name: String,
    /// Attributes as (name, value) pairs in document order.
    pub attrs: Vec<(String, String)>,
    /// Child nodes in document order.
    pub children: Vec<Node>,
    /// 1-based line of the opening `<`.
    pub line: u32,
}

/// A child node.
#[derive(Debug, Clone)]
pub enum Node {
    /// A nested element.
    Element(Element),
    /// Character data (entity-decoded). Includes whitespace runs.
    Text(String),
    /// A `<![CDATA[...]]>` section, verbatim.
    CData { text: String, line: u32 },
    /// A `<!-- ... -->` comment, its text verbatim. Kept for the
    /// `sipr-lint:` directives; everything else ignores comments.
    Comment { text: String, line: u32 },
}

impl Element {
    /// Attribute value by name, if present.
    #[must_use]
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Child elements only.
    pub fn child_elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            _ => None,
        })
    }
}

/// A parse error with a 1-based line number.
#[derive(Debug, Clone)]
pub struct XmlError {
    /// 1-based line where the problem was found.
    pub line: u32,
    /// What went wrong.
    pub message: String,
}

/// Parse a document and return its root element.
///
/// # Errors
///
/// Returns [`XmlError`] on malformed input: unterminated constructs,
/// mismatched tags, bad attribute syntax, or trailing content.
pub fn parse(input: &str) -> Result<Element, XmlError> {
    let mut p = Parser {
        chars: input.chars().collect(),
        pos: 0,
        line: 1,
    };
    p.skip_prolog();
    let root = p.parse_element()?;
    p.skip_misc();
    if !p.at_end() {
        return Err(p.err("unexpected content after the root element"));
    }
    Ok(root)
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    line: u32,
}

impl Parser {
    fn at_end(&self) -> bool {
        self.pos >= self.chars.len()
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        if c == '\n' {
            self.line += 1;
        }
        Some(c)
    }

    fn starts_with(&self, s: &str) -> bool {
        self.chars[self.pos..]
            .iter()
            .zip(s.chars())
            .filter(|(a, b)| **a == *b)
            .count()
            == s.chars().count()
            && self.chars.len() - self.pos >= s.chars().count()
    }

    fn eat(&mut self, s: &str) -> bool {
        if self.starts_with(s) {
            for _ in s.chars() {
                self.bump();
            }
            true
        } else {
            false
        }
    }

    fn err(&self, message: impl Into<String>) -> XmlError {
        XmlError {
            line: self.line,
            message: message.into(),
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(c) if c.is_whitespace()) {
            self.bump();
        }
    }

    /// Skip the XML declaration, DOCTYPE, comments, and whitespace.
    fn skip_prolog(&mut self) {
        loop {
            self.skip_ws();
            if self.starts_with("<?") {
                while !self.at_end() && !self.eat("?>") {
                    self.bump();
                }
            } else if self.starts_with("<!--") {
                self.skip_comment();
            } else if self.starts_with("<!DOCTYPE") {
                // The scenario DOCTYPE has no internal subset; skip to '>'.
                while let Some(c) = self.bump() {
                    if c == '>' {
                        break;
                    }
                }
            } else {
                return;
            }
        }
    }

    /// Skip trailing comments/whitespace after the root element.
    fn skip_misc(&mut self) {
        loop {
            self.skip_ws();
            if self.starts_with("<!--") {
                self.skip_comment();
            } else {
                return;
            }
        }
    }

    fn skip_comment(&mut self) {
        self.parse_comment();
    }

    /// Consume a comment and return its text.
    fn parse_comment(&mut self) -> String {
        // Caller guarantees "<!--".
        self.eat("<!--");
        let mut text = String::new();
        while !self.at_end() && !self.eat("-->") {
            if let Some(c) = self.bump() {
                text.push(c);
            }
        }
        text
    }

    fn parse_name(&mut self) -> Result<String, XmlError> {
        let mut name = String::new();
        while let Some(c) = self.peek() {
            if c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | ':') {
                name.push(c);
                self.bump();
            } else {
                break;
            }
        }
        if name.is_empty() {
            return Err(self.err("expected a name"));
        }
        Ok(name)
    }

    fn parse_element(&mut self) -> Result<Element, XmlError> {
        let line = self.line;
        if !self.eat("<") {
            return Err(self.err("expected '<'"));
        }
        let name = self.parse_name()?;
        let mut attrs = Vec::new();
        loop {
            self.skip_ws();
            if self.eat("/>") {
                return Ok(Element {
                    name,
                    attrs,
                    children: Vec::new(),
                    line,
                });
            }
            if self.eat(">") {
                break;
            }
            let attr_name = self
                .parse_name()
                .map_err(|_| self.err(format!("bad attribute in <{name}>")))?;
            self.skip_ws();
            if !self.eat("=") {
                return Err(self.err(format!("attribute '{attr_name}' in <{name}> needs '='")));
            }
            self.skip_ws();
            let quote = match self.bump() {
                Some(q @ ('"' | '\'')) => q,
                _ => {
                    return Err(self.err(format!(
                        "attribute '{attr_name}' in <{name}> needs a quoted value"
                    )));
                }
            };
            let mut value = String::new();
            loop {
                match self.bump() {
                    Some(c) if c == quote => break,
                    Some(c) => value.push(c),
                    None => {
                        return Err(self.err(format!(
                            "unterminated value for attribute '{attr_name}' in <{name}>"
                        )));
                    }
                }
            }
            if attrs.iter().any(|(n, _)| *n == attr_name) {
                return Err(self.err(format!("duplicate attribute '{attr_name}' in <{name}>")));
            }
            attrs.push((attr_name, decode_entities(&value)));
        }
        let children = self.parse_children(&name)?;
        Ok(Element {
            name,
            attrs,
            children,
            line,
        })
    }

    fn parse_children(&mut self, parent: &str) -> Result<Vec<Node>, XmlError> {
        let mut children = Vec::new();
        let mut text = String::new();
        let text_flushed = |children: &mut Vec<Node>, text: &mut String| {
            if !text.is_empty() {
                children.push(Node::Text(decode_entities(text)));
                text.clear();
            }
        };
        loop {
            if self.starts_with("<![CDATA[") {
                text_flushed(&mut children, &mut text);
                let line = self.line;
                self.eat("<![CDATA[");
                let mut cdata = String::new();
                loop {
                    if self.eat("]]>") {
                        break;
                    }
                    match self.bump() {
                        Some(c) => cdata.push(c),
                        None => return Err(self.err(format!("unterminated CDATA in <{parent}>"))),
                    }
                }
                children.push(Node::CData { text: cdata, line });
            } else if self.starts_with("<!--") {
                text_flushed(&mut children, &mut text);
                let line = self.line;
                let comment = self.parse_comment();
                children.push(Node::Comment {
                    text: comment,
                    line,
                });
            } else if self.starts_with("</") {
                text_flushed(&mut children, &mut text);
                self.eat("</");
                let close = self.parse_name()?;
                if close != parent {
                    return Err(self.err(format!(
                        "mismatched closing tag: expected </{parent}>, found </{close}>"
                    )));
                }
                self.skip_ws();
                if !self.eat(">") {
                    return Err(self.err(format!("malformed closing tag </{close}>")));
                }
                return Ok(children);
            } else if self.starts_with("<") {
                text_flushed(&mut children, &mut text);
                children.push(Node::Element(self.parse_element()?));
            } else {
                match self.bump() {
                    Some(c) => text.push(c),
                    None => return Err(self.err(format!("unclosed element <{parent}>"))),
                }
            }
        }
    }
}

fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(idx) = rest.find('&') {
        out.push_str(&rest[..idx]);
        rest = &rest[idx..];
        let mut matched = false;
        for (entity, ch) in [
            ("&lt;", '<'),
            ("&gt;", '>'),
            ("&amp;", '&'),
            ("&quot;", '"'),
            ("&apos;", '\''),
        ] {
            if let Some(tail) = rest.strip_prefix(entity) {
                out.push(ch);
                rest = tail;
                matched = true;
                break;
            }
        }
        if !matched {
            // Unknown entity: keep the ampersand verbatim (be liberal).
            out.push('&');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_scenario_shape() {
        let doc = r#"<?xml version="1.0" encoding="ISO-8859-1" ?>
<!DOCTYPE scenario SYSTEM "sipp.dtd">
<!-- a comment -->
<scenario name="t">
  <send retrans="500"><![CDATA[INVITE sip:x SIP/2.0]]></send>
  <recv response="200" optional="false"/>
</scenario>
"#;
        let root = parse(doc).unwrap();
        assert_eq!(root.name, "scenario");
        assert_eq!(root.attr("name"), Some("t"));
        assert_eq!(root.line, 4);
        let kids: Vec<_> = root.child_elements().collect();
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[0].name, "send");
        assert_eq!(kids[0].line, 5);
        assert!(matches!(&kids[0].children[0],
            Node::CData { text, .. } if text == "INVITE sip:x SIP/2.0"));
        assert_eq!(kids[1].attr("response"), Some("200"));
    }

    #[test]
    fn cdata_preserves_everything_verbatim() {
        let doc = "<a><![CDATA[  <not-a-tag> && [keyword]\n line2 ]]></a>";
        let root = parse(doc).unwrap();
        assert!(matches!(&root.children[0],
            Node::CData { text, .. } if text.contains("<not-a-tag> && [keyword]")));
    }

    #[test]
    fn entities_decode_in_text_and_attrs() {
        let root = parse(r#"<a x="1 &lt; 2 &amp; 3">a &gt; b</a>"#).unwrap();
        assert_eq!(root.attr("x"), Some("1 < 2 & 3"));
        assert!(matches!(&root.children[0], Node::Text(t) if t == "a > b"));
    }

    #[test]
    fn mismatched_tag_reports_line() {
        let err = parse("<a>\n<b>\n</a>").unwrap_err();
        assert_eq!(err.line, 3);
        assert!(err.message.contains("expected </b>"), "{}", err.message);
    }

    #[test]
    fn unterminated_cdata_is_an_error() {
        let err = parse("<a><![CDATA[oops</a>").unwrap_err();
        assert!(
            err.message.contains("unterminated CDATA"),
            "{}",
            err.message
        );
    }

    #[test]
    fn duplicate_attribute_rejected() {
        let err = parse(r#"<a x="1" x="2"/>"#).unwrap_err();
        assert!(
            err.message.contains("duplicate attribute"),
            "{}",
            err.message
        );
    }

    #[test]
    fn trailing_garbage_rejected() {
        let err = parse("<a/><b/>").unwrap_err();
        assert!(err.message.contains("after the root"), "{}", err.message);
    }

    #[test]
    fn comments_inside_elements_are_kept_as_nodes() {
        let root = parse("<a><!-- hi --><b/>\n<!-- bye --></a>").unwrap();
        assert_eq!(root.child_elements().count(), 1);
        let comments: Vec<(&str, u32)> = root
            .children
            .iter()
            .filter_map(|n| match n {
                Node::Comment { text, line } => Some((text.as_str(), *line)),
                _ => None,
            })
            .collect();
        assert_eq!(comments, [(" hi ", 1), (" bye ", 2)]);
    }
}
