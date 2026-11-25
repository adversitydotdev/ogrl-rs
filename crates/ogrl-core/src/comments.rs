//! YAML comment extraction and reattachment for `ogrl fmt`.
//!
//! Comments are non-normative (RFC 0001 §6.1) and are stripped from canonical
//! JSON. This module only supports preserving them through the CLI formatter
//! for hand-authored repository files.

use std::collections::HashMap;

use crate::yaml::{SpanMap, escape_pointer};

/// Where a comment sits relative to the node it is attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentPlacement {
    /// File-level comments before the first real node (after optional `---` / blanks).
    Header,
    /// Full-line comment immediately before the attached node.
    Leading,
    /// End-of-line comment on the line that introduces the attached node.
    Trailing,
    /// Comments with no following node, emitted at the end of the document.
    DocumentEnd,
}

/// A single `#` comment extracted from a YAML document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YamlComment {
    /// 1-based source line of the `#`.
    pub line: usize,
    /// 1-based source column of the `#`.
    pub col: usize,
    /// Comment text starting at `#`, trailing whitespace stripped.
    pub text: String,
    pub placement: CommentPlacement,
    /// JSON pointer of the attached node. Empty for header and document-end.
    pub pointer: String,
}

/// Split a leading comment header from the rest of a document.
///
/// Blank lines and document markers (`---` / `...`) at the top are skipped so a
/// comment after a leading `---` is still treated as a file header. Trailing
/// comments on a leading document marker are kept as header comments.
pub fn leading_comment_header(text: &str) -> Option<String> {
    let mut lines = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(comment) = document_marker_comment(trimmed) {
            if let Some(c) = comment {
                lines.push(c.to_string());
            }
            continue;
        }
        if trimmed.starts_with('#') {
            lines.push(line.trim_end().to_string());
            continue;
        }
        break;
    }
    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

/// Line number (1-based) of the first non-header content line, or one past the
/// last line when the file is only a header.
pub fn header_end_line(text: &str) -> usize {
    let mut line_no = 0;
    for line in text.lines() {
        line_no += 1;
        let trimmed = line.trim();
        if trimmed.is_empty()
            || document_marker_comment(trimmed).is_some()
            || trimmed.starts_with('#')
        {
            continue;
        }
        return line_no;
    }
    line_no + 1
}

fn document_marker_comment(trimmed: &str) -> Option<Option<&str>> {
    for marker in ["---", "..."] {
        if let Some(rest) = trimmed.strip_prefix(marker) {
            if rest.is_empty() || rest.starts_with(char::is_whitespace) {
                let rest = rest.trim_start();
                if rest.is_empty() {
                    return Some(None);
                }
                if rest.starts_with('#') {
                    return Some(Some(rest));
                }
            }
        }
    }
    None
}

/// Collect comments from `input` and attach them to JSON pointers in `spans`.
///
/// Header comments (before the first real node) are returned with
/// [`CommentPlacement::Header`]. Body comments attach to the next pointer, or
/// to the pointer on the same line for trailing comments. Comments after the
/// last node are [`CommentPlacement::DocumentEnd`].
pub fn collect_attached_comments(input: &str, spans: &SpanMap) -> Vec<YamlComment> {
    let raw = scan_comments(input);
    let header_limit = header_end_line(input);
    attach_comments(raw, spans, header_limit)
}

#[derive(Debug, Clone)]
pub(crate) struct RawComment {
    line: usize,
    col: usize,
    pub(crate) text: String,
    trailing: bool,
}

pub(crate) fn scan_comments(input: &str) -> Vec<RawComment> {
    let mut comments = Vec::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut block: Option<BlockState> = None;

    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);

        if let Some(block_state) = block.as_mut() {
            if continue_block(block_state, line) {
                continue;
            }
            block = None;
        }

        if in_single || in_double {
            let (s, d, _) = scan_flow_line(line, 0, in_single, in_double);
            in_single = s;
            in_double = d;
            continue;
        }

        if let Some(comment) = full_line_comment(line) {
            comments.push(RawComment {
                line: line_no,
                col: comment.col,
                text: comment.text,
                trailing: false,
            });
            continue;
        }

        let indent = leading_spaces(line);
        let (s, d, trailing) = scan_flow_line(line, 0, false, false);
        in_single = s;
        in_double = d;
        if let Some((col, text)) = trailing {
            comments.push(RawComment {
                line: line_no,
                col,
                text,
                trailing: true,
            });
        }
        if !s && !d && block_indicator(line) {
            block = Some(BlockState {
                parent_indent: indent,
                content_indent: explicit_block_indent(line).map(|n| indent + n),
            });
        }
    }
    comments
}

struct BlockState {
    parent_indent: usize,
    content_indent: Option<usize>,
}

struct FoundComment {
    col: usize,
    text: String,
}

fn continue_block(block: &mut BlockState, line: &str) -> bool {
    if line.trim().is_empty() {
        return true;
    }
    if document_marker_comment(line.trim()).is_some() && leading_spaces(line) == 0 {
        return false;
    }
    let indent = leading_spaces(line);
    match block.content_indent {
        Some(content) => indent >= content,
        None => {
            if indent > block.parent_indent {
                block.content_indent = Some(indent);
                true
            } else {
                false
            }
        }
    }
}

fn full_line_comment(line: &str) -> Option<FoundComment> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        let col = leading_spaces(line) + 1;
        Some(FoundComment {
            col,
            text: trimmed.trim_end().to_string(),
        })
    } else {
        None
    }
}

fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ').count()
}

/// True when this line introduces a `|` or `>` block scalar (comment after the
/// indicator is allowed).
fn block_indicator(line: &str) -> bool {
    let Some(idx) = block_indicator_index(line) else {
        return false;
    };
    let rest = line[idx + 1..].trim_start();
    // Optional indentation indicator and/or chomping, then end or a comment.
    let rest = rest.trim_start_matches(['+', '-']);
    let rest = match rest.chars().next() {
        Some(c) if c.is_ascii_digit() => rest[1..].trim_start_matches(['+', '-']).trim_start(),
        _ => rest,
    };
    rest.is_empty() || rest.starts_with('#')
}

fn block_indicator_index(line: &str) -> Option<usize> {
    // Look for a `|` or `>` that starts a value: preceded by `:` or `-` (list)
    // and whitespace, or at the start of a list item (`- |`).
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'|' || b == b'>' {
            if indicator_is_value(line, i) {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn indicator_is_value(line: &str, idx: usize) -> bool {
    let before = line[..idx].trim_end();
    before.is_empty()
        || before.ends_with(':')
        || before.ends_with('-')
        || before.ends_with("- ")
        || before == "-"
}

fn explicit_block_indent(line: &str) -> Option<usize> {
    let idx = block_indicator_index(line)?;
    let rest = line[idx + 1..].trim_start();
    let rest = rest.trim_start_matches(['+', '-']);
    rest.chars()
        .next()
        .and_then(|c| c.to_digit(10).map(|n| n as usize))
}

/// Scan a line starting at `start`, honoring inherited quote state. Returns
/// the ending quote state and an optional trailing comment `(col, text)`.
fn scan_flow_line(
    line: &str,
    start: usize,
    mut in_single: bool,
    mut in_double: bool,
) -> (bool, bool, Option<(usize, String)>) {
    let bytes = line.as_bytes();
    let mut i = start;
    while i < bytes.len() {
        let b = bytes[i];
        if in_double {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        if in_single {
            if b == b'\'' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                    i += 2;
                    continue;
                }
                in_single = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' => {
                in_single = true;
                i += 1;
            }
            b'"' => {
                in_double = true;
                i += 1;
            }
            b'#' => {
                // In YAML, `#` starts a comment when it is at the start of the
                // token (preceded by start/whitespace, or by a flow indicator
                // we already handled by being outside quotes).
                if i == 0 || bytes[i - 1].is_ascii_whitespace() {
                    let col = i + 1;
                    let text = line[i..].trim_end().to_string();
                    return (false, false, Some((col, text)));
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    (in_single, in_double, None)
}

fn next_pointer(nodes: &[(usize, usize, String)], line: usize, col: usize) -> Option<String> {
    let following: Vec<&(usize, usize, String)> = nodes
        .iter()
        .filter(|(n_line, n_col, _)| *n_line > line || (*n_line == line && *n_col >= col))
        .collect();
    let (min_line, _) = following
        .iter()
        .map(|(n_line, n_col, _)| (*n_line, *n_col))
        .min()?;
    // Prefer the most specific pointer on the first following line so a
    // comment between `parts:` and the first item attaches to the item,
    // not the collection (whose SequenceStart span may sit on that item).
    following
        .into_iter()
        .filter(|(n_line, _, _)| *n_line == min_line)
        .max_by_key(|(_, _, pointer)| pointer.len())
        .map(|(_, _, pointer)| pointer.clone())
}

fn attach_comments(raw: Vec<RawComment>, spans: &SpanMap, header_limit: usize) -> Vec<YamlComment> {
    let mut nodes: Vec<(usize, usize, String)> = spans
        .iter()
        .map(|(pointer, span)| (span.line, span.col, pointer.clone()))
        .collect();
    nodes.sort_by_key(|(line, col, pointer)| (*line, *col, pointer.clone()));

    let mut out = Vec::with_capacity(raw.len());
    for comment in raw {
        if comment.line < header_limit {
            out.push(YamlComment {
                line: comment.line,
                col: comment.col,
                text: comment.text,
                placement: CommentPlacement::Header,
                pointer: String::new(),
            });
            continue;
        }
        if comment.trailing {
            let pointer = nodes
                .iter()
                .filter(|(line, col, _)| *line == comment.line && *col < comment.col)
                .max_by_key(|(line, col, _)| (*line, *col))
                .map(|(_, _, p)| p.clone());
            if let Some(pointer) = pointer {
                out.push(YamlComment {
                    line: comment.line,
                    col: comment.col,
                    text: comment.text,
                    placement: CommentPlacement::Trailing,
                    pointer,
                });
                continue;
            }
        }
        let pointer = next_pointer(&nodes, comment.line, comment.col);
        match pointer {
            Some(pointer) => out.push(YamlComment {
                line: comment.line,
                col: comment.col,
                text: comment.text,
                placement: CommentPlacement::Leading,
                pointer,
            }),
            None => out.push(YamlComment {
                line: comment.line,
                col: comment.col,
                text: comment.text,
                placement: CommentPlacement::DocumentEnd,
                pointer: String::new(),
            }),
        }
    }
    out
}

/// Comments grouped for emission next to formatted nodes.
#[derive(Debug, Default)]
pub struct CommentBook {
    by_pointer: HashMap<String, PointerComments>,
    document_end: Vec<YamlComment>,
}

#[derive(Debug, Default)]
struct PointerComments {
    leading: Vec<YamlComment>,
    trailing: Vec<YamlComment>,
}

impl CommentBook {
    pub fn from_comments(comments: impl IntoIterator<Item = YamlComment>) -> Self {
        let mut book = Self::default();
        for comment in comments {
            match comment.placement {
                CommentPlacement::Header => {}
                CommentPlacement::Leading => book
                    .by_pointer
                    .entry(comment.pointer.clone())
                    .or_default()
                    .leading
                    .push(comment),
                CommentPlacement::Trailing => book
                    .by_pointer
                    .entry(comment.pointer.clone())
                    .or_default()
                    .trailing
                    .push(comment),
                CommentPlacement::DocumentEnd => book.document_end.push(comment),
            }
        }
        book
    }

    pub fn write_leading(&self, out: &mut String, pointer: &str, indent: usize) {
        let Some(entry) = self.by_pointer.get(pointer) else {
            return;
        };
        let pad = " ".repeat(indent);
        for comment in &entry.leading {
            let _ = std::fmt::Write::write_fmt(out, format_args!("{pad}{}\n", comment.text));
        }
    }

    pub fn trailing_suffix(&self, pointer: &str) -> Option<String> {
        let entry = self.by_pointer.get(pointer)?;
        if entry.trailing.is_empty() {
            return None;
        }
        let text = entry
            .trailing
            .iter()
            .map(|c| c.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        Some(format!("  {text}"))
    }

    pub fn write_document_end(&self, out: &mut String) {
        if self.document_end.is_empty() {
            return;
        }
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        for comment in &self.document_end {
            let _ = std::fmt::Write::write_fmt(out, format_args!("{}\n", comment.text));
        }
    }
}

pub(crate) fn join_pointer(parent: &str, segment: &str) -> String {
    format!("{parent}/{}", escape_pointer(segment))
}

pub(crate) fn index_pointer(parent: &str, index: usize) -> String {
    format!("{parent}/{index}")
}

/// Normalize a comment to its `#` body for drop-detection (indent ignored).
pub fn comment_body(text: &str) -> &str {
    text.trim()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yaml::{ParseOptions, parse_yaml_with_spans};
    use serde_json::Value;

    fn parse(input: &str) -> (Value, SpanMap) {
        parse_yaml_with_spans(input, ParseOptions { strict: true }).unwrap()
    }

    #[test]
    fn header_accepts_document_marker_and_blank_lines() {
        let src = "---\n\n# top comment\ntype: implementation\n";
        assert_eq!(
            leading_comment_header(src).as_deref(),
            Some("# top comment")
        );
        let src = "\n# top comment\ntype: implementation\n";
        assert_eq!(
            leading_comment_header(src).as_deref(),
            Some("# top comment")
        );
        let src = "--- # from marker\n# top\ntype: implementation\n";
        assert_eq!(
            leading_comment_header(src).as_deref(),
            Some("# from marker\n# top")
        );
    }

    #[test]
    fn scan_skips_hash_inside_quotes_and_block_scalars() {
        let src = "narrative: \"has # hash\"\nfolded: |\n  # still content\n# real\n";
        let found = scan_comments(src);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].text, "# real");
        assert!(!found[0].trailing);
    }

    #[test]
    fn scan_keeps_trailing_and_sequence_comments() {
        let src = "narrative: x  # trailing\nparts:\n  # item note\n  - id: a\n";
        let found = scan_comments(src);
        assert_eq!(found.len(), 2);
        assert!(found[0].trailing);
        assert_eq!(found[0].text, "# trailing");
        assert!(!found[1].trailing);
        assert_eq!(found[1].text, "# item note");
    }

    #[test]
    fn attach_follows_next_pointer_and_end_of_file() {
        let src = "type: implementation\n# moves with component_ref\ncomponent_ref: component--dev.x.y\nnarrative: x  # trailing\n# eof\n";
        let (_, spans) = parse(src);
        let comments = collect_attached_comments(src, &spans);
        let body: Vec<_> = comments
            .iter()
            .filter(|c| c.placement != CommentPlacement::Header)
            .collect();
        assert_eq!(body.len(), 3);
        assert_eq!(body[0].placement, CommentPlacement::Leading);
        assert_eq!(body[0].pointer, "/component_ref");
        assert_eq!(body[1].placement, CommentPlacement::Trailing);
        assert_eq!(body[1].pointer, "/narrative");
        assert_eq!(body[2].placement, CommentPlacement::DocumentEnd);
    }
}
