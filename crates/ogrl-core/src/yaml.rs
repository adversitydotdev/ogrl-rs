//! Strict YAML 1.2 parser (with line/column spans) and canonical YAML formatter
//! implementing RFC 0001 §6.1.
//!
//! Enforced YAML 1.2 authoring rules:
//! - Rejects YAML anchors (`&anchor`), aliases (`*alias`), and merge keys (`<<`).
//! - Rejects explicit `null` / `~` values.
//! - Rejects duplicate mapping keys.
//! - Uses YAML 1.2 Core Schema (so `yes`/`no`/`on`/`off` and dates remain strings).

use std::collections::HashMap;
use std::fmt::Write as _;

use serde_json::{Map, Number, Value};

use crate::comments::{CommentBook, index_pointer, join_pointer};
use thiserror::Error;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::{Marker, TScalarStyle};

/// Source position (1-based line and column) within a YAML/JSON document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub line: usize,
    pub col: usize,
}

/// Maps RFC 6901 JSON pointers (e.g. `/parts/0/id`) to source spans.
pub type SpanMap = HashMap<String, Span>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub struct YamlError {
    pub message: String,
    pub pointer: String,
    pub span: Option<Span>,
}

impl std::fmt::Display for YamlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(span) = self.span {
            write!(f, "line {}, col {}: {}", span.line, span.col, self.message)
        } else {
            write!(f, "{}", self.message)
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ParseOptions {
    /// Enforce RFC 0001 §6.1 strict rules (no anchors, aliases, merge keys, nulls, duplicate keys).
    pub strict: bool,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self { strict: true }
    }
}

/// Parse a single YAML 1.2 (or JSON) document into `serde_json::Value` plus JSON-pointer spans.
pub fn parse_yaml_with_spans(
    input: &str,
    options: ParseOptions,
) -> Result<(Value, SpanMap), Vec<YamlError>> {
    let mut parser = Parser::new_from_str(input);
    let mut builder = EventBuilder::new(options);
    if let Err(err) = parser.load(&mut builder, false) {
        let m = err.marker();
        builder.errors.push(YamlError {
            message: err.info().to_string(),
            pointer: builder.current_pointer(),
            span: Some(Span {
                line: m.line(),
                col: m.col() + 1,
            }),
        });
    }
    if !builder.errors.is_empty() {
        return Err(builder.errors);
    }
    match builder.root {
        Some(v) => Ok((v, builder.spans)),
        None => Err(vec![YamlError {
            message: "empty YAML document".to_string(),
            pointer: String::new(),
            span: Some(Span { line: 1, col: 1 }),
        }]),
    }
}

/// Convenience wrapper for strict YAML 1.2 parsing.
pub fn parse_yaml(input: &str) -> Result<(Value, SpanMap), Vec<YamlError>> {
    parse_yaml_with_spans(input, ParseOptions::default())
}

enum Container {
    Seq {
        items: Vec<Value>,
        pointer: String,
    },
    Map {
        entries: Map<String, Value>,
        pending_key: Option<(String, Span)>,
        pointer: String,
    },
}

struct EventBuilder {
    options: ParseOptions,
    stack: Vec<Container>,
    root: Option<Value>,
    spans: SpanMap,
    errors: Vec<YamlError>,
    doc_count: usize,
}

impl EventBuilder {
    fn new(options: ParseOptions) -> Self {
        Self {
            options,
            stack: Vec::new(),
            root: None,
            spans: HashMap::new(),
            errors: Vec::new(),
            doc_count: 0,
        }
    }

    fn current_pointer(&self) -> String {
        match self.stack.last() {
            None => String::new(),
            Some(Container::Seq { items, pointer }) => format!("{pointer}/{}", items.len()),
            Some(Container::Map {
                pending_key: Some((k, _)),
                pointer,
                ..
            }) => format!("{pointer}/{}", escape_pointer(k)),
            Some(Container::Map { pointer, .. }) => pointer.clone(),
        }
    }

    fn push_value(&mut self, value: Value, span: Span) {
        let ptr = self.current_pointer();
        self.spans.entry(ptr).or_insert(span);
        let mut key_span: Option<(String, Span)> = None;
        match self.stack.last_mut() {
            None => {
                self.root = Some(value);
            }
            Some(Container::Seq { items, .. }) => {
                items.push(value);
            }
            Some(Container::Map {
                entries,
                pending_key,
                pointer,
            }) => {
                if let Some((key, key_span)) = pending_key.take() {
                    if entries.contains_key(&key) {
                        self.errors.push(YamlError {
                            message: format!("duplicate mapping key {key:?}"),
                            pointer: format!("{pointer}/{}", escape_pointer(&key)),
                            span: Some(key_span),
                        });
                    }
                    entries.insert(key, value);
                } else {
                    // This value IS the mapping key.
                    let key_str = match value {
                        Value::String(s) => s,
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        other => {
                            self.errors.push(YamlError {
                                message: format!("mapping key must be a scalar, got {other}"),
                                pointer: pointer.clone(),
                                span: Some(span),
                            });
                            String::new()
                        }
                    };
                    let key_ptr = format!("{pointer}/{}", escape_pointer(&key_str));
                    *pending_key = Some((key_str, span));
                    key_span = Some((key_ptr, span));
                }
            }
        }
        if let Some((key_ptr, key_at)) = key_span {
            self.spans.entry(key_ptr).or_insert(key_at);
        }
    }

    fn is_expecting_map_key(&self) -> bool {
        matches!(
            self.stack.last(),
            Some(Container::Map {
                pending_key: None,
                ..
            })
        )
    }
}

impl MarkedEventReceiver for EventBuilder {
    fn on_event(&mut self, ev: Event, mark: Marker) {
        let span = Span {
            line: mark.line(),
            col: mark.col() + 1,
        };
        match ev {
            Event::DocumentStart => {
                self.doc_count += 1;
                if self.doc_count > 1 {
                    self.errors.push(YamlError {
                        message: "multiple YAML documents in one file are not permitted (RFC 0001 §6.1: one object per file)".to_string(),
                        pointer: String::new(),
                        span: Some(span),
                    });
                }
            }
            Event::StreamStart | Event::StreamEnd | Event::DocumentEnd | Event::Nothing => {}
            Event::Alias(_) => {
                self.errors.push(YamlError {
                    message: "YAML aliases (*alias) are forbidden by RFC 0001 §6.1".to_string(),
                    pointer: self.current_pointer(),
                    span: Some(span),
                });
                self.push_value(Value::Null, span);
            }
            Event::SequenceStart(anchor_id, _) => {
                if self.options.strict && anchor_id != 0 {
                    self.errors.push(YamlError {
                        message: "YAML anchors (&anchor) are forbidden by RFC 0001 §6.1"
                            .to_string(),
                        pointer: self.current_pointer(),
                        span: Some(span),
                    });
                }
                let ptr = self.current_pointer();
                self.spans.entry(ptr.clone()).or_insert(span);
                self.stack.push(Container::Seq {
                    items: Vec::new(),
                    pointer: ptr,
                });
            }
            Event::SequenceEnd => {
                if let Some(Container::Seq { items, .. }) = self.stack.pop() {
                    self.push_value(Value::Array(items), span);
                }
            }
            Event::MappingStart(anchor_id, _) => {
                if self.options.strict && anchor_id != 0 {
                    self.errors.push(YamlError {
                        message: "YAML anchors (&anchor) are forbidden by RFC 0001 §6.1"
                            .to_string(),
                        pointer: self.current_pointer(),
                        span: Some(span),
                    });
                }
                let ptr = self.current_pointer();
                self.spans.entry(ptr.clone()).or_insert(span);
                self.stack.push(Container::Map {
                    entries: Map::new(),
                    pending_key: None,
                    pointer: ptr,
                });
            }
            Event::MappingEnd => {
                if let Some(Container::Map { entries, .. }) = self.stack.pop() {
                    self.push_value(Value::Object(entries), span);
                }
            }
            Event::Scalar(raw, style, anchor_id, _tag) => {
                if self.options.strict && anchor_id != 0 {
                    self.errors.push(YamlError {
                        message: "YAML anchors (&anchor) are forbidden by RFC 0001 §6.1"
                            .to_string(),
                        pointer: self.current_pointer(),
                        span: Some(span),
                    });
                }
                if self.is_expecting_map_key() {
                    if self.options.strict && style == TScalarStyle::Plain && raw == "<<" {
                        self.errors.push(YamlError {
                            message: "YAML merge keys (<<) are forbidden by RFC 0001 §6.1"
                                .to_string(),
                            pointer: self.current_pointer(),
                            span: Some(span),
                        });
                    }
                    self.push_value(Value::String(raw), span);
                    return;
                }

                let val = parse_yaml_1_2_scalar(&raw, style);
                if self.options.strict && val.is_null() {
                    self.errors.push(YamlError {
                        message: "explicit null values are invalid in OGRL (RFC 0001 §6.1); omit empty fields instead".to_string(),
                        pointer: self.current_pointer(),
                        span: Some(span),
                    });
                }
                self.push_value(val, span);
            }
        }
    }
}

/// YAML 1.2 Core Schema scalar resolution.
fn parse_yaml_1_2_scalar(raw: &str, style: TScalarStyle) -> Value {
    if style != TScalarStyle::Plain {
        return Value::String(raw.to_string());
    }
    match raw {
        "" | "null" | "Null" | "NULL" | "~" => Value::Null,
        "true" | "True" | "TRUE" => Value::Bool(true),
        "false" | "False" | "FALSE" => Value::Bool(false),
        _ => {
            if is_plain_int(raw) {
                if let Ok(i) = raw.parse::<i64>() {
                    return Value::Number(Number::from(i));
                }
            }
            if is_plain_float(raw) {
                if let Ok(f) = raw.parse::<f64>() {
                    if let Some(n) = Number::from_f64(f) {
                        return Value::Number(n);
                    }
                }
            }
            Value::String(raw.to_string())
        }
    }
}

fn is_plain_int(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let start = usize::from(bytes[0] == b'+' || bytes[0] == b'-');
    if start == bytes.len() {
        return false;
    }
    bytes[start..].iter().all(u8::is_ascii_digit)
}

fn is_plain_float(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut i = usize::from(bytes[0] == b'+' || bytes[0] == b'-');
    if i == bytes.len() {
        return false;
    }
    let mut has_dot = false;
    let mut has_exp = false;
    let mut digits = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'0'..=b'9' => digits += 1,
            b'.' if !has_dot && !has_exp => has_dot = true,
            b'e' | b'E' if !has_exp && digits > 0 => {
                has_exp = true;
                digits = 0;
                if i + 1 < bytes.len() && (bytes[i + 1] == b'+' || bytes[i + 1] == b'-') {
                    i += 1;
                }
            }
            _ => return false,
        }
        i += 1;
    }
    (has_dot || has_exp) && digits > 0
}

pub(crate) fn escape_pointer(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

// ---------------------------------------------------------------------------
// Canonical YAML formatter (RFC 0001 §6.1, matching Python/Go key order & wrap)
// ---------------------------------------------------------------------------

/// Envelope keys always emitted first in this order.
pub const ENVELOPE_ORDER: &[&str] = &[
    "type",
    "id",
    "spec_version",
    "created",
    "modified",
    "name",
    "display_id",
    "revoked",
    "created_by_ref",
];

/// Format an OGRL object or bundle manifest as deterministic canonical YAML 1.2.
///
/// `header_comment`, when set, is written as a single `# {header_comment}` line.
/// This is the Python-binding contract and does not interpret already-hashed
/// header lines. CLI formatting uses [`format_yaml_with_comments`] instead.
pub fn format_yaml(value: &Value, header_comment: Option<&str>) -> String {
    format_yaml_inner(value, header_comment, true, None)
}

/// Format `value` in canonical key order, re-emitting `header` (already including
/// `#` lines) and comments from `comments` next to the pointers they attach to.
pub fn format_yaml_with_comments(
    value: &Value,
    header: Option<&str>,
    comments: &CommentBook,
) -> String {
    format_yaml_inner(value, header, false, Some(comments))
}

fn format_yaml_inner(
    value: &Value,
    header: Option<&str>,
    hash_prefix: bool,
    comments: Option<&CommentBook>,
) -> String {
    let mut out = String::new();
    if let Some(comment) = header {
        if hash_prefix {
            let _ = writeln!(out, "# {comment}");
        } else {
            out.push_str(comment);
            if !comment.ends_with('\n') {
                out.push('\n');
            }
        }
    }
    match value {
        Value::Object(map) => write_map(&mut out, map, 0, true, "", comments),
        other => {
            write_value(&mut out, other, 0, "", comments);
            if !out.ends_with('\n') {
                out.push('\n');
            }
        }
    }
    if let Some(book) = comments {
        book.write_document_end(&mut out);
    }
    out
}

fn trailing_suffix(comments: Option<&CommentBook>, pointer: &str) -> String {
    comments
        .and_then(|c| c.trailing_suffix(pointer))
        .unwrap_or_default()
}

/// Result of formatting a YAML document, including any comments that did not survive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatResult {
    pub formatted: String,
    /// Comments from the source that are not present in `formatted`.
    pub dropped: Vec<crate::comments::YamlComment>,
}

/// Parse `source`, format it canonically, and optionally preserve comments.
///
/// When `drop_comments` is true, only the leading header is kept. Otherwise
/// comments are reattached to the keys they belong to (and move with those
/// keys when the formatter reorders). Any comment the emitter could not
/// preserve is listed in [`FormatResult::dropped`].
pub fn format_source(source: &str, drop_comments: bool) -> Result<FormatResult, Vec<YamlError>> {
    use crate::comments::{
        CommentBook, CommentPlacement, collect_attached_comments, comment_body,
        leading_comment_header, scan_comments,
    };
    use std::collections::HashMap;

    let header = leading_comment_header(source);
    let (val, spans) = parse_yaml_with_spans(source, ParseOptions { strict: true })?;
    let attached = collect_attached_comments(source, &spans);
    let formatted = if drop_comments {
        format_yaml_with_comments(&val, header.as_deref(), &CommentBook::default())
    } else {
        let book = CommentBook::from_comments(attached.iter().cloned());
        format_yaml_with_comments(&val, header.as_deref(), &book)
    };

    let scanned = scan_comments(&formatted);
    let mut remaining: HashMap<&str, usize> = HashMap::new();
    for raw in &scanned {
        *remaining.entry(comment_body(&raw.text)).or_insert(0) += 1;
    }
    let mut dropped = Vec::new();
    for comment in attached {
        if drop_comments && comment.placement == CommentPlacement::Header {
            // Header is still written; count it against the formatted comments.
        }
        let body = comment_body(&comment.text);
        match remaining.get_mut(body) {
            Some(count) if *count > 0 => *count -= 1,
            _ => {
                if !(drop_comments && comment.placement == CommentPlacement::Header) {
                    dropped.push(comment);
                }
            }
        }
    }
    Ok(FormatResult { formatted, dropped })
}

fn ordered_keys(map: &Map<String, Value>, is_top_level: bool) -> Vec<&String> {
    let mut keys: Vec<&String> = Vec::with_capacity(map.len());
    if is_top_level {
        for &env_key in ENVELOPE_ORDER {
            if let Some((k, _)) = map.get_key_value(env_key) {
                keys.push(k);
            }
        }
    }
    let mut rest: Vec<&String> = map
        .keys()
        .filter(|k| !is_top_level || !ENVELOPE_ORDER.contains(&k.as_str()))
        .collect();
    rest.sort();
    keys.extend(rest);
    keys
}

fn write_map(
    out: &mut String,
    map: &Map<String, Value>,
    indent: usize,
    is_top_level: bool,
    pointer: &str,
    comments: Option<&CommentBook>,
) {
    let pad = " ".repeat(indent);
    for key in ordered_keys(map, is_top_level) {
        let val = &map[key];
        if val.is_null() {
            continue;
        }
        let child = join_pointer(pointer, key);
        if let Some(book) = comments {
            book.write_leading(out, &child, indent);
        }
        write_kv(out, &pad, indent, key, val, &child, comments);
    }
}

fn write_kv(
    out: &mut String,
    pad: &str,
    indent: usize,
    key: &str,
    val: &Value,
    pointer: &str,
    comments: Option<&CommentBook>,
) {
    let key_fmt = format_key(key);
    let trail = trailing_suffix(comments, pointer);
    match val {
        Value::String(s) => {
            if should_use_block(s, indent + key_fmt.len() + 2) {
                write_prose(out, indent, &key_fmt, s, &trail);
            } else {
                let _ = writeln!(out, "{pad}{key_fmt}: {}{trail}", yaml_scalar(s));
            }
        }
        Value::Bool(b) => {
            let _ = writeln!(out, "{pad}{key_fmt}: {b}{trail}");
        }
        Value::Number(n) => {
            let _ = writeln!(out, "{pad}{key_fmt}: {n}{trail}");
        }
        Value::Array(items) if items.is_empty() => {
            let _ = writeln!(out, "{pad}{key_fmt}: []{trail}");
        }
        Value::Array(items) => {
            let _ = writeln!(out, "{pad}{key_fmt}:{trail}");
            write_seq(out, items, indent + 2, pointer, comments);
        }
        Value::Object(map) if map.is_empty() => {
            let _ = writeln!(out, "{pad}{key_fmt}: {{}}{trail}");
        }
        Value::Object(map) => {
            let _ = writeln!(out, "{pad}{key_fmt}:{trail}");
            write_map(out, map, indent + 2, false, pointer, comments);
        }
        Value::Null => {}
    }
}

fn write_seq(
    out: &mut String,
    items: &[Value],
    indent: usize,
    pointer: &str,
    comments: Option<&CommentBook>,
) {
    let pad = " ".repeat(indent);
    for (idx, item) in items.iter().enumerate() {
        let item_ptr = index_pointer(pointer, idx);
        if let Some(book) = comments {
            book.write_leading(out, &item_ptr, indent);
        }
        let item_trail = trailing_suffix(comments, &item_ptr);
        match item {
            Value::Object(map) if !map.is_empty() => {
                // Keep `id` or `source` or `method` or `name` first on list-item objects for readability.
                let mut keys: Vec<&String> = Vec::with_capacity(map.len());
                for priority in [
                    "id",
                    "type",
                    "name",
                    "source",
                    "method",
                    "path",
                    "party_ref",
                ] {
                    if let Some((k, _)) = map.get_key_value(priority) {
                        keys.push(k);
                    }
                }
                let mut rest: Vec<&String> = map.keys().filter(|k| !keys.contains(k)).collect();
                rest.sort();
                keys.extend(rest);

                let mut first = true;
                for key in keys {
                    let val = &map[key];
                    if val.is_null() {
                        continue;
                    }
                    let child = join_pointer(&item_ptr, key);
                    if first {
                        first = false;
                        if let Some(book) = comments {
                            book.write_leading(out, &child, indent);
                        }
                        let trail = {
                            let t = trailing_suffix(comments, &child);
                            if t.is_empty() { item_trail.clone() } else { t }
                        };
                        let key_fmt = format_key(key);
                        match val {
                            Value::String(s)
                                if should_use_block(s, indent + 2 + key_fmt.len() + 2) =>
                            {
                                let _ = write!(out, "{pad}- ");
                                write_prose_inline_first(out, indent + 2, &key_fmt, s, &trail);
                            }
                            Value::String(s) => {
                                let _ =
                                    writeln!(out, "{pad}- {key_fmt}: {}{trail}", yaml_scalar(s));
                            }
                            Value::Bool(b) => {
                                let _ = writeln!(out, "{pad}- {key_fmt}: {b}{trail}");
                            }
                            Value::Number(n) => {
                                let _ = writeln!(out, "{pad}- {key_fmt}: {n}{trail}");
                            }
                            Value::Array(arr) if arr.is_empty() => {
                                let _ = writeln!(out, "{pad}- {key_fmt}: []{trail}");
                            }
                            Value::Array(arr) => {
                                let _ = writeln!(out, "{pad}- {key_fmt}:{trail}");
                                write_seq(out, arr, indent + 4, &child, comments);
                            }
                            Value::Object(sub) if sub.is_empty() => {
                                let _ = writeln!(out, "{pad}- {key_fmt}: {{}}{trail}");
                            }
                            Value::Object(sub) => {
                                let _ = writeln!(out, "{pad}- {key_fmt}:{trail}");
                                write_map(out, sub, indent + 4, false, &child, comments);
                            }
                            Value::Null => {}
                        }
                    } else {
                        if let Some(book) = comments {
                            book.write_leading(out, &child, indent + 2);
                        }
                        let sub_pad = " ".repeat(indent + 2);
                        write_kv(out, &sub_pad, indent + 2, key, val, &child, comments);
                    }
                }
            }
            Value::String(s) if should_use_block(s, indent + 2) => {
                let _ = writeln!(out, "{pad}- |{}{item_trail}", chomp(s));
                for line in s.trim_end_matches('\n').split('\n') {
                    if line.is_empty() {
                        out.push('\n');
                    } else {
                        let _ = writeln!(out, "{pad}  {line}");
                    }
                }
            }
            Value::String(s) => {
                let _ = writeln!(out, "{pad}- {}{item_trail}", yaml_scalar(s));
            }
            Value::Bool(b) => {
                let _ = writeln!(out, "{pad}- {b}{item_trail}");
            }
            Value::Number(n) => {
                let _ = writeln!(out, "{pad}- {n}{item_trail}");
            }
            Value::Array(sub) => {
                let _ = writeln!(out, "{pad}-{item_trail}");
                write_seq(out, sub, indent + 2, &item_ptr, comments);
            }
            Value::Object(_) => {
                let _ = writeln!(out, "{pad}- {{}}{item_trail}");
            }
            Value::Null => {}
        }
    }
}

fn write_value(
    out: &mut String,
    val: &Value,
    indent: usize,
    pointer: &str,
    comments: Option<&CommentBook>,
) {
    match val {
        Value::String(s) => out.push_str(&yaml_scalar(s)),
        Value::Bool(b) => {
            let _ = write!(out, "{b}");
        }
        Value::Number(n) => {
            let _ = write!(out, "{n}");
        }
        Value::Array(items) => write_seq(out, items, indent, pointer, comments),
        Value::Object(map) => write_map(out, map, indent, false, pointer, comments),
        Value::Null => out.push_str("null"),
    }
}

/// Maximum rendered line width (indent included) for formatted YAML.
pub const MAX_LINE_WIDTH: usize = 68;
/// Floor for wrapped prose width so deeply nested blocks stay readable.
const MIN_PROSE_WIDTH: usize = 40;

/// Prose width available to a block scalar whose content sits at `indent + 2`.
fn prose_width(indent: usize) -> usize {
    MAX_LINE_WIDTH
        .saturating_sub(indent + 2)
        .max(MIN_PROSE_WIDTH)
}

/// Whether a string should render as a block scalar. `prefix_len` is the
/// width of everything preceding the value on an inline line (indent, `- `,
/// key, and `: `).
fn should_use_block(s: &str, prefix_len: usize) -> bool {
    let trimmed = s.trim_end_matches('\n');
    if trimmed.contains('\n') {
        return true;
    }
    trimmed.contains(' ') && prefix_len + yaml_scalar(s).len() > MAX_LINE_WIDTH
}

/// Block chomping indicator that round-trips the value's trailing newline:
/// clip (default) when it ends with one, strip (`-`) when it does not.
fn chomp(s: &str) -> &'static str {
    if s.ends_with('\n') { "" } else { "-" }
}

fn format_key(key: &str) -> String {
    if needs_quote(key) {
        serde_json::to_string(key).unwrap()
    } else {
        key.to_string()
    }
}

/// Format a YAML scalar, quoting when required to avoid ambiguity or syntax errors.
pub fn yaml_scalar(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".to_string();
    }
    if needs_quote(s) {
        serde_json::to_string(s).unwrap()
    } else {
        s.to_string()
    }
}

fn needs_quote(s: &str) -> bool {
    if matches!(
        s.to_ascii_lowercase().as_str(),
        "true" | "false" | "null" | "yes" | "no" | "on" | "off" | "~"
    ) {
        return true;
    }
    if s.trim() != s {
        return true;
    }
    let Some(first) = s.chars().next() else {
        return true;
    };
    if matches!(
        first,
        '&' | '*'
            | '!'
            | '%'
            | '@'
            | '`'
            | '"'
            | '\''
            | '['
            | ']'
            | '{'
            | '}'
            | ','
            | '#'
            | '|'
            | '>'
            | '?'
            | ':'
            | '-'
    ) || first.is_ascii_digit()
    {
        return true;
    }
    for ch in s.chars() {
        if matches!(
            ch,
            ':' | '#'
                | '{'
                | '}'
                | '['
                | ']'
                | ','
                | '&'
                | '*'
                | '!'
                | '|'
                | '>'
                | '\''
                | '"'
                | '%'
                | '@'
                | '`'
                | '('
                | ')'
                | '\n'
                | '\r'
                | '\t'
        ) {
            return true;
        }
    }
    false
}

fn write_prose(out: &mut String, indent: usize, key: &str, text: &str, trail: &str) {
    let pad = " ".repeat(indent);
    let trimmed = text.trim();
    let chomp = chomp(text);
    if !trimmed.contains('\n') {
        let _ = writeln!(out, "{pad}{key}: >{chomp}{trail}");
        for line in wrap_prose(trimmed, prose_width(indent)) {
            let _ = writeln!(out, "{pad}  {line}");
        }
        return;
    }
    let _ = writeln!(out, "{pad}{key}: |{chomp}{trail}");
    for line in trimmed.split('\n') {
        if line.is_empty() {
            out.push('\n');
        } else {
            let _ = writeln!(out, "{pad}  {line}");
        }
    }
}

fn write_prose_inline_first(out: &mut String, indent: usize, key: &str, text: &str, trail: &str) {
    let pad = " ".repeat(indent);
    let trimmed = text.trim();
    let chomp = chomp(text);
    if !trimmed.contains('\n') {
        let _ = writeln!(out, "{key}: >{chomp}{trail}");
        for line in wrap_prose(trimmed, prose_width(indent)) {
            let _ = writeln!(out, "{pad}  {line}");
        }
        return;
    }
    let _ = writeln!(out, "{key}: |{chomp}{trail}");
    for line in trimmed.split('\n') {
        if line.is_empty() {
            out.push('\n');
        } else {
            let _ = writeln!(out, "{pad}  {line}");
        }
    }
}

/// Word-wrap prose while keeping `{{ parameter }}` placeholders (and adjacent punctuation) intact.
pub fn wrap_prose(s: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in param_fields(s) {
        if cur.is_empty() {
            cur.push_str(&word);
            continue;
        }
        if cur.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut cur));
            cur.push_str(&word);
            continue;
        }
        cur.push(' ');
        cur.push_str(&word);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn param_fields(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_param = false;
    let mut i = 0;

    let flush = |out: &mut Vec<String>, cur: &mut String| {
        if !cur.is_empty() {
            out.push(std::mem::take(cur));
        }
    };

    while i < bytes.len() {
        if !in_param && i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            if !cur.is_empty()
                && !cur
                    .trim_matches(|c: char| {
                        matches!(c, '.' | ',' | ';' | ':' | '(' | ')' | '[' | ']')
                    })
                    .is_empty()
            {
                flush(&mut out, &mut cur);
            }
            in_param = true;
            cur.push_str("{{");
            i += 2;
            continue;
        }
        if in_param && i + 1 < bytes.len() && bytes[i] == b'}' && bytes[i + 1] == b'}' {
            cur.push_str("}}");
            in_param = false;
            i += 2;
            continue;
        }
        let ch = s[i..].chars().next().unwrap();
        if !in_param && ch.is_whitespace() {
            flush(&mut out, &mut cur);
        } else {
            cur.push(ch);
        }
        i += ch.len_utf8();
    }
    flush(&mut out, &mut cur);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_null_anchors_aliases_merge_and_duplicates() {
        assert!(parse_yaml("type: control\nname: null\n").is_err());
        assert!(parse_yaml("type: control\nname: ~\n").is_err());
        assert!(parse_yaml("a: &x foo\nb: *x\n").is_err());
        assert!(parse_yaml("<<: {a: 1}\n").is_err());
        assert!(parse_yaml("a: 1\na: 2\n").is_err());
    }

    #[test]
    fn yaml_1_2_keeps_yes_no_and_dates_as_strings() {
        let (val, spans) = parse_yaml("flag: yes\ndate: 2026-11-08\nver: 0.1.0\n").unwrap();
        assert_eq!(val["flag"], Value::String("yes".into()));
        assert_eq!(val["date"], Value::String("2026-11-08".into()));
        assert_eq!(val["ver"], Value::String("0.1.0".into()));
        assert_eq!(spans.get("/date").unwrap().line, 2);
    }

    #[test]
    fn wrap_keeps_placeholders_intact() {
        let lines = wrap_prose(
            "Create accounts in accordance with {{ ac_02_odp_04 }}; and stop.",
            40,
        );
        for line in &lines {
            assert!(!line.contains("{{") || line.contains("}}"));
        }
        assert!(lines.join(" ").contains("{{ ac_02_odp_04 }};"));
    }

    fn long_prose() -> String {
        "Restrict logical access to systems, administrative interfaces, and \
         sensitive data using role-based access control scoped to least \
         privilege, requiring {{ privileged_elevation }} for administrative \
         actions."
            .to_string()
    }

    #[test]
    fn format_respects_max_line_width_at_every_depth() {
        let prose = long_prose();
        let doc = serde_json::json!({
            "type": "control",
            "summary": "Short inline value stays inline.",
            "statement": prose,
            "parameters": {"privileged_elevation": {"label": "x", "value": prose}},
            "parts": [{"id": "a", "statement": prose}],
        });
        let out = format_yaml(&doc, None);
        for line in out.lines() {
            assert!(
                line.len() <= MAX_LINE_WIDTH,
                "line exceeds {MAX_LINE_WIDTH}: {line:?}"
            );
        }
        assert!(out.contains("summary: Short inline value stays inline.\n"));
    }

    #[test]
    fn format_round_trips_trailing_newline_exactly() {
        let prose = long_prose();
        let with_nl = format!("{prose}\n");
        let doc = serde_json::json!({
            "type": "control",
            "statement": prose,
            "guidance": with_nl,
            "objective": "line one\nline two",
            "tags": ["one two three four five six seven eight nine ten eleven twelve"],
        });
        let out = format_yaml(&doc, None);
        let (back, _) = parse_yaml(&out).unwrap();
        assert_eq!(back, doc, "formatted output:\n{out}");
        assert_eq!(format_yaml(&back, None), out, "format is not idempotent");
    }

    #[test]
    fn format_source_preserves_comments_through_reorder() {
        let src = "---\n# top comment\n# continues\ntype: implementation\nid: implementation--com.acme.x\nspec_version: \"0.1.0\"\ncreated: 2026-11-08T00:00:00Z\nmodified: 2026-11-08T00:00:00Z\nstatus: implemented\nresponsibility: provider\n# moves with component_ref\ncomponent_ref: component--dev.x.y\nnarrative: x  # trailing\nparts:\n  # item note\n  - id: a\n    statement: \"ok\"\n# eof\n";
        let once = format_source(src, false).unwrap();
        assert!(once.dropped.is_empty(), "dropped: {:?}", once.dropped);
        assert!(
            once.formatted.starts_with("# top comment\n# continues\n"),
            "{}",
            once.formatted
        );
        assert!(
            once.formatted
                .contains("# moves with component_ref\ncomponent_ref:")
        );
        assert!(once.formatted.contains("narrative: x  # trailing"));
        assert!(
            once.formatted.contains("# item note\n  - id: a"),
            "formatted:\n{}",
            once.formatted
        );
        assert!(
            once.formatted.trim_end().ends_with("# eof"),
            "{}",
            once.formatted
        );
        // Leading `---` is not required in canonical form; comments after it are kept.
        assert!(!once.formatted.starts_with("---"));
        let twice = format_source(&once.formatted, false).unwrap();
        assert!(twice.dropped.is_empty());
        assert_eq!(twice.formatted, once.formatted, "fmt is not idempotent");
    }

    #[test]
    fn format_source_does_not_treat_hash_in_scalars_as_comments() {
        let src = "type: control\nstatement: \"has # hash\"\nfolded: |\n  # still content\n";
        let once = format_source(src, false).unwrap();
        assert!(once.dropped.is_empty(), "dropped: {:?}", once.dropped);
        let (back, _) = parse_yaml(&once.formatted).unwrap();
        assert_eq!(back["statement"], Value::String("has # hash".into()));
        assert_eq!(back["folded"].as_str().unwrap().trim(), "# still content");
    }

    #[test]
    fn format_source_drop_comments_keeps_only_the_header() {
        let src = "---\n# top\ntype: implementation\n# mid\ncomponent_ref: component--dev.x.y\nnarrative: x  # trailing\n";
        let dropped = format_source(src, true).unwrap();
        assert!(dropped.formatted.starts_with("# top\n"));
        assert!(!dropped.formatted.contains("# mid"));
        assert!(!dropped.formatted.contains("# trailing"));
        assert_eq!(dropped.dropped.len(), 2);
    }
}
