//! OSCAL 1.2.3 XML parser & serializer helpers (Catalog, Component Definition, and 6-doc export).

use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::{Reader, Writer};
use serde_json::{Map, Value};
use thiserror::Error;

pub const OSCAL_XML_NS: &str = "http://csrc.nist.gov/ns/oscal/1.0";

#[derive(Debug, Error)]
pub enum XmlError {
    #[error("XML error: {0}")]
    QuickXml(#[from] quick_xml::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("unexpected XML structure: {0}")]
    Invalid(String),
}

/// Returns true if `bytes` starts with an XML `<` (ignoring leading UTF-8 BOM / whitespace).
pub fn looks_like_xml(bytes: &[u8]) -> bool {
    let trimmed = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    trimmed
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|&b| b == b'<')
}

/// Convert an OSCAL JSON document (single top-level key like `{"profile": {...}}`)
/// into well-formed OSCAL 1.2.3 XML with the standard OSCAL namespace.
pub fn oscal_json_to_xml(doc: &Value) -> Result<Vec<u8>, XmlError> {
    let Some(map) = doc.as_object() else {
        return Err(XmlError::Invalid(
            "OSCAL document must be a JSON object".into(),
        ));
    };
    if map.len() != 1 {
        return Err(XmlError::Invalid(
            "OSCAL document must have exactly one root element".into(),
        ));
    }
    let (root_name, root_val) = map.iter().next().unwrap();

    let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);
    writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;
    write_element(&mut writer, root_name, root_val, true)?;
    Ok(writer.into_inner())
}

/// OSCAL keys that serialize as XML attributes rather than child elements.
fn is_xml_attr(key: &str) -> bool {
    matches!(
        key,
        "uuid"
            | "id"
            | "href"
            | "rel"
            | "name"
            | "ns"
            | "value"
            | "class"
            | "type"
            | "control-id"
            | "param-id"
            | "statement-id"
            | "component-uuid"
            | "party-uuid"
            | "actor-uuid"
            | "risk-uuid"
            | "finding-uuid"
            | "target-id"
            | "id-ref"
            | "algorithm"
            | "system"
            | "identifier-type"
            | "state"
            | "lifecycle"
            | "method"
            | "category"
            | "source"
    )
}

/// Map OSCAL JSON plural array field names to their singular XML element names.
fn singular_elem(key: &str) -> &str {
    match key {
        "props" => "prop",
        "links" => "link",
        "rlinks" => "rlink",
        "hashes" => "hash",
        "parts" => "part",
        "params" => "param",
        "controls" => "control",
        "groups" => "group",
        "imports" => "import",
        "include-controls" => "include-controls",
        "with-ids" => "with-id",
        "set-parameters" => "set-parameter",
        "values" => "value",
        "system-ids" => "system-id",
        "information-types" => "information-type",
        "users" => "user",
        "components" => "component",
        "leveraged-authorizations" => "leveraged-authorization",
        "implemented-requirements" => "implemented-requirement",
        "by-components" => "by-component",
        "statements" => "statement",
        "control-implementations" => "control-implementation",
        "results" => "result",
        "findings" => "finding",
        "resources" => "resource",
        "related-risks" => "related-risk",
        "related-findings" => "related-finding",
        "poam-items" => "poam-item",
        "risks" => "risk",
        "characterizations" => "characterization",
        "actors" => "actor",
        "facets" => "facet",
        "remediations" => "remediation",
        "tasks" => "task",
        "control-selections" => "control-selection",
        "mappings" => "mapping",
        "maps" => "map",
        "sources" => "source",
        "targets" => "target",
        "parties" => "party",
        "responsible-roles" => "responsible-role",
        "party-uuids" => "party-uuid",
        other => other,
    }
}

fn write_element(
    writer: &mut Writer<Vec<u8>>,
    name: &str,
    val: &Value,
    is_root: bool,
) -> Result<(), XmlError> {
    match val {
        Value::Object(map) => {
            let mut start = BytesStart::new(name);
            if is_root {
                start.push_attribute(("xmlns", OSCAL_XML_NS));
            }
            let mut children: Vec<(&String, &Value)> = Vec::new();
            let mut text_body: Option<&str> = None;

            for (k, v) in map {
                if let Value::String(s) = v {
                    if is_xml_attr(k) && !is_root_text_field(name, k) {
                        start.push_attribute((k.as_str(), s.as_str()));
                        continue;
                    }
                    if k == "id" && name == "system-id" {
                        text_body = Some(s.as_str());
                        continue;
                    }
                }
                children.push((k, v));
            }

            if children.is_empty() && text_body.is_none() {
                writer.write_event(Event::Empty(start))?;
                return Ok(());
            }

            writer.write_event(Event::Start(start))?;
            if let Some(body) = text_body {
                writer.write_event(Event::Text(BytesText::new(body)))?;
            }
            for (k, v) in children {
                match v {
                    Value::Array(items) => {
                        let elem = singular_elem(k);
                        for item in items {
                            write_element(writer, elem, item, false)?;
                        }
                    }
                    other => {
                        write_element(writer, k, other, false)?;
                    }
                }
            }
            writer.write_event(Event::End(BytesEnd::new(name)))?;
        }
        Value::String(s) => {
            writer.write_event(Event::Start(BytesStart::new(name)))?;
            writer.write_event(Event::Text(BytesText::new(s)))?;
            writer.write_event(Event::End(BytesEnd::new(name)))?;
        }
        Value::Number(n) => {
            let s = n.to_string();
            writer.write_event(Event::Start(BytesStart::new(name)))?;
            writer.write_event(Event::Text(BytesText::new(&s)))?;
            writer.write_event(Event::End(BytesEnd::new(name)))?;
        }
        Value::Bool(b) => {
            let s = if *b { "true" } else { "false" };
            writer.write_event(Event::Start(BytesStart::new(name)))?;
            writer.write_event(Event::Text(BytesText::new(s)))?;
            writer.write_event(Event::End(BytesEnd::new(name)))?;
        }
        Value::Array(items) => {
            let elem = singular_elem(name);
            for item in items {
                write_element(writer, elem, item, false)?;
            }
        }
        Value::Null => {}
    }
    Ok(())
}

fn is_root_text_field(parent: &str, key: &str) -> bool {
    // `system-id` holds `id` as element text, `hash` holds `value` as element text.
    (parent == "system-id" && key == "id") || (parent == "hash" && key == "value")
}

/// Generic minimal XML -> OSCAL JSON converter for importing XML OSCAL catalogs
/// and component definitions via the same typed deserialization pipeline as JSON.
pub fn oscal_xml_to_json(xml_bytes: &[u8]) -> Result<Value, XmlError> {
    let mut reader = Reader::from_reader(xml_bytes);
    reader.config_mut().trim_text(false);

    struct Node {
        name: String,
        attrs: Map<String, Value>,
        children: Vec<(String, Value)>,
        text: String,
    }

    let mut stack: Vec<Node> = Vec::new();
    let mut root: Option<(String, Value)> = None;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                let mut attrs = Map::new();
                for attr in e.attributes().flatten() {
                    let k = String::from_utf8_lossy(attr.key.local_name().as_ref()).into_owned();
                    if k == "xmlns" || k.starts_with("xmlns:") {
                        continue;
                    }
                    let v = attr.unescape_value().unwrap_or_default().into_owned();
                    attrs.insert(k, Value::String(v));
                }
                stack.push(Node {
                    name,
                    attrs,
                    children: Vec::new(),
                    text: String::new(),
                });
            }
            Event::Empty(e) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                let mut attrs = Map::new();
                for attr in e.attributes().flatten() {
                    let k = String::from_utf8_lossy(attr.key.local_name().as_ref()).into_owned();
                    if k == "xmlns" || k.starts_with("xmlns:") {
                        continue;
                    }
                    let v = attr.unescape_value().unwrap_or_default().into_owned();
                    attrs.insert(k, Value::String(v));
                }
                let val = Value::Object(attrs);
                if let Some(parent) = stack.last_mut() {
                    parent.children.push((name, val));
                } else {
                    root = Some((name, val));
                }
            }
            Event::Text(e) => {
                if let Some(node) = stack.last_mut() {
                    let t = e.unescape().unwrap_or_default();
                    node.text.push_str(&t);
                }
            }
            Event::End(_) => {
                if let Some(node) = stack.pop() {
                    let val =
                        finalize_xml_node(node.name.clone(), node.attrs, node.children, node.text);
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push((node.name, val));
                    } else {
                        root = Some((node.name, val));
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    let Some((name, val)) = root else {
        return Err(XmlError::Invalid("empty XML document".into()));
    };
    let mut doc = Map::new();
    doc.insert(name, val);
    Ok(Value::Object(doc))
}

fn finalize_xml_node(
    name: String,
    mut attrs: Map<String, Value>,
    children: Vec<(String, Value)>,
    text: String,
) -> Value {
    // Handle inline OSCAL `<insert type="param" id-ref="..."/>` inside `<p>` prose!
    if name == "p" || name == "prose" {
        let mut prose = text.trim().to_string();
        for (ck, cv) in children {
            if ck == "insert" {
                if let Some(id_ref) = cv.get("id-ref").and_then(Value::as_str) {
                    if !prose.is_empty() && !prose.ends_with(' ') {
                        prose.push(' ');
                    }
                    prose.push_str(&format!("{{{{ insert: param, {id_ref} }}}}"));
                }
            } else if let Value::String(s) = cv {
                if !s.is_empty() {
                    if !prose.is_empty() {
                        prose.push(' ');
                    }
                    prose.push_str(&s);
                }
            }
        }
        return Value::String(prose);
    }

    if attrs.is_empty() && children.is_empty() {
        return Value::String(text.trim().to_string());
    }

    let mut prose_lines: Vec<String> = Vec::new();
    for (ck, cv) in children {
        if ck == "p" {
            if let Value::String(s) = cv {
                if !s.is_empty() {
                    prose_lines.push(s);
                }
            }
            continue;
        }
        let target_key = plural_field(&ck).to_string();
        if is_array_field(&target_key) {
            let entry = attrs
                .entry(target_key)
                .or_insert_with(|| Value::Array(Vec::new()));
            if let Value::Array(arr) = entry {
                arr.push(cv);
            }
        } else {
            attrs.insert(target_key, cv);
        }
    }
    if !prose_lines.is_empty() {
        attrs.insert("prose".to_string(), Value::String(prose_lines.join("\n\n")));
    } else {
        let trimmed = text.trim();
        if !trimmed.is_empty() && !attrs.contains_key("prose") && !attrs.contains_key("value") {
            if name == "hash" {
                attrs.insert("value".to_string(), Value::String(trimmed.to_string()));
            } else if name == "description" || name == "remarks" || name == "label" {
                return Value::String(trimmed.to_string());
            }
        }
    }
    Value::Object(attrs)
}

fn plural_field(singular: &str) -> &str {
    match singular {
        "group" => "groups",
        "control" => "controls",
        "param" => "params",
        "prop" => "props",
        "link" => "links",
        "rlink" => "rlinks",
        "part" => "parts",
        "resource" => "resources",
        "party" => "parties",
        "component" => "components",
        "responsible-role" => "responsible-roles",
        "party-uuid" => "party-uuids",
        "control-implementation" => "control-implementations",
        "implemented-requirement" => "implemented-requirements",
        other => other,
    }
}

fn is_array_field(key: &str) -> bool {
    matches!(
        key,
        "groups"
            | "controls"
            | "params"
            | "props"
            | "links"
            | "rlinks"
            | "parts"
            | "resources"
            | "parties"
            | "components"
            | "responsible-roles"
            | "party-uuids"
            | "control-implementations"
            | "implemented-requirements"
    )
}
