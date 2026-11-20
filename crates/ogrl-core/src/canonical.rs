//! Canonical JSON (RFC 8785 / JCS) and SHA-256 digests (RFC 0001 §6.1, RFC 0002).

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::model::OgrlObject;

/// Serialize a JSON value in canonical form (sorted object keys, no whitespace, UTF-8).
///
/// `serde_json::Map` uses `BTreeMap` by default (sorted lexicographically by UTF-8, which
/// matches UTF-16 code-unit order for all BMP/ASCII keys). We recursively normalize so
/// any value produces deterministic bytes identical to Python's `bundles.canonical_json`.
pub fn canonical_json(value: &Value) -> Vec<u8> {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out.into_bytes()
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            // serde_json::to_string produces RFC 8259 minimal escaping with raw UTF-8.
            out.push_str(&serde_json::to_string(s).expect("string serialization cannot fail"));
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // Sort by UTF-16 code units per RFC 8785 §3.2.3.
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("key serialization cannot fail"));
                out.push(':');
                write_canonical(v, out);
            }
            out.push('}');
        }
    }
}

/// Lowercase hex SHA-256 digest of raw bytes.
pub fn sha256_hex(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Stable projection digest over a set of OGRL objects, independent of file layout.
/// Matches Python `ogrl.kernel.bundles.projection_digest`: `"sha-256:<hex>"`.
pub fn projection_digest<'a>(objects: impl IntoIterator<Item = &'a OgrlObject>) -> String {
    let mut bodies: Vec<Value> = objects.into_iter().map(OgrlObject::to_json_value).collect();
    bodies.sort_by(|a, b| {
        let ka = a.get("id").and_then(Value::as_str).unwrap_or("");
        let kb = b.get("id").and_then(Value::as_str).unwrap_or("");
        ka.cmp(kb)
    });
    let bytes = canonical_json(&Value::Array(bodies));
    format!("sha-256:{}", sha256_hex(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_sorts_keys_compactly() {
        let v = json!({"b": 1, "a": {"z": true, "m": "hi"}});
        assert_eq!(
            String::from_utf8(canonical_json(&v)).unwrap(),
            r#"{"a":{"m":"hi","z":true},"b":1}"#
        );
    }
}
