//! Repository-form (parallel directory) and exchange-form bundle I/O (RFC 0001 §6.5).

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use walkdir::WalkDir;

use crate::constraints::{Diagnostic, Severity, StorageOrigin};
use crate::graph::Graph;
use crate::ids;
use crate::model::{OgrlObject, SPEC_VERSION, readable_spec_version};
use crate::yaml::{self, ParseOptions, SpanMap};

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BundleManifest {
    #[serde(rename = "type")]
    pub object_type: String,
    pub id: String,
    pub spec_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub providers: Option<Vec<Value>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
pub struct LoadedObject {
    pub object: OgrlObject,
    pub file: Option<PathBuf>,
    pub spans: SpanMap,
    pub origin: StorageOrigin,
}

#[derive(Debug, Clone)]
pub struct LoadedBundle {
    pub manifest: Option<BundleManifest>,
    pub objects: Vec<LoadedObject>,
    pub diagnostics: Vec<Diagnostic>,
}

impl LoadedBundle {
    /// Construct an indexed `Graph` from all successfully parsed objects.
    pub fn to_graph(&self) -> Graph {
        let mut library_ids = Vec::new();
        let mut provider_ids = Vec::new();
        let mut objs = Vec::with_capacity(self.objects.len());
        for lo in &self.objects {
            match lo.origin {
                StorageOrigin::Library => library_ids.push(lo.object.id().to_string()),
                StorageOrigin::Provider => provider_ids.push(lo.object.id().to_string()),
                StorageOrigin::Organization => {}
            }
            objs.push(lo.object.clone());
        }
        Graph::new(objs, library_ids, provider_ids)
    }

    pub fn metadata_index(
        &self,
    ) -> HashMap<&str, (Option<PathBuf>, Option<&SpanMap>, StorageOrigin)> {
        self.objects
            .iter()
            .map(|lo| {
                (
                    lo.object.id(),
                    (lo.file.clone(), Some(&lo.spans), lo.origin),
                )
            })
            .collect()
    }
}

/// Infer default storage origin from the bundle manifest when `--profile auto` is used.
pub fn infer_origin(manifest: Option<&BundleManifest>, default: StorageOrigin) -> StorageOrigin {
    if let Some(m) = manifest {
        if m.id == "bundle--ogrl-library" {
            return StorageOrigin::Library;
        }
        if m.library.is_some() && m.providers.is_none() {
            // Provider bundle manifest pins `library:` without `providers:` (RFC 0002 §7).
            return StorageOrigin::Provider;
        }
    }
    default
}

/// Read a repository-form directory in parallel using Rayon.
/// Collects all YAML/schema/duplicate-ID errors as structured diagnostics rather than
/// stopping at the first error.
pub fn read_directory(
    root: &Path,
    options: ParseOptions,
    origin_override: Option<StorageOrigin>,
) -> Result<LoadedBundle, BundleError> {
    if !root.is_dir() {
        return Err(BundleError::Invalid(format!(
            "{} is not a directory",
            root.display()
        )));
    }

    let mut diagnostics = Vec::new();
    let manifest_path = root.join("bundle.yaml");
    let manifest = if manifest_path.is_file() {
        match fs::read_to_string(&manifest_path) {
            Ok(text) => match parse_manifest(&text, options) {
                Ok(m) => Some(m),
                Err(errs) => {
                    for mut d in errs {
                        d.file = Some(manifest_path.clone());
                        diagnostics.push(d);
                    }
                    None
                }
            },
            Err(e) => {
                return Err(BundleError::Io {
                    path: manifest_path,
                    source: e,
                });
            }
        }
    } else {
        None
    };

    let default_origin = origin_override
        .unwrap_or_else(|| infer_origin(manifest.as_ref(), StorageOrigin::Organization));

    // Collect all YAML files under root (skipping dotfiles and bundle.yaml).
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|e| BundleError::Invalid(e.to_string()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path == manifest_path {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        // Skip hidden directories like `.git/`.
        if path.strip_prefix(root).ok().is_some_and(|rel| {
            rel.components()
                .any(|c| c.as_os_str().to_string_lossy().starts_with('.'))
        }) {
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml") {
            files.push(path.to_path_buf());
        }
    }
    files.sort();

    // Parse all object files in parallel with Rayon!
    let parsed: Vec<(Option<LoadedObject>, Vec<Diagnostic>)> = files
        .par_iter()
        .map(|path| {
            let rel = path.strip_prefix(root).unwrap_or(path);
            let is_provider_dir = rel
                .components()
                .next()
                .is_some_and(|c| c.as_os_str() == "provider");
            let file_origin = if is_provider_dir && origin_override.is_none() {
                StorageOrigin::Provider
            } else {
                default_origin
            };

            let text = match fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) => {
                    return (
                        None,
                        vec![Diagnostic {
                            severity: Severity::Error,
                            code: "E_IO".into(),
                            object_id: None,
                            file: Some(path.clone()),
                            line: None,
                            col: None,
                            pointer: String::new(),
                            detail: e.to_string(),
                            conflict: false,
                        }],
                    );
                }
            };

            match yaml::parse_yaml_with_spans(&text, options) {
                Err(errs) => {
                    let diags = errs
                        .into_iter()
                        .map(|e| Diagnostic {
                            severity: Severity::Error,
                            code: "E_YAML".into(),
                            object_id: None,
                            file: Some(path.clone()),
                            line: e.span.map(|s| s.line),
                            col: e.span.map(|s| s.col),
                            pointer: e.pointer,
                            detail: e.message,
                            conflict: false,
                        })
                        .collect();
                    (None, diags)
                }
                Ok((value, spans)) => {
                    let obj_id = value.get("id").and_then(Value::as_str).map(String::from);
                    match OgrlObject::from_value(value) {
                        Ok(object) => (
                            Some(LoadedObject {
                                object,
                                file: Some(path.clone()),
                                spans,
                                origin: file_origin,
                            }),
                            Vec::new(),
                        ),
                        Err(e) => {
                            let span = spans.get("/id").or_else(|| spans.get("")).copied();
                            (
                                None,
                                vec![Diagnostic {
                                    severity: Severity::Error,
                                    code: "E_SCHEMA".into(),
                                    object_id: obj_id,
                                    file: Some(path.clone()),
                                    line: span.map(|s| s.line),
                                    col: span.map(|s| s.col),
                                    pointer: String::new(),
                                    detail: e.to_string(),
                                    conflict: false,
                                }],
                            )
                        }
                    }
                }
            }
        })
        .collect();

    let mut objects = Vec::with_capacity(files.len());
    let mut seen_ids: HashMap<String, PathBuf> = HashMap::new();
    let expected_spec = manifest.as_ref().map(|m| m.spec_version.clone());

    for (maybe_obj, mut file_diags) in parsed {
        diagnostics.append(&mut file_diags);
        if let Some(lo) = maybe_obj {
            if let Some(ref spec) = expected_spec {
                if lo.object.spec_version() != spec {
                    let span = lo.spans.get("/spec_version").copied();
                    diagnostics.push(Diagnostic {
                        severity: Severity::Error,
                        code: "E_SPEC_VERSION".into(),
                        object_id: Some(lo.object.id().to_string()),
                        file: lo.file.clone(),
                        line: span.map(|s| s.line),
                        col: span.map(|s| s.col),
                        pointer: "/spec_version".into(),
                        detail: format!(
                            "object spec_version {} does not match bundle spec_version {spec} (RFC 0001 §6.2)",
                            lo.object.spec_version()
                        ),
                        conflict: false,
                    });
                }
            }
            if let Some(first_path) = seen_ids.get(lo.object.id()) {
                let span = lo.spans.get("/id").copied();
                diagnostics.push(Diagnostic {
                    severity: Severity::Error,
                    code: "E_DUPLICATE_ID".into(),
                    object_id: Some(lo.object.id().to_string()),
                    file: lo.file.clone(),
                    line: span.map(|s| s.line),
                    col: span.map(|s| s.col),
                    pointer: "/id".into(),
                    detail: format!(
                        "duplicate object id {} (first seen in {})",
                        lo.object.id(),
                        first_path.display()
                    ),
                    conflict: true,
                });
            } else {
                if let Some(ref f) = lo.file {
                    seen_ids.insert(lo.object.id().to_string(), f.clone());
                }
                objects.push(lo);
            }
        }
    }

    Ok(LoadedBundle {
        manifest,
        objects,
        diagnostics,
    })
}

fn looks_like_json(content: &str) -> bool {
    content.trim_start().starts_with('{')
}

fn find_null_pointers(val: &Value, ptr: &str, out: &mut Vec<String>) {
    match val {
        Value::Null => out.push(ptr.to_string()),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                find_null_pointers(item, &format!("{ptr}/{i}"), out);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                let esc = k.replace('~', "~0").replace('/', "~1");
                find_null_pointers(v, &format!("{ptr}/{esc}"), out);
            }
        }
        _ => {}
    }
}

fn parse_document(content: &str, options: ParseOptions) -> Result<(Value, SpanMap), BundleError> {
    if looks_like_json(content) {
        if let Ok(val) = serde_json::from_str::<Value>(content) {
            if options.strict {
                let mut nulls = Vec::new();
                find_null_pointers(&val, "", &mut nulls);
                if !nulls.is_empty() {
                    return Err(BundleError::Invalid(format!(
                        "explicit null values are invalid in OGRL (RFC 0001 §6.1) at {}",
                        nulls.join(", ")
                    )));
                }
            }
            return Ok((val, SpanMap::new()));
        }
    }
    yaml::parse_yaml_with_spans(content, options).map_err(|errs| {
        BundleError::Invalid(
            errs.into_iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; "),
        )
    })
}

/// Read an exchange-form bundle (YAML 1.2 or JSON) containing an inline `objects` array.
pub fn read_exchange(
    content: &str,
    source_path: Option<PathBuf>,
    options: ParseOptions,
    origin_override: Option<StorageOrigin>,
) -> Result<LoadedBundle, BundleError> {
    let (value, spans) = parse_document(content, options)?;
    read_exchange_value(value, spans, source_path, origin_override)
}

fn read_exchange_value(
    value: Value,
    spans: SpanMap,
    source_path: Option<PathBuf>,
    origin_override: Option<StorageOrigin>,
) -> Result<LoadedBundle, BundleError> {
    let Some(mut map) = value.as_object().cloned() else {
        return Err(BundleError::Invalid("bundle is not a mapping".into()));
    };
    if map.get("type").and_then(Value::as_str) != Some("bundle") {
        return Err(BundleError::Invalid("the manifest is not a bundle".into()));
    }
    let Some(Value::Array(raw_objects)) = map.remove("objects") else {
        return Err(BundleError::Invalid(
            "an exchange bundle lists its objects in `objects`".into(),
        ));
    };

    let manifest: BundleManifest = serde_json::from_value(Value::Object(map))
        .map_err(|e| BundleError::Invalid(format!("invalid bundle manifest: {e}")))?;
    if !readable_spec_version(&manifest.spec_version) {
        return Err(BundleError::Invalid(format!(
            "spec_version {:?} is not readable as {SPEC_VERSION}",
            manifest.spec_version
        )));
    }
    let origin = origin_override
        .unwrap_or_else(|| infer_origin(Some(&manifest), StorageOrigin::Organization));

    // Deserialize all exchange objects in parallel with Rayon.
    let has_spans = !spans.is_empty();
    let parsed: Vec<Result<(OgrlObject, SpanMap), Diagnostic>> = raw_objects
        .into_par_iter()
        .enumerate()
        .map(|(idx, item)| {
            let obj_id = item.get("id").and_then(Value::as_str).map(String::from);
            let ptr_prefix = format!("/objects/{idx}");
            match OgrlObject::from_value(item) {
                Ok(object) => {
                    let mut obj_spans = SpanMap::new();
                    if has_spans {
                        for (k, v) in &spans {
                            if let Some(rest) = k.strip_prefix(&ptr_prefix) {
                                obj_spans.insert(rest.to_string(), *v);
                            }
                        }
                    }
                    Ok((object, obj_spans))
                }
                Err(e) => {
                    let span = spans.get(&ptr_prefix).copied();
                    Err(Diagnostic {
                        severity: Severity::Error,
                        code: "E_SCHEMA".into(),
                        object_id: obj_id,
                        file: source_path.clone(),
                        line: span.map(|s| s.line),
                        col: span.map(|s| s.col),
                        pointer: ptr_prefix,
                        detail: e.to_string(),
                        conflict: false,
                    })
                }
            }
        })
        .collect();

    let mut objects = Vec::with_capacity(parsed.len());
    let mut diagnostics = Vec::new();
    let mut seen_ids = std::collections::HashSet::new();

    for (idx, item) in parsed.into_iter().enumerate() {
        match item {
            Ok((object, obj_spans)) => {
                if !seen_ids.insert(object.id().to_string()) {
                    let ptr = format!("/objects/{idx}/id");
                    let span = spans.get(&ptr).copied();
                    diagnostics.push(Diagnostic {
                        severity: Severity::Error,
                        code: "E_DUPLICATE_ID".into(),
                        object_id: Some(object.id().to_string()),
                        file: source_path.clone(),
                        line: span.map(|s| s.line),
                        col: span.map(|s| s.col),
                        pointer: ptr,
                        detail: format!("duplicate object id {}", object.id()),
                        conflict: true,
                    });
                    continue;
                }
                objects.push(LoadedObject {
                    object,
                    file: source_path.clone(),
                    spans: obj_spans,
                    origin,
                });
            }
            Err(diag) => diagnostics.push(diag),
        }
    }

    Ok(LoadedBundle {
        manifest: Some(manifest),
        objects,
        diagnostics,
    })
}

/// Read either a repository-form directory or a single exchange-form file.
pub fn read_path(
    path: &Path,
    options: ParseOptions,
    origin_override: Option<StorageOrigin>,
) -> Result<LoadedBundle, BundleError> {
    if path.is_dir() {
        read_directory(path, options, origin_override)
    } else if path.is_file() {
        let content = fs::read_to_string(path).map_err(|e| BundleError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        let (val, spans) = parse_document(&content, options)?;
        if val.get("type").and_then(Value::as_str) == Some("bundle") {
            read_exchange_value(val, spans, Some(path.to_path_buf()), origin_override)
        } else {
            let origin = origin_override.unwrap_or(StorageOrigin::Organization);
            let object = OgrlObject::from_value(val)
                .map_err(|e| BundleError::Invalid(format!("{}: {e}", path.display())))?;
            Ok(LoadedBundle {
                manifest: None,
                objects: vec![LoadedObject {
                    object,
                    file: Some(path.to_path_buf()),
                    spans,
                    origin,
                }],
                diagnostics: Vec::new(),
            })
        }
    } else {
        Err(BundleError::Invalid(format!(
            "{} does not exist",
            path.display()
        )))
    }
}

/// Pack a manifest + objects into an exchange-form JSON `Value`.
pub fn pack_exchange(manifest: &BundleManifest, objects: &[OgrlObject]) -> Value {
    let mut val = serde_json::to_value(manifest).expect("manifest serialization");
    let mut sorted: Vec<&OgrlObject> = objects.iter().collect();
    sorted.sort_by(|a, b| a.id().cmp(b.id()));
    let arr: Vec<Value> = sorted.into_iter().map(OgrlObject::to_json_value).collect();
    if let Some(map) = val.as_object_mut() {
        map.insert("objects".to_string(), Value::Array(arr));
    }
    val
}

/// Write a manifest + objects out in repository-form (`bundle.yaml` + `{type}/{remainder}.yaml`).
pub fn write_directory(
    out_dir: &Path,
    manifest: Option<&BundleManifest>,
    objects: &[OgrlObject],
    header_comment: Option<&str>,
) -> Result<(), BundleError> {
    fs::create_dir_all(out_dir).map_err(|e| BundleError::Io {
        path: out_dir.to_path_buf(),
        source: e,
    })?;
    if let Some(m) = manifest {
        let val = serde_json::to_value(m).expect("manifest serialization");
        let text = yaml::format_yaml(&val, header_comment);
        let path = out_dir.join("bundle.yaml");
        fs::write(&path, text).map_err(|e| BundleError::Io { path, source: e })?;
    }
    for obj in objects {
        let rel = ids::object_path(obj.id()).map_err(|e| BundleError::Invalid(e.to_string()))?;
        let dest = out_dir.join(rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| BundleError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        let text = yaml::format_yaml(&obj.to_json_value(), header_comment);
        fs::write(&dest, text).map_err(|e| BundleError::Io {
            path: dest,
            source: e,
        })?;
    }
    Ok(())
}

fn parse_manifest(text: &str, options: ParseOptions) -> Result<BundleManifest, Vec<Diagnostic>> {
    let (val, spans) = yaml::parse_yaml_with_spans(text, options).map_err(|errs| {
        errs.into_iter()
            .map(|e| Diagnostic {
                severity: Severity::Error,
                code: "E_YAML".into(),
                object_id: None,
                file: None,
                line: e.span.map(|s| s.line),
                col: e.span.map(|s| s.col),
                pointer: e.pointer,
                detail: e.message,
                conflict: false,
            })
            .collect::<Vec<_>>()
    })?;
    if val.get("type").and_then(Value::as_str) != Some("bundle") {
        let sp = spans.get("/type").copied();
        return Err(vec![Diagnostic {
            severity: Severity::Error,
            code: "E_MANIFEST".into(),
            object_id: None,
            file: None,
            line: sp.map(|s| s.line),
            col: sp.map(|s| s.col),
            pointer: "/type".into(),
            detail: "the manifest must have type: bundle".into(),
            conflict: false,
        }]);
    }
    let manifest: BundleManifest = serde_json::from_value(val).map_err(|e| {
        vec![Diagnostic {
            severity: Severity::Error,
            code: "E_MANIFEST".into(),
            object_id: None,
            file: None,
            line: Some(1),
            col: Some(1),
            pointer: String::new(),
            detail: format!("invalid bundle manifest: {e}"),
            conflict: false,
        }]
    })?;
    if !readable_spec_version(&manifest.spec_version) {
        let sp = spans.get("/spec_version").copied();
        return Err(vec![Diagnostic {
            severity: Severity::Error,
            code: "E_SPEC_VERSION".into(),
            object_id: Some(manifest.id.clone()),
            file: None,
            line: sp.map(|s| s.line),
            col: sp.map(|s| s.col),
            pointer: "/spec_version".into(),
            detail: format!(
                "spec_version {:?} is not readable as {SPEC_VERSION}",
                manifest.spec_version
            ),
            conflict: false,
        }]);
    }
    Ok(manifest)
}
