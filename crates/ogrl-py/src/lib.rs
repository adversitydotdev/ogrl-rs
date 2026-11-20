//! Coarse-grained PyO3 bindings for `ogrl-core` and `ogrl-oscal`.
//!
//! All heavy parsing, constraint validation, status evaluation, and OSCAL rendering
//! release the Python GIL (`py.detach`) and run in parallel Rust (`rayon`), passing
//! JSON strings/bytes across the boundary so FastAPI/Pydantic keep owning HTTP models.

use std::collections::HashSet;
use std::path::Path;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde_json::{Value, json};

use ogrl_core::bundle::{LoadedBundle, read_directory, read_exchange, read_path};
use ogrl_core::canonical::{
    canonical_json as core_canonical_json, projection_digest as core_digest,
};
use ogrl_core::constraints::{StorageOrigin, check, check_graph_parallel};
use ogrl_core::graph::Graph;
use ogrl_core::model::OgrlObject;
use ogrl_core::status::{self, compare_revisions};
use ogrl_core::time::parse_timestamp;
use ogrl_core::yaml::{self, ParseOptions};
use ogrl_oscal::{
    ImportOptions, RenderedFile, import_catalog_bytes, import_component_definition, index_only,
    render_oscal_package, render_ssp,
};

fn py_err(msg: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(msg.to_string())
}

fn parse_origin(origin: &str) -> PyResult<StorageOrigin> {
    match origin {
        "organization" | "org" => Ok(StorageOrigin::Organization),
        "library" => Ok(StorageOrigin::Library),
        "provider" => Ok(StorageOrigin::Provider),
        other => Err(py_err(format!(
            "unknown origin {other:?}; expected 'organization', 'library', or 'provider'"
        ))),
    }
}

fn parse_profile_override(profile: &str) -> PyResult<Option<StorageOrigin>> {
    match profile {
        "auto" => Ok(None),
        other => parse_origin(other).map(Some),
    }
}

fn parse_objects_json(objects_json: &str) -> Result<Vec<OgrlObject>, String> {
    let arr: Vec<Value> =
        serde_json::from_str(objects_json).map_err(|e| format!("invalid objects JSON: {e}"))?;
    arr.into_iter()
        .enumerate()
        .map(|(i, v)| OgrlObject::from_value(v).map_err(|e| format!("objects[{i}]: {e}")))
        .collect()
}

fn build_graph_from_json(
    objects_json: &str,
    library_ids: Vec<String>,
    provider_ids: Vec<String>,
) -> Result<Graph, String> {
    let objs = parse_objects_json(objects_json)?;
    Ok(Graph::new(objs, library_ids, provider_ids))
}

fn loaded_bundle_to_json(bundle: LoadedBundle) -> String {
    let objects: Vec<Value> = bundle
        .objects
        .iter()
        .map(|lo| lo.object.to_json_value())
        .collect();
    let out = json!({
        "manifest": bundle.manifest,
        "objects": objects,
        "diagnostics": bundle.diagnostics,
    });
    serde_json::to_string(&out).expect("bundle JSON serialization")
}

fn rendered_files_to_py<'py>(
    py: Python<'py>,
    files: Vec<RenderedFile>,
) -> Vec<(String, String, Bound<'py, PyBytes>)> {
    files
        .into_iter()
        .map(|f| (f.name, f.media_type, PyBytes::new(py, &f.content)))
        .collect()
}

/// Reusable indexed OGRL graph held in Rust memory.
///
/// Construct once from a directory, exchange bundle, or list of objects, then run
/// repeated `check_object`, `check_all`, `evaluate`, `summarize`, or `render_*`
/// calls with zero re-parsing overhead.
#[pyclass(frozen)]
struct OgrlGraph {
    inner: Graph,
}

#[pymethods]
impl OgrlGraph {
    /// Build a graph from JSON-encoded object list and optional library/provider ID sets.
    #[staticmethod]
    #[pyo3(signature = (objects_json, library_ids=vec![], provider_ids=vec![]))]
    fn from_json(
        py: Python<'_>,
        objects_json: &str,
        library_ids: Vec<String>,
        provider_ids: Vec<String>,
    ) -> PyResult<Self> {
        let graph = py
            .detach(|| build_graph_from_json(objects_json, library_ids, provider_ids))
            .map_err(py_err)?;
        Ok(Self { inner: graph })
    }

    /// Load a graph directly from a repository-form directory or exchange bundle path.
    #[staticmethod]
    #[pyo3(signature = (path, library=None, strict=true, profile="auto"))]
    fn from_path(
        py: Python<'_>,
        path: &str,
        library: Option<&str>,
        strict: bool,
        profile: &str,
    ) -> PyResult<Self> {
        let origin_override = parse_profile_override(profile)?;
        let graph = py
            .detach(|| -> Result<Graph, String> {
                let opts = ParseOptions { strict };
                let main =
                    read_path(Path::new(path), opts, origin_override).map_err(|e| e.to_string())?;
                if !main.diagnostics.is_empty() {
                    return Err(format!(
                        "{} parse/schema error(s): {}",
                        main.diagnostics.len(),
                        main.diagnostics[0].detail
                    ));
                }
                if let Some(lib_path) = library {
                    let lib = read_path(Path::new(lib_path), opts, Some(StorageOrigin::Library))
                        .map_err(|e| e.to_string())?;
                    if !lib.diagnostics.is_empty() {
                        return Err(format!(
                            "library has {} parse/schema error(s): {}",
                            lib.diagnostics.len(),
                            lib.diagnostics[0].detail
                        ));
                    }
                    let mut objs = Vec::with_capacity(lib.objects.len() + main.objects.len());
                    let mut lib_ids = Vec::with_capacity(lib.objects.len());
                    let mut prov_ids = Vec::new();
                    for lo in lib.objects {
                        lib_ids.push(lo.object.id().to_string());
                        objs.push(lo.object);
                    }
                    for lo in main.objects {
                        match lo.origin {
                            StorageOrigin::Library => lib_ids.push(lo.object.id().to_string()),
                            StorageOrigin::Provider => prov_ids.push(lo.object.id().to_string()),
                            StorageOrigin::Organization => {}
                        }
                        objs.push(lo.object);
                    }
                    Ok(Graph::new(objs, lib_ids, prov_ids))
                } else {
                    Ok(main.to_graph())
                }
            })
            .map_err(py_err)?;
        Ok(Self { inner: graph })
    }

    /// Number of objects in this graph.
    fn __len__(&self) -> usize {
        self.inner.objects.len()
    }

    /// Projection SHA-256 digest of all objects in this graph.
    fn digest(&self, py: Python<'_>) -> String {
        py.detach(|| core_digest(self.inner.objects.values()))
    }

    /// Check one object (JSON string) against this graph. Returns JSON list of violations.
    #[pyo3(signature = (object_json, origin="organization"))]
    fn check_object(&self, py: Python<'_>, object_json: &str, origin: &str) -> PyResult<String> {
        let storage_origin = parse_origin(origin)?;
        py.detach(|| -> Result<String, String> {
            let val: Value =
                serde_json::from_str(object_json).map_err(|e| format!("invalid JSON: {e}"))?;
            let obj = OgrlObject::from_value(val).map_err(|e| e.to_string())?;
            let violations = check(&obj, &self.inner, storage_origin);
            Ok(serde_json::to_string(&violations).expect("violation serialization"))
        })
        .map_err(py_err)
    }

    /// Check every object in this graph in parallel. Returns JSON list of diagnostics.
    fn check_all(&self, py: Python<'_>) -> String {
        py.detach(|| {
            let diags = check_graph_parallel(
                &self.inner,
                |id| {
                    if self.inner.is_library(id) {
                        StorageOrigin::Library
                    } else if self.inner.is_provider(id) {
                        StorageOrigin::Provider
                    } else {
                        StorageOrigin::Organization
                    }
                },
                |_| (None, None),
            );
            serde_json::to_string(&diags).expect("diagnostics serialization")
        })
    }

    /// Evaluate RFC 0001 §8 program status at RFC 3339 timestamp `at`. Returns JSON string.
    #[pyo3(signature = (program_id, at, framework_id=None))]
    fn evaluate(
        &self,
        py: Python<'_>,
        program_id: &str,
        at: &str,
        framework_id: Option<&str>,
    ) -> PyResult<String> {
        let instant = parse_timestamp(at).map_err(py_err)?;
        py.detach(|| -> Result<String, String> {
            let program = self
                .inner
                .program(program_id)
                .ok_or_else(|| format!("program {program_id} not found"))?;
            let st = status::evaluate(&self.inner, program, instant, framework_id);
            Ok(serde_json::to_string(&st).expect("status serialization"))
        })
        .map_err(py_err)
    }

    /// Compute RFC 0001 §8 readiness summary at RFC 3339 timestamp `at`. Returns JSON string.
    fn summarize(&self, py: Python<'_>, program_id: &str, at: &str) -> PyResult<String> {
        let instant = parse_timestamp(at).map_err(py_err)?;
        py.detach(|| -> Result<String, String> {
            let program = self
                .inner
                .program(program_id)
                .ok_or_else(|| format!("program {program_id} not found"))?;
            let sum = status::summarize(&self.inner, program, instant);
            Ok(serde_json::to_string(&sum).expect("summary serialization"))
        })
        .map_err(py_err)
    }

    /// Diff this graph against a candidate library object list (JSON string). Returns JSON string.
    fn compare_library(
        &self,
        py: Python<'_>,
        after_library_json: &str,
        at: &str,
    ) -> PyResult<String> {
        let instant = parse_timestamp(at).map_err(py_err)?;
        py.detach(|| -> Result<String, String> {
            let next_lib = parse_objects_json(after_library_json)?;
            let after = self.inner.with_library(next_lib);
            let diff = compare_revisions(&self.inner, &after, instant);
            Ok(serde_json::to_string(&diff).expect("diff serialization"))
        })
        .map_err(py_err)
    }

    /// Render the 6-document OSCAL 1.2.3 package (JSON, plus optional XML).
    #[pyo3(signature = (program_id, framework_id, at, include_xml=false))]
    fn render_oscal<'py>(
        &self,
        py: Python<'py>,
        program_id: &str,
        framework_id: &str,
        at: &str,
        include_xml: bool,
    ) -> PyResult<Vec<(String, String, Bound<'py, PyBytes>)>> {
        let instant = parse_timestamp(at).map_err(py_err)?;
        let files = py
            .detach(|| -> Result<Vec<RenderedFile>, String> {
                let program = self
                    .inner
                    .program(program_id)
                    .ok_or_else(|| format!("program {program_id} not found"))?;
                render_oscal_package(&self.inner, program, framework_id, instant, include_xml)
                    .map_err(|e| e.to_string())
            })
            .map_err(py_err)?;
        Ok(rendered_files_to_py(py, files))
    }

    /// Render the narrative SSP (`ssp.md`, `ssp.json`).
    fn render_ssp<'py>(
        &self,
        py: Python<'py>,
        program_id: &str,
        at: &str,
    ) -> PyResult<Vec<(String, String, Bound<'py, PyBytes>)>> {
        let instant = parse_timestamp(at).map_err(py_err)?;
        let files = py
            .detach(|| -> Result<Vec<RenderedFile>, String> {
                let program = self
                    .inner
                    .program(program_id)
                    .ok_or_else(|| format!("program {program_id} not found"))?;
                Ok(render_ssp(&self.inner, program, instant))
            })
            .map_err(py_err)?;
        Ok(rendered_files_to_py(py, files))
    }

    /// Import an OSCAL 1.2.3 component definition (JSON or XML) against this graph's library.
    fn import_oscal_component(&self, py: Python<'_>, content: &[u8]) -> PyResult<String> {
        py.detach(|| -> Result<String, String> {
            let imported =
                import_component_definition(content, &self.inner).map_err(|e| e.to_string())?;
            let objects: Vec<Value> = imported
                .objects
                .iter()
                .map(OgrlObject::to_json_value)
                .collect();
            let out = json!({
                "manifest": imported.manifest,
                "objects": objects,
                "warnings": imported.warnings,
            });
            Ok(serde_json::to_string(&out).expect("component bundle serialization"))
        })
        .map_err(py_err)
    }
}

// --- Stateless module functions ---------------------------------------------

#[pyfunction]
#[pyo3(signature = (text, strict=true))]
fn parse_yaml_json(py: Python<'_>, text: &str, strict: bool) -> PyResult<String> {
    py.detach(|| -> Result<String, String> {
        let (val, _) =
            yaml::parse_yaml_with_spans(text, ParseOptions { strict }).map_err(|errs| {
                errs.into_iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; ")
            })?;
        Ok(serde_json::to_string(&val).expect("JSON serialization"))
    })
    .map_err(py_err)
}

#[pyfunction]
#[pyo3(signature = (object_json, header_comment=None))]
fn format_yaml_str(
    py: Python<'_>,
    object_json: &str,
    header_comment: Option<&str>,
) -> PyResult<String> {
    py.detach(|| -> Result<String, String> {
        let val: Value =
            serde_json::from_str(object_json).map_err(|e| format!("invalid JSON: {e}"))?;
        Ok(yaml::format_yaml(&val, header_comment))
    })
    .map_err(py_err)
}

#[pyfunction]
fn canonical_json_bytes<'py>(py: Python<'py>, value_json: &str) -> PyResult<Bound<'py, PyBytes>> {
    let bytes = py
        .detach(|| -> Result<Vec<u8>, String> {
            let val: Value =
                serde_json::from_str(value_json).map_err(|e| format!("invalid JSON: {e}"))?;
            Ok(core_canonical_json(&val))
        })
        .map_err(py_err)?;
    Ok(PyBytes::new(py, &bytes))
}

#[pyfunction]
fn projection_digest_json(py: Python<'_>, objects_json: &str) -> PyResult<String> {
    py.detach(|| -> Result<String, String> {
        let objs = parse_objects_json(objects_json)?;
        Ok(core_digest(objs.iter()))
    })
    .map_err(py_err)
}

#[pyfunction]
#[pyo3(signature = (root, strict=true, profile="auto"))]
fn read_directory_json(
    py: Python<'_>,
    root: &str,
    strict: bool,
    profile: &str,
) -> PyResult<String> {
    let origin_override = parse_profile_override(profile)?;
    py.detach(|| -> Result<String, String> {
        let loaded = read_directory(Path::new(root), ParseOptions { strict }, origin_override)
            .map_err(|e| e.to_string())?;
        Ok(loaded_bundle_to_json(loaded))
    })
    .map_err(py_err)
}

#[pyfunction]
#[pyo3(signature = (content, strict=true, profile="auto"))]
fn read_exchange_json(
    py: Python<'_>,
    content: &str,
    strict: bool,
    profile: &str,
) -> PyResult<String> {
    let origin_override = parse_profile_override(profile)?;
    py.detach(|| -> Result<String, String> {
        let loaded = read_exchange(content, None, ParseOptions { strict }, origin_override)
            .map_err(|e| e.to_string())?;
        Ok(loaded_bundle_to_json(loaded))
    })
    .map_err(py_err)
}

#[pyfunction]
#[pyo3(signature = (path, library=None, strict=true, profile="auto"))]
fn lint_path_json(
    py: Python<'_>,
    path: &str,
    library: Option<&str>,
    strict: bool,
    profile: &str,
) -> PyResult<String> {
    let origin_override = parse_profile_override(profile)?;
    py.detach(|| -> Result<String, String> {
        let opts = ParseOptions { strict };
        let mut target =
            read_path(Path::new(path), opts, origin_override).map_err(|e| e.to_string())?;
        let mut diagnostics = std::mem::take(&mut target.diagnostics);

        let combined = if let Some(lib_path) = library {
            let lib = read_path(Path::new(lib_path), opts, Some(StorageOrigin::Library))
                .map_err(|e| e.to_string())?;
            let mut all_objs = Vec::with_capacity(lib.objects.len() + target.objects.len());
            let mut lib_ids = Vec::new();
            let mut prov_ids = Vec::new();
            for lo in &lib.objects {
                lib_ids.push(lo.object.id().to_string());
                all_objs.push(lo.object.clone());
            }
            for lo in &target.objects {
                match lo.origin {
                    StorageOrigin::Library => lib_ids.push(lo.object.id().to_string()),
                    StorageOrigin::Provider => prov_ids.push(lo.object.id().to_string()),
                    StorageOrigin::Organization => {}
                }
                all_objs.push(lo.object.clone());
            }
            Graph::new(all_objs, lib_ids, prov_ids)
        } else {
            target.to_graph()
        };

        let meta = target.metadata_index();
        let target_ids: HashSet<&str> = target.objects.iter().map(|lo| lo.object.id()).collect();
        let mut graph_diags = check_graph_parallel(
            &combined,
            |id| {
                meta.get(id)
                    .map(|(_, _, origin)| *origin)
                    .unwrap_or(StorageOrigin::Library)
            },
            |id| match meta.get(id) {
                Some((f, spans, _)) => (f.clone(), *spans),
                None => (None, None),
            },
        );
        graph_diags.retain(|d| {
            d.object_id
                .as_deref()
                .is_none_or(|id| target_ids.contains(id))
        });
        diagnostics.extend(graph_diags);

        let out = json!({
            "ok": diagnostics.is_empty(),
            "objects": target.objects.len(),
            "errors": diagnostics.len(),
            "diagnostics": diagnostics,
        });
        Ok(serde_json::to_string(&out).expect("lint JSON serialization"))
    })
    .map_err(py_err)
}

#[pyfunction]
#[pyo3(signature = (
    content,
    framework_id,
    name=None,
    publisher="NIST",
    source_uri=None,
    source_path=None,
    commit=None,
    resolve_catalog=None,
    resolve_framework=None,
))]
#[allow(clippy::too_many_arguments)]
fn import_oscal_catalog_json(
    py: Python<'_>,
    content: &[u8],
    framework_id: &str,
    name: Option<String>,
    publisher: &str,
    source_uri: Option<String>,
    source_path: Option<String>,
    commit: Option<String>,
    resolve_catalog: Option<&[u8]>,
    resolve_framework: Option<&str>,
) -> PyResult<String> {
    py.detach(|| -> Result<String, String> {
        let resolve_idx = match (resolve_catalog, resolve_framework) {
            (Some(raw), Some(fw)) => Some(index_only(raw, fw).map_err(|e| e.to_string())?),
            (Some(_), None) => {
                return Err("resolve_framework is required when resolve_catalog is set".into());
            }
            _ => None,
        };
        let opt = ImportOptions {
            framework_id: framework_id.to_string(),
            name,
            publisher: publisher.to_string(),
            source_uri,
            source_path,
            commit,
            version: None,
        };
        let output =
            import_catalog_bytes(content, &opt, resolve_idx.as_ref()).map_err(|e| e.to_string())?;
        let reqs: Vec<Value> = output
            .requirements
            .into_iter()
            .map(|(_, r)| OgrlObject::Requirement(r).to_json_value())
            .collect();
        let maps: Vec<Value> = output
            .mappings
            .into_iter()
            .map(|m| OgrlObject::Mapping(m).to_json_value())
            .collect();
        let out = json!({
            "framework_id": output.framework_id,
            "framework": OgrlObject::Framework(output.framework).to_json_value(),
            "requirements": reqs,
            "mappings": maps,
            "withdrawn_count": output.withdrawn_count,
            "objectives_count": output.objectives_count,
        });
        Ok(serde_json::to_string(&out).expect("catalog output serialization"))
    })
    .map_err(py_err)
}

#[pymodule]
fn _ogrl_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<OgrlGraph>()?;
    m.add_function(wrap_pyfunction!(parse_yaml_json, m)?)?;
    m.add_function(wrap_pyfunction!(format_yaml_str, m)?)?;
    m.add_function(wrap_pyfunction!(canonical_json_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(projection_digest_json, m)?)?;
    m.add_function(wrap_pyfunction!(read_directory_json, m)?)?;
    m.add_function(wrap_pyfunction!(read_exchange_json, m)?)?;
    m.add_function(wrap_pyfunction!(lint_path_json, m)?)?;
    m.add_function(wrap_pyfunction!(import_oscal_catalog_json, m)?)?;
    Ok(())
}
