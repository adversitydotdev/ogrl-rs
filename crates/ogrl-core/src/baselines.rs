//! Effective baseline resolution, RFC 0001 section 7.5.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::graph::Graph;
use crate::model::Baseline;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveBaseline {
    pub baseline_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extends_id: Option<String>,
    pub framework_ids: Vec<String>,
    pub control_ids: Vec<String>,
    pub requirement_ids: Vec<String>,
    #[serde(default)]
    pub parameter_bindings: BTreeMap<String, BTreeMap<String, String>>,
}

fn ordered_union(lists: Vec<Vec<String>>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for list in lists {
        for item in list {
            if seen.insert(item.clone()) {
                out.push(item);
            }
        }
    }
    out
}

/// `requirement_refs`, or every live non-withdrawn requirement of `framework_refs` when omitted.
pub fn own_requirements(graph: &Graph, baseline: &Baseline) -> Vec<String> {
    if let Some(refs) = &baseline.requirement_refs {
        if !refs.is_empty() {
            return refs.clone();
        }
    }
    let mut result = Vec::new();
    for fw_id in baseline.framework_refs.as_deref().unwrap_or(&[]) {
        for req in graph.requirements_for_framework(fw_id) {
            if !req.is_withdrawn() {
                result.push(req.id.clone());
            }
        }
    }
    result
}

/// Resolve a baseline including its 1-level `extends_ref` parent.
pub fn effective(graph: &Graph, baseline: &Baseline) -> EffectiveBaseline {
    let base = baseline
        .extends_ref
        .as_deref()
        .and_then(|id| graph.baseline(id));
    let mut layers: Vec<&Baseline> = Vec::with_capacity(2);
    if let Some(b) = base {
        layers.push(b);
    }
    layers.push(baseline);

    let mut bindings: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for layer in &layers {
        if let Some(pb) = &layer.parameter_bindings {
            for (target, values) in pb {
                let entry = bindings.entry(target.clone()).or_default();
                for (k, v) in values {
                    entry.insert(k.clone(), v.clone());
                }
            }
        }
    }

    let framework_ids = ordered_union(
        layers
            .iter()
            .map(|b| b.framework_refs.clone().unwrap_or_default())
            .collect(),
    );
    let control_ids = ordered_union(
        layers
            .iter()
            .map(|b| b.control_refs.clone().unwrap_or_default())
            .collect(),
    );
    let requirement_ids =
        ordered_union(layers.iter().map(|b| own_requirements(graph, b)).collect());

    EffectiveBaseline {
        baseline_id: baseline.id.clone(),
        extends_id: baseline.extends_ref.clone(),
        framework_ids,
        control_ids,
        requirement_ids,
        parameter_bindings: bindings,
    }
}
