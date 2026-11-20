//! Parameter resolution, RFC 0001 sections 7.3 and 7.4.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::graph::Graph;
use crate::ids;
use crate::model::{Control, Implementation};

static PLACEHOLDER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}").unwrap());

/// Unique placeholder parameter names in first-seen order.
pub fn placeholders(text: Option<&str>) -> Vec<String> {
    let Some(text) = text else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for cap in PLACEHOLDER_RE.captures_iter(text) {
        let name = cap[1].to_string();
        if seen.insert(name.clone()) {
            out.push(name);
        }
    }
    out
}

/// Resolve control parameters: implementation value -> baseline binding -> control default.
pub fn control_values(
    control: &Control,
    implementation: Option<&Implementation>,
    bindings: &BTreeMap<String, BTreeMap<String, String>>,
) -> BTreeMap<String, Option<String>> {
    let mut names = Vec::new();
    let mut seen = HashSet::new();
    if let Some(params) = &control.parameters {
        for k in params.keys() {
            if seen.insert(k.clone()) {
                names.push(k.clone());
            }
        }
    }
    for name in placeholders(Some(&control.statement)) {
        if seen.insert(name.clone()) {
            names.push(name);
        }
    }

    let own = implementation.and_then(|i| i.parameter_values.as_ref());
    let bound = bindings.get(&control.id);
    let mut values = BTreeMap::new();
    for name in names {
        let val = own
            .and_then(|m| m.get(&name))
            .filter(|v| !v.is_empty())
            .or_else(|| bound.and_then(|m| m.get(&name)).filter(|v| !v.is_empty()))
            .or_else(|| {
                control
                    .parameters
                    .as_ref()
                    .and_then(|m| m.get(&name))
                    .and_then(|p| p.value.as_ref())
                    .filter(|v| !v.is_empty())
            })
            .cloned();
        values.insert(name, val);
    }
    values
}

/// Parameters named in `control.statement` that have no resolved value for this program.
pub fn unresolved(
    control: &Control,
    implementation: Option<&Implementation>,
    bindings: &BTreeMap<String, BTreeMap<String, String>>,
) -> Vec<String> {
    let values = control_values(control, implementation, bindings);
    placeholders(Some(&control.statement))
        .into_iter()
        .filter(|name| {
            values
                .get(name)
                .and_then(|v| v.as_deref())
                .is_none_or(str::is_empty)
        })
        .collect()
}

/// Substitute resolved parameter values into prose, leaving unbound placeholders intact.
pub fn render(text: Option<&str>, values: &BTreeMap<String, Option<String>>) -> String {
    let Some(text) = text else {
        return String::new();
    };
    PLACEHOLDER_RE
        .replace_all(text, |caps: &regex::Captures<'_>| {
            let name = &caps[1];
            match values.get(name).and_then(|v| v.as_deref()) {
                Some(v) if !v.is_empty() => v.to_string(),
                _ => caps[0].to_string(),
            }
        })
        .into_owned()
}

/// Resolve one target-framework parameter (RFC 0001 §7.4):
/// implementation `requirement_parameter_values` -> baseline literal -> unique `parameter_map`.
pub fn requirement_value(
    graph: &Graph,
    requirement_id: &str,
    key: &str,
    program_controls: &[String],
    implementations: &HashMap<String, &Implementation>,
    bindings: &BTreeMap<String, BTreeMap<String, String>>,
) -> Option<String> {
    let controls: HashSet<&str> = program_controls.iter().map(String::as_str).collect();
    let mappings = graph.mappings_by_target(requirement_id);

    let mut sources = BTreeSet::new();
    let mut candidates = Vec::new();
    for m in &mappings {
        if !controls.contains(m.source_ref.as_str()) {
            continue;
        }
        sources.insert(m.source_ref.as_str());
        if let Some(pm) = &m.parameter_map {
            if let Some(ctrl_param) = pm.get(key) {
                candidates.push((*m, ctrl_param.as_str()));
            }
        }
    }

    for source in sources {
        if let Some(impl_row) = implementations.get(source) {
            if let Some(val) = impl_row
                .requirement_parameter_values
                .as_ref()
                .and_then(|m| m.get(requirement_id))
                .and_then(|m| m.get(key))
                .filter(|v| !v.is_empty())
            {
                return Some(val.clone());
            }
        }
    }

    if let Some(literal) = bindings
        .get(requirement_id)
        .and_then(|m| m.get(key))
        .filter(|v| !v.is_empty())
    {
        return Some(literal.clone());
    }

    let unique: HashSet<(&str, &str)> = candidates
        .iter()
        .map(|(m, name)| (m.source_ref.as_str(), *name))
        .collect();
    if unique.len() != 1 {
        return None;
    }
    let (mapping, name) = candidates[0];
    let control = graph.control(&mapping.source_ref)?;
    let values = control_values(control, implementations.get(&control.id).copied(), bindings);
    values.get(name).cloned().flatten()
}

/// All parameter keys defined on a requirement.
pub fn requirement_parameter_keys(graph: &Graph, requirement_id: &str) -> Vec<String> {
    let Some(req) = graph.requirement(ids::base(requirement_id)) else {
        return Vec::new();
    };
    req.parameters
        .as_ref()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}
