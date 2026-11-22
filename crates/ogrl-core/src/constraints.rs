//! Graph constraints & linter diagnostics, RFC 0001 section 7.20 and RFC 0002.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::LazyLock;

use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::graph::{Graph, objective_exists, part_ids};
use crate::ids;
use crate::model::{
    Baseline, Component, Control, ControlOrigin, DocumentStatus, Evidence, ExceptionObj, Finding,
    Implementation, Mapping, MappingReview, OgrlObject, Policy, Procedure, Program, Requirement,
    Responsibility, Risk, RiskStatus, System, SystemPartyRole, Test, TestMethod, TestResult,
    Treatment,
};
use crate::yaml::{Span, SpanMap};

static ENV_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap());
static TIMEOUT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([1-9][0-9]*)([sm])$").unwrap());

pub const MAX_TIMEOUT_SECONDS: u64 = 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageOrigin {
    Organization,
    Library,
    Provider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    pub pointer: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub conflict: bool,
    #[serde(default)]
    pub severity: Severity,
}

/// A rich diagnostic combining object ID, file path, source span, JSON pointer, and message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col: Option<usize>,
    pub pointer: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub conflict: bool,
}

/// Parse `run.timeout`: positive integer + `s` or `m`, at most `60m`. Defaults to 300s.
pub fn timeout_seconds(value: Option<&str>) -> Result<u64, String> {
    let Some(value) = value else {
        return Ok(300);
    };
    let Some(caps) = TIMEOUT_RE.captures(value) else {
        return Err("timeout is a positive integer followed by s or m".to_string());
    };
    let n: u64 = caps[1]
        .parse()
        .map_err(|_| "timeout integer overflow".to_string())?;
    let mult = if &caps[2] == "m" { 60 } else { 1 };
    let seconds = n.saturating_mul(mult);
    if seconds > MAX_TIMEOUT_SECONDS {
        return Err("timeout is at most 60m".to_string());
    }
    Ok(seconds)
}

struct Checker<'a> {
    graph: &'a Graph,
    origin: StorageOrigin,
    out: Vec<Violation>,
}

impl<'a> Checker<'a> {
    fn new(graph: &'a Graph, origin: StorageOrigin) -> Self {
        Self {
            graph,
            origin,
            out: Vec::new(),
        }
    }

    fn fail(&mut self, pointer: impl Into<String>, detail: impl Into<String>) {
        self.out.push(Violation {
            pointer: pointer.into(),
            detail: detail.into(),
            conflict: false,
            severity: Severity::Error,
        });
    }

    fn warn(&mut self, pointer: impl Into<String>, detail: impl Into<String>) {
        self.out.push(Violation {
            pointer: pointer.into(),
            detail: detail.into(),
            conflict: false,
            severity: Severity::Warning,
        });
    }

    fn conflict(&mut self, pointer: impl Into<String>, detail: impl Into<String>) {
        self.out.push(Violation {
            pointer: pointer.into(),
            detail: detail.into(),
            conflict: true,
            severity: Severity::Error,
        });
    }

    fn check_ref(
        &mut self,
        pointer: &str,
        value: Option<&str>,
        types: &[&str],
        allow_fragment: bool,
    ) -> bool {
        let Some(value) = value else {
            return false;
        };
        if !allow_fragment && value.contains('#') {
            self.fail(
                pointer,
                "this reference takes an object id without a fragment",
            );
            return false;
        }
        let Some(kind) = ids::type_of(value) else {
            self.fail(pointer, format!("{value} is not an OGRL id"));
            return false;
        };
        if !types.contains(&kind) {
            self.fail(pointer, format!("{value} must be a {}", types.join(" or ")));
            return false;
        }
        if self.graph.get(value).is_none() {
            self.fail(pointer, format!("{} does not resolve", ids::base(value)));
            return false;
        }
        true
    }

    fn check_refs(&mut self, pointer: &str, values: Option<&[String]>, types: &[&str]) {
        for (idx, val) in values.unwrap_or(&[]).iter().enumerate() {
            self.check_ref(
                &format!("{pointer}/{idx}"),
                Some(val.as_str()),
                types,
                false,
            );
        }
    }

    fn check_objective(&mut self, pointer: &str, value: &str) {
        if ids::objective_of(value).is_none() {
            self.fail(
                pointer,
                "an objective reference is a requirement id plus #obj.<id>",
            );
        } else if !objective_exists(self.graph, value) {
            self.fail(
                pointer,
                format!("{value} does not match an objective on that requirement"),
            );
        }
    }
}

/// Check RFC 0001 §7.20 and RFC 0002 constraints for one object against a graph.
pub fn check(obj: &OgrlObject, graph: &Graph, origin: StorageOrigin) -> Vec<Violation> {
    let mut c = Checker::new(graph, origin);

    // Storage origin type & namespace rules (RFC 0002 §§3, 7).
    match origin {
        StorageOrigin::Library => {
            if !obj.object_type().is_library_type() {
                c.fail(
                    "/type",
                    format!("a {} is not a library object", obj.object_type()),
                );
            }
        }
        StorageOrigin::Provider => {
            if !obj.object_type().is_provider_type() {
                c.fail(
                    "/type",
                    format!("a provider bundle does not carry a {}", obj.object_type()),
                );
            }
            if ids::is_reserved(obj.id()).unwrap_or(true) {
                c.fail(
                    "/id",
                    "a provider does not mint ids in the standard-library space",
                );
            }
        }
        StorageOrigin::Organization => {}
    }

    match obj {
        OgrlObject::Requirement(r) => check_requirement(&mut c, r),
        OgrlObject::Control(ctrl) => check_control(&mut c, ctrl),
        OgrlObject::Mapping(m) => check_mapping(&mut c, m),
        OgrlObject::Baseline(b) => check_baseline(&mut c, b),
        OgrlObject::Test(t) => check_test(&mut c, t),
        OgrlObject::Component(comp) => check_component(&mut c, comp),
        OgrlObject::System(sys) => check_system(&mut c, sys),
        OgrlObject::Program(p) => check_program(&mut c, p),
        OgrlObject::Implementation(i) => check_implementation(&mut c, i),
        OgrlObject::Result(r) => check_result(&mut c, r),
        OgrlObject::Finding(f) => check_finding(&mut c, f),
        OgrlObject::Evidence(e) => check_evidence(&mut c, e),
        OgrlObject::Policy(p) => check_policy(&mut c, p),
        OgrlObject::Procedure(p) => check_procedure(&mut c, p),
        OgrlObject::Risk(r) => check_risk(&mut c, r),
        OgrlObject::Exception(e) => check_exception(&mut c, e),
        OgrlObject::MappingReview(r) => check_mapping_review(&mut c, r),
        OgrlObject::Framework(_) | OgrlObject::Party(_) => {}
    }
    check_library_id_conventions(&mut c, obj);
    c.out
}

fn check_library_id_conventions(c: &mut Checker<'_>, obj: &OgrlObject) {
    if c.origin != StorageOrigin::Library {
        return;
    }
    let id = obj.id();
    let Ok((kind, remainder)) = ids::split(id) else {
        return;
    };
    if ids::is_reserved(id).unwrap_or(false) && kind != "mapping" && remainder.contains('_') {
        c.fail(
            "/id",
            "standard-library ids use underscores only in derived mapping _to_ / _part_ joins",
        );
    }
    if let OgrlObject::Mapping(m) = obj {
        if !ids::is_reserved(id).unwrap_or(false) {
            return;
        }
        let Ok(expected) = ids::derived_mapping_id(&m.source_ref, &m.target_ref) else {
            return;
        };
        if id == expected {
            return;
        }
        let legacy_delimiter = remainder.contains("-to-") && !remainder.contains("_to_");
        let detail = if legacy_delimiter {
            format!(
                "mapping id should follow RFC 0001 section 6.3 derived form {expected} (use _to_ and _part_, not -to-)"
            )
        } else {
            format!("mapping id should follow RFC 0001 section 6.3 derived form {expected}")
        };
        if crate::model::spec_is_0_2(obj.spec_version()) {
            c.fail("/id", detail);
        } else {
            c.warn("/id", detail);
        }
    }
}

fn check_requirement(c: &mut Checker<'_>, r: &Requirement) {
    c.check_ref(
        "/framework_ref",
        Some(&r.framework_ref),
        &["framework"],
        false,
    );
    let mut seen_parts = HashSet::new();
    for (idx, part) in r.parts.as_deref().unwrap_or(&[]).iter().enumerate() {
        if !seen_parts.insert(part.id.as_str()) {
            c.conflict(
                format!("/parts/{idx}/id"),
                format!("duplicate requirement part id {:?}", part.id),
            );
        }
    }
    let mut seen_objs = HashSet::new();
    for (idx, obj) in r.objectives.as_deref().unwrap_or(&[]).iter().enumerate() {
        if !seen_objs.insert(obj.id.as_str()) {
            c.conflict(
                format!("/objectives/{idx}/id"),
                format!("duplicate assessment objective id {:?}", obj.id),
            );
        }
    }
}

fn check_control(c: &mut Checker<'_>, ctrl: &Control) {
    if c.origin == StorageOrigin::Organization && ctrl.origin == ControlOrigin::Standard {
        c.fail("/origin", "an organization control has origin custom");
    }
    if c.origin == StorageOrigin::Library && ctrl.origin != ControlOrigin::Standard {
        c.fail("/origin", "library controls have origin standard");
    }
}

fn check_mapping(c: &mut Checker<'_>, m: &Mapping) {
    for other in c.graph.mappings() {
        if other.id == m.id {
            continue;
        }
        if other
            .combined_with_refs
            .as_deref()
            .unwrap_or(&[])
            .contains(&m.id)
            && !m.is_revoked()
        {
            if m.target_ref != other.target_ref {
                c.fail(
                    "/target_ref",
                    format!("this mapping is in the combined set on {}", other.id),
                );
            }
            if ids::type_of(&m.source_ref) != Some("control") || !m.relationship.is_contribution() {
                c.fail(
                    "/relationship",
                    format!(
                        "a member of the combined set on {} is a control mapping with subset-of or intersects-with",
                        other.id
                    ),
                );
            }
        }
    }

    if c.check_ref("/target_ref", Some(&m.target_ref), &["requirement"], true) {
        if let Some(frag) = ids::fragment(&m.target_ref) {
            if let Some(req) = c.graph.requirement(&m.target_ref) {
                if !part_ids(req).contains(&frag) {
                    c.fail(
                        "/target_ref",
                        format!("#{frag} is not a part of {}", req.id),
                    );
                }
            }
        }
    }
    c.check_ref(
        "/source_ref",
        Some(&m.source_ref),
        &["control", "requirement"],
        false,
    );
    let source_is_control = ids::type_of(&m.source_ref) == Some("control");

    if let Some(pm) = &m.parameter_map {
        if !pm.is_empty() {
            if !source_is_control {
                c.fail(
                    "/parameter_map",
                    "parameter_map needs a control as source_ref",
                );
            }
            let ctrl = c.graph.control(&m.source_ref);
            let req = c.graph.requirement(&m.target_ref);
            for (key, name) in pm {
                if let Some(r) = req {
                    if !r.parameters.as_ref().is_some_and(|p| p.contains_key(key)) {
                        c.fail(
                            format!("/parameter_map/{key}"),
                            format!("{key} is not a parameter of {}", r.id),
                        );
                    }
                }
                if let Some(ctl) = ctrl {
                    if !ctl
                        .parameters
                        .as_ref()
                        .is_some_and(|p| p.contains_key(name))
                    {
                        c.fail(
                            format!("/parameter_map/{key}"),
                            format!("{name} is not a parameter of {}", ctl.id),
                        );
                    }
                }
            }
        }
    }

    if let Some(combined) = &m.combined_with_refs {
        if !combined.is_empty() {
            if !source_is_control || !m.relationship.is_contribution() {
                c.fail(
                    "/combined_with_refs",
                    "a combined set has controls as sources and subset-of or intersects-with",
                );
            }
            let mut members: HashSet<&str> = HashSet::new();
            members.insert(&m.id);
            for (idx, r) in combined.iter().enumerate() {
                members.insert(r);
                let ptr = format!("/combined_with_refs/{idx}");
                if !c.check_ref(&ptr, Some(r), &["mapping"], false) {
                    continue;
                }
                if let Some(member) = c.graph.mapping(r) {
                    if member.target_ref != m.target_ref {
                        c.fail(&ptr, format!("{r} has a different target_ref"));
                    }
                    if ids::type_of(&member.source_ref) != Some("control")
                        || !member.relationship.is_contribution()
                    {
                        c.fail(
                            &ptr,
                            format!(
                                "{r} is not a control mapping with subset-of or intersects-with"
                            ),
                        );
                    }
                }
            }
            for other in c.graph.mappings() {
                if other.id == m.id {
                    continue;
                }
                if let Some(other_c) = &other.combined_with_refs {
                    if !other_c.is_empty()
                        && (members.contains(other.id.as_str())
                            || other_c.iter().any(|x| members.contains(x.as_str())))
                    {
                        c.fail(
                            "/combined_with_refs",
                            format!("a mapping here is already in the set on {}", other.id),
                        );
                    }
                }
            }
        }
    }

    if matches!(
        c.origin,
        StorageOrigin::Organization | StorageOrigin::Library
    ) {
        for other in c.graph.mappings() {
            if other.id == m.id || m.is_revoked() || other.is_revoked() {
                continue;
            }
            let same_scope = match c.origin {
                StorageOrigin::Organization => c.graph.is_organization(&other.id),
                StorageOrigin::Library => c.graph.is_library(&other.id),
                StorageOrigin::Provider => false,
            };
            if same_scope && other.source_ref == m.source_ref && other.target_ref == m.target_ref {
                c.conflict(
                    "/target_ref",
                    format!("{} already maps this source and target", other.id),
                );
            }
        }
    }
}

fn check_baseline(c: &mut Checker<'_>, b: &Baseline) {
    if let Some(ext) = &b.extends_ref {
        if c.graph
            .baselines()
            .iter()
            .any(|o| o.id != b.id && o.extends_ref.as_deref() == Some(b.id.as_str()))
        {
            c.fail(
                "/extends_ref",
                "another baseline extends this one; one level deep",
            );
        }
        if c.check_ref("/extends_ref", Some(ext), &["baseline"], false) {
            if ext == &b.id {
                c.fail("/extends_ref", "a baseline does not extend itself");
            } else if let Some(base) = c.graph.baseline(ext) {
                if base.extends_ref.is_some() {
                    c.fail(
                        "/extends_ref",
                        format!("{ext} extends another baseline; one level deep"),
                    );
                }
            }
        }
        if c.origin == StorageOrigin::Library {
            c.fail("/extends_ref", "a library baseline has no extends_ref");
        }
    }
    c.check_refs(
        "/framework_refs",
        b.framework_refs.as_deref(),
        &["framework"],
    );
    for (idx, r) in b.control_refs.as_deref().unwrap_or(&[]).iter().enumerate() {
        let ptr = format!("/control_refs/{idx}");
        if c.check_ref(&ptr, Some(r), &["control"], false) && c.origin == StorageOrigin::Library {
            if let Some(ctrl) = c.graph.control(r) {
                if ctrl.origin != ControlOrigin::Standard {
                    c.fail(&ptr, "a library baseline lists standard controls only");
                }
            }
        }
    }
    let fw_refs = b.framework_refs.as_deref().unwrap_or(&[]);
    for (idx, r) in b
        .requirement_refs
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .enumerate()
    {
        let ptr = format!("/requirement_refs/{idx}");
        if !c.check_ref(&ptr, Some(r), &["requirement"], false) {
            continue;
        }
        if let Some(req) = c.graph.requirement(r) {
            if req.is_withdrawn() {
                c.fail(&ptr, format!("{r} is withdrawn"));
            }
            if !fw_refs.contains(&req.framework_ref) {
                c.fail(
                    &ptr,
                    format!("{r} is not in one of this baseline's framework_refs"),
                );
            }
        }
    }
    if let Some(pb) = &b.parameter_bindings {
        for key in pb.keys() {
            c.check_ref(
                &format!("/parameter_bindings/{key}"),
                Some(key),
                &["control", "requirement"],
                false,
            );
        }
    }
}

fn check_test(c: &mut Checker<'_>, t: &Test) {
    c.check_ref("/control_ref", Some(&t.control_ref), &["control"], false);
    for other in c.graph.tests() {
        if other.id != t.id
            && other.fulfills_ref.as_deref() == Some(t.id.as_str())
            && !t.is_revoked()
        {
            if t.fulfills_ref.is_some() {
                c.fail(
                    "/fulfills_ref",
                    format!("{} fulfills this test; one level deep", other.id),
                );
            }
            if other.control_ref != t.control_ref {
                c.fail(
                    "/control_ref",
                    format!("{} fulfills this test with another control", other.id),
                );
            }
        }
    }
    if let Some(fref) = &t.fulfills_ref {
        if c.check_ref("/fulfills_ref", Some(fref), &["test"], false) {
            if fref == &t.id {
                c.fail("/fulfills_ref", "a test does not fulfill itself");
            } else if let Some(target) = c.graph.test(fref) {
                if target.control_ref != t.control_ref {
                    c.fail(
                        "/fulfills_ref",
                        "fulfills_ref points at a test with the same control_ref",
                    );
                }
                if target.fulfills_ref.is_some() {
                    c.fail(
                        "/fulfills_ref",
                        format!("{} fulfills another test; one level deep", target.id),
                    );
                }
            }
        }
    }
    if t.system_refs.as_ref().is_some_and(|s| !s.is_empty())
        && c.origin != StorageOrigin::Organization
    {
        c.fail(
            "/system_refs",
            "library and provider tests do not set system_refs",
        );
    }
    c.check_refs("/system_refs", t.system_refs.as_deref(), &["system"]);
    for (idx, r) in t
        .objective_refs
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .enumerate()
    {
        c.check_objective(&format!("/objective_refs/{idx}"), r);
    }
    c.check_ref(
        "/procedure_ref",
        t.procedure_ref.as_deref(),
        &["procedure"],
        false,
    );

    let Some(run) = &t.run else {
        return;
    };
    if c.origin == StorageOrigin::Provider {
        c.fail("/run", "a provider test describes a check and has no run");
    }
    if t.method == TestMethod::Manual {
        c.fail("/run", "a manual test has no run block");
    }
    match run.runner.as_str() {
        "shell" => {
            if run.command.as_deref().is_none_or(str::is_empty) {
                c.fail("/run/command", "runner shell requires command");
            }
        }
        "rule" => check_rule_run(c, run),
        "integration" => check_integration_run(c, run),
        _ => {}
    }
    if let Err(msg) = timeout_seconds(run.timeout.as_deref()) {
        c.fail("/run/timeout", msg);
    }
    for (idx, name) in run.env.as_deref().unwrap_or(&[]).iter().enumerate() {
        if !ENV_NAME_RE.is_match(name) {
            c.fail(
                format!("/run/env/{idx}"),
                "env lists variable names, not values",
            );
        }
    }
    for (idx, item) in run.evidence.as_deref().unwrap_or(&[]).iter().enumerate() {
        let p = &item.path;
        let has_dotdot = p.split('/').any(|seg| seg == "..");
        if p.starts_with('/') || p.starts_with('\\') || has_dotdot {
            c.fail(
                format!("/run/evidence/{idx}/path"),
                "a relative path with no ..",
            );
        }
    }
}

fn check_component(c: &mut Checker<'_>, comp: &Component) {
    c.check_ref("/party_ref", comp.party_ref.as_deref(), &["party"], false);
}

fn check_system(c: &mut Checker<'_>, s: &System) {
    c.check_refs(
        "/component_refs",
        s.component_refs.as_deref(),
        &["component"],
    );
    let own: HashSet<&str> = s
        .component_refs
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(String::as_str)
        .collect();
    for (i, info) in s
        .information_types
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .enumerate()
    {
        for (j, r) in info
            .component_refs
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .enumerate()
        {
            if !own.contains(r.as_str()) {
                c.fail(
                    format!("/information_types/{i}/component_refs/{j}"),
                    "not one of the system's components",
                );
            }
        }
    }
    for (i, party) in s.parties.as_deref().unwrap_or(&[]).iter().enumerate() {
        c.check_ref(
            &format!("/parties/{i}/party_ref"),
            Some(&party.party_ref),
            &["party"],
            false,
        );
        if party.authorization.is_some() && party.role != SystemPartyRole::Subservice {
            c.fail(
                format!("/parties/{i}/authorization"),
                "authorization belongs on a subservice party",
            );
        }
    }
}

fn check_program(c: &mut Checker<'_>, p: &Program) {
    c.check_ref("/system_ref", Some(&p.system_ref), &["system"], false);
    c.check_ref("/baseline_ref", Some(&p.baseline_ref), &["baseline"], false);
}

fn check_implementation(c: &mut Checker<'_>, i: &Implementation) {
    if i.system_ref.is_none() && i.component_ref.is_none() {
        c.fail(
            "/system_ref",
            "an implementation has system_ref, component_ref, or both",
        );
    }
    if i.control_ref.is_none() && i.requirement_ref.is_none() {
        c.fail(
            "/control_ref",
            "an implementation has control_ref, requirement_ref, or both",
        );
    }
    c.check_ref("/system_ref", i.system_ref.as_deref(), &["system"], false);
    c.check_ref(
        "/component_ref",
        i.component_ref.as_deref(),
        &["component"],
        false,
    );
    c.check_ref(
        "/control_ref",
        i.control_ref.as_deref(),
        &["control"],
        false,
    );
    c.check_ref(
        "/requirement_ref",
        i.requirement_ref.as_deref(),
        &["requirement"],
        false,
    );
    c.check_ref("/owner_ref", i.owner_ref.as_deref(), &["party"], false);
    c.check_ref(
        "/subservice_ref",
        i.subservice_ref.as_deref(),
        &["party"],
        false,
    );
    if i.responsibility == Responsibility::Subservice
        && i.subservice_ref.is_none()
        && !i.is_provider()
    {
        c.fail(
            "/subservice_ref",
            "responsibility subservice names the party in subservice_ref",
        );
    }
    if i.is_provider()
        && matches!(
            i.responsibility,
            Responsibility::Shared | Responsibility::Customer
        )
        && i.customer_responsibility
            .as_deref()
            .is_none_or(str::is_empty)
    {
        c.fail(
            "/customer_responsibility",
            "provider implementations with responsibility shared or customer require customer_responsibility",
        );
    }
    if i.is_revoked() || i.control_ref.is_none() {
        return;
    }
    for other in c.graph.implementations() {
        if other.id == i.id || other.control_ref != i.control_ref {
            continue;
        }
        let same = other.system_ref == i.system_ref
            && other.component_ref == i.component_ref
            && (i.system_ref.is_some() || i.component_ref.is_some());
        if same {
            c.conflict(
                "/control_ref",
                format!("{} already implements this control here", other.id),
            );
        }
    }
}

fn check_result(c: &mut Checker<'_>, r: &TestResult) {
    let test_ok = c.check_ref("/test_ref", Some(&r.test_ref), &["test"], false);
    let impl_ok = c.check_ref(
        "/implementation_ref",
        Some(&r.implementation_ref),
        &["implementation"],
        false,
    );
    if test_ok && impl_ok {
        if let (Some(test), Some(imp)) = (
            c.graph.test(&r.test_ref),
            c.graph.implementation(&r.implementation_ref),
        ) {
            if imp.control_ref.as_deref() != Some(test.control_ref.as_str()) {
                c.fail(
                    "/implementation_ref",
                    "the test's control and the implementation's control differ",
                );
            }
        }
    }
    for (idx, oref) in r
        .objective_refs
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .enumerate()
    {
        c.check_objective(&format!("/objective_refs/{idx}"), oref);
    }
    c.check_refs("/evidence_refs", r.evidence_refs.as_deref(), &["evidence"]);
}

fn check_finding(c: &mut Checker<'_>, f: &Finding) {
    c.check_ref("/system_ref", Some(&f.system_ref), &["system"], false);
    c.check_objective("/objective_ref", &f.objective_ref);
    c.check_ref(
        "/implementation_ref",
        f.implementation_ref.as_deref(),
        &["implementation"],
        false,
    );
    c.check_refs("/evidence_refs", f.evidence_refs.as_deref(), &["evidence"]);
    c.check_ref("/risk_ref", f.risk_ref.as_deref(), &["risk"], false);
}

fn check_evidence(c: &mut Checker<'_>, e: &Evidence) {
    if e.implementation_ref.is_none() && e.result_ref.is_none() {
        c.fail(
            "/implementation_ref",
            "evidence has implementation_ref, result_ref, or both",
        );
    }
    c.check_ref(
        "/implementation_ref",
        e.implementation_ref.as_deref(),
        &["implementation"],
        false,
    );
    c.check_ref("/result_ref", e.result_ref.as_deref(), &["result"], false);
    if let (Some(vf), Some(vu)) = (e.valid_from, e.valid_until) {
        if vu < vf {
            c.fail("/valid_until", "valid_until is before valid_from");
        }
    }
}

fn check_policy(c: &mut Checker<'_>, p: &Policy) {
    c.check_ref("/owner_ref", p.owner_ref.as_deref(), &["party"], false);
    c.check_refs("/control_refs", p.control_refs.as_deref(), &["control"]);
    if p.status == DocumentStatus::Adopted {
        if p.resource
            .as_ref()
            .and_then(|r| r.digest.as_ref())
            .is_none()
        {
            c.fail(
                "/status",
                "an adopted document requires resource.digest; upload its content first",
            );
        }
        if p.owner_ref.is_none() {
            c.fail("/owner_ref", "an adopted document requires owner_ref");
        }
        if p.adopted.is_none() {
            c.fail("/adopted", "an adopted policy requires the adopted date");
        }
    }
}

fn check_procedure(c: &mut Checker<'_>, p: &Procedure) {
    c.check_ref("/owner_ref", p.owner_ref.as_deref(), &["party"], false);
    c.check_refs("/control_refs", p.control_refs.as_deref(), &["control"]);
    c.check_ref("/policy_ref", p.policy_ref.as_deref(), &["policy"], false);
    if p.status == DocumentStatus::Adopted {
        if p.resource
            .as_ref()
            .and_then(|r| r.digest.as_ref())
            .is_none()
        {
            c.fail(
                "/status",
                "an adopted document requires resource.digest; upload its content first",
            );
        }
        if p.owner_ref.is_none() {
            c.fail("/owner_ref", "an adopted document requires owner_ref");
        }
    }
}

fn check_risk(c: &mut Checker<'_>, r: &Risk) {
    c.check_ref("/system_ref", r.system_ref.as_deref(), &["system"], false);
    c.check_ref("/owner_ref", r.owner_ref.as_deref(), &["party"], false);
    c.check_ref(
        "/approver_ref",
        r.approver_ref.as_deref(),
        &["party"],
        false,
    );
    c.check_refs("/control_refs", r.control_refs.as_deref(), &["control"]);
    if r.status == RiskStatus::Accepted {
        if r.treatment != Treatment::Accept {
            c.fail("/treatment", "status accepted requires treatment accept");
        }
        if r.approver_ref.is_none() {
            c.fail("/approver_ref", "status accepted requires approver_ref");
        }
        if r.review_on.is_none() {
            c.fail("/review_on", "status accepted requires review_on");
        }
    }
    let created_date = r.created.date_naive();
    for (idx, m) in r.milestones.as_deref().unwrap_or(&[]).iter().enumerate() {
        if let Some(done) = m.done {
            if done < created_date {
                c.fail(
                    format!("/milestones/{idx}/done"),
                    "done is on or after the risk's created date",
                );
            }
        }
    }
}

fn check_exception(c: &mut Checker<'_>, e: &ExceptionObj) {
    if c.check_ref(
        "/implementation_ref",
        Some(&e.implementation_ref),
        &["implementation"],
        false,
    ) {
        if let Some(target) = c.graph.implementation(&e.implementation_ref) {
            if target.is_provider() || !c.graph.is_organization(&target.id) {
                c.fail(
                    "/implementation_ref",
                    "an exception waives an organization implementation; write one for the system",
                );
            }
        }
    }
    c.check_ref("/approver_ref", Some(&e.approver_ref), &["party"], false);
    c.check_ref("/risk_ref", e.risk_ref.as_deref(), &["risk"], false);
}

fn run_extra_str<'a>(run: &'a crate::model::RunSpec, key: &str) -> Option<&'a str> {
    run.extra.get(key).and_then(serde_json::Value::as_str)
}

fn run_extra_str_list<'a>(run: &'a crate::model::RunSpec, key: &str) -> Option<Vec<&'a str>> {
    run.extra
        .get(key)
        .and_then(|v| v.as_array())
        .map(|items| items.iter().filter_map(serde_json::Value::as_str).collect())
}

fn check_rule_run(c: &mut Checker<'_>, run: &crate::model::RunSpec) {
    let source = run_extra_str(run, "source");
    let Some(source) = source else {
        c.fail("/run/source", "runner rule requires source");
        return;
    };
    if !ids::is_run_source(source) {
        c.fail(
            "/run/source",
            format!("source must be <integration>/<resource>@<major>, not {source:?}"),
        );
    }
    let has_assert = run_extra_str(run, "assert").is_some();
    let has_aggregate = run_extra_str(run, "aggregate").is_some();
    if has_assert == has_aggregate {
        c.fail(
            "/run/assert",
            "runner rule requires exactly one of assert or aggregate",
        );
    }
}

fn check_integration_run(c: &mut Checker<'_>, run: &crate::model::RunSpec) {
    let check = run_extra_str(run, "check");
    let Some(check) = check else {
        c.fail("/run/check", "runner integration requires check");
        return;
    };
    if !ids::is_run_source(check) {
        c.fail(
            "/run/check",
            format!("check must be <integration>/<check>@<major>, not {check:?}"),
        );
    }
    let sources = run_extra_str_list(run, "sources");
    let Some(sources) = sources else {
        c.fail("/run/sources", "runner integration requires sources");
        return;
    };
    if sources.is_empty() {
        c.fail("/run/sources", "runner integration requires sources");
        return;
    }
    let check_integration = check.split('/').next();
    for (idx, source) in sources.iter().enumerate() {
        if !ids::is_run_source(source) {
            c.fail(
                format!("/run/sources/{idx}"),
                format!("each source must be <integration>/<resource>@<major>, not {source:?}"),
            );
        }
        if let Some(integration) = check_integration {
            if source.split('/').next() != Some(integration) {
                c.fail(
                    format!("/run/sources/{idx}"),
                    "each source must belong to the same integration as check",
                );
            }
        }
    }
}

fn check_mapping_review(c: &mut Checker<'_>, r: &MappingReview) {
    c.check_ref("/mapping_ref", Some(&r.mapping_ref), &["mapping"], false);
    if r.is_revoked() {
        return;
    }
    for other in c.graph.mapping_reviews() {
        if other.id != r.id && other.mapping_ref == r.mapping_ref {
            c.conflict(
                "/mapping_ref",
                format!("{} already reviews this mapping", other.id),
            );
        }
    }
}

/// Validate all objects in a graph in parallel using Rayon, attaching source file and span info.
pub fn check_graph_parallel<'a, F>(
    graph: &Graph,
    origin_for: impl Fn(&str) -> StorageOrigin + Sync,
    meta_for: F,
) -> Vec<Diagnostic>
where
    F: Fn(&str) -> (Option<PathBuf>, Option<&'a SpanMap>) + Sync,
{
    let items: Vec<&OgrlObject> = graph.objects.values().collect();
    let mut diagnostics: Vec<Diagnostic> = items
        .par_iter()
        .flat_map(|obj| {
            let origin = origin_for(obj.id());
            let violations = check(obj, graph, origin);
            let (file, spans) = meta_for(obj.id());
            violations
                .into_iter()
                .map(|v| {
                    let span = spans.and_then(|s| lookup_span(s, &v.pointer));
                    Diagnostic {
                        severity: v.severity,
                        code: if v.conflict {
                            "E_CONFLICT".to_string()
                        } else if v.severity == Severity::Warning {
                            "W_CONSTRAINT".to_string()
                        } else {
                            "E_CONSTRAINT".to_string()
                        },
                        object_id: Some(obj.id().to_string()),
                        file: file.clone(),
                        line: span.map(|sp| sp.line),
                        col: span.map(|sp| sp.col),
                        pointer: v.pointer,
                        detail: v.detail,
                        conflict: v.conflict,
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect();

    diagnostics.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.object_id.cmp(&b.object_id))
            .then(a.pointer.cmp(&b.pointer))
    });
    diagnostics
}

fn lookup_span(spans: &SpanMap, pointer: &str) -> Option<Span> {
    if let Some(sp) = spans.get(pointer) {
        return Some(*sp);
    }
    // Walk up parent pointer if exact leaf span wasn't recorded.
    let mut cur = pointer;
    while let Some((parent, _)) = cur.rsplit_once('/') {
        if let Some(sp) = spans.get(parent) {
            return Some(*sp);
        }
        cur = parent;
    }
    spans.get("").copied()
}
