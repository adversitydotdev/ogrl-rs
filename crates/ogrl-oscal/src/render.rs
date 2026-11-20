//! OSCAL 1.2.3 6-document package renderer (RFC 0002 §9) in JSON and optional XML.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use thiserror::Error;
use uuid::Uuid;

use ogrl_core::graph::Graph;
use ogrl_core::ids;
use ogrl_core::model::{
    Determination, Framework, Implementation, ImplementationStatus, Mapping, Program, Requirement,
    Responsibility, Risk, RiskStatus,
};
use ogrl_core::parameters::{requirement_parameter_keys, requirement_value};
use ogrl_core::time::format_timestamp;

use crate::walk::{ControlEntry, Walk, walk};
use crate::xml::{XmlError, oscal_json_to_xml};

pub const OSCAL_VERSION: &str = "1.2.3";
const NAMESPACE: Uuid = Uuid::from_u128(0x5b0c_8f3e_6a3b_4d55_9e0e_0f9c_1e6a_1d00);

const RISK_LEVEL: [[&str; 5]; 5] = [
    ["low", "low", "low", "medium", "medium"],
    ["low", "low", "medium", "medium", "high"],
    ["low", "medium", "medium", "high", "high"],
    ["medium", "medium", "high", "high", "critical"],
    ["medium", "high", "high", "critical", "critical"],
];

#[derive(Debug, Error)]
pub enum RenderError {
    #[error("framework {0} is not in the pinned library")]
    MissingFramework(String),
    #[error("XML serialization error: {0}")]
    Xml(#[from] XmlError),
}

#[derive(Debug, Clone)]
pub struct RenderedFile {
    pub name: String,
    pub media_type: String,
    pub content: Vec<u8>,
}

fn uid(parts: &[&str]) -> String {
    let joined = parts.join("|");
    Uuid::new_v5(&NAMESPACE, joined.as_bytes()).to_string()
}

fn origination(r: Responsibility) -> &'static str {
    match r {
        Responsibility::Provider | Responsibility::Subservice => "inherited",
        Responsibility::Shared => "shared",
        Responsibility::Customer => "customer-configured",
    }
}

/// RFC 0002 §9: `AC-2(1)` -> `ac-2.1`; SP 800-171 r3 -> `SP_800_171_03.01.01`.
pub fn oscal_control_id(requirement: &Requirement) -> String {
    let fallback = ids::split(&requirement.id)
        .map(|(_, r)| r)
        .unwrap_or(&requirement.id);
    let label = requirement.display_id.as_deref().unwrap_or(fallback);
    if requirement.framework_ref.contains("800-171") {
        return format!("SP_800_171_{label}");
    }
    label
        .to_ascii_lowercase()
        .replace('(', ".")
        .replace([')', ' '], "")
}

fn metadata(title: &str, at: DateTime<Utc>, version: &str) -> Value {
    json!({
        "title": title,
        "last-modified": format_timestamp(&at),
        "version": version,
        "oscal-version": OSCAL_VERSION,
    })
}

/// RFC 0002 §9 implementation-status aggregation table.
pub fn oscal_implementation_status(
    impls: &[&Implementation],
    mappings: &[&Mapping],
) -> &'static str {
    let statuses: HashSet<ImplementationStatus> = impls.iter().map(|i| i.status).collect();
    if statuses.len() == 1
        && statuses.contains(&ImplementationStatus::Implemented)
        && mappings.iter().all(|m| m.relationship.is_full_coverage())
    {
        return "implemented";
    }
    if statuses.len() == 1 && statuses.contains(&ImplementationStatus::NotApplicable) {
        return "not-applicable";
    }
    if statuses.contains(&ImplementationStatus::Planned)
        && !statuses.contains(&ImplementationStatus::Implemented)
        && !statuses.contains(&ImplementationStatus::Partial)
    {
        return "planned";
    }
    "partial"
}

struct Package<'a> {
    w: Walk<'a>,
    framework: &'a Framework,
    controls_by_id: HashMap<&'a str, usize>,
    in_scope: BTreeMap<String, (&'a Requirement, Vec<&'a Mapping>)>,
}

impl<'a> Package<'a> {
    fn new(w: Walk<'a>, framework: &'a Framework) -> Self {
        let controls_by_id: HashMap<&'a str, usize> = w
            .controls
            .iter()
            .enumerate()
            .map(|(idx, e)| (e.control.id.as_str(), idx))
            .collect();

        let mut in_scope: BTreeMap<String, (&'a Requirement, Vec<&'a Mapping>)> = BTreeMap::new();
        for req_id in &w.evaluator.baseline.requirement_ids {
            let Some(req) = w.graph.requirement(req_id) else {
                continue;
            };
            if req.is_withdrawn() || req.is_revoked() || req.framework_ref != framework.id {
                continue;
            }
            let mappings: Vec<&'a Mapping> = w
                .graph
                .mappings_by_target(&req.id)
                .into_iter()
                .filter(|m| {
                    controls_by_id
                        .get(m.source_ref.as_str())
                        .is_some_and(|&idx| !w.controls[idx].implementations.is_empty())
                        && !w.evaluator.is_replaced(m)
                })
                .collect();
            if !mappings.is_empty() {
                in_scope.insert(req.id.clone(), (req, mappings));
            }
        }

        Self {
            w,
            framework,
            controls_by_id,
            in_scope,
        }
    }

    fn entry(&self, control_id: &str) -> &ControlEntry<'a> {
        &self.w.controls[self.controls_by_id[control_id]]
    }

    fn implementations_by_control(&self) -> HashMap<String, &'a Implementation> {
        self.w
            .controls
            .iter()
            .filter_map(|e| {
                e.implementations
                    .first()
                    .map(|&i| (e.control.id.clone(), i))
            })
            .collect()
    }

    fn parameters(&self, requirement: &Requirement) -> Vec<Value> {
        let impls_by_ctrl = self.implementations_by_control();
        let mut out = Vec::new();
        for key in requirement_parameter_keys(self.w.graph, &requirement.id) {
            if let Some(val) = requirement_value(
                self.w.graph,
                &requirement.id,
                &key,
                &self.w.evaluator.baseline.control_ids,
                &impls_by_ctrl,
                &self.w.evaluator.baseline.parameter_bindings,
            ) {
                out.push(json!({"param-id": key, "values": [val]}));
            }
        }
        out
    }

    fn profile(&self) -> Value {
        let source = self.framework.source.as_ref();
        let uri = source
            .and_then(|s| s.get("uri"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let href = match source.and_then(|s| s.get("path")).and_then(Value::as_str) {
            Some(path) => {
                let commit = source
                    .and_then(|s| s.get("commit"))
                    .and_then(Value::as_str)
                    .unwrap_or("main");
                format!("{}/blob/{commit}/{path}", uri.trim_end_matches('/'))
            }
            None => uri.to_string(),
        };
        let mut with_ids: Vec<String> = self
            .in_scope
            .values()
            .map(|(r, _)| oscal_control_id(r))
            .collect();
        with_ids.sort();
        let set_params: Vec<Value> = self
            .in_scope
            .values()
            .flat_map(|(r, _)| self.parameters(r))
            .collect();

        let mut doc = Map::new();
        doc.insert(
            "uuid".into(),
            Value::String(uid(&["profile", &self.w.program.id, &self.framework.id])),
        );
        doc.insert(
            "metadata".into(),
            metadata(
                &format!("{}: {}", self.w.program.name, self.framework.name),
                self.w.evaluator.at,
                "1.0",
            ),
        );
        doc.insert(
            "imports".into(),
            json!([{
                "href": href,
                "include-controls": [{"with-ids": with_ids}],
            }]),
        );
        if !set_params.is_empty() {
            doc.insert("modify".into(), json!({"set-parameters": set_params}));
        }
        json!({"profile": Value::Object(doc)})
    }

    fn ssp(&self) -> Value {
        let system = self.w.system;
        let program = self.w.program;
        let mut components = vec![json!({
            "uuid": uid(&["component", "this-system", &program.system_ref]),
            "type": "this-system",
            "title": "This system",
            "description": system.and_then(|s| s.function.as_deref()).unwrap_or("This system"),
            "status": {"state": "operational"},
        })];
        for r in system
            .and_then(|s| s.component_refs.as_deref())
            .unwrap_or(&[])
        {
            if let Some(comp) = self.w.graph.component(r) {
                components.push(json!({
                    "uuid": uid(&["component", &comp.id]),
                    "type": comp.kind.as_str(),
                    "title": comp.name,
                    "description": comp.description.as_deref().unwrap_or(&comp.name),
                    "status": {"state": "operational"},
                    "props": [{
                        "name": "ogrl-id",
                        "ns": "https://ogrl.dev/ns",
                        "value": comp.id,
                    }],
                }));
            }
        }

        let leveraged: Vec<Value> = system
            .and_then(|s| s.parties.as_deref())
            .unwrap_or(&[])
            .iter()
            .filter_map(|p| {
                let auth = p.authorization.as_ref()?;
                if p.role.as_str() != "subservice" {
                    return None;
                }
                Some(json!({
                    "uuid": uid(&["leveraged", &p.party_ref]),
                    "title": p.function.as_deref().unwrap_or(&p.party_ref),
                    "party-uuid": uid(&["party", &p.party_ref]),
                    "date-authorized": auth.authorized.to_string(),
                    "props": [{
                        "name": "authorization-identifier",
                        "ns": "https://ogrl.dev/ns",
                        "value": auth.identifier,
                    }],
                }))
            })
            .collect();

        let info_types: Vec<Value> = system
            .and_then(|s| s.information_types.as_deref())
            .unwrap_or(&[])
            .iter()
            .map(|i| {
                json!({
                    "uuid": uid(&["info", &program.system_ref, &i.name]),
                    "title": i.name,
                    "description": i.description.as_deref().unwrap_or(&i.name),
                    "confidentiality-impact": {"base": format!("fips-199-{}", i.confidentiality.as_str())},
                    "integrity-impact": {"base": format!("fips-199-{}", i.integrity.as_str())},
                    "availability-impact": {"base": format!("fips-199-{}", i.availability.as_str())},
                })
            })
            .collect();

        let mut requirements = Vec::new();
        for (req, mappings) in self.in_scope.values() {
            let impls: Vec<&Implementation> = mappings
                .iter()
                .flat_map(|m| self.entry(&m.source_ref).implementations.iter().copied())
                .collect();
            let mut remarks = Vec::new();
            for m in mappings {
                let entry = self.entry(&m.source_ref);
                let reviews = self.w.graph.reviews_for_mapping(&m.id);
                let review_str = reviews
                    .last()
                    .map(|r| format!("; organization review: {}", r.review_status.as_str()))
                    .unwrap_or_default();
                remarks.push(format!(
                    "{} ({}{review_str}): {}",
                    entry
                        .control
                        .display_id
                        .as_deref()
                        .unwrap_or(&entry.control.id),
                    m.relationship.as_str(),
                    entry.statement.trim()
                ));
                for imp in &entry.implementations {
                    if let Some(narr) = &imp.narrative {
                        remarks.push(format!("{}: {}", imp.id, narr.trim()));
                    }
                }
                for exc in &entry.exceptions {
                    remarks.push(format!(
                        "Exception until {}: {}",
                        exc.expires,
                        exc.justification.trim()
                    ));
                }
            }
            for f in &self.w.findings {
                if ids::base(&f.objective_ref) == req.id {
                    remarks.push(format!(
                        "Finding {}: {} on {}",
                        f.id,
                        f.determination.as_str(),
                        f.observed
                    ));
                }
            }

            let by_component: Vec<Value> = impls
                .iter()
                .map(|i| {
                    let comp_uuid = match &i.component_ref {
                        Some(cref) => uid(&["component", cref]),
                        None => uid(&["component", "this-system", &program.system_ref]),
                    };
                    let state = if i.status == ImplementationStatus::Exception {
                        "partial"
                    } else {
                        i.status.as_str()
                    };
                    json!({
                        "component-uuid": comp_uuid,
                        "uuid": uid(&["by-component", &req.id, &i.id]),
                        "description": i.narrative.as_deref().unwrap_or(&i.id),
                        "implementation-status": {"state": state},
                    })
                })
                .collect();

            let statement_ids: BTreeSet<&str> = mappings
                .iter()
                .filter_map(|m| ids::fragment(&m.target_ref))
                .collect();
            let control_id = oscal_control_id(req);
            let mut item = Map::new();
            item.insert(
                "uuid".into(),
                Value::String(uid(&["implemented-requirement", &program.id, &req.id])),
            );
            item.insert("control-id".into(), Value::String(control_id.clone()));
            item.insert(
                "props".into(),
                json!([{
                    "name": "implementation-status",
                    "value": oscal_implementation_status(&impls, mappings),
                }]),
            );
            item.insert("by-components".into(), Value::Array(by_component));
            item.insert("remarks".into(), Value::String(remarks.join("\n\n")));
            let params = self.parameters(req);
            if !params.is_empty() {
                item.insert("set-parameters".into(), Value::Array(params));
            }
            if !statement_ids.is_empty() {
                let stmts: Vec<Value> = statement_ids
                    .into_iter()
                    .map(|s| {
                        json!({
                            "statement-id": format!("{control_id}_smt.{s}"),
                            "uuid": uid(&["statement", &req.id, s]),
                        })
                    })
                    .collect();
                item.insert("statements".into(), Value::Array(stmts));
            }
            requirements.push(Value::Object(item));
        }

        let mut sys_impl = Map::new();
        sys_impl.insert("users".into(), json!([]));
        sys_impl.insert("components".into(), Value::Array(components));
        if !leveraged.is_empty() {
            sys_impl.insert("leveraged-authorizations".into(), Value::Array(leveraged));
        }

        let sys_name = system
            .map(|s| s.name.as_str())
            .unwrap_or(program.system_ref.as_str());
        json!({
            "system-security-plan": {
                "uuid": uid(&["ssp", &program.id, &self.framework.id]),
                "metadata": metadata(&format!("System security plan: {sys_name}"), self.w.evaluator.at, "1.0"),
                "import-profile": {"href": "profile.json"},
                "system-characteristics": {
                    "system-ids": [{"identifier-type": "https://ogrl.dev/ns", "id": program.system_ref}],
                    "system-name": sys_name,
                    "description": system.and_then(|s| s.function.as_deref()).unwrap_or(""),
                    "system-information": {"information-types": info_types},
                    "status": {"state": "operational"},
                    "authorization-boundary": {"description": system.and_then(|s| s.boundary.as_deref()).unwrap_or("")},
                },
                "system-implementation": Value::Object(sys_impl),
                "control-implementation": {
                    "description": format!("Implementations for {}.", self.framework.name),
                    "implemented-requirements": requirements,
                },
            }
        })
    }

    fn mapping_collection(&self) -> Value {
        let mut maps = Vec::new();
        for req in self.w.graph.requirements_for_framework(&self.framework.id) {
            for m in self.w.graph.mappings_by_target(&req.id) {
                if !self.w.graph.is_library(&m.id) {
                    continue;
                }
                let target = oscal_control_id(req);
                let target_ref = match ids::fragment(&m.target_ref) {
                    Some(frag) => format!("{target}_smt.{frag}"),
                    None => target,
                };
                let mut props = vec![json!({
                    "name": "review-status",
                    "value": m.review_status.map(|r| r.as_str()).unwrap_or("draft"),
                })];
                for rev in self.w.graph.reviews_for_mapping(&m.id) {
                    props.push(json!({
                        "name": "mapping-review",
                        "value": rev.review_status.as_str(),
                    }));
                }
                if let Some(pm) = &m.parameter_map {
                    for (k, v) in pm {
                        props.push(json!({
                            "name": "parameter-map",
                            "value": format!("{k}={v}"),
                        }));
                    }
                }
                let mut entry = Map::new();
                entry.insert("uuid".into(), Value::String(uid(&["map", &m.id])));
                entry.insert(
                    "relationship".into(),
                    Value::String(m.relationship.as_str().into()),
                );
                entry.insert(
                    "sources".into(),
                    json!([{"type": "control", "id-ref": m.source_ref}]),
                );
                entry.insert(
                    "targets".into(),
                    json!([{"type": "control", "id-ref": target_ref}]),
                );
                entry.insert("props".into(), Value::Array(props));
                if let Some(rat) = m.rationale {
                    entry.insert("rationale".into(), Value::String(rat.as_str().into()));
                }
                if let Some(conf) = m.confidence {
                    entry.insert(
                        "confidence-score".into(),
                        json!({"category": conf.as_str()}),
                    );
                }
                maps.push(Value::Object(entry));
            }
        }
        json!({
            "mapping-collection": {
                "uuid": uid(&["mappings", &self.framework.id]),
                "metadata": metadata(&format!("OGRL mappings to {}", self.framework.name), self.w.evaluator.at, "1.0"),
                "provenance": {
                    "method": "human",
                    "remarks": format!("Generated from the pinned library ({} objects).", self.w.graph.library_ids.len()),
                },
                "mappings": [{"uuid": uid(&["mapping-set", &self.framework.id]), "maps": maps}],
            }
        })
    }

    fn component_definition(&self) -> Value {
        let mut components = Vec::new();
        for cref in self
            .w
            .system
            .and_then(|s| s.component_refs.as_deref())
            .unwrap_or(&[])
        {
            let Some(comp) = self.w.graph.component(cref) else {
                continue;
            };
            let impls: Vec<&Implementation> = self
                .w
                .graph
                .implementations()
                .into_iter()
                .filter(|i| {
                    i.component_ref.as_deref() == Some(cref.as_str()) && i.system_ref.is_none()
                })
                .collect();
            let mut reqs = Vec::new();
            for imp in impls {
                let targets: Vec<&Requirement> = if let Some(ref rref) = imp.requirement_ref {
                    self.w.graph.requirement(rref).into_iter().collect()
                } else if let Some(ref ctrl_ref) = imp.control_ref {
                    self.w
                        .graph
                        .mappings_by_source(ctrl_ref)
                        .into_iter()
                        .filter_map(|m| self.w.graph.requirement(&m.target_ref))
                        .collect()
                } else {
                    Vec::new()
                };
                for target in targets {
                    if target.framework_ref != self.framework.id {
                        continue;
                    }
                    let desc_parts: Vec<&str> = [
                        imp.narrative.as_deref(),
                        imp.customer_responsibility.as_deref(),
                    ]
                    .into_iter()
                    .flatten()
                    .filter(|s| !s.is_empty())
                    .collect();
                    let description = if desc_parts.is_empty() {
                        imp.id.clone()
                    } else {
                        desc_parts.join("\n\n")
                    };
                    reqs.push(json!({
                        "uuid": uid(&["cd-req", &imp.id, &target.id]),
                        "control-id": oscal_control_id(target),
                        "description": description,
                        "props": [{
                            "name": "control-origination",
                            "value": origination(imp.responsibility),
                        }],
                    }));
                }
            }
            let ctrl_impls = if reqs.is_empty() {
                vec![]
            } else {
                let source_uri = self
                    .framework
                    .source
                    .as_ref()
                    .and_then(|s| s.get("uri"))
                    .and_then(Value::as_str)
                    .unwrap_or(&self.framework.id);
                vec![json!({
                    "uuid": uid(&["cd-impl", &comp.id, &self.framework.id]),
                    "source": source_uri,
                    "description": format!("{} against {}.", comp.name, self.framework.name),
                    "implemented-requirements": reqs,
                })]
            };
            components.push(json!({
                "uuid": uid(&["component", &comp.id]),
                "type": comp.kind.as_str(),
                "title": comp.name,
                "description": comp.description.as_deref().unwrap_or(&comp.name),
                "control-implementations": ctrl_impls,
            }));
        }
        json!({
            "component-definition": {
                "uuid": uid(&["component-definition", &self.w.program.system_ref]),
                "metadata": metadata("Components of the system", self.w.evaluator.at, "1.0"),
                "components": components,
            }
        })
    }

    fn evidence_resources(&self, refs: &[String]) -> Vec<Value> {
        let mut out = Vec::new();
        for r in refs {
            let Some(ev) = self.w.graph.evidence(r) else {
                continue;
            };
            let Some(res) = &ev.resource else {
                continue;
            };
            let mut obj = Map::new();
            obj.insert("uuid".into(), Value::String(uid(&["resource", &ev.id])));
            obj.insert("title".into(), Value::String(ev.name.clone()));
            if let Some(uri) = &res.uri {
                let mut rlink = Map::new();
                rlink.insert("href".into(), Value::String(uri.clone()));
                if let Some(d) = &res.digest {
                    rlink.insert(
                        "hashes".into(),
                        json!([{"algorithm": "SHA-256", "value": d.value}]),
                    );
                }
                obj.insert("rlinks".into(), Value::Array(vec![Value::Object(rlink)]));
            }
            out.push(Value::Object(obj));
        }
        out
    }

    fn assessment_results(&self) -> Value {
        let mut findings = Vec::new();
        let mut resources = Vec::new();
        for f in &self.w.findings {
            let Some(req) = self.w.graph.requirement(&f.objective_ref) else {
                continue;
            };
            if req.framework_ref != self.framework.id {
                continue;
            }
            let obj_part = ids::objective_of(&f.objective_ref).unwrap_or("");
            let target_id = format!("{}_obj.{obj_part}", oscal_control_id(req));
            let mut entry = Map::new();
            entry.insert("uuid".into(), Value::String(uid(&["finding", &f.id])));
            entry.insert("title".into(), Value::String(f.name.clone()));
            entry.insert("description".into(), Value::String(f.narrative.clone()));
            entry.insert(
                "target".into(),
                json!({
                    "type": "objective-id",
                    "target-id": target_id,
                    "status": {"state": f.determination.as_str()},
                }),
            );
            if let Some(rref) = &f.risk_ref {
                entry.insert(
                    "related-risks".into(),
                    json!([{"risk-uuid": uid(&["risk", rref])}]),
                );
            }
            findings.push(Value::Object(entry));
            resources.extend(self.evidence_resources(f.evidence_refs.as_deref().unwrap_or(&[])));
        }
        let stamp = format_timestamp(&self.w.evaluator.at);
        let mut doc = Map::new();
        doc.insert(
            "uuid".into(),
            Value::String(uid(&[
                "assessment-results",
                &self.w.program.id,
                &self.framework.id,
            ])),
        );
        doc.insert(
            "metadata".into(),
            metadata("Assessment results", self.w.evaluator.at, "1.0"),
        );
        doc.insert("import-ap".into(), json!({"href": "#"}));
        doc.insert(
            "results".into(),
            json!([{
                "uuid": uid(&["result", &self.w.program.id, &stamp]),
                "title": "Findings in force",
                "description": "Findings in force for the system.",
                "start": stamp,
                "reviewed-controls": {"control-selections": [{"include-all": {}}]},
                "findings": findings,
            }]),
        );
        if !resources.is_empty() {
            doc.insert("back-matter".into(), json!({"resources": resources}));
        }
        json!({"assessment-results": Value::Object(doc)})
    }

    fn poam(&self) -> Value {
        let mut items = Vec::new();
        let mut risks = Vec::new();
        let mapped: HashSet<&str> = self
            .in_scope
            .values()
            .flat_map(|(_, ms)| ms.iter().map(|m| m.source_ref.as_str()))
            .collect();

        for risk in self.w.graph.risks() {
            if matches!(risk.status, RiskStatus::Accepted | RiskStatus::Closed) {
                continue;
            }
            if risk.milestones.as_deref().is_none_or(<[_]>::is_empty) {
                continue;
            }
            if !risk
                .control_refs
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .any(|c| mapped.contains(c.as_str()))
            {
                continue;
            }
            risks.push(self.render_risk(risk));
            items.push(json!({
                "uuid": uid(&["poam-risk", &risk.id]),
                "title": risk.name,
                "description": risk.statement,
                "related-risks": [{"risk-uuid": uid(&["risk", &risk.id])}],
            }));
        }

        let in_scope_impls: HashSet<&str> = self
            .w
            .controls
            .iter()
            .flat_map(|e| e.implementations.iter().map(|i| i.id.as_str()))
            .collect();
        for exc in self.w.graph.exceptions() {
            if in_scope_impls.contains(exc.implementation_ref.as_str())
                && exc.expires >= self.w.evaluator.date
            {
                items.push(json!({
                    "uuid": uid(&["poam-exception", &exc.id]),
                    "title": format!("Exception {}", exc.id),
                    "description": format!("{} Expires {}.", exc.justification.trim(), exc.expires),
                }));
            }
        }

        for f in &self.w.findings {
            if f.determination == Determination::NotSatisfied {
                let mut item = Map::new();
                item.insert("uuid".into(), Value::String(uid(&["poam-finding", &f.id])));
                item.insert("title".into(), Value::String(f.name.clone()));
                item.insert("description".into(), Value::String(f.narrative.clone()));
                item.insert(
                    "related-findings".into(),
                    json!([{"finding-uuid": uid(&["finding", &f.id])}]),
                );
                if let Some(rref) = &f.risk_ref {
                    item.insert(
                        "related-risks".into(),
                        json!([{"risk-uuid": uid(&["risk", rref])}]),
                    );
                }
                items.push(Value::Object(item));
            }
        }

        let mut doc = Map::new();
        doc.insert(
            "uuid".into(),
            Value::String(uid(&["poam", &self.w.program.id, &self.framework.id])),
        );
        doc.insert(
            "metadata".into(),
            metadata("Plan of action and milestones", self.w.evaluator.at, "1.0"),
        );
        doc.insert("import-ssp".into(), json!({"href": "ssp.json"}));
        doc.insert("poam-items".into(), Value::Array(items));
        if !risks.is_empty() {
            doc.insert("risks".into(), Value::Array(risks));
        }
        json!({"plan-of-action-and-milestones": Value::Object(doc)})
    }

    fn render_risk(&self, risk: &Risk) -> Value {
        let li = usize::from(risk.likelihood.clamp(1, 5) - 1);
        let im = usize::from(risk.impact.clamp(1, 5) - 1);
        let level = RISK_LEVEL[li][im];
        let tasks: Vec<Value> = risk
            .milestones
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|m| {
                let mut task = Map::new();
                task.insert(
                    "uuid".into(),
                    Value::String(uid(&["task", &risk.id, &m.name])),
                );
                task.insert("type".into(), Value::String("milestone".into()));
                task.insert("title".into(), Value::String(m.name.clone()));
                task.insert(
                    "timing".into(),
                    json!({"on-date": {"date": format!("{}T00:00:00Z", m.due)}}),
                );
                if let Some(done) = m.done {
                    task.insert("remarks".into(), Value::String(format!("done {done}")));
                }
                Value::Object(task)
            })
            .collect();

        json!({
            "uuid": uid(&["risk", &risk.id]),
            "title": risk.name,
            "description": risk.statement,
            "statement": risk.statement,
            "status": risk.status.as_str(),
            "characterizations": [{
                "origin": {"actors": [{"type": "party", "actor-uuid": uid(&["org"])}]},
                "facets": [
                    {"name": "likelihood", "system": "https://ogrl.dev/ns", "value": risk.likelihood.to_string()},
                    {"name": "impact", "system": "https://ogrl.dev/ns", "value": risk.impact.to_string()},
                    {"name": "risk", "system": "https://ogrl.dev/ns", "value": level},
                ],
            }],
            "remediations": [{
                "uuid": uid(&["remediation", &risk.id]),
                "lifecycle": "planned",
                "title": risk.treatment.as_str(),
                "description": risk.treatment.as_str(),
                "tasks": tasks,
            }],
        })
    }
}

/// Render the full 6-document OSCAL 1.2.3 package for one program and target framework.
/// When `include_xml` is true, also emits the parallel `.xml` files per RFC 0002 §9.
pub fn render_oscal_package(
    graph: &Graph,
    program: &Program,
    framework_id: &str,
    at: DateTime<Utc>,
    include_xml: bool,
) -> Result<Vec<RenderedFile>, RenderError> {
    let Some(framework) = graph.framework(framework_id) else {
        return Err(RenderError::MissingFramework(framework_id.to_string()));
    };
    let w = walk(graph, program, at, Some(framework_id));
    let pkg = Package::new(w, framework);

    let docs = [
        ("profile", pkg.profile()),
        ("ssp", pkg.ssp()),
        ("mapping-collection", pkg.mapping_collection()),
        ("component-definition", pkg.component_definition()),
        ("assessment-results", pkg.assessment_results()),
        ("poam", pkg.poam()),
    ];

    let mut files = Vec::with_capacity(if include_xml { 12 } else { 6 });
    for (stem, doc) in docs {
        files.push(RenderedFile {
            name: format!("{stem}.json"),
            media_type: "application/json".into(),
            content: serde_json::to_vec_pretty(&doc).unwrap(),
        });
        if include_xml {
            let xml_bytes = oscal_json_to_xml(&doc)?;
            files.push(RenderedFile {
                name: format!("{stem}.xml"),
                media_type: "application/xml".into(),
                content: xml_bytes,
            });
        }
    }
    Ok(files)
}
