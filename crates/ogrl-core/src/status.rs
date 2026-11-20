//! Computed compliance status (RFC 0001 §8) and library revision diff (RFC 0002 §5).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

use crate::baselines::{self, EffectiveBaseline};
use crate::graph::{Graph, leaf_units, units_reached};
use crate::ids;
use crate::model::{
    Control, Determination, Evidence, Finding, Implementation, ImplementationStatus, Mapping,
    MappingReviewStatus, Outcome, Program, Relationship, Responsibility, ReviewStatus, RiskStatus,
    Test, TestMethod,
};
use crate::parameters::unresolved;
use crate::time::{freshness_days, on_or_after, serde_timestamp};

pub const MET: &str = "met";
pub const GAP: &str = "gap";
pub const WAIVED: &str = "waived";
pub const OUT_OF_SCOPE: &str = "out_of_scope";

pub const COVERED: &str = "covered";
pub const CONTRIBUTION: &str = "contribution";
pub const UNMAPPED: &str = "unmapped";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlStatus {
    pub control_id: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub implementation_id: Option<String>,
    #[serde(default)]
    pub failed: Vec<String>,
    #[serde(default)]
    pub implementation_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequirementCoverage {
    pub requirement_id: String,
    pub state: String,
    #[serde(default)]
    pub mapping_ids: Vec<String>,
    #[serde(default)]
    pub unmet_control_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramStatus {
    pub program_id: String,
    #[serde(with = "serde_timestamp")]
    pub at: DateTime<Utc>,
    pub controls: Vec<ControlStatus>,
    pub requirements: Vec<RequirementCoverage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramSummary {
    pub program_id: String,
    #[serde(with = "serde_timestamp")]
    pub at: DateTime<Utc>,
    pub controls: BTreeMap<String, usize>,
    pub requirements: BTreeMap<String, usize>,
    pub failing_tests: usize,
    pub open_risks: usize,
    pub expiring_evidence: usize,
    pub expiring_exceptions: usize,
    pub open_findings: usize,
}

#[derive(Debug, Clone)]
pub struct Evaluation<'a> {
    pub implementations: Vec<&'a Implementation>,
    pub provider_halves: Vec<&'a Implementation>,
}

pub struct Evaluator<'a> {
    pub graph: &'a Graph,
    pub program: &'a Program,
    pub at: DateTime<Utc>,
    pub date: NaiveDate,
    pub baseline: EffectiveBaseline,
    pub system_id: String,
    pub component_ids: Vec<String>,
    control_set: HashSet<String>,
    control_status_cache: HashMap<String, ControlStatus>,
}

impl<'a> Evaluator<'a> {
    pub fn new(graph: &'a Graph, program: &'a Program, at: DateTime<Utc>) -> Self {
        let date = at.date_naive();
        let baseline = match graph.baseline(&program.baseline_ref) {
            Some(b) => baselines::effective(graph, b),
            None => EffectiveBaseline {
                baseline_id: program.baseline_ref.clone(),
                extends_id: None,
                framework_ids: Vec::new(),
                control_ids: Vec::new(),
                requirement_ids: Vec::new(),
                parameter_bindings: BTreeMap::new(),
            },
        };
        let component_ids = graph
            .system(&program.system_ref)
            .and_then(|s| s.component_refs.clone())
            .unwrap_or_default();
        let control_set: HashSet<String> = baseline.control_ids.iter().cloned().collect();

        Self {
            graph,
            program,
            at,
            date,
            baseline,
            system_id: program.system_ref.clone(),
            component_ids,
            control_set,
            control_status_cache: HashMap::new(),
        }
    }

    // --- Mappings -----------------------------------------------------------

    pub fn is_reviewed(&self, mapping: &Mapping) -> bool {
        let current: Vec<_> = self
            .graph
            .reviews_for_mapping(&mapping.id)
            .into_iter()
            .filter(|r| r.mapping_modified.is_some_and(|m| m == mapping.modified))
            .collect();
        if current
            .iter()
            .any(|r| r.review_status == MappingReviewStatus::Rejected)
        {
            return false;
        }
        mapping.review_status == Some(ReviewStatus::Reviewed)
            || current
                .iter()
                .any(|r| r.review_status == MappingReviewStatus::Reviewed)
    }

    pub fn is_replaced(&self, mapping: &Mapping) -> bool {
        if !self.graph.is_library(&mapping.id) {
            return false;
        }
        self.graph
            .mappings_by_source(&mapping.source_ref)
            .into_iter()
            .any(|other| {
                other.target_ref == mapping.target_ref && self.graph.is_organization(&other.id)
            })
    }

    pub fn counts(&self, mapping: &Mapping) -> bool {
        !mapping.is_revoked()
            && mapping.relationship != Relationship::NoRelationship
            && self.control_set.contains(&mapping.source_ref)
            && self.is_reviewed(mapping)
            && !self.is_replaced(mapping)
    }

    // --- Implementations ----------------------------------------------------

    fn joins(&self, implementation: &Implementation, control_id: &str) -> bool {
        if !(implementation.is_provider() && implementation.requirement_ref.is_some()) {
            return false;
        }
        if implementation.control_ref.is_some() {
            return false;
        }
        let req_ref = implementation.requirement_ref.as_deref().unwrap();
        self.graph
            .mappings_by_source(control_id)
            .into_iter()
            .any(|m| {
                ids::base(&m.target_ref) == req_ref
                    && m.relationship.is_joining()
                    && self.is_reviewed(m)
                    && !self.is_replaced(m)
            })
    }

    pub fn under_evaluation(&self, control_id: &str) -> Evaluation<'a> {
        let candidates: Vec<&'a Implementation> = self
            .graph
            .implementations()
            .into_iter()
            .filter(|i| i.control_ref.as_deref() == Some(control_id) || self.joins(i, control_id))
            .collect();

        let system_rows: Vec<&'a Implementation> = candidates
            .iter()
            .copied()
            .filter(|i| {
                i.system_ref.as_deref() == Some(self.system_id.as_str())
                    && i.component_ref.is_none()
            })
            .collect();

        let mut overrides: BTreeMap<&str, &'a Implementation> = BTreeMap::new();
        for &i in &candidates {
            if i.system_ref.as_deref() == Some(self.system_id.as_str()) {
                if let Some(comp) = i.component_ref.as_deref() {
                    if self.component_ids.iter().any(|c| c == comp) {
                        overrides.insert(comp, i);
                    }
                }
            }
        }

        let inherited: Vec<&'a Implementation> = candidates
            .iter()
            .copied()
            .filter(|i| {
                i.system_ref.is_none()
                    && i.component_ref.as_deref().is_some_and(|comp| {
                        self.component_ids.iter().any(|c| c == comp)
                            && !overrides.contains_key(comp)
                    })
            })
            .collect();

        if let Some(&primary) = system_rows.first() {
            let halves = inherited
                .into_iter()
                .filter(|i| i.is_provider() && i.responsibility == Responsibility::Shared)
                .collect();
            return Evaluation {
                implementations: vec![primary],
                provider_halves: halves,
            };
        }
        let mut combined: Vec<&'a Implementation> = overrides.into_values().collect();
        combined.extend(inherited);
        Evaluation {
            implementations: combined,
            provider_halves: Vec::new(),
        }
    }

    // --- Tests & Evidence ---------------------------------------------------

    pub fn applies(&self, test: &Test) -> bool {
        match &test.system_refs {
            None => true,
            Some(refs) if refs.is_empty() => true,
            Some(refs) => refs.iter().any(|s| s == &self.system_id),
        }
    }

    pub fn evidence_valid(&self, evidence: Option<&Evidence>) -> bool {
        let Some(e) = evidence else {
            return false;
        };
        !e.is_revoked() && e.is_complete() && e.valid_until.is_some_and(|vu| vu >= self.date)
    }

    pub fn has_unexpired_evidence(&self, implementation: &Implementation) -> bool {
        self.graph
            .evidence_for_implementation(&implementation.id)
            .into_iter()
            .any(|e| self.evidence_valid(Some(e)))
    }

    pub fn passing(&self, test: &Test, implementation: &Implementation) -> Vec<String> {
        let results: Vec<_> = self
            .graph
            .results_for_pair(&test.id, &implementation.id)
            .into_iter()
            .filter(|r| r.observed <= self.at)
            .collect();
        if results.is_empty() {
            return vec![format!(
                "test {} has no result for {}",
                test.id, implementation.id
            )];
        }
        let current = results
            .into_iter()
            .max_by_key(|r| (r.observed, r.modified))
            .unwrap();
        if current.outcome != Outcome::Pass {
            return vec![format!(
                "test {}: current result {} is {}",
                test.id,
                current.id,
                current.outcome.as_str()
            )];
        }
        if let Some(interval) = test.interval {
            if interval.as_str() == "event-driven" {
                if current.valid_until.is_none_or(|vu| self.at > vu) {
                    return vec![format!(
                        "test {}: result {} is no longer valid",
                        test.id, current.id
                    )];
                }
            } else if let Some(days) = freshness_days(interval.as_str()) {
                if self.at > current.observed + Duration::days(days) {
                    return vec![format!(
                        "test {}: result {} is older than its {} window",
                        test.id,
                        current.id,
                        interval.as_str()
                    )];
                }
            }
        }
        current
            .evidence_refs
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .filter(|eid| !self.evidence_valid(self.graph.evidence(eid)))
            .map(|eid| {
                format!(
                    "evidence {eid} cited by {} is expired, revoked, or incomplete",
                    current.id
                )
            })
            .collect()
    }

    pub fn test_failures(&self, control: &Control, implementation: &Implementation) -> Vec<String> {
        let required: Vec<&Test> = self
            .graph
            .tests_by_control(&control.id)
            .into_iter()
            .filter(|t| t.required.unwrap_or(false) && t.fulfills_ref.is_none() && self.applies(t))
            .collect();
        if required.is_empty() {
            if self.has_unexpired_evidence(implementation) {
                return Vec::new();
            }
            return vec![format!(
                "{} has no unexpired evidence and no required test applies",
                implementation.id
            )];
        }

        let mut failures = Vec::new();
        for test in required {
            let fulfilling: Vec<&Test> = self
                .graph
                .fulfillers_of(&test.id)
                .into_iter()
                .filter(|t| self.applies(t) && t.control_ref == control.id)
                .collect();
            if !fulfilling.is_empty() {
                for t in fulfilling {
                    failures.extend(self.passing(t, implementation));
                }
            } else if implementation.is_provider()
                && matches!(
                    implementation.responsibility,
                    Responsibility::Provider | Responsibility::Subservice
                )
                && !self.graph.is_organization(&test.id)
            {
                if !self.has_unexpired_evidence(implementation) {
                    failures.push(format!(
                        "test {}: provider row {} has no unexpired evidence",
                        test.id, implementation.id
                    ));
                }
            } else if test.method == TestMethod::Automated && test.run.is_none() {
                failures.push(format!("test {}: no methodology has been defined", test.id));
            } else {
                failures.extend(self.passing(test, implementation));
            }
        }
        failures
    }

    // --- One control --------------------------------------------------------

    pub fn implementation_failures(
        &self,
        control: &Control,
        impl_row: &Implementation,
    ) -> Vec<String> {
        let mut failures = Vec::new();
        if impl_row.status != ImplementationStatus::Implemented {
            failures.push(format!(
                "{}: status is {}",
                impl_row.id,
                impl_row.status.as_str()
            ));
        }
        if impl_row.is_provider()
            && matches!(
                impl_row.responsibility,
                Responsibility::Shared | Responsibility::Customer
            )
        {
            failures.push(format!(
                "{}: provider responsibility is {}; the organization's implementation is missing",
                impl_row.id,
                impl_row.responsibility.as_str()
            ));
        }
        if !impl_row.is_provider()
            && matches!(
                impl_row.responsibility,
                Responsibility::Customer | Responsibility::Subservice
            )
        {
            failures.push(format!(
                "{}: responsibility {} is not the organization's",
                impl_row.id,
                impl_row.responsibility.as_str()
            ));
        }
        for name in unresolved(control, Some(impl_row), &self.baseline.parameter_bindings) {
            failures.push(format!("{}: parameter {name} has no value", impl_row.id));
        }
        failures.extend(self.test_failures(control, impl_row));
        failures
    }

    pub fn half_failures(&self, half: &Implementation) -> Vec<String> {
        let mut failures = Vec::new();
        if half.status != ImplementationStatus::Implemented {
            failures.push(format!(
                "provider's half {}: status is {}",
                half.id,
                half.status.as_str()
            ));
        }
        for evidence in self.graph.evidence_for_implementation(&half.id) {
            if evidence.is_revoked() || !evidence.is_complete() {
                continue;
            }
            if evidence.valid_until.is_none_or(|vu| vu < self.date) {
                failures.push(format!(
                    "provider's half {}: evidence {} has expired",
                    half.id, evidence.id
                ));
            }
        }
        failures
    }

    pub fn waived(&self, impl_row: &Implementation) -> bool {
        impl_row.status == ImplementationStatus::Exception
            && self
                .graph
                .exceptions_for_implementation(&impl_row.id)
                .into_iter()
                .any(|e| on_or_after(Some(e.expires), self.date))
    }

    pub fn out_of_scope(impl_row: &Implementation) -> bool {
        impl_row.status == ImplementationStatus::NotApplicable
            || (!impl_row.is_provider()
                && matches!(
                    impl_row.responsibility,
                    Responsibility::Customer | Responsibility::Subservice
                ))
    }

    pub fn control_status(&mut self, control_id: &str) -> ControlStatus {
        if let Some(cached) = self.control_status_cache.get(control_id) {
            return cached.clone();
        }
        let status = self.compute_control(control_id);
        self.control_status_cache
            .insert(control_id.to_string(), status.clone());
        status
    }

    fn compute_control(&self, control_id: &str) -> ControlStatus {
        let Some(control) = self.graph.control(control_id) else {
            return ControlStatus {
                control_id: control_id.to_string(),
                state: GAP.to_string(),
                implementation_id: None,
                failed: vec![format!("control {control_id} is not loaded")],
                implementation_ids: Vec::new(),
            };
        };
        let eval = self.under_evaluation(control_id);
        let rows = eval.implementations;
        if rows.is_empty() {
            return ControlStatus {
                control_id: control_id.to_string(),
                state: GAP.to_string(),
                implementation_id: None,
                failed: vec!["no implementation on the system or its components".to_string()],
                implementation_ids: Vec::new(),
            };
        }
        let primary = Some(rows[0].id.clone());
        let all_ids: Vec<String> = rows.iter().map(|i| i.id.clone()).collect();
        let mut failures: Vec<String> = rows
            .iter()
            .flat_map(|i| self.implementation_failures(control, i))
            .collect();
        let halves: Vec<String> = eval
            .provider_halves
            .iter()
            .flat_map(|h| self.half_failures(h))
            .collect();

        if failures.is_empty() && halves.is_empty() {
            return ControlStatus {
                control_id: control_id.to_string(),
                state: MET.to_string(),
                implementation_id: primary,
                failed: Vec::new(),
                implementation_ids: all_ids,
            };
        }
        if rows.iter().all(|i| self.waived(i)) {
            return ControlStatus {
                control_id: control_id.to_string(),
                state: WAIVED.to_string(),
                implementation_id: primary,
                failed: Vec::new(),
                implementation_ids: all_ids,
            };
        }
        if rows.iter().all(|i| Self::out_of_scope(i)) {
            return ControlStatus {
                control_id: control_id.to_string(),
                state: OUT_OF_SCOPE.to_string(),
                implementation_id: primary,
                failed: Vec::new(),
                implementation_ids: all_ids,
            };
        }
        failures.extend(halves);
        ControlStatus {
            control_id: control_id.to_string(),
            state: GAP.to_string(),
            implementation_id: primary,
            failed: failures,
            implementation_ids: all_ids,
        }
    }

    // --- Requirement coverage -----------------------------------------------

    pub fn coverage(&mut self, requirement_id: &str) -> Option<RequirementCoverage> {
        let req = self.graph.requirement(requirement_id)?;
        if req.is_revoked() || req.is_withdrawn() {
            return None;
        }
        let units = leaf_units(req);
        let counted: BTreeMap<String, &Mapping> = self
            .graph
            .mappings_by_target(&req.id)
            .into_iter()
            .filter(|m| self.counts(m))
            .map(|m| (m.id.clone(), m))
            .collect();
        let mapping_ids: Vec<String> = counted.keys().cloned().collect();

        if !counted
            .values()
            .any(|m| !units_reached(req, &m.target_ref).is_empty())
        {
            return Some(RequirementCoverage {
                requirement_id: req.id.clone(),
                state: UNMAPPED.to_string(),
                mapping_ids,
                unmet_control_ids: Vec::new(),
            });
        }

        let mut paths: HashMap<String, Vec<BTreeSet<String>>> =
            units.iter().map(|u| (u.clone(), Vec::new())).collect();

        for mapping in counted.values() {
            if mapping.relationship.is_full_coverage() {
                for unit in units_reached(req, &mapping.target_ref) {
                    let mut set = BTreeSet::new();
                    set.insert(mapping.source_ref.clone());
                    paths.entry(unit).or_default().push(set);
                }
            }
            if let Some(combined) = &mapping.combined_with_refs {
                if !combined.is_empty() {
                    let mut members = Vec::with_capacity(1 + combined.len());
                    members.push(mapping.id.as_str());
                    members.extend(combined.iter().map(String::as_str));
                    if members.iter().all(|mid| {
                        counted
                            .get(*mid)
                            .is_some_and(|m| m.target_ref == mapping.target_ref)
                    }) {
                        let sources: BTreeSet<String> = members
                            .iter()
                            .map(|mid| counted[*mid].source_ref.clone())
                            .collect();
                        for unit in units_reached(req, &mapping.target_ref) {
                            paths.entry(unit).or_default().push(sources.clone());
                        }
                    }
                }
            }
        }

        if units.iter().any(|u| paths.get(u).is_none_or(Vec::is_empty)) {
            return Some(RequirementCoverage {
                requirement_id: req.id.clone(),
                state: CONTRIBUTION.to_string(),
                mapping_ids,
                unmet_control_ids: Vec::new(),
            });
        }

        let mut failing_units = Vec::new();
        for u in &units {
            let unit_paths = &paths[u];
            let mut unit_met = false;
            for path in unit_paths {
                let mut all_met = true;
                for c in path {
                    if self.control_status(c).state != MET {
                        all_met = false;
                        break;
                    }
                }
                if all_met {
                    unit_met = true;
                    break;
                }
            }
            if !unit_met {
                failing_units.push(u.clone());
            }
        }

        if !failing_units.is_empty() {
            let mut unmet = BTreeSet::new();
            for u in &failing_units {
                for path in &paths[u] {
                    for c in path {
                        if self.control_status(c).state != MET {
                            unmet.insert(c.clone());
                        }
                    }
                }
            }
            return Some(RequirementCoverage {
                requirement_id: req.id.clone(),
                state: GAP.to_string(),
                mapping_ids,
                unmet_control_ids: unmet.into_iter().collect(),
            });
        }

        Some(RequirementCoverage {
            requirement_id: req.id.clone(),
            state: COVERED.to_string(),
            mapping_ids,
            unmet_control_ids: Vec::new(),
        })
    }

    pub fn evaluate(&mut self, framework_id: Option<&str>) -> ProgramStatus {
        let control_ids = self.baseline.control_ids.clone();
        let controls: Vec<ControlStatus> =
            control_ids.iter().map(|c| self.control_status(c)).collect();

        let req_ids = self.baseline.requirement_ids.clone();
        let mut requirements = Vec::new();
        for req_id in &req_ids {
            if let Some(fw) = framework_id {
                if self
                    .graph
                    .requirement(req_id)
                    .is_none_or(|r| r.framework_ref != fw)
                {
                    continue;
                }
            }
            if let Some(cov) = self.coverage(req_id) {
                requirements.push(cov);
            }
        }
        ProgramStatus {
            program_id: self.program.id.clone(),
            at: self.at,
            controls,
            requirements,
        }
    }
}

pub fn evaluate(
    graph: &Graph,
    program: &Program,
    at: DateTime<Utc>,
    framework_id: Option<&str>,
) -> ProgramStatus {
    Evaluator::new(graph, program, at).evaluate(framework_id)
}

/// Non-revoked finding with latest `observed` (tie-broken by `modified`) per objective.
pub fn findings_in_force<'a>(
    graph: &'a Graph,
    system_id: &str,
    at: DateTime<Utc>,
) -> Vec<&'a Finding> {
    let eval_date = at.date_naive();
    let mut latest: BTreeMap<&str, &'a Finding> = BTreeMap::new();
    for finding in graph.findings() {
        if finding.system_ref != system_id || finding.observed > eval_date {
            continue;
        }
        match latest.get(finding.objective_ref.as_str()) {
            None => {
                latest.insert(&finding.objective_ref, finding);
            }
            Some(held) => {
                if (finding.observed, finding.modified) > (held.observed, held.modified) {
                    latest.insert(&finding.objective_ref, finding);
                }
            }
        }
    }
    latest.into_values().collect()
}

pub fn summarize(graph: &Graph, program: &Program, at: DateTime<Utc>) -> ProgramSummary {
    let mut evaluator = Evaluator::new(graph, program, at);
    let status = evaluator.evaluate(None);

    let mut control_counts: BTreeMap<String, usize> = [
        (MET.to_string(), 0),
        (GAP.to_string(), 0),
        (WAIVED.to_string(), 0),
        (OUT_OF_SCOPE.to_string(), 0),
    ]
    .into_iter()
    .collect();
    for c in &status.controls {
        *control_counts.entry(c.state.clone()).or_insert(0) += 1;
    }

    let mut req_counts: BTreeMap<String, usize> = [
        (COVERED.to_string(), 0),
        (CONTRIBUTION.to_string(), 0),
        (UNMAPPED.to_string(), 0),
        (GAP.to_string(), 0),
    ]
    .into_iter()
    .collect();
    for r in &status.requirements {
        *req_counts.entry(r.state.clone()).or_insert(0) += 1;
    }

    let horizon = evaluator.date + Duration::days(30);
    let implementations: HashSet<&str> = status
        .controls
        .iter()
        .flat_map(|c| c.implementation_ids.iter().map(String::as_str))
        .collect();

    let mut failing_tests = 0;
    for control_id in &evaluator.baseline.control_ids {
        for test in graph.tests_by_control(control_id) {
            if !evaluator.applies(test) {
                continue;
            }
            for &impl_id in &implementations {
                let latest = graph
                    .results_for_pair(&test.id, impl_id)
                    .into_iter()
                    .filter(|r| r.observed <= evaluator.at)
                    .max_by_key(|r| r.observed);
                if let Some(r) = latest {
                    if matches!(r.outcome, Outcome::Fail | Outcome::Error) {
                        failing_tests += 1;
                    }
                }
            }
        }
    }

    let control_set: HashSet<&str> = evaluator
        .baseline
        .control_ids
        .iter()
        .map(String::as_str)
        .collect();
    let open_risks = graph
        .risks()
        .into_iter()
        .filter(|r| {
            matches!(r.status, RiskStatus::Open | RiskStatus::Treating)
                && (r.system_ref.as_deref() == Some(program.system_ref.as_str())
                    || (r.system_ref.is_none()
                        && r.control_refs
                            .as_deref()
                            .unwrap_or(&[])
                            .iter()
                            .any(|c| control_set.contains(c.as_str()))))
        })
        .count();

    let expiring_evidence = implementations
        .iter()
        .flat_map(|&id| graph.evidence_for_implementation(id))
        .filter(|e| {
            evaluator.evidence_valid(Some(e)) && e.valid_until.is_some_and(|vu| vu <= horizon)
        })
        .count();

    let expiring_exceptions = implementations
        .iter()
        .flat_map(|&id| graph.exceptions_for_implementation(id))
        .filter(|e| e.expires >= evaluator.date && e.expires <= horizon)
        .count();

    let open_findings = findings_in_force(graph, &program.system_ref, at)
        .into_iter()
        .filter(|f| f.determination == Determination::NotSatisfied)
        .count();

    ProgramSummary {
        program_id: program.id.clone(),
        at: evaluator.at,
        controls: control_counts,
        requirements: req_counts,
        failing_tests,
        open_risks,
        expiring_evidence,
        expiring_exceptions,
        open_findings,
    }
}

// --- Library Revision Diff (RFC 0002 §5) ------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateChange {
    pub id: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramDiff {
    pub program_id: String,
    pub controls: Vec<StateChange>,
    pub requirements: Vec<StateChange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawnAlert {
    pub baseline_id: String,
    pub requirement_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibraryDiff {
    #[serde(with = "serde_timestamp")]
    pub at: DateTime<Utc>,
    pub added_objects: usize,
    pub removed_objects: usize,
    pub modified_objects: usize,
    pub programs: Vec<ProgramDiff>,
    pub stale_reviews: Vec<String>,
    pub withdrawn: Vec<WithdrawnAlert>,
}

/// Compare two graphs (e.g., before and after a library revision pull) at one instant.
pub fn compare_revisions(before: &Graph, after: &Graph, at: DateTime<Utc>) -> LibraryDiff {
    let mut added_objects = 0;
    let mut removed_objects = 0;
    let mut modified_objects = 0;
    for (id, obj) in &after.objects {
        if !after.is_library(id) {
            continue;
        }
        match before.objects.get(id) {
            None => added_objects += 1,
            Some(old) if old != obj => modified_objects += 1,
            Some(_) => {}
        }
    }
    for id in &before.library_ids {
        if !after.objects.contains_key(id)
            || after.objects.get(id).is_some_and(|o| {
                o.is_revoked() && !before.objects.get(id).is_some_and(|b| b.is_revoked())
            })
        {
            removed_objects += 1;
        }
    }

    let mut programs = Vec::new();
    for program in before.programs() {
        let old = evaluate(before, program, at, None);
        let new = evaluate(after, program, at, None);
        let old_c: HashMap<&str, &str> = old
            .controls
            .iter()
            .map(|c| (c.control_id.as_str(), c.state.as_str()))
            .collect();
        let new_c: HashMap<&str, &str> = new
            .controls
            .iter()
            .map(|c| (c.control_id.as_str(), c.state.as_str()))
            .collect();
        let all_c: BTreeSet<&str> = old_c.keys().chain(new_c.keys()).copied().collect();
        let controls: Vec<StateChange> = all_c
            .into_iter()
            .filter(|c| old_c.get(c) != new_c.get(c))
            .map(|c| StateChange {
                id: c.to_string(),
                before: old_c.get(c).map(|s| (*s).to_string()),
                after: new_c.get(c).map(|s| (*s).to_string()),
            })
            .collect();

        let old_r: HashMap<&str, &str> = old
            .requirements
            .iter()
            .map(|r| (r.requirement_id.as_str(), r.state.as_str()))
            .collect();
        let new_r: HashMap<&str, &str> = new
            .requirements
            .iter()
            .map(|r| (r.requirement_id.as_str(), r.state.as_str()))
            .collect();
        let all_r: BTreeSet<&str> = old_r.keys().chain(new_r.keys()).copied().collect();
        let requirements: Vec<StateChange> = all_r
            .into_iter()
            .filter(|r| old_r.get(r) != new_r.get(r))
            .map(|r| StateChange {
                id: r.to_string(),
                before: old_r.get(r).map(|s| (*s).to_string()),
                after: new_r.get(r).map(|s| (*s).to_string()),
            })
            .collect();

        if !controls.is_empty() || !requirements.is_empty() {
            programs.push(ProgramDiff {
                program_id: program.id.clone(),
                controls,
                requirements,
            });
        }
    }

    let mut stale_reviews = Vec::new();
    for mapping_id in before.all_review_mapping_ids() {
        let old_m = before.mapping(mapping_id);
        let new_m = after.mapping(mapping_id);
        for review in before.reviews_for_mapping(mapping_id) {
            let was_current = old_m.is_some_and(|m| review.mapping_modified == Some(m.modified));
            let still_current = new_m
                .is_some_and(|m| !m.is_revoked() && review.mapping_modified == Some(m.modified));
            if was_current && !still_current {
                stale_reviews.push(review.id.clone());
            }
        }
    }
    stale_reviews.sort();

    let mut withdrawn = Vec::new();
    for baseline in after.baselines() {
        for r in baseline.requirement_refs.as_deref().unwrap_or(&[]) {
            let old_req = before.requirement(r);
            let new_req = after.requirement(r);
            if new_req.is_some_and(|nr| nr.is_withdrawn())
                && !old_req.is_some_and(|or| or.is_withdrawn())
            {
                withdrawn.push(WithdrawnAlert {
                    baseline_id: baseline.id.clone(),
                    requirement_id: r.clone(),
                });
            }
        }
    }

    LibraryDiff {
        at,
        added_objects,
        removed_objects,
        modified_objects,
        programs,
        stale_reviews,
        withdrawn,
    }
}
