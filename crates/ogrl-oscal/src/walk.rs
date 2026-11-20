//! Shared program walk for SSP and OSCAL renderers (RFC 0001 §8.1).

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};

use ogrl_core::graph::Graph;
use ogrl_core::model::{
    Control, DocumentStatus, Evidence, ExceptionObj, Finding, Implementation, Policy, Procedure,
    Program, Risk, RiskStatus, System, TestResult,
};
use ogrl_core::parameters::{control_values, render as render_params};
use ogrl_core::status::{self, ControlStatus, Evaluator, RequirementCoverage};

pub struct ControlEntry<'a> {
    pub control: &'a Control,
    pub status: ControlStatus,
    pub statement: String,
    pub implementations: Vec<&'a Implementation>,
    pub latest_results: Vec<&'a TestResult>,
    pub evidence: Vec<&'a Evidence>,
    pub exceptions: Vec<&'a ExceptionObj>,
}

pub struct Walk<'a> {
    pub graph: &'a Graph,
    pub program: &'a Program,
    pub evaluator: Evaluator<'a>,
    pub system: Option<&'a System>,
    pub controls: Vec<ControlEntry<'a>>,
    pub findings: Vec<&'a Finding>,
    pub policies: Vec<&'a Policy>,
    pub procedures: Vec<&'a Procedure>,
    pub risks: Vec<&'a Risk>,
    pub requirements: Vec<RequirementCoverage>,
}

pub fn walk<'a>(
    graph: &'a Graph,
    program: &'a Program,
    at: DateTime<Utc>,
    framework_id: Option<&str>,
) -> Walk<'a> {
    let mut evaluator = Evaluator::new(graph, program, at);
    let evaluated = evaluator.evaluate(framework_id);
    let by_control: HashMap<String, ControlStatus> = evaluated
        .controls
        .into_iter()
        .map(|c| (c.control_id.clone(), c))
        .collect();

    let mut entries = Vec::new();
    let control_ids = evaluator.baseline.control_ids.clone();
    for control_id in &control_ids {
        let Some(control) = graph.control(control_id) else {
            continue;
        };
        let eval = evaluator.under_evaluation(control_id);
        let mut impls = eval.implementations;
        impls.extend(eval.provider_halves);
        let primary = impls.first().copied();
        let values = control_values(control, primary, &evaluator.baseline.parameter_bindings);

        let mut latest_results = Vec::new();
        for test in graph.tests_by_control(control_id) {
            if !(test.required.unwrap_or(false) && evaluator.applies(test)) {
                continue;
            }
            for &imp in &impls {
                if let Some(res) = graph
                    .results_for_pair(&test.id, &imp.id)
                    .into_iter()
                    .filter(|r| r.observed <= evaluator.at)
                    .max_by_key(|r| r.observed)
                {
                    latest_results.push(res);
                }
            }
        }

        let mut evidence = Vec::new();
        let mut exceptions = Vec::new();
        for &imp in &impls {
            for e in graph.evidence_for_implementation(&imp.id) {
                if evaluator.evidence_valid(Some(e)) {
                    evidence.push(e);
                }
            }
            exceptions.extend(graph.exceptions_for_implementation(&imp.id));
        }

        entries.push(ControlEntry {
            control,
            status: by_control[control_id].clone(),
            statement: render_params(Some(&control.statement), &values),
            implementations: impls,
            latest_results,
            evidence,
            exceptions,
        });
    }

    let control_set: HashSet<&str> = control_ids.iter().map(String::as_str).collect();
    let findings = status::findings_in_force(graph, &program.system_ref, at);
    let policies = graph
        .policies()
        .into_iter()
        .filter(|p| {
            p.status == DocumentStatus::Adopted
                && p.control_refs
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .any(|c| control_set.contains(c.as_str()))
        })
        .collect();
    let procedures = graph
        .procedures()
        .into_iter()
        .filter(|p| {
            p.status == DocumentStatus::Adopted
                && p.control_refs
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .any(|c| control_set.contains(c.as_str()))
        })
        .collect();
    let risks = graph
        .risks()
        .into_iter()
        .filter(|r| {
            matches!(r.status, RiskStatus::Open | RiskStatus::Treating)
                && r.control_refs
                    .as_deref()
                    .unwrap_or(&[])
                    .iter()
                    .any(|c| control_set.contains(c.as_str()))
        })
        .collect();

    Walk {
        graph,
        program,
        evaluator,
        system: graph.system(&program.system_ref),
        controls: entries,
        findings,
        policies,
        procedures,
        risks,
        requirements: evaluated.requirements,
    }
}
