//! Narrative SSP renderer (`ssp.md` and `ssp.json`, RFC 0001 §8.1).

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use ogrl_core::graph::Graph;
use ogrl_core::model::{OgrlObject, Program};
use ogrl_core::time::format_timestamp;

use crate::render::RenderedFile;
use crate::walk::walk;

pub fn render_ssp(graph: &Graph, program: &Program, at: DateTime<Utc>) -> Vec<RenderedFile> {
    let w = walk(graph, program, at, None);
    let mut lines: Vec<String> = Vec::new();
    let sys_title = w
        .system
        .map(|s| s.name.as_str())
        .unwrap_or(program.system_ref.as_str());

    lines.push(format!("# System security plan: {sys_title}"));
    lines.push(String::new());
    lines.push(format!("Program: {} ({})", program.name, program.id));
    lines.push(format!("Baseline: {}", program.baseline_ref));
    lines.push(format!(
        "Evaluated at: {}",
        format_timestamp(&w.evaluator.at)
    ));
    lines.push(String::new());

    if let Some(sys) = w.system {
        lines.push("## System".into());
        lines.push(String::new());
        lines.push(format!(
            "**Function.** {}",
            sys.function.as_deref().unwrap_or("—")
        ));
        lines.push(String::new());
        lines.push(format!(
            "**Boundary.** {}",
            sys.boundary.as_deref().unwrap_or("—")
        ));
        lines.push(String::new());
        for info in sys.information_types.as_deref().unwrap_or(&[]) {
            lines.push(format!(
                "- {}: confidentiality {}, integrity {}, availability {}",
                info.name,
                info.confidentiality.as_str(),
                info.integrity.as_str(),
                info.availability.as_str()
            ));
        }
        let comps: Vec<_> = sys
            .component_refs
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .filter_map(|r| w.graph.component(r))
            .collect();
        if !comps.is_empty() {
            lines.push(String::new());
            lines.push("**Components.**".into());
            lines.push(String::new());
            for c in comps {
                lines.push(format!("- {} ({})", c.name, c.kind.as_str()));
            }
        }
        for party in sys.parties.as_deref().unwrap_or(&[]) {
            let suffix = match &party.authorization {
                Some(auth) => format!(", authorization {} until {}", auth.identifier, auth.expires),
                None => String::new(),
            };
            lines.push(format!(
                "- Party {}: {}{}",
                party.party_ref,
                party.role.as_str(),
                suffix
            ));
        }
        lines.push(String::new());
    }

    lines.push("## Controls".into());
    lines.push(String::new());
    for entry in &w.controls {
        let c = entry.control;
        lines.push(format!(
            "### {} {}",
            c.display_id.as_deref().unwrap_or(&c.id),
            c.name
        ));
        lines.push(String::new());
        lines.push(format!("**Status:** {}", entry.status.state));
        lines.push(String::new());
        lines.push(entry.statement.trim().to_string());
        lines.push(String::new());
        for imp in &entry.implementations {
            let where_ref = imp
                .component_ref
                .as_deref()
                .or(imp.system_ref.as_deref())
                .unwrap_or("");
            lines.push(format!(
                "- **{}**, {}, on {where_ref}: {}",
                imp.status.as_str(),
                imp.responsibility.as_str(),
                imp.narrative.as_deref().unwrap_or("").trim()
            ));
        }
        for res in &entry.latest_results {
            lines.push(format!(
                "- Latest result of {}: {} at {}",
                res.test_ref,
                res.outcome.as_str(),
                format_timestamp(&res.observed)
            ));
        }
        for ev in &entry.evidence {
            let vu = ev
                .valid_until
                .map(|d| d.to_string())
                .unwrap_or_else(|| "open".into());
            lines.push(format!("- Evidence {}, valid until {vu}", ev.name));
        }
        for exc in &entry.exceptions {
            lines.push(format!(
                "- Exception until {}: {}",
                exc.expires,
                exc.justification.trim()
            ));
        }
        for failure in &entry.status.failed {
            lines.push(format!("- Gap: {failure}"));
        }
        lines.push(String::new());
    }

    if !w.findings.is_empty() {
        lines.push("## Findings in force".into());
        lines.push(String::new());
        for f in &w.findings {
            lines.push(format!(
                "- {}: {} ({})",
                f.objective_ref,
                f.determination.as_str(),
                f.observed
            ));
        }
        lines.push(String::new());
    }

    if !w.policies.is_empty() || !w.procedures.is_empty() {
        lines.push("## Policies and procedures".into());
        lines.push(String::new());
        for p in &w.policies {
            let label = match &p.version {
                Some(v) if !v.is_empty() => format!("Policy {} {v}", p.name),
                _ => format!("Policy {}", p.name),
            };
            lines.push(format!("- {label}"));
        }
        for p in &w.procedures {
            lines.push(format!("- Procedure {}", p.name));
        }
        lines.push(String::new());
    }

    if !w.risks.is_empty() {
        lines.push("## Open risks".into());
        lines.push(String::new());
        for r in &w.risks {
            lines.push(format!(
                "- {}: likelihood {}, impact {}, {}",
                r.name,
                r.likelihood,
                r.impact,
                r.treatment.as_str()
            ));
            for m in r.milestones.as_deref().unwrap_or(&[]) {
                let done = m.done.map(|d| format!(", done {d}")).unwrap_or_default();
                lines.push(format!("  - {}, due {}{done}", m.name, m.due));
            }
        }
    }

    let controls_json: Vec<Value> = w
        .controls
        .iter()
        .map(|e| {
            json!({
                "control_id": e.control.id,
                "state": e.status.state,
                "failed": e.status.failed,
                "statement": e.statement,
                "implementations": e.implementations.iter().map(|i| OgrlObject::Implementation((*i).clone()).to_json_value()).collect::<Vec<_>>(),
                "latest_results": e.latest_results.iter().map(|r| OgrlObject::Result((*r).clone()).to_json_value()).collect::<Vec<_>>(),
                "evidence": e.evidence.iter().map(|x| OgrlObject::Evidence((*x).clone()).to_json_value()).collect::<Vec<_>>(),
                "exceptions": e.exceptions.iter().map(|x| OgrlObject::Exception((*x).clone()).to_json_value()).collect::<Vec<_>>(),
            })
        })
        .collect();

    let data = json!({
        "program_id": program.id,
        "at": format_timestamp(&w.evaluator.at),
        "system": w.system.map(|s| OgrlObject::System(s.clone()).to_json_value()),
        "controls": controls_json,
        "findings": w.findings.iter().map(|f| OgrlObject::Finding((*f).clone()).to_json_value()).collect::<Vec<_>>(),
        "policies": w.policies.iter().map(|p| OgrlObject::Policy((*p).clone()).to_json_value()).collect::<Vec<_>>(),
        "procedures": w.procedures.iter().map(|p| OgrlObject::Procedure((*p).clone()).to_json_value()).collect::<Vec<_>>(),
        "risks": w.risks.iter().map(|r| OgrlObject::Risk((*r).clone()).to_json_value()).collect::<Vec<_>>(),
    });

    vec![
        RenderedFile {
            name: "ssp.md".into(),
            media_type: "text/markdown".into(),
            content: lines.join("\n").into_bytes(),
        },
        RenderedFile {
            name: "ssp.json".into(),
            media_type: "application/json".into(),
            content: serde_json::to_vec_pretty(&data).unwrap(),
        },
    ]
}
