//! Regression probes for RFC 0001 §7.6 test runners, §7.20 constraints, and §6.3 mapping ids.

use serde_json::json;

use ogrl_core::constraints::{Severity, StorageOrigin, check};
use ogrl_core::graph::Graph;
use ogrl_core::model::OgrlObject;

const STAMP: &str = "2026-11-08T00:00:00Z";
const CTRL: &str = "control--ogrl-ac-01";
const REQ: &str = "requirement--nist-sp-800-53-r5-ac-2";

fn minimal_graph(extra: Vec<serde_json::Value>) -> Graph {
    let seed = vec![
        json!({
            "type": "control", "id": CTRL, "spec_version": "0.1.0",
            "created": STAMP, "modified": STAMP,
            "display_id": "OGRL-AC-01", "name": "Unique identities",
            "origin": "standard", "statement": "Assign unique identities.",
            "objective": "One owner per account."
        }),
        json!({
            "type": "requirement", "id": REQ, "spec_version": "0.1.0",
            "created": STAMP, "modified": STAMP,
            "name": "Account Management", "display_id": "AC-2",
            "framework_ref": "framework--nist-sp-800-53-r5",
            "class": "control", "statement": "Manage accounts."
        }),
    ];
    let mut lib_ids: Vec<String> = seed
        .iter()
        .filter_map(|v| v.get("id").and_then(|x| x.as_str()).map(str::to_string))
        .collect();
    let mut objs: Vec<OgrlObject> = seed
        .into_iter()
        .map(|v| OgrlObject::from_value(v).unwrap())
        .collect();
    for v in extra {
        if let Some(id) = v.get("id").and_then(|x| x.as_str()) {
            lib_ids.push(id.to_string());
        }
        objs.push(OgrlObject::from_value(v).unwrap());
    }
    Graph::new(objs, lib_ids, vec![])
}

fn has_error(obj: &OgrlObject, graph: &Graph, origin: StorageOrigin, needle: &str) -> bool {
    check(obj, graph, origin)
        .iter()
        .any(|v| v.severity == Severity::Error && v.detail.contains(needle))
}

fn no_errors(obj: &OgrlObject, graph: &Graph, origin: StorageOrigin) -> bool {
    check(obj, graph, origin)
        .iter()
        .all(|v| v.severity != Severity::Error)
}

#[test]
fn rule_runner_requires_assert_or_aggregate_and_valid_source() {
    let bad_source = OgrlObject::from_value(json!({
        "type": "test", "id": "test--com.acme.t1", "spec_version": "0.1.0",
        "created": STAMP, "modified": STAMP,
        "name": "Bad source", "control_ref": CTRL, "method": "automated",
        "run": { "runner": "rule", "source": "not-a-source", "assert": "true" }
    }))
    .unwrap();
    let g = minimal_graph(vec![]);
    assert!(has_error(
        &bad_source,
        &g,
        StorageOrigin::Organization,
        "<integration>/<resource>@<major>"
    ));

    let missing_assert = OgrlObject::from_value(json!({
        "type": "test", "id": "test--com.acme.t2", "spec_version": "0.1.0",
        "created": STAMP, "modified": STAMP,
        "name": "Missing assert", "control_ref": CTRL, "method": "automated",
        "run": { "runner": "rule", "source": "dev.adversity.okta/users@1" }
    }))
    .unwrap();
    assert!(has_error(
        &missing_assert,
        &g,
        StorageOrigin::Organization,
        "assert or aggregate"
    ));
}

#[test]
fn integration_runner_requires_check_and_sources() {
    let missing_check = OgrlObject::from_value(json!({
        "type": "test", "id": "test--com.acme.t3", "spec_version": "0.1.0",
        "created": STAMP, "modified": STAMP,
        "name": "Missing check", "control_ref": CTRL, "method": "automated",
        "run": {
            "runner": "integration",
            "sources": ["dev.adversity.github/rulesets@1"]
        }
    }))
    .unwrap();
    let g = minimal_graph(vec![]);
    assert!(has_error(
        &missing_check,
        &g,
        StorageOrigin::Organization,
        "requires check"
    ));
}

#[test]
fn provider_shared_requires_customer_responsibility() {
    let imp = OgrlObject::from_value(json!({
        "type": "implementation", "id": "implementation--com.example.idp-ac-01",
        "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
        "origin": "provider", "component_ref": "component--com.example.idp",
        "control_ref": CTRL, "status": "implemented", "responsibility": "shared"
    }))
    .unwrap();
    let g = minimal_graph(vec![json!({
        "type": "component", "id": "component--com.example.idp",
        "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
        "name": "IdP", "kind": "service"
    })]);
    assert!(has_error(
        &imp,
        &g,
        StorageOrigin::Provider,
        "customer_responsibility"
    ));
}

#[test]
fn revoked_mapping_does_not_count_toward_uniqueness() {
    let active = OgrlObject::from_value(json!({
        "type": "mapping", "id": "mapping--ogrl-ac-01_to_nist-sp-800-53-r5-ac-2",
        "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
        "source_ref": CTRL, "target_ref": REQ,
        "relationship": "equal-to", "review_status": "reviewed"
    }))
    .unwrap();
    let g = minimal_graph(vec![
        json!({
            "type": "mapping", "id": "mapping--ogrl-ac-01_to_nist-sp-800-53-r5-ac-2",
            "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
            "source_ref": CTRL, "target_ref": REQ,
            "relationship": "equal-to", "review_status": "reviewed"
        }),
        json!({
            "type": "mapping", "id": "mapping--revoked-duplicate",
            "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
            "revoked": true,
            "source_ref": CTRL, "target_ref": REQ,
            "relationship": "equal-to", "review_status": "draft"
        }),
    ]);
    assert!(no_errors(&active, &g, StorageOrigin::Library));
}

#[test]
fn library_mapping_id_mismatch_is_warning_not_error() {
    let legacy = OgrlObject::from_value(json!({
        "type": "mapping", "id": "mapping--ogrl-ac-01-to-soc2-cc6-2",
        "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
        "source_ref": CTRL, "target_ref": "requirement--soc2-tsc-2017-cc6-2",
        "relationship": "equal-to", "review_status": "reviewed"
    }))
    .unwrap();
    let g = minimal_graph(vec![]);
    let violations = check(&legacy, &g, StorageOrigin::Library);
    assert!(
        violations
            .iter()
            .any(|v| v.severity == Severity::Warning && v.pointer == "/id")
    );
    assert!(
        violations
            .iter()
            .all(|v| v.severity != Severity::Error || v.pointer != "/id")
    );
}
