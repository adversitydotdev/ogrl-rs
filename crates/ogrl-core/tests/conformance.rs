//! Conformance tests for RFC 0001 §7.20 constraints, §8 status evaluation,
//! §7.3/7.4 parameter resolution, and RFC 0002 §5 library diffs.

use chrono::{TimeZone, Utc};
use serde_json::{Value, json};

use ogrl_core::constraints::{StorageOrigin, check};
use ogrl_core::graph::Graph;
use ogrl_core::model::OgrlObject;
use ogrl_core::parameters::requirement_value;
use ogrl_core::status::{self, compare_revisions};
use std::collections::HashMap;

const STAMP: &str = "2026-11-08T00:00:00Z";
const FW_53: &str = "framework--nist-sp-800-53-r5";
const AC2: &str = "requirement--nist-sp-800-53-r5-ac-2";
const AC3: &str = "requirement--nist-sp-800-53-r5-ac-3";
const C1: &str = "control--ogrl-ac-01";
const C2: &str = "control--ogrl-ac-02";
const LIB_BASELINE: &str = "baseline--ogrl-soc2";
const LIB_TEST: &str = "test--ogrl-ac-01-unique";
const AC2_A: &str = "mapping--ogrl-ac-01_to_nist-sp-800-53-r5-ac-2_part_a";
const AC2_J: &str = "mapping--ogrl-ac-02_to_nist-sp-800-53-r5-ac-2_part_j";

fn library_fixture() -> Vec<OgrlObject> {
    let raw = vec![
        json!({
            "type": "framework", "id": FW_53, "spec_version": "0.1.0",
            "created": STAMP, "modified": STAMP,
            "name": "NIST SP 800-53 r5", "publisher": "NIST", "version": "5.2.0",
            "reproduction": "permitted"
        }),
        json!({
            "type": "requirement", "id": AC2, "spec_version": "0.1.0",
            "created": STAMP, "modified": STAMP,
            "name": "Account Management", "display_id": "AC-2",
            "framework_ref": FW_53, "class": "control",
            "parameters": { "ac_02_odp_10": { "label": "frequency" } },
            "parts": [
                { "id": "a", "statement": "Define account types." },
                { "id": "j", "statement": "Review accounts {{ ac_02_odp_10 }}." }
            ],
            "objectives": [
                { "id": "a", "statement": "Determine if account types are defined." }
            ]
        }),
        json!({
            "type": "requirement", "id": AC3, "spec_version": "0.1.0",
            "created": STAMP, "modified": STAMP,
            "name": "Access Enforcement", "display_id": "AC-3",
            "framework_ref": FW_53, "class": "control",
            "statement": "Enforce approved authorizations."
        }),
        json!({
            "type": "control", "id": C1, "spec_version": "0.1.0",
            "created": STAMP, "modified": STAMP,
            "display_id": "OGRL-AC-01", "name": "Unique identities",
            "origin": "standard", "statement": "Assign unique identities.",
            "objective": "One owner per account."
        }),
        json!({
            "type": "control", "id": C2, "spec_version": "0.1.0",
            "created": STAMP, "modified": STAMP,
            "display_id": "OGRL-AC-02", "name": "Access review",
            "origin": "standard", "statement": "Review accounts regularly.",
            "objective": "Stale accounts removed."
        }),
        json!({
            "type": "mapping", "id": AC2_A, "spec_version": "0.1.0",
            "created": STAMP, "modified": STAMP,
            "source_ref": C1, "target_ref": format!("{AC2}#a"),
            "relationship": "equal-to", "review_status": "reviewed"
        }),
        json!({
            "type": "mapping", "id": AC2_J, "spec_version": "0.1.0",
            "created": STAMP, "modified": STAMP,
            "source_ref": C2, "target_ref": format!("{AC2}#j"),
            "relationship": "subset-of", "review_status": "draft"
        }),
        json!({
            "type": "mapping", "id": "mapping--ogrl-ac-02_to_nist-sp-800-53-r5-ac-3",
            "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
            "source_ref": C2, "target_ref": AC3,
            "relationship": "intersects-with", "review_status": "draft"
        }),
        json!({
            "type": "baseline", "id": LIB_BASELINE, "spec_version": "0.1.0",
            "created": STAMP, "modified": STAMP,
            "name": "SOC 2", "framework_refs": [FW_53],
            "control_refs": [C1, C2]
        }),
        json!({
            "type": "test", "id": LIB_TEST, "spec_version": "0.1.0",
            "created": STAMP, "modified": STAMP,
            "name": "Unique IDs check", "control_ref": C1,
            "method": "automated", "interval": "monthly", "required": true
        }),
    ];
    raw.into_iter()
        .map(|v| OgrlObject::from_value(v).unwrap())
        .collect()
}

fn graph_with(extra: Vec<Value>) -> Graph {
    let lib = library_fixture();
    let lib_ids: Vec<String> = lib.iter().map(|o| o.id().to_string()).collect();
    let mut objs = lib;
    let mut prov_ids = Vec::new();
    for v in extra {
        let is_prov = v.get("origin").and_then(Value::as_str) == Some("provider");
        let obj = OgrlObject::from_value(v).unwrap();
        if is_prov {
            prov_ids.push(obj.id().to_string());
        }
        objs.push(obj);
    }
    Graph::new(objs, lib_ids, prov_ids)
}

fn base_org() -> Vec<Value> {
    vec![
        json!({
            "type": "component", "id": "component--com.example.idp",
            "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
            "name": "IdP", "kind": "service"
        }),
        json!({
            "type": "system", "id": "system--com.acme.prod",
            "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
            "name": "Prod", "component_refs": ["component--com.example.idp"]
        }),
        json!({
            "type": "program", "id": "program--com.acme.p",
            "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
            "name": "P", "system_ref": "system--com.acme.prod",
            "baseline_ref": LIB_BASELINE
        }),
    ]
}

#[test]
fn provider_evidence_satisfies_unfulfilled_library_test() {
    let mut extra = base_org();
    extra.push(json!({
        "type": "implementation", "id": "implementation--com.example.idp-ac-01",
        "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
        "origin": "provider", "component_ref": "component--com.example.idp",
        "control_ref": C1, "status": "implemented", "responsibility": "provider"
    }));
    let at = Utc.with_ymd_and_hms(2026, 11, 9, 0, 0, 0).unwrap();

    let g1 = graph_with(extra.clone());
    let st1 = status::evaluate(&g1, g1.program("program--com.acme.p").unwrap(), at, None);
    let c1 = st1.controls.iter().find(|c| c.control_id == C1).unwrap();
    assert_eq!(c1.state, "gap");
    assert!(c1.failed[0].contains("provider row"));

    extra.push(json!({
        "type": "evidence", "id": "evidence--com.example.soc2",
        "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
        "name": "SOC 2", "method": "attestation",
        "implementation_ref": "implementation--com.example.idp-ac-01",
        "valid_until": "2027-06-01",
        "resource": {
            "uri": "https://example.com/soc2.pdf",
            "digest": { "algorithm": "sha-256", "value": "00" }
        }
    }));
    let g2 = graph_with(extra);
    let st2 = status::evaluate(&g2, g2.program("program--com.acme.p").unwrap(), at, None);
    let c1 = st2.controls.iter().find(|c| c.control_id == C1).unwrap();
    assert_eq!(c1.state, "met");
}

#[test]
fn shared_provider_half_requires_org_half_and_unexpired_provider_evidence() {
    let mut extra = base_org();
    extra.push(json!({
        "type": "implementation", "id": "implementation--com.example.idp-ac-02",
        "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
        "origin": "provider", "component_ref": "component--com.example.idp",
        "control_ref": C2, "status": "implemented", "responsibility": "shared",
        "customer_responsibility": "Review guests."
    }));
    let at = Utc.with_ymd_and_hms(2026, 11, 9, 0, 0, 0).unwrap();
    let g1 = graph_with(extra.clone());
    let c2 = status::evaluate(&g1, g1.program("program--com.acme.p").unwrap(), at, None)
        .controls
        .into_iter()
        .find(|c| c.control_id == C2)
        .unwrap();
    assert_eq!(c2.state, "gap");
    assert!(c2.failed[0].contains("organization's implementation is missing"));

    extra.push(json!({
        "type": "implementation", "id": "implementation--com.acme.ac-02",
        "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
        "system_ref": "system--com.acme.prod", "control_ref": C2,
        "status": "implemented", "responsibility": "shared"
    }));
    extra.push(json!({
        "type": "evidence", "id": "evidence--com.acme.review",
        "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
        "name": "Review", "method": "link",
        "implementation_ref": "implementation--com.acme.ac-02",
        "valid_until": "2027-01-01"
    }));
    let g2 = graph_with(extra.clone());
    let c2 = status::evaluate(&g2, g2.program("program--com.acme.p").unwrap(), at, None)
        .controls
        .into_iter()
        .find(|c| c.control_id == C2)
        .unwrap();
    assert_eq!(c2.state, "met");

    extra.push(json!({
        "type": "evidence", "id": "evidence--com.example.old",
        "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
        "name": "Old", "method": "link",
        "implementation_ref": "implementation--com.example.idp-ac-02",
        "valid_until": "2026-01-01"
    }));
    let g3 = graph_with(extra);
    let c2 = status::evaluate(&g3, g3.program("program--com.acme.p").unwrap(), at, None)
        .controls
        .into_iter()
        .find(|c| c.control_id == C2)
        .unwrap();
    assert_eq!(c2.state, "gap");
}

#[test]
fn requirement_only_provider_row_joins_and_combined_set_covers() {
    let mut extra = base_org();
    extra.push(json!({
        "type": "implementation", "id": "implementation--com.example.idp-ac-2",
        "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
        "origin": "provider", "component_ref": "component--com.example.idp",
        "requirement_ref": AC2, "status": "implemented", "responsibility": "provider"
    }));
    let at = Utc.with_ymd_and_hms(2026, 11, 9, 0, 0, 0).unwrap();
    let g = graph_with(extra);
    let st = status::evaluate(&g, g.program("program--com.acme.p").unwrap(), at, None);
    let c1 = st.controls.iter().find(|c| c.control_id == C1).unwrap();
    assert_eq!(
        c1.implementation_ids,
        vec!["implementation--com.example.idp-ac-2"]
    );
}

#[test]
fn requirement_override_and_constraints_and_diff() {
    let g = graph_with(base_org());
    let impl_obj = OgrlObject::from_value(json!({
        "type": "implementation", "id": "implementation--com.acme.ac-01",
        "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
        "system_ref": "system--com.acme.prod", "control_ref": C1,
        "status": "implemented", "responsibility": "provider",
        "requirement_parameter_values": { AC2: { "ac_02_odp_10": "weekly" } }
    }))
    .unwrap();
    let imp = match &impl_obj {
        OgrlObject::Implementation(i) => i,
        _ => unreachable!(),
    };
    let mut impls = HashMap::new();
    impls.insert(C1.to_string(), imp);
    let val = requirement_value(
        &g,
        AC2,
        "ac_02_odp_10",
        &[C1.into()],
        &impls,
        &Default::default(),
    );
    assert_eq!(val.as_deref(), Some("weekly"));

    // Constraint check: invalid #part fragment on mapping is caught.
    let bad_map = OgrlObject::from_value(json!({
        "type": "mapping", "id": "mapping--com.acme.bad",
        "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
        "source_ref": C1, "target_ref": format!("{AC2}#z"),
        "relationship": "equal-to"
    }))
    .unwrap();
    let violations = check(&bad_map, &g, StorageOrigin::Organization);
    assert!(
        violations
            .iter()
            .any(|v| v.detail.contains("#z is not a part"))
    );

    // Revision diff detects stale mapping review when upstream mapping modified advances.
    let mut before_extra = base_org();
    before_extra.push(json!({
        "type": "mapping_review", "id": "mapping_review--com.acme.r1",
        "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
        "mapping_ref": AC2_J, "library_version": "0.1.0",
        "mapping_modified": STAMP, "review_status": "reviewed"
    }));
    let before = graph_with(before_extra);
    let mut next_lib = library_fixture();
    for o in &mut next_lib {
        if let OgrlObject::Mapping(m) = o {
            if m.id == AC2_J {
                m.modified = Utc.with_ymd_and_hms(2026, 11, 10, 0, 0, 0).unwrap();
            }
        }
    }
    let after = before.with_library(next_lib);
    let diff = compare_revisions(
        &before,
        &after,
        Utc.with_ymd_and_hms(2026, 11, 10, 0, 0, 0).unwrap(),
    );
    assert_eq!(diff.stale_reviews, vec!["mapping_review--com.acme.r1"]);
}

#[test]
fn unknown_fields_survive_round_trip() {
    let input = json!({
        "type": "party", "id": "party--com.acme.sec",
        "spec_version": "0.1.0", "created": STAMP, "modified": STAMP,
        "name": "Security", "kind": "team",
        "future_field": { "nested": [1, 2, 3] }
    });
    let obj = OgrlObject::from_value(input.clone()).unwrap();
    let out = obj.to_json_value();
    assert_eq!(out["future_field"], input["future_field"]);
}
