//! Tests for OSCAL 1.2.3 catalog import (including assessment objectives),
//! component-definition import, and 6-doc JSON + XML package rendering.

use chrono::{TimeZone, Utc};
use serde_json::{Value, json};
use tempfile::TempDir;

use ogrl_core::bundle::read_directory;
use ogrl_core::constraints::{StorageOrigin, check_graph_parallel};
use ogrl_core::graph::Graph;
use ogrl_core::model::OgrlObject;
use ogrl_core::yaml::ParseOptions;
use ogrl_oscal::{
    ImportOptions, import_catalog_bytes, import_component_definition, render_oscal_package,
    render_ssp, write_library_bundle, write_library_output,
};

const FIXTURE_53: &str = r##"{
  "catalog": {
    "metadata": {
      "title": "Fixture",
      "last-modified": "2026-10-22T11:30:00.00000-00:00",
      "version": "5.2.0",
      "oscal-version": "1.2.3"
    },
    "groups": [{
      "id": "ac",
      "controls": [{
        "id": "ac-2",
        "class": "SP800-53",
        "title": "Account Management",
        "params": [{
          "id": "ac-02_odp.01",
          "label": "frequency",
          "props": [{"name": "alt-identifier", "value": "ac-2_prm_1"}]
        }],
        "props": [
          {"name": "label", "value": "AC-02", "class": "zero-padded"},
          {"name": "label", "value": "AC-2"},
          {"name": "sort-id", "value": "ac-02"}
        ],
        "links": [
          {"href": "#pub", "rel": "reference"},
          {"href": "#ac-1", "rel": "related"}
        ],
        "parts": [
          {
            "id": "ac-2_smt",
            "name": "statement",
            "parts": [{
              "id": "ac-2_smt.a",
              "name": "item",
              "props": [{"name": "label", "value": "a."}],
              "prose": "Review accounts {{ insert: param, ac-2_prm_1 }}.",
              "parts": [{
                "id": "ac-2_smt.a.1",
                "name": "item",
                "props": [{"name": "label", "value": "1."}],
                "prose": "Include emergency accounts."
              }]
            }]
          },
          {
            "id": "ac-2_obj",
            "name": "assessment-objective",
            "parts": [{
              "id": "ac-2_obj.a",
              "name": "assessment-objective",
              "prose": "Determine if accounts are reviewed {{ insert: param, ac-2_prm_1 }}."
            }]
          },
          {
            "id": "ac-2_mth.examine",
            "name": "assessment-method",
            "props": [{"name": "method", "value": "EXAMINE"}],
            "parts": [{"name": "assessment-objects", "prose": "Account management policy."}]
          }
        ],
        "controls": [{
          "id": "ac-2.1",
          "class": "SP800-53-enhancement",
          "title": "Automated System Account Management",
          "props": [
            {"name": "label", "value": "AC-02(01)", "class": "zero-padded"},
            {"name": "label", "value": "AC-2(1)"},
            {"name": "status", "value": "withdrawn"}
          ],
          "links": [{"href": "#ac-2_smt.a", "rel": "incorporated-into"}],
          "parts": [{
            "id": "ac-2.1_smt",
            "name": "statement",
            "prose": "Support the management of system accounts using {{ insert: param, ac-02_odp.01 }}."
          }]
        }]
      }]
    }],
    "back-matter": {
      "resources": [{
        "uuid": "pub",
        "title": "SP 800-162",
        "rlinks": [{"href": "https://csrc.nist.gov/publications/detail/sp/800-162"}]
      }]
    }
  }
}"##;

const FIXTURE_171: &str = r##"{
  "catalog": {
    "metadata": {
      "title": "Fixture 171",
      "last-modified": "2026-10-22T11:30:00Z",
      "version": "1.1.0"
    },
    "groups": [{
      "id": "03.01",
      "controls": [{
        "id": "SP_800_171_03.01.01",
        "class": "requirement",
        "title": "Account Management",
        "props": [
          {"name": "sort-id", "value": "03.01.01"},
          {"name": "label", "value": "Account Management (03.01.01)"}
        ],
        "links": [
          {"href": "#ac02", "rel": "reference"},
          {"href": "#guide", "rel": "reference"}
        ],
        "parts": [
          {
            "id": "stmt",
            "name": "statement",
            "parts": [{
              "name": "item",
              "props": [{"name": "label", "value": "SR-03.01.01.a"}],
              "prose": "Define the types of system accounts allowed and prohibited."
            }]
          },
          {
            "id": "assessment-objective_DS-A.03.01.01.a.01",
            "name": "assessment-objective",
            "prose": "system account types allowed are defined."
          }
        ]
      }, {
        "id": "SP_800_171_03.01.14",
        "class": "requirement",
        "title": "03.01.14",
        "props": [
          {"name": "sort-id", "value": "03.01.14"},
          {"name": "status", "value": "withdrawn"}
        ],
        "links": [{"href": "03.01.01", "rel": "incorporated_into"}]
      }]
    }],
    "back-matter": {
      "resources": [
        {"uuid": "ac02", "title": "AC-02", "rlinks": [{"href": "https://csrc.nist.gov/projects/cprt/catalog"}]},
        {"uuid": "guide", "title": "SP 800-162", "rlinks": [{"href": "https://csrc.nist.gov/publications/detail/sp/800-162"}]}
      ]
    }
  }
}"##;

#[test]
fn catalog_import_extracts_parts_params_objectives_and_validates_cleanly() {
    let dir = TempDir::new().unwrap();
    let out53 = import_catalog_bytes(
        FIXTURE_53.as_bytes(),
        &ImportOptions {
            framework_id: "nist-sp-800-53-r5".into(),
            name: Some("NIST SP 800-53 Revision 5".into()),
            publisher: "NIST".into(),
            source_uri: Some("https://github.com/usnistgov/oscal-content".into()),
            source_path: Some(
                "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json".into(),
            ),
            commit: Some("abc".into()),
            version: None,
        },
        None,
    )
    .unwrap();
    assert_eq!(out53.requirements.len(), 2);
    assert_eq!(out53.withdrawn_count, 1);
    assert_eq!(out53.mappings.len(), 1);
    assert_eq!(out53.objectives_count, 1);

    let ac2 = &out53.requirements[0].1;
    let objs = ac2.objectives.as_ref().unwrap();
    assert_eq!(objs[0].id, "a");
    assert!(objs[0].statement.contains("{{ ac_02_odp_01 }}"));
    assert_eq!(objs[0].methods.as_ref().unwrap().len(), 1);

    write_library_output(dir.path(), &out53).unwrap();

    let out171 = import_catalog_bytes(
        FIXTURE_171.as_bytes(),
        &ImportOptions {
            framework_id: "nist-sp-800-171-r3".into(),
            name: Some("NIST SP 800-171 Revision 3".into()),
            publisher: "NIST".into(),
            ..Default::default()
        },
        Some(&out53.index),
    )
    .unwrap();
    assert_eq!(out171.requirements.len(), 2);
    assert_eq!(out171.withdrawn_count, 1);
    assert_eq!(out171.mappings.len(), 2);
    assert_eq!(out171.objectives_count, 1);
    assert_eq!(
        out171.requirements[0].1.objectives.as_ref().unwrap()[0].id,
        "a.01"
    );
    write_library_output(dir.path(), &out171).unwrap();
    write_library_bundle(dir.path(), out53.modified, out53.modified).unwrap();

    // Parse back with strict YAML 1.2 loader and run full graph validation!
    let loaded = read_directory(
        dir.path(),
        ParseOptions::default(),
        Some(StorageOrigin::Library),
    )
    .unwrap();
    assert!(
        loaded.diagnostics.is_empty(),
        "diags: {:?}",
        loaded.diagnostics
    );
    let graph = loaded.to_graph();
    let meta = loaded.metadata_index();
    let diags = check_graph_parallel(
        &graph,
        |_| StorageOrigin::Library,
        |id| {
            meta.get(id)
                .map(|(f, s, _)| (f.clone(), *s))
                .unwrap_or((None, None))
        },
    );
    assert!(diags.is_empty(), "constraint diags: {diags:?}");
}

#[test]
fn component_definition_import_and_oscal_json_xml_render() {
    let out53 = import_catalog_bytes(
        FIXTURE_53.as_bytes(),
        &ImportOptions {
            framework_id: "nist-sp-800-53-r5".into(),
            name: Some("NIST SP 800-53 Revision 5".into()),
            ..Default::default()
        },
        None,
    )
    .unwrap();

    let mut lib_objs: Vec<OgrlObject> = vec![OgrlObject::Framework(out53.framework)];
    lib_objs.extend(
        out53
            .requirements
            .into_iter()
            .map(|(_, r)| OgrlObject::Requirement(r)),
    );
    lib_objs.extend(out53.mappings.into_iter().map(OgrlObject::Mapping));
    let lib_ids: Vec<String> = lib_objs.iter().map(|o| o.id().to_string()).collect();
    let lib_graph = Graph::new(lib_objs.clone(), lib_ids.clone(), vec![]);

    let cd_json = json!({
        "component-definition": {
            "uuid": "11111111-1111-4111-8111-111111111111",
            "metadata": {
                "title": "Django",
                "last-modified": "2026-11-08T00:00:00Z",
                "version": "1.0",
                "parties": [{
                    "uuid": "22222222-2222-4222-8222-222222222222",
                    "type": "organization",
                    "name": "CivicActions"
                }]
            },
            "components": [{
                "uuid": "33333333-3333-4333-8333-333333333333",
                "type": "software",
                "title": "Django Framework",
                "description": "Web framework",
                "responsible-roles": [{"party-uuids": ["22222222-2222-4222-8222-222222222222"]}],
                "control-implementations": [{
                    "source": "NIST_SP-800-53_rev5_catalog.json",
                    "implemented-requirements": [{
                        "uuid": "44444444-4444-4444-8444-444444444444",
                        "control-id": "ac-2",
                        "description": "Django auth manages accounts.",
                        "props": [{"name": "control-origination", "value": "shared"}]
                    }]
                }]
            }]
        }
    });

    let imported =
        import_component_definition(serde_json::to_vec(&cd_json).unwrap().as_slice(), &lib_graph)
            .unwrap();
    assert!(imported.warnings.is_empty());
    assert_eq!(imported.objects.len(), 3); // party + component + implementation

    // Build a small program graph and render OSCAL (JSON + XML) and narrative SSP.
    let stamp = "2026-11-08T00:00:00Z";
    let mut all_objs = lib_objs;
    all_objs.extend(imported.objects);
    for extra in [
        json!({
            "type": "control", "id": "control--ogrl-ac-01", "spec_version": "0.1.0",
            "created": stamp, "modified": stamp, "origin": "standard",
            "name": "Account Management", "statement": "Manage accounts.", "objective": "Managed."
        }),
        json!({
            "type": "mapping", "id": "mapping--ogrl-ac-01_to_nist-sp-800-53-r5-ac-2",
            "spec_version": "0.1.0", "created": stamp, "modified": stamp,
            "source_ref": "control--ogrl-ac-01",
            "target_ref": "requirement--nist-sp-800-53-r5-ac-2",
            "relationship": "equal-to", "review_status": "reviewed"
        }),
        json!({
            "type": "baseline", "id": "baseline--com.acme.b1", "spec_version": "0.1.0",
            "created": stamp, "modified": stamp, "name": "B1",
            "framework_refs": ["framework--nist-sp-800-53-r5"],
            "control_refs": ["control--ogrl-ac-01"]
        }),
        json!({
            "type": "system", "id": "system--com.acme.s1", "spec_version": "0.1.0",
            "created": stamp, "modified": stamp, "name": "App",
            "component_refs": ["component--33333333-3333-4333-8333-333333333333"]
        }),
        json!({
            "type": "program", "id": "program--com.acme.p1", "spec_version": "0.1.0",
            "created": stamp, "modified": stamp, "name": "FedRAMP",
            "system_ref": "system--com.acme.s1", "baseline_ref": "baseline--com.acme.b1"
        }),
        json!({
            "type": "implementation", "id": "implementation--com.acme.i1", "spec_version": "0.1.0",
            "created": stamp, "modified": stamp,
            "system_ref": "system--com.acme.s1", "control_ref": "control--ogrl-ac-01",
            "status": "implemented", "responsibility": "provider",
            "narrative": "Managed centrally."
        }),
    ] {
        all_objs.push(OgrlObject::from_value(extra).unwrap());
    }

    let g = Graph::new(all_objs, lib_ids, vec![]);
    let prog = g.program("program--com.acme.p1").unwrap();
    let at = Utc.with_ymd_and_hms(2026, 11, 9, 0, 0, 0).unwrap();

    let files = render_oscal_package(&g, prog, "framework--nist-sp-800-53-r5", at, true).unwrap();
    assert_eq!(files.len(), 12); // 6 JSON + 6 XML
    let ssp_json: Value =
        serde_json::from_slice(&files.iter().find(|f| f.name == "ssp.json").unwrap().content)
            .unwrap();
    assert_eq!(
        ssp_json["system-security-plan"]["control-implementation"]["implemented-requirements"][0]["control-id"],
        "ac-2"
    );
    let ssp_xml = String::from_utf8(
        files
            .iter()
            .find(|f| f.name == "ssp.xml")
            .unwrap()
            .content
            .clone(),
    )
    .unwrap();
    assert!(ssp_xml.contains("http://csrc.nist.gov/ns/oscal/1.0"));
    assert!(ssp_xml.contains("<system-security-plan"));

    let ssp_files = render_ssp(&g, prog, at);
    assert_eq!(ssp_files.len(), 2);
}
