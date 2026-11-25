"""Python binding tests for `ogrl_rs`, including live parity checks against ogrl-library."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

import ogrl_rs

STAMP = "2026-11-08T00:00:00Z"


def test_binding_version_matches_package_metadata() -> None:
    import importlib.metadata
    import re

    assert re.fullmatch(r"\d+\.\d+\.\d+", ogrl_rs.__version__)
    assert ogrl_rs.__version__ == importlib.metadata.version("ogrl-rs")


OGRL_LIBRARY = Path(__file__).resolve().parents[3] / "ogrl-library" / "library"


def test_strict_yaml_and_canonical_roundtrip() -> None:
    obj = {
        "type": "party",
        "id": "party--com.acme.sec",
        "spec_version": "0.1.0",
        "created": STAMP,
        "modified": STAMP,
        "name": "Security",
        "kind": "team",
        "custom_extra": {"preserved": True},
    }
    yml = ogrl_rs.format_yaml(obj)
    parsed = ogrl_rs.parse_yaml(yml)
    assert parsed == obj

    # Explicit null and anchors are rejected in strict YAML 1.2 mode.
    with pytest.raises(ValueError, match="null"):
        ogrl_rs.parse_yaml("type: party\nname: null\n")
    with pytest.raises(ValueError, match="anchor"):
        ogrl_rs.parse_yaml("a: &x foo\nb: *x\n")

    # RFC 8785 canonical JSON sorts keys compactly.
    assert ogrl_rs.canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_graph_constraints_eval_diff_and_renders() -> None:
    fw_id = "framework--nist-sp-800-53-r5"
    ac2_id = "requirement--nist-sp-800-53-r5-ac-2"
    c1_id = "control--ogrl-ac-01"
    map_id = "mapping--ogrl-ac-01_to_nist-sp-800-53-r5-ac-2"
    base_id = "baseline--ogrl-test"

    library = [
        {
            "type": "framework",
            "id": fw_id,
            "spec_version": "0.1.0",
            "created": STAMP,
            "modified": STAMP,
            "name": "NIST SP 800-53 r5",
            "publisher": "NIST",
            "version": "5.2.0",
            "reproduction": "permitted",
        },
        {
            "type": "requirement",
            "id": ac2_id,
            "spec_version": "0.1.0",
            "created": STAMP,
            "modified": STAMP,
            "display_id": "AC-2",
            "name": "Account Management",
            "framework_ref": fw_id,
            "class": "control",
            "statement": "Manage accounts.",
            "objectives": [{"id": "a", "statement": "Accounts are managed."}],
        },
        {
            "type": "control",
            "id": c1_id,
            "spec_version": "0.1.0",
            "created": STAMP,
            "modified": STAMP,
            "display_id": "OGRL-AC-01",
            "name": "Unique accounts",
            "origin": "standard",
            "statement": "Assign unique accounts.",
            "objective": "One owner per account.",
        },
        {
            "type": "mapping",
            "id": map_id,
            "spec_version": "0.1.0",
            "created": STAMP,
            "modified": STAMP,
            "source_ref": c1_id,
            "target_ref": ac2_id,
            "relationship": "equal-to",
            "review_status": "reviewed",
        },
        {
            "type": "baseline",
            "id": base_id,
            "spec_version": "0.1.0",
            "created": STAMP,
            "modified": STAMP,
            "name": "Test baseline",
            "framework_refs": [fw_id],
            "control_refs": [c1_id],
        },
    ]
    org = [
        {
            "type": "system",
            "id": "system--com.acme.app",
            "spec_version": "0.1.0",
            "created": STAMP,
            "modified": STAMP,
            "name": "App",
        },
        {
            "type": "program",
            "id": "program--com.acme.p1",
            "spec_version": "0.1.0",
            "created": STAMP,
            "modified": STAMP,
            "name": "FedRAMP",
            "system_ref": "system--com.acme.app",
            "baseline_ref": base_id,
        },
        {
            "type": "implementation",
            "id": "implementation--com.acme.i1",
            "spec_version": "0.1.0",
            "created": STAMP,
            "modified": STAMP,
            "system_ref": "system--com.acme.app",
            "control_ref": c1_id,
            "status": "implemented",
            "responsibility": "provider",
            "narrative": "SSO enforces unique user accounts.",
        },
        {
            "type": "evidence",
            "id": "evidence--com.acme.e1",
            "spec_version": "0.1.0",
            "created": STAMP,
            "modified": STAMP,
            "name": "SSO config",
            "method": "link",
            "implementation_ref": "implementation--com.acme.i1",
            "valid_until": "2027-12-31",
            "resource": {"uri": "https://wiki.example/sso"},
        },
    ]

    lib_ids = [o["id"] for o in library]
    graph = ogrl_rs.OgrlGraph.from_objects(library + org, library_ids=lib_ids)
    assert len(graph) == len(library) + len(org)
    assert graph.check_all() == []
    assert graph.digest().startswith("sha-256:")

    at = datetime(2026, 11, 9, tzinfo=UTC)
    status = graph.evaluate("program--com.acme.p1", at)
    assert status["controls"][0]["state"] == "met"
    assert status["requirements"][0]["state"] == "covered"

    summary = graph.summarize("program--com.acme.p1", at)
    assert summary["controls"]["met"] == 1
    assert summary["requirements"]["covered"] == 1

    # OSCAL 6-doc JSON + XML render
    oscal_files = graph.render_oscal("program--com.acme.p1", fw_id, at, include_xml=True)
    names = {f.name for f in oscal_files}
    assert {"profile.json", "ssp.json", "ssp.xml", "poam.json", "poam.xml"} <= names
    ssp = json.loads(next(f.content for f in oscal_files if f.name == "ssp.json"))
    assert ssp["system-security-plan"]["control-implementation"]["implemented-requirements"][0][
        "control-id"
    ] == "ac-2"

    # Narrative SSP render
    ssp_files = graph.render_ssp("program--com.acme.p1", at)
    assert {f.name for f in ssp_files} == {"ssp.md", "ssp.json"}

    # OSCAL component definition import against graph
    cd = {
        "component-definition": {
            "uuid": "11111111-1111-4111-8111-111111111111",
            "metadata": {"title": "IdP", "last-modified": STAMP, "version": "1.0"},
            "components": [
                {
                    "uuid": "22222222-2222-4222-8222-222222222222",
                    "type": "service",
                    "title": "Cloud IdP",
                    "control-implementations": [
                        {
                            "source": "NIST_SP-800-53_rev5_catalog.json",
                            "implemented-requirements": [
                                {
                                    "uuid": "33333333-3333-4333-8333-333333333333",
                                    "control-id": "ac-2",
                                    "description": "IdP manages accounts.",
                                    "props": [
                                        {"name": "control-origination", "value": "inherited"}
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    }
    imported = graph.import_oscal_component(json.dumps(cd))
    assert imported["warnings"] == []
    assert len(imported["objects"]) == 2
    assert imported["objects"][1]["responsibility"] == "provider"


@pytest.mark.skipif(not OGRL_LIBRARY.is_dir(), reason="ogrl-library/library not present")
def test_live_library_lint_and_graph_load() -> None:
    report = ogrl_rs.lint_path(OGRL_LIBRARY)
    assert report["ok"] is True
    assert report["objects"] > 1000
    assert report["errors"] == 0

    graph = ogrl_rs.OgrlGraph.from_path(OGRL_LIBRARY)
    assert len(graph) == report["objects"]
    assert graph.digest().startswith("sha-256:")
