//! NIST SP 800-171 Rev 2 from the official SP 800-171A assessment-procedures CSV.
//!
//! NIST publishes OSCAL for SP 800-171 Rev 3 but not Rev 2, which CMMC Level 2 still
//! assesses (RFC 0001 §10). The SP 800-171A CSV carries every Rev 2 security requirement,
//! its assessment objectives, and its examine/interview/test methods. This module pins
//! that file by SHA-256 and converts it into an in-memory OSCAL catalog so the regular
//! catalog importer emits Rev 2 exactly like the other NIST catalogs.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::catalog::ImportOptions;

/// Official SP 800-171A assessment procedures (CSV), updated 2022-03-31.
pub const SP800_171A_CSV_URL: &str =
    "https://csrc.nist.gov/files/pubs/sp/800/171/a/final/docs/sp800-171a-assessment-procedures.csv";
/// SHA-256 of the pinned CSV.
pub const SP800_171A_CSV_SHA256: &str =
    "adbdcb46836ea581fe8d7c1f768d8fdb6a13e14da465c60b897d9743ee31c51c";
/// Date of the CSV revision (per NIST's accompanying README), used as the catalog timestamp.
const SP800_171A_CSV_MODIFIED: &str = "2022-03-31T00:00:00Z";

/// Requirement statements taken from the SP 800-171 Rev 2 PDF
/// (<https://doi.org/10.6028/NIST.SP.800-171r2>). The CSV omits 3.13.12 and carries the
/// pre-Rev 2 wording for the others.
const STATEMENT_ERRATA: &[(&str, &str)] = &[
    (
        "3.1.21",
        "Limit use of portable storage devices on external systems.",
    ),
    (
        "3.2.2",
        "Ensure that personnel are trained to carry out their assigned information \
         security-related duties and responsibilities.",
    ),
    (
        "3.3.2",
        "Ensure that the actions of individual system users can be uniquely traced to those \
         users, so they can be held accountable for their actions.",
    ),
    (
        "3.13.12",
        "Prohibit remote activation of collaborative computing devices and provide indication \
         of devices in use to users present at the device.",
    ),
];

/// Assessment objectives where the CSV diverges from the normative SP 800-171A PDF
/// (<https://doi.org/10.6028/NIST.SP.800-171A>), keyed `requirement[objective]`.
const OBJECTIVE_ERRATA: &[(&str, &str)] = &[
    (
        "3.1.1[c]",
        "devices (and other systems) authorized to connect to the system are identified.",
    ),
    (
        "3.1.3[c]",
        "designated sources and destinations (e.g., networks, individuals, and devices) for CUI within the system and between interconnected systems are identified.",
    ),
    (
        "3.1.4[a]",
        "the duties of individuals requiring separation are defined.",
    ),
    (
        "3.1.4[b]",
        "responsibilities for duties that require separation are assigned to separate individuals.",
    ),
    (
        "3.1.4[c]",
        "access privileges that enable individuals to exercise the duties that require separation are granted to separate individuals.",
    ),
    (
        "3.1.17[a]",
        "wireless access to the system is protected using authentication.",
    ),
    (
        "3.1.17[b]",
        "wireless access to the system is protected using encryption.",
    ),
    ("3.1.18[b]", "mobile device connections are authorized."),
    ("3.1.20[b]", "the use of external systems is identified."),
    ("3.1.20[d]", "the use of external systems is verified."),
    (
        "3.1.20[f]",
        "the use of external systems is controlled/limited.",
    ),
    (
        "3.1.21[a]",
        "the use of portable storage devices containing CUI on external systems is identified and documented.",
    ),
    (
        "3.1.21[b]",
        "limits on the use of portable storage devices containing CUI on external systems are defined.",
    ),
    (
        "3.1.21[c]",
        "the use of portable storage devices containing CUI on external systems is limited as defined.",
    ),
    (
        "3.1.22[c]",
        "a review process is in place prior to posting of any content to publicly accessible systems.",
    ),
    (
        "3.1.22[d]",
        "content on publicly accessible systems is reviewed to ensure that it does not include CUI.",
    ),
    (
        "3.4.4[a]",
        "the security impact of changes to the system is analyzed prior to implementation.",
    ),
    (
        "3.5.4[a]",
        "replay-resistant authentication mechanisms are implemented for network account access to privileged and non-privileged accounts.",
    ),
    (
        "3.7.5[a]",
        "multifactor authentication is used to establish nonlocal maintenance sessions via external network connections.",
    ),
    (
        "3.8.7[a]",
        "the use of removable media on system components is controlled.",
    ),
    (
        "3.9.1[a]",
        "individuals are screened prior to authorizing access to organizational systems containing CUI.",
    ),
    (
        "3.9.2[a]",
        "a policy and/or process for terminating system access and any credentials coincident with personnel actions is established.",
    ),
    (
        "3.10.2[a]",
        "the physical facility where organizational systems reside is protected.",
    ),
    (
        "3.10.2[b]",
        "the support infrastructure for organizational systems is protected.",
    ),
    (
        "3.10.2[c]",
        "the physical facility where organizational systems reside is monitored.",
    ),
    (
        "3.10.2[d]",
        "the support infrastructure for organizational systems is monitored.",
    ),
    (
        "3.11.2[a]",
        "the frequency to scan for vulnerabilities in organizational systems and applications is defined.",
    ),
    (
        "3.11.2[b]",
        "vulnerability scans are performed on organizational systems with the defined frequency.",
    ),
    (
        "3.11.2[c]",
        "vulnerability scans are performed on applications with the defined frequency.",
    ),
    (
        "3.11.2[d]",
        "vulnerability scans are performed on organizational systems when new vulnerabilities are identified.",
    ),
    (
        "3.11.2[e]",
        "vulnerability scans are performed on applications when new vulnerabilities are identified.",
    ),
];

const EXPECTED_REQUIREMENTS: usize = 110;
const EXPECTED_OBJECTIVES: usize = 320;

/// Import options for the Rev 2 framework.
pub fn sp800_171r2_options() -> ImportOptions {
    ImportOptions {
        framework_id: "nist-sp-800-171-r2".into(),
        name: Some("NIST SP 800-171 Revision 2".into()),
        publisher: "NIST".into(),
        source_uri: Some(SP800_171A_CSV_URL.into()),
        source_path: None,
        commit: None,
        version: Some("2".into()),
    }
}

/// Source descriptor recorded on the generated framework (replaces the OSCAL default).
pub fn sp800_171r2_source() -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("format".into(), Value::String("nist-sp800-171a-csv".into())),
        ("uri".into(), Value::String(SP800_171A_CSV_URL.into())),
        ("sha256".into(), Value::String(SP800_171A_CSV_SHA256.into())),
    ])
}

/// Verify the pinned digest of downloaded CSV bytes.
pub fn verify_sp800_171a_csv(bytes: &[u8]) -> Result<(), String> {
    let got = hex::encode(Sha256::digest(bytes));
    if got == SP800_171A_CSV_SHA256 {
        Ok(())
    } else {
        Err(format!(
            "SP 800-171A CSV digest mismatch: expected {SP800_171A_CSV_SHA256}, got {got}"
        ))
    }
}

struct Req {
    id: String,
    family: String,
    statement: String,
    methods: Vec<(&'static str, String)>,
    objectives: Vec<String>,
    bracketed: bool,
}

/// Convert the SP 800-171A CSV into an OSCAL catalog document (JSON bytes).
pub fn sp800_171a_csv_to_oscal(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("CSV is not UTF-8: {e}"))?;
    let text = text.trim_start_matches('\u{feff}');
    let mut rdr = csv::Reader::from_reader(text.as_bytes());
    let headers = rdr.headers().map_err(|e| e.to_string())?.clone();
    let col = |name: &str| {
        headers
            .iter()
            .position(|h| h.trim() == name)
            .ok_or_else(|| format!("CSV missing column {name:?}"))
    };
    let (c_family, c_id, c_req, c_obj) = (
        col("Family")?,
        col("Identifier")?,
        col("Security Requirement")?,
        col("Assessment Objective")?,
    );
    let c_methods = [
        (
            "EXAMINE",
            col("Potential Assessment Method and Objects: Examine")?,
        ),
        (
            "INTERVIEW",
            col("Potential Assessment Method and Objects: Interview")?,
        ),
        (
            "TEST",
            col("Potential Assessment Method and Objects: Test")?,
        ),
    ];

    let mut reqs: Vec<Req> = Vec::new();
    for rec in rdr.records() {
        let rec = rec.map_err(|e| e.to_string())?;
        let get = |i: usize| rec.get(i).unwrap_or("").trim().to_string();
        let ident = get(c_id);
        if ident.is_empty() {
            continue;
        }
        let methods: Vec<(&'static str, String)> = c_methods
            .iter()
            .filter_map(|(kind, i)| clean_method(&get(*i)).map(|m| (*kind, m)))
            .collect();

        if let Some((base, _)) = ident.split_once('[') {
            // Bracketed objective row, e.g. `3.1.1[a]` (one row is written `3.12.4.[h]`).
            let base = base.trim().trim_end_matches('.');
            let req = reqs
                .iter_mut()
                .rfind(|r| r.id == base)
                .ok_or_else(|| format!("objective {ident} precedes its requirement"))?;
            // Bracketed objectives replace any inline lead-in on the requirement row
            // (3.1.22 repeats a summary sentence there before listing `[a]`-`[e]`).
            if !req.bracketed {
                req.objectives.clear();
                req.bracketed = true;
            }
            req.objectives.push(clean_prose(&get(c_obj)));
            // 3.1.19 carries its methods on the `[a]` row instead of the requirement row.
            if req.methods.is_empty() {
                req.methods = methods;
            }
            continue;
        }

        let mut statement = clean_prose(&get(c_req));
        if let Some((_, s)) = STATEMENT_ERRATA.iter().find(|(id, _)| *id == ident) {
            statement = (*s).to_string();
        }
        if statement.is_empty() {
            return Err(format!("requirement {ident} has no statement"));
        }
        // Several CSV statements drop their closing period.
        if !statement.ends_with('.') {
            statement.push('.');
        }
        // Single-objective requirements state their objective inline:
        // "Determine if FIPS-validated cryptography is employed ...".
        let inline = strip_determine_if(&clean_prose(&get(c_obj)));
        reqs.push(Req {
            id: ident,
            family: get(c_family),
            statement,
            methods,
            objectives: if inline.is_empty() {
                Vec::new()
            } else {
                vec![inline]
            },
            bracketed: false,
        });
    }

    let objective_total: usize = reqs.iter().map(|r| r.objectives.len()).sum();
    if reqs.len() != EXPECTED_REQUIREMENTS || objective_total != EXPECTED_OBJECTIVES {
        return Err(format!(
            "expected {EXPECTED_REQUIREMENTS} requirements / {EXPECTED_OBJECTIVES} objectives, \
             got {} / {objective_total}",
            reqs.len()
        ));
    }
    if let Some(r) = reqs.iter().find(|r| r.methods.is_empty()) {
        return Err(format!("requirement {} has no assessment methods", r.id));
    }

    apply_objective_errata(&mut reqs)?;
    for obj in reqs.iter_mut().flat_map(|r| r.objectives.iter_mut()) {
        if !obj.ends_with('.') {
            obj.push('.');
        }
    }

    let mut groups: Vec<(String, Vec<Value>)> = Vec::new();
    for r in &reqs {
        let control = control_json(r);
        match groups.iter_mut().find(|(f, _)| *f == r.family) {
            Some((_, controls)) => controls.push(control),
            None => groups.push((r.family.clone(), vec![control])),
        }
    }
    let groups: Vec<Value> = groups
        .into_iter()
        .map(|(family, controls)| {
            let gid = family_number(&controls).unwrap_or_default();
            json!({ "id": gid, "title": family, "controls": controls })
        })
        .collect();

    let doc = json!({
        "catalog": {
            "metadata": {
                "title": "NIST SP 800-171 Revision 2",
                "last-modified": SP800_171A_CSV_MODIFIED,
                "version": "2",
            },
            "groups": groups,
        }
    });
    serde_json::to_vec(&doc).map_err(|e| e.to_string())
}

fn apply_objective_errata(reqs: &mut [Req]) -> Result<(), String> {
    for (key, text) in OBJECTIVE_ERRATA {
        let (id, rest) = key
            .split_once('[')
            .ok_or_else(|| format!("malformed erratum key {key}"))?;
        let idx = rest
            .trim_end_matches(']')
            .bytes()
            .next()
            .map(|b| usize::from(b - b'a'))
            .ok_or_else(|| format!("malformed erratum key {key}"))?;
        let slot = reqs
            .iter_mut()
            .find(|r| r.id == id)
            .and_then(|r| r.objectives.get_mut(idx))
            .ok_or_else(|| format!("erratum {key} matches no objective in the CSV"))?;
        *slot = (*text).to_string();
    }
    Ok(())
}

fn control_json(r: &Req) -> Value {
    let mut parts = vec![json!({
        "id": format!("{}_smt", r.id),
        "name": "statement",
        "prose": r.statement,
    })];
    let objectives: Vec<Value> = r
        .objectives
        .iter()
        .enumerate()
        .map(|(i, prose)| {
            json!({
                "id": format!("{}_obj.{}", r.id, letter(i)),
                "name": "assessment-objective",
                "prose": prose,
            })
        })
        .collect();
    parts.push(json!({
        "id": format!("{}_obj", r.id),
        "name": "assessment-objective",
        "parts": objectives,
    }));
    for (kind, prose) in &r.methods {
        parts.push(json!({
            "name": "assessment-method",
            "props": [{ "name": "method", "value": kind }],
            "prose": prose,
        }));
    }
    json!({
        "id": r.id,
        "props": [{ "name": "label", "value": r.id }],
        "parts": parts,
    })
}

/// `3.1.1` -> `3.1` (family number used as the OSCAL group id).
fn family_number(controls: &[Value]) -> Option<String> {
    let id = controls.first()?.get("id")?.as_str()?;
    let (fam, _) = id.rsplit_once('.')?;
    Some(fam.to_string())
}

fn letter(i: usize) -> char {
    char::from(b'a' + u8::try_from(i).expect("objective index fits in u8"))
}

/// Collapse whitespace (the CSV contains stray tabs and line breaks).
fn clean_prose(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn strip_determine_if(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    if !lower.starts_with("determine if") {
        return s.to_string();
    }
    s["determine if".len()..]
        .trim_start_matches([':', ' '])
        .to_string()
}

/// `[SELECT FROM: a; b; c].` -> `a; b; c`.
fn clean_method(s: &str) -> Option<String> {
    let s = clean_prose(s);
    if s.is_empty() {
        return None;
    }
    let inner = s
        .strip_prefix("[SELECT FROM:")
        .map(|rest| rest.trim_end_matches('.').trim_end_matches(']'))
        .unwrap_or(&s)
        .trim();
    (!inner.is_empty()).then(|| inner.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\u{feff}Family,Identifier,Sort-As,Security Requirement,Assessment Objective,Potential Assessment Method and Objects: Examine,Potential Assessment Method and Objects: Interview,Potential Assessment Method and Objects: Test\n\
Access Control,3.1.1,03.01.01.0,\"Limit system access.\",Determine If: ,\"[SELECT FROM: Policy; plan].\",[SELECT FROM: Admins].,[SELECT FROM: Mechanisms].\n\
Access Control,\"3.1.1[a]\t \",03.01.01.a,,authorized users are identified.,,,\n\
Access Control,3.1.1[b] ,03.01.01.b,,processes are identified.,,,\n";

    #[test]
    fn helpers_clean_csv_artifacts() {
        assert_eq!(
            clean_method("[SELECT FROM: a; b].").as_deref(),
            Some("a; b")
        );
        assert_eq!(
            strip_determine_if("Determine if FIPS-validated cryptography is employed."),
            "FIPS-validated cryptography is employed."
        );
        assert_eq!(strip_determine_if("Determine If: "), "");
        assert_eq!(clean_prose("a\t b\n c"), "a b c");
    }

    #[test]
    fn rejects_incomplete_catalogs() {
        let err = sp800_171a_csv_to_oscal(SAMPLE.as_bytes()).unwrap_err();
        assert!(err.contains("expected 110 requirements"), "{err}");
    }

    #[test]
    fn errata_keys_are_well_formed_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for (key, text) in OBJECTIVE_ERRATA {
            let (id, rest) = key.split_once('[').expect("key has [");
            assert!(id.starts_with("3."), "{key}");
            assert!(rest.len() == 2 && rest.ends_with(']'), "{key}");
            assert!(text.ends_with('.'), "{key}");
            assert!(seen.insert(*key), "duplicate erratum {key}");
        }
        for (id, text) in STATEMENT_ERRATA {
            assert!(id.starts_with("3.") && text.ends_with('.'), "{id}");
        }
    }

    #[test]
    fn digest_mismatch_is_reported() {
        assert!(verify_sp800_171a_csv(b"not the csv").is_err());
    }
}
