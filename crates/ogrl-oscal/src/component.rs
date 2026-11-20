//! OSCAL 1.2.3 Component Definition (JSON or XML) -> OGRL provider bundle (RFC 0002 §7).

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use ogrl_core::bundle::BundleManifest;
use ogrl_core::graph::Graph;
use ogrl_core::model::{
    Component, ComponentKind, Implementation, ImplementationOrigin, ImplementationStatus,
    OgrlObject, Party, PartyKind, Responsibility, SPEC_VERSION,
};
use ogrl_core::time::{format_timestamp, parse_timestamp};

use crate::xml::{looks_like_xml, oscal_xml_to_json};

#[derive(Debug, Error)]
pub enum ComponentImportError {
    #[error("failed to parse OSCAL component definition: {0}")]
    Parse(String),
    #[error("the document has no component-definition with a valid uuid")]
    MissingDefinition,
}

#[derive(Debug, Clone)]
pub struct ImportedProviderBundle {
    pub manifest: BundleManifest,
    pub objects: Vec<OgrlObject>,
    pub warnings: Vec<String>,
}

fn map_component_kind(oscal_type: &str) -> ComponentKind {
    match oscal_type {
        "software" => ComponentKind::Software,
        "service" => ComponentKind::Service,
        "hardware" | "interconnection" | "this-system" => ComponentKind::Infrastructure,
        "policy" | "process" | "procedure" | "plan" | "guidance" | "standard" | "validation" => {
            ComponentKind::Procedure
        }
        _ => ComponentKind::Software,
    }
}

fn map_party_kind(oscal_type: &str) -> PartyKind {
    match oscal_type {
        "person" => PartyKind::Person,
        _ => PartyKind::Organization,
    }
}

fn props_map(item: &Value) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Some(arr) = item.get("props").and_then(Value::as_array) {
        for p in arr {
            if let Some(name) = p.get("name").and_then(Value::as_str) {
                let val = p
                    .get("value")
                    .and_then(|v| v.as_str().map(String::from).or_else(|| Some(v.to_string())))
                    .unwrap_or_default();
                out.insert(name.to_string(), val);
            }
        }
    }
    out
}

/// First-match precedence table from RFC 0002 §7.
pub fn derive_responsibility(item: &Value) -> Responsibility {
    let props = props_map(item);
    let origination = props
        .get("control-origination")
        .map(String::as_str)
        .unwrap_or("");
    if props
        .get("provider")
        .is_some_and(|v| v.eq_ignore_ascii_case("no"))
        || matches!(origination, "customer-configured" | "customer-provided")
    {
        return Responsibility::Customer;
    }
    if matches!(
        origination,
        "inherited" | "service-provider-corporate" | "service-provider-system"
    ) {
        return Responsibility::Provider;
    }
    Responsibility::Shared
}

/// Determine which pinned NIST framework a `control-implementation.source` refers to.
pub fn catalog_of(source: &str) -> Option<&'static str> {
    let text = source.to_ascii_lowercase().replace('_', "-");
    if text.contains("800-171") {
        Some("nist-sp-800-171-r3")
    } else if text.contains("800-53") {
        Some("nist-sp-800-53-r5")
    } else {
        None
    }
}

/// `ac-3` -> `requirement--nist-sp-800-53-r5-ac-3`; `ac-2.1` -> `...-ac-2-1`.
pub fn requirement_id(control_id: &str, framework: &str) -> String {
    let lower = control_id.to_ascii_lowercase();
    let slug = lower
        .strip_prefix("sp_800_171_")
        .unwrap_or(&lower)
        .replace(['_', '.'], "-");
    format!("requirement--{framework}-{slug}")
}

/// Import an OSCAL 1.2.3 component definition (JSON or XML) against a pinned library `Graph`.
pub fn import_component_definition(
    content: &[u8],
    library_graph: &Graph,
) -> Result<ImportedProviderBundle, ComponentImportError> {
    let document: Value = if looks_like_xml(content) {
        oscal_xml_to_json(content).map_err(|e| ComponentImportError::Parse(e.to_string()))?
    } else {
        serde_json::from_slice(content).map_err(|e| ComponentImportError::Parse(e.to_string()))?
    };

    let Some(definition) = document
        .get("component-definition")
        .and_then(Value::as_object)
    else {
        return Err(ComponentImportError::MissingDefinition);
    };
    let def_uuid = definition
        .get("uuid")
        .and_then(Value::as_str)
        .filter(|s| Uuid::parse_str(s).is_ok())
        .ok_or(ComponentImportError::MissingDefinition)?
        .to_ascii_lowercase();

    let metadata = definition.get("metadata");
    let stamp: DateTime<Utc> = metadata
        .and_then(|m| m.get("last-modified"))
        .and_then(Value::as_str)
        .and_then(|s| parse_timestamp(s).ok())
        .unwrap_or(DateTime::UNIX_EPOCH);

    let mut objects = Vec::new();
    let mut warnings = Vec::new();

    if let Some(parties) = metadata
        .and_then(|m| m.get("parties"))
        .and_then(Value::as_array)
    {
        for party in parties {
            let Some(puuid) = party.get("uuid").and_then(Value::as_str) else {
                continue;
            };
            let name = party
                .get("name")
                .or_else(|| party.get("short-name"))
                .and_then(Value::as_str)
                .unwrap_or(puuid)
                .to_string();
            let kind = map_party_kind(party.get("type").and_then(Value::as_str).unwrap_or(""));
            objects.push(OgrlObject::Party(Party {
                object_type: "party".into(),
                id: format!("party--{}", puuid.to_ascii_lowercase()),
                spec_version: SPEC_VERSION.into(),
                created: stamp,
                modified: stamp,
                name,
                revoked: None,
                created_by_ref: None,
                tags: None,
                external_references: None,
                extensions: None,
                lang: None,
                kind,
                extra: BTreeMap::new(),
            }));
        }
    }

    if let Some(components) = definition.get("components").and_then(Value::as_array) {
        for comp in components {
            let Some(cuuid) = comp.get("uuid").and_then(Value::as_str) else {
                continue;
            };
            let component_id = format!("component--{}", cuuid.to_ascii_lowercase());
            let party_ref = comp
                .get("responsible-roles")
                .and_then(Value::as_array)
                .and_then(|roles| {
                    roles.iter().find_map(|role| {
                        role.get("party-uuids")
                            .and_then(Value::as_array)
                            .and_then(|uuids| uuids.first())
                            .and_then(Value::as_str)
                            .map(|u| format!("party--{}", u.to_ascii_lowercase()))
                    })
                });
            objects.push(OgrlObject::Component(Component {
                object_type: "component".into(),
                id: component_id.clone(),
                spec_version: SPEC_VERSION.into(),
                created: stamp,
                modified: stamp,
                name: comp
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or(cuuid)
                    .to_string(),
                revoked: None,
                created_by_ref: None,
                tags: None,
                external_references: None,
                extensions: None,
                lang: None,
                kind: map_component_kind(comp.get("type").and_then(Value::as_str).unwrap_or("")),
                description: comp
                    .get("description")
                    .and_then(Value::as_str)
                    .map(String::from),
                party_ref,
                extra: BTreeMap::new(),
            }));

            if let Some(blocks) = comp
                .get("control-implementations")
                .and_then(Value::as_array)
            {
                for block in blocks {
                    let source = block.get("source").and_then(Value::as_str).unwrap_or("");
                    let Some(framework) = catalog_of(source) else {
                        warnings.push(format!("{source}: not a pinned catalog; skipped"));
                        continue;
                    };
                    if let Some(reqs) = block
                        .get("implemented-requirements")
                        .and_then(Value::as_array)
                    {
                        for item in reqs {
                            let control_id =
                                item.get("control-id").and_then(Value::as_str).unwrap_or("");
                            let req_ref = requirement_id(control_id, framework);
                            if library_graph.requirement(&req_ref).is_none() {
                                warnings.push(format!(
                                    "{control_id}: {req_ref} is not in the pinned library"
                                ));
                                continue;
                            }
                            let Some(iuuid) = item.get("uuid").and_then(Value::as_str) else {
                                continue;
                            };
                            objects.push(OgrlObject::Implementation(Implementation {
                                object_type: "implementation".into(),
                                id: format!("implementation--{}", iuuid.to_ascii_lowercase()),
                                spec_version: SPEC_VERSION.into(),
                                created: stamp,
                                modified: stamp,
                                name: None,
                                revoked: None,
                                created_by_ref: None,
                                tags: None,
                                external_references: None,
                                extensions: None,
                                lang: None,
                                system_ref: None,
                                component_ref: Some(component_id.clone()),
                                control_ref: None,
                                requirement_ref: Some(req_ref),
                                status: ImplementationStatus::Implemented,
                                responsibility: derive_responsibility(item),
                                subservice_ref: None,
                                origin: Some(ImplementationOrigin::Provider),
                                parameter_values: None,
                                requirement_parameter_values: None,
                                owner_ref: None,
                                narrative: item
                                    .get("description")
                                    .and_then(Value::as_str)
                                    .map(String::from),
                                customer_responsibility: None,
                                extra: BTreeMap::new(),
                            }));
                        }
                    }
                }
            }
        }
    }

    let stamp_str = format_timestamp(&stamp);
    let manifest = BundleManifest {
        object_type: "bundle".into(),
        id: format!("bundle--{def_uuid}"),
        spec_version: SPEC_VERSION.into(),
        created: Some(stamp_str.clone()),
        modified: Some(stamp_str),
        name: metadata
            .and_then(|m| m.get("title"))
            .and_then(Value::as_str)
            .map(String::from),
        version: metadata
            .and_then(|m| m.get("version"))
            .and_then(Value::as_str)
            .map(String::from)
            .or_else(|| Some(String::new())),
        library: None,
        providers: None,
        extra: BTreeMap::new(),
    };

    Ok(ImportedProviderBundle {
        manifest,
        objects,
        warnings,
    })
}
