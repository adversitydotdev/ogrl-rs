//! Read-only indexed view over an OGRL object graph (RFC 0001 §8).

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::ids;
use crate::model::{
    Baseline, Component, Control, Evidence, ExceptionObj, Finding, Framework, Implementation,
    Mapping, MappingReview, ObjectType, OgrlObject, Party, Policy, Procedure, Program, Requirement,
    Risk, System, Test, TestResult,
};

#[derive(Debug, Clone)]
pub struct Graph {
    pub objects: BTreeMap<String, OgrlObject>,
    pub library_ids: HashSet<String>,
    pub provider_ids: HashSet<String>,

    by_type: HashMap<ObjectType, Vec<String>>,
    mappings_by_target: HashMap<String, Vec<String>>,
    mappings_by_source: HashMap<String, Vec<String>>,
    tests_by_control: HashMap<String, Vec<String>>,
    fulfillers: HashMap<String, Vec<String>>,
    results_by_pair: HashMap<(String, String), Vec<String>>,
    evidence_by_implementation: HashMap<String, Vec<String>>,
    exceptions_by_implementation: HashMap<String, Vec<String>>,
    reviews_by_mapping: HashMap<String, Vec<String>>,
    requirements_by_framework: HashMap<String, Vec<String>>,
}

impl Graph {
    /// Build an indexed graph from objects and optional library/provider ID sets.
    pub fn new(
        objects: impl IntoIterator<Item = OgrlObject>,
        library_ids: impl IntoIterator<Item = String>,
        provider_ids: impl IntoIterator<Item = String>,
    ) -> Self {
        let mut map = BTreeMap::new();
        for obj in objects {
            map.insert(obj.id().to_string(), obj);
        }
        let library_ids: HashSet<String> = library_ids.into_iter().collect();
        let provider_ids: HashSet<String> = provider_ids.into_iter().collect();

        let mut by_type: HashMap<ObjectType, Vec<String>> = HashMap::new();
        let mut mappings_by_target: HashMap<String, Vec<String>> = HashMap::new();
        let mut mappings_by_source: HashMap<String, Vec<String>> = HashMap::new();
        let mut tests_by_control: HashMap<String, Vec<String>> = HashMap::new();
        let mut fulfillers: HashMap<String, Vec<String>> = HashMap::new();
        let mut results_by_pair: HashMap<(String, String), Vec<String>> = HashMap::new();
        let mut evidence_by_implementation: HashMap<String, Vec<String>> = HashMap::new();
        let mut exceptions_by_implementation: HashMap<String, Vec<String>> = HashMap::new();
        let mut reviews_by_mapping: HashMap<String, Vec<String>> = HashMap::new();
        let mut requirements_by_framework: HashMap<String, Vec<String>> = HashMap::new();

        // BTreeMap iteration is sorted by ID, preserving deterministic index ordering.
        for (id, obj) in &map {
            by_type
                .entry(obj.object_type())
                .or_default()
                .push(id.clone());

            if obj.is_revoked() {
                continue;
            }
            match obj {
                OgrlObject::Mapping(m) => {
                    mappings_by_target
                        .entry(ids::base(&m.target_ref).to_string())
                        .or_default()
                        .push(id.clone());
                    mappings_by_source
                        .entry(m.source_ref.clone())
                        .or_default()
                        .push(id.clone());
                }
                OgrlObject::Test(t) => {
                    tests_by_control
                        .entry(t.control_ref.clone())
                        .or_default()
                        .push(id.clone());
                    if let Some(ref f) = t.fulfills_ref {
                        fulfillers.entry(f.clone()).or_default().push(id.clone());
                    }
                }
                OgrlObject::Result(r) => {
                    results_by_pair
                        .entry((r.test_ref.clone(), r.implementation_ref.clone()))
                        .or_default()
                        .push(id.clone());
                }
                OgrlObject::Evidence(e) => {
                    if let Some(ref impl_ref) = e.implementation_ref {
                        evidence_by_implementation
                            .entry(impl_ref.clone())
                            .or_default()
                            .push(id.clone());
                    }
                }
                OgrlObject::Exception(e) => {
                    exceptions_by_implementation
                        .entry(e.implementation_ref.clone())
                        .or_default()
                        .push(id.clone());
                }
                OgrlObject::MappingReview(r) => {
                    reviews_by_mapping
                        .entry(r.mapping_ref.clone())
                        .or_default()
                        .push(id.clone());
                }
                OgrlObject::Requirement(r) => {
                    requirements_by_framework
                        .entry(r.framework_ref.clone())
                        .or_default()
                        .push(id.clone());
                }
                _ => {}
            }
        }

        Self {
            objects: map,
            library_ids,
            provider_ids,
            by_type,
            mappings_by_target,
            mappings_by_source,
            tests_by_control,
            fulfillers,
            results_by_pair,
            evidence_by_implementation,
            exceptions_by_implementation,
            reviews_by_mapping,
            requirements_by_framework,
        }
    }

    pub fn contains(&self, object_id: &str) -> bool {
        self.objects.contains_key(ids::base(object_id))
    }

    pub fn get(&self, object_id: &str) -> Option<&OgrlObject> {
        self.objects.get(ids::base(object_id))
    }

    pub fn is_library(&self, object_id: &str) -> bool {
        self.library_ids.contains(object_id)
    }

    pub fn is_provider(&self, object_id: &str) -> bool {
        self.provider_ids.contains(object_id)
    }

    pub fn is_organization(&self, object_id: &str) -> bool {
        !self.library_ids.contains(object_id) && !self.provider_ids.contains(object_id)
    }

    pub fn all_of_type(&self, kind: ObjectType, include_revoked: bool) -> Vec<&OgrlObject> {
        self.by_type
            .get(&kind)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.objects.get(id))
                    .filter(|o| include_revoked || !o.is_revoked())
                    .collect()
            })
            .unwrap_or_default()
    }

    // --- Typed lookups ------------------------------------------------------

    pub fn framework(&self, id: &str) -> Option<&Framework> {
        match self.get(id)? {
            OgrlObject::Framework(x) => Some(x),
            _ => None,
        }
    }

    pub fn requirement(&self, id: &str) -> Option<&Requirement> {
        match self.get(id)? {
            OgrlObject::Requirement(x) => Some(x),
            _ => None,
        }
    }

    pub fn control(&self, id: &str) -> Option<&Control> {
        match self.get(id)? {
            OgrlObject::Control(x) => Some(x),
            _ => None,
        }
    }

    pub fn mapping(&self, id: &str) -> Option<&Mapping> {
        match self.get(id)? {
            OgrlObject::Mapping(x) => Some(x),
            _ => None,
        }
    }

    pub fn baseline(&self, id: &str) -> Option<&Baseline> {
        match self.get(id)? {
            OgrlObject::Baseline(x) => Some(x),
            _ => None,
        }
    }

    pub fn test(&self, id: &str) -> Option<&Test> {
        match self.get(id)? {
            OgrlObject::Test(x) => Some(x),
            _ => None,
        }
    }

    pub fn party(&self, id: &str) -> Option<&Party> {
        match self.get(id)? {
            OgrlObject::Party(x) => Some(x),
            _ => None,
        }
    }

    pub fn component(&self, id: &str) -> Option<&Component> {
        match self.get(id)? {
            OgrlObject::Component(x) => Some(x),
            _ => None,
        }
    }

    pub fn system(&self, id: &str) -> Option<&System> {
        match self.get(id)? {
            OgrlObject::System(x) => Some(x),
            _ => None,
        }
    }

    pub fn program(&self, id: &str) -> Option<&Program> {
        match self.get(id)? {
            OgrlObject::Program(x) => Some(x),
            _ => None,
        }
    }

    pub fn implementation(&self, id: &str) -> Option<&Implementation> {
        match self.get(id)? {
            OgrlObject::Implementation(x) => Some(x),
            _ => None,
        }
    }

    pub fn evidence(&self, id: &str) -> Option<&Evidence> {
        match self.get(id)? {
            OgrlObject::Evidence(x) => Some(x),
            _ => None,
        }
    }

    // --- Typed live collections ---------------------------------------------

    pub fn implementations(&self) -> Vec<&Implementation> {
        self.all_of_type(ObjectType::Implementation, false)
            .into_iter()
            .filter_map(|o| match o {
                OgrlObject::Implementation(x) => Some(x),
                _ => None,
            })
            .collect()
    }

    pub fn mappings(&self) -> Vec<&Mapping> {
        self.all_of_type(ObjectType::Mapping, false)
            .into_iter()
            .filter_map(|o| match o {
                OgrlObject::Mapping(x) => Some(x),
                _ => None,
            })
            .collect()
    }

    pub fn baselines(&self) -> Vec<&Baseline> {
        self.all_of_type(ObjectType::Baseline, false)
            .into_iter()
            .filter_map(|o| match o {
                OgrlObject::Baseline(x) => Some(x),
                _ => None,
            })
            .collect()
    }

    pub fn tests(&self) -> Vec<&Test> {
        self.all_of_type(ObjectType::Test, false)
            .into_iter()
            .filter_map(|o| match o {
                OgrlObject::Test(x) => Some(x),
                _ => None,
            })
            .collect()
    }

    pub fn programs(&self) -> Vec<&Program> {
        self.all_of_type(ObjectType::Program, false)
            .into_iter()
            .filter_map(|o| match o {
                OgrlObject::Program(x) => Some(x),
                _ => None,
            })
            .collect()
    }

    pub fn findings(&self) -> Vec<&Finding> {
        self.all_of_type(ObjectType::Finding, false)
            .into_iter()
            .filter_map(|o| match o {
                OgrlObject::Finding(x) => Some(x),
                _ => None,
            })
            .collect()
    }

    pub fn policies(&self) -> Vec<&Policy> {
        self.all_of_type(ObjectType::Policy, false)
            .into_iter()
            .filter_map(|o| match o {
                OgrlObject::Policy(x) => Some(x),
                _ => None,
            })
            .collect()
    }

    pub fn procedures(&self) -> Vec<&Procedure> {
        self.all_of_type(ObjectType::Procedure, false)
            .into_iter()
            .filter_map(|o| match o {
                OgrlObject::Procedure(x) => Some(x),
                _ => None,
            })
            .collect()
    }

    pub fn risks(&self) -> Vec<&Risk> {
        self.all_of_type(ObjectType::Risk, false)
            .into_iter()
            .filter_map(|o| match o {
                OgrlObject::Risk(x) => Some(x),
                _ => None,
            })
            .collect()
    }

    pub fn exceptions(&self) -> Vec<&ExceptionObj> {
        self.all_of_type(ObjectType::Exception, false)
            .into_iter()
            .filter_map(|o| match o {
                OgrlObject::Exception(x) => Some(x),
                _ => None,
            })
            .collect()
    }

    pub fn mapping_reviews(&self) -> Vec<&MappingReview> {
        self.all_of_type(ObjectType::MappingReview, false)
            .into_iter()
            .filter_map(|o| match o {
                OgrlObject::MappingReview(x) => Some(x),
                _ => None,
            })
            .collect()
    }

    // --- Indexed queries ----------------------------------------------------

    pub fn mappings_by_target(&self, requirement_id: &str) -> Vec<&Mapping> {
        self.mappings_by_target
            .get(ids::base(requirement_id))
            .map(|ids| ids.iter().filter_map(|id| self.mapping(id)).collect())
            .unwrap_or_default()
    }

    pub fn mappings_by_source(&self, source_id: &str) -> Vec<&Mapping> {
        self.mappings_by_source
            .get(source_id)
            .map(|ids| ids.iter().filter_map(|id| self.mapping(id)).collect())
            .unwrap_or_default()
    }

    pub fn tests_by_control(&self, control_id: &str) -> Vec<&Test> {
        self.tests_by_control
            .get(control_id)
            .map(|ids| ids.iter().filter_map(|id| self.test(id)).collect())
            .unwrap_or_default()
    }

    pub fn fulfillers_of(&self, test_id: &str) -> Vec<&Test> {
        self.fulfillers
            .get(test_id)
            .map(|ids| ids.iter().filter_map(|id| self.test(id)).collect())
            .unwrap_or_default()
    }

    pub fn results_for_pair(&self, test_id: &str, implementation_id: &str) -> Vec<&TestResult> {
        self.results_by_pair
            .get(&(test_id.to_string(), implementation_id.to_string()))
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| match self.objects.get(id)? {
                        OgrlObject::Result(r) => Some(r),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn evidence_for_implementation(&self, implementation_id: &str) -> Vec<&Evidence> {
        self.evidence_by_implementation
            .get(implementation_id)
            .map(|ids| ids.iter().filter_map(|id| self.evidence(id)).collect())
            .unwrap_or_default()
    }

    pub fn exceptions_for_implementation(&self, implementation_id: &str) -> Vec<&ExceptionObj> {
        self.exceptions_by_implementation
            .get(implementation_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| match self.objects.get(id)? {
                        OgrlObject::Exception(e) => Some(e),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn reviews_for_mapping(&self, mapping_id: &str) -> Vec<&MappingReview> {
        self.reviews_by_mapping
            .get(mapping_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| match self.objects.get(id)? {
                        OgrlObject::MappingReview(r) => Some(r),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn all_review_mapping_ids(&self) -> impl Iterator<Item = &String> {
        self.reviews_by_mapping.keys()
    }

    pub fn requirements_for_framework(&self, framework_id: &str) -> Vec<&Requirement> {
        self.requirements_by_framework
            .get(framework_id)
            .map(|ids| ids.iter().filter_map(|id| self.requirement(id)).collect())
            .unwrap_or_default()
    }

    /// Return a new graph with its library projection replaced by `library`,
    /// revoking any prior library ID absent from `library` (RFC 0002 §5).
    pub fn with_library(&self, library: Vec<OgrlObject>) -> Self {
        let incoming: HashSet<String> = library.iter().map(|o| o.id().to_string()).collect();
        let mut next_objects: Vec<OgrlObject> = self
            .objects
            .values()
            .filter(|o| !self.is_library(o.id()))
            .cloned()
            .collect();
        let mut next_library_ids: Vec<String> = incoming.iter().cloned().collect();
        for obj in self.objects.values() {
            if self.is_library(obj.id()) && !incoming.contains(obj.id()) {
                next_library_ids.push(obj.id().to_string());
                next_objects.push(obj.with_revoked(true));
            }
        }
        next_objects.extend(library);
        Self::new(next_objects, next_library_ids, self.provider_ids.clone())
    }
}

/// All statement part IDs on a requirement.
pub fn part_ids(requirement: &Requirement) -> Vec<&str> {
    requirement
        .parts
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|p| p.id.as_str())
        .collect()
}

/// RFC 0001 §8 leaf units. A requirement with no parts is one unit `""`.
pub fn leaf_units(requirement: &Requirement) -> Vec<String> {
    let parts = part_ids(requirement);
    if parts.is_empty() {
        return vec![String::new()];
    }
    parts
        .iter()
        .filter(|&&p| {
            let prefix = format!("{p}.");
            !parts.iter().any(|&q| q.starts_with(&prefix))
        })
        .map(|&p| p.to_string())
        .collect()
}

/// The leaf units a mapping `target_ref` reaches: all of them, or those under `#part`.
pub fn units_reached(requirement: &Requirement, target_ref: &str) -> Vec<String> {
    let units = leaf_units(requirement);
    let Some(frag) = ids::fragment(target_ref) else {
        return units;
    };
    let prefix = format!("{frag}.");
    units
        .into_iter()
        .filter(|u| u == frag || u.starts_with(&prefix))
        .collect()
}

/// True when `requirement--...#obj.<id>` resolves to an objective on that requirement.
pub fn objective_exists(graph: &Graph, reference: &str) -> bool {
    let Some(req) = graph.requirement(reference) else {
        return false;
    };
    let Some(obj_id) = ids::objective_of(reference) else {
        return false;
    };
    req.objectives
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .any(|o| o.id == obj_id)
}
