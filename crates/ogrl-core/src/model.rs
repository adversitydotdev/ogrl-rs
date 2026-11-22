//! RFC 0001 object model (all 19 closed object types) with unknown-field round-tripping.

use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::ids;
use crate::time::{serde_opt_timestamp, serde_timestamp};

/// The OGRL specification revision this toolchain primarily emits (RFC 0001 header).
pub const SPEC_VERSION: &str = "0.2.0";

/// `major.minor` language revisions this reader implements (RFC 0001 §6.2).
pub const READABLE_SPEC_MAJOR_MINOR: &[&str] = &["0.1", "0.2"];

/// Human-readable list of accepted `spec_version` families for diagnostics.
pub fn readable_spec_version_label() -> &'static str {
    "0.1.x or 0.2.x"
}

/// Parse `major.minor.patch` when present and well-formed.
fn parse_spec_semver(version: &str) -> Option<(&str, &str, &str)> {
    let mut parts = version.split('.');
    let major = parts.next()?;
    let minor = parts.next()?;
    let patch = parts.next()?;
    if parts.next().is_some()
        || major.is_empty()
        || minor.is_empty()
        || patch.is_empty()
        || !major.chars().all(|c| c.is_ascii_digit())
        || !minor.chars().all(|c| c.is_ascii_digit())
        || !patch.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    Some((major, minor, patch))
}

/// A reader accepts any object whose `major.minor` matches an implemented revision,
/// regardless of `patch` (RFC 0001 §6.2).
pub fn readable_spec_version(version: &str) -> bool {
    let Some((major, minor, _patch)) = parse_spec_semver(version) else {
        return false;
    };
    let key = format!("{major}.{minor}");
    READABLE_SPEC_MAJOR_MINOR.contains(&key.as_str())
}

/// True when the object's `spec_version` is RFC 0001 0.2.x (stricter §6.3 mapping IDs).
pub fn spec_is_0_2(version: &str) -> bool {
    parse_spec_semver(version).is_some_and(|(major, minor, _)| major == "0" && minor == "2")
}

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("object is not a JSON/YAML mapping")]
    NotAMapping,
    #[error("missing or unknown object type {0:?}")]
    UnknownType(String),
    #[error("spec_version {0:?} is not readable ({1})")]
    UnsupportedSpecVersion(String, &'static str),
    #[error("id error: {0}")]
    InvalidId(#[from] ids::IdError),
    #[error("{id}: id type {id_type:?} does not match object type {obj_type:?}")]
    IdTypeMismatch {
        id: String,
        id_type: String,
        obj_type: String,
    },
    #[error("score {0} must be between 1 and 5")]
    InvalidScore(u8),
    #[error("schema validation failed: {0}")]
    Deserialize(#[from] serde_json::Error),
}

/// Closed set of 19 RFC 0001 / RFC 0002 object types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectType {
    Framework,
    Requirement,
    Control,
    Mapping,
    Baseline,
    Test,
    Party,
    Component,
    System,
    Program,
    Implementation,
    Result,
    Finding,
    Evidence,
    Policy,
    Procedure,
    Risk,
    Exception,
    MappingReview,
}

impl ObjectType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Framework => "framework",
            Self::Requirement => "requirement",
            Self::Control => "control",
            Self::Mapping => "mapping",
            Self::Baseline => "baseline",
            Self::Test => "test",
            Self::Party => "party",
            Self::Component => "component",
            Self::System => "system",
            Self::Program => "program",
            Self::Implementation => "implementation",
            Self::Result => "result",
            Self::Finding => "finding",
            Self::Evidence => "evidence",
            Self::Policy => "policy",
            Self::Procedure => "procedure",
            Self::Risk => "risk",
            Self::Exception => "exception",
            Self::MappingReview => "mapping_review",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "framework" => Some(Self::Framework),
            "requirement" => Some(Self::Requirement),
            "control" => Some(Self::Control),
            "mapping" => Some(Self::Mapping),
            "baseline" => Some(Self::Baseline),
            "test" => Some(Self::Test),
            "party" => Some(Self::Party),
            "component" => Some(Self::Component),
            "system" => Some(Self::System),
            "program" => Some(Self::Program),
            "implementation" => Some(Self::Implementation),
            "result" => Some(Self::Result),
            "finding" => Some(Self::Finding),
            "evidence" => Some(Self::Evidence),
            "policy" => Some(Self::Policy),
            "procedure" => Some(Self::Procedure),
            "risk" => Some(Self::Risk),
            "exception" => Some(Self::Exception),
            "mapping_review" => Some(Self::MappingReview),
            _ => None,
        }
    }

    pub const fn is_library_type(self) -> bool {
        matches!(
            self,
            Self::Framework
                | Self::Requirement
                | Self::Control
                | Self::Mapping
                | Self::Baseline
                | Self::Test
        )
    }

    pub const fn is_provider_type(self) -> bool {
        matches!(
            self,
            Self::Party | Self::Component | Self::Implementation | Self::Evidence | Self::Test
        )
    }
}

impl std::fmt::Display for ObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// --- Shared nested structs --------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ExternalReference {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DigestAlgorithm {
    #[serde(rename = "sha-256")]
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Digest {
    pub algorithm: DigestAlgorithm,
    pub value: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Resource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<Digest>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

fn default_spec_version() -> String {
    SPEC_VERSION.to_string()
}

// --- Enums ------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reproduction {
    Permitted,
    CitationOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequirementClass {
    Criterion,
    Control,
    Enhancement,
    Clause,
    Specification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssessmentMethodKind {
    Examine,
    Interview,
    Test,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlOrigin {
    Standard,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlType {
    Preventive,
    Detective,
    Corrective,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Interval {
    Continuous,
    Daily,
    Weekly,
    Monthly,
    Quarterly,
    Annual,
    EventDriven,
}

impl Interval {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Continuous => "continuous",
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
            Self::Quarterly => "quarterly",
            Self::Annual => "annual",
            Self::EventDriven => "event-driven",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Relationship {
    EqualTo,
    EquivalentTo,
    SubsetOf,
    SupersetOf,
    IntersectsWith,
    NoRelationship,
}

impl Relationship {
    pub const fn is_full_coverage(self) -> bool {
        matches!(self, Self::EqualTo | Self::EquivalentTo | Self::SupersetOf)
    }

    pub const fn is_contribution(self) -> bool {
        matches!(self, Self::SubsetOf | Self::IntersectsWith)
    }

    pub const fn is_joining(self) -> bool {
        matches!(self, Self::EqualTo | Self::EquivalentTo | Self::SubsetOf)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EqualTo => "equal-to",
            Self::EquivalentTo => "equivalent-to",
            Self::SubsetOf => "subset-of",
            Self::SupersetOf => "superset-of",
            Self::IntersectsWith => "intersects-with",
            Self::NoRelationship => "no-relationship",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Rationale {
    Functional,
    Semantic,
    Syntactic,
}

impl Rationale {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Functional => "functional",
            Self::Semantic => "semantic",
            Self::Syntactic => "syntactic",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewStatus {
    Draft,
    Reviewed,
}

impl ReviewStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Reviewed => "reviewed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MappingReviewStatus {
    Reviewed,
    Rejected,
}

impl MappingReviewStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reviewed => "reviewed",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TestMethod {
    Automated,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PartyKind {
    Person,
    Team,
    Role,
    Organization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentKind {
    Infrastructure,
    Software,
    People,
    Data,
    Procedure,
    Service,
}

impl ComponentKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Infrastructure => "infrastructure",
            Self::Software => "software",
            Self::People => "people",
            Self::Data => "data",
            Self::Procedure => "procedure",
            Self::Service => "service",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Impact {
    Low,
    Moderate,
    High,
}

impl Impact {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Moderate => "moderate",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SystemPartyRole {
    Subservice,
    Customer,
    Operator,
}

impl SystemPartyRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subservice => "subservice",
            Self::Customer => "customer",
            Self::Operator => "operator",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImplementationStatus {
    Planned,
    Implemented,
    Partial,
    NotApplicable,
    Exception,
}

impl ImplementationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Implemented => "implemented",
            Self::Partial => "partial",
            Self::NotApplicable => "not-applicable",
            Self::Exception => "exception",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Responsibility {
    Provider,
    Customer,
    Shared,
    Subservice,
}

impl Responsibility {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Customer => "customer",
            Self::Shared => "shared",
            Self::Subservice => "subservice",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImplementationOrigin {
    Organization,
    Provider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Pass,
    Fail,
    Error,
    Skip,
}

impl Outcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Error => "error",
            Self::Skip => "skip",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Determination {
    Satisfied,
    NotSatisfied,
}

impl Determination {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::NotSatisfied => "not-satisfied",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceMethod {
    Automated,
    Upload,
    Attestation,
    Link,
}

impl EvidenceMethod {
    pub const fn requires_digest(self) -> bool {
        matches!(self, Self::Automated | Self::Upload | Self::Attestation)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DocumentStatus {
    Draft,
    Adopted,
    Retired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Treatment {
    Mitigate,
    Accept,
    Transfer,
    Avoid,
}

impl Treatment {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mitigate => "mitigate",
            Self::Accept => "accept",
            Self::Transfer => "transfer",
            Self::Avoid => "avoid",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskStatus {
    Open,
    Treating,
    Accepted,
    Closed,
}

impl RiskStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Treating => "treating",
            Self::Accepted => "accepted",
            Self::Closed => "closed",
        }
    }
}

// --- Nested parts -----------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Parameter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequirementPart {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub statement: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssessmentMethod {
    pub method: AssessmentMethodKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Objective {
    pub id: String,
    pub statement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<AssessmentMethod>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunEvidence {
    pub path: String,
    pub name: String,
    pub media_type: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunSpec {
    pub runner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<RunEvidence>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InformationType {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub confidentiality: Impact,
    pub integrity: Impact,
    pub availability: Impact,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component_refs: Option<Vec<String>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Authorization {
    pub identifier: String,
    pub authorized: NaiveDate,
    pub expires: NaiveDate,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemParty {
    pub party_ref: String,
    pub role: SystemPartyRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Authorization>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Subject {
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Milestone {
    pub name: String,
    pub due: NaiveDate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub done: Option<NaiveDate>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

// --- 19 Object Types --------------------------------------------------------

macro_rules! define_object {
    (
        $name:ident,
        type_str = $type_str:literal,
        name_field = required,
        { $($field:tt)* }
    ) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        pub struct $name {
            #[serde(rename = "type", default = "default_type_placeholder")]
            pub object_type: String,
            pub id: String,
            #[serde(default = "default_spec_version")]
            pub spec_version: String,
            #[serde(with = "serde_timestamp")]
            pub created: DateTime<Utc>,
            #[serde(with = "serde_timestamp")]
            pub modified: DateTime<Utc>,
            pub name: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub revoked: Option<bool>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub created_by_ref: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub tags: Option<Vec<String>>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub external_references: Option<Vec<ExternalReference>>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub extensions: Option<BTreeMap<String, Value>>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub lang: Option<String>,
            $($field)*
            #[serde(flatten)]
            pub extra: BTreeMap<String, Value>,
        }

        impl $name {
            pub fn is_revoked(&self) -> bool {
                self.revoked.unwrap_or(false)
            }
        }
    };
    (
        $name:ident,
        type_str = $type_str:literal,
        name_field = optional,
        { $($field:tt)* }
    ) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        pub struct $name {
            #[serde(rename = "type", default = "default_type_placeholder")]
            pub object_type: String,
            pub id: String,
            #[serde(default = "default_spec_version")]
            pub spec_version: String,
            #[serde(with = "serde_timestamp")]
            pub created: DateTime<Utc>,
            #[serde(with = "serde_timestamp")]
            pub modified: DateTime<Utc>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub name: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub revoked: Option<bool>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub created_by_ref: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub tags: Option<Vec<String>>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub external_references: Option<Vec<ExternalReference>>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub extensions: Option<BTreeMap<String, Value>>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub lang: Option<String>,
            $($field)*
            #[serde(flatten)]
            pub extra: BTreeMap<String, Value>,
        }

        impl $name {
            pub fn is_revoked(&self) -> bool {
                self.revoked.unwrap_or(false)
            }
        }
    };
}

fn default_type_placeholder() -> String {
    String::new()
}

define_object!(Framework, type_str = "framework", name_field = required, {
    pub publisher: String,
    pub version: String,
    pub reproduction: Reproduction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<BTreeMap<String, Value>>,
});

define_object!(Requirement, type_str = "requirement", name_field = required, {
    pub framework_ref: String,
    #[serde(rename = "class")]
    pub class: RequirementClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub citation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<BTreeMap<String, Parameter>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parts: Option<Vec<RequirementPart>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objectives: Option<Vec<Objective>>,
});

impl Requirement {
    pub fn is_withdrawn(&self) -> bool {
        self.withdrawn.unwrap_or(false)
    }
}

define_object!(Control, type_str = "control", name_field = required, {
    pub origin: ControlOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_type: Option<ControlType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frequency: Option<Interval>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub statement: String,
    pub objective: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<BTreeMap<String, Parameter>>,
});

define_object!(Mapping, type_str = "mapping", name_field = optional, {
    pub source_ref: String,
    pub target_ref: String,
    pub relationship: Relationship,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<Rationale>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_status: Option<ReviewStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameter_map: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub combined_with_refs: Option<Vec<String>>,
});

define_object!(Baseline, type_str = "baseline", name_field = required, {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extends_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirement_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameter_bindings: Option<BTreeMap<String, BTreeMap<String, String>>>,
});

define_object!(Test, type_str = "test", name_field = required, {
    pub control_ref: String,
    pub method: TestMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fulfills_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objective_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<Interval>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub procedure_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<RunSpec>,
});

define_object!(Party, type_str = "party", name_field = required, {
    pub kind: PartyKind,
});

define_object!(Component, type_str = "component", name_field = required, {
    pub kind: ComponentKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub party_ref: Option<String>,
});

define_object!(System, type_str = "system", name_field = required, {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub information_types: Option<Vec<InformationType>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parties: Option<Vec<SystemParty>>,
});

define_object!(Program, type_str = "program", name_field = required, {
    pub system_ref: String,
    pub baseline_ref: String,
});

define_object!(Implementation, type_str = "implementation", name_field = optional, {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirement_ref: Option<String>,
    pub status: ImplementationStatus,
    pub responsibility: Responsibility,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subservice_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<ImplementationOrigin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameter_values: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirement_parameter_values: Option<BTreeMap<String, BTreeMap<String, String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub narrative: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_responsibility: Option<String>,
});

impl Implementation {
    pub fn is_provider(&self) -> bool {
        self.origin == Some(ImplementationOrigin::Provider)
    }
}

define_object!(TestResult, type_str = "result", name_field = optional, {
    pub test_ref: String,
    pub implementation_ref: String,
    #[serde(with = "serde_timestamp")]
    pub observed: DateTime<Utc>,
    pub outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_opt_timestamp")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objective_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subjects: Option<Vec<Subject>>,
});

define_object!(Finding, type_str = "finding", name_field = required, {
    pub system_ref: String,
    pub objective_ref: String,
    pub determination: Determination,
    pub observed: NaiveDate,
    pub narrative: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_ref: Option<String>,
});

define_object!(Evidence, type_str = "evidence", name_field = required, {
    pub method: EvidenceMethod,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_opt_timestamp")]
    pub collected: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<NaiveDate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<NaiveDate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<Resource>,
});

impl Evidence {
    /// RFC 0001 §7.14: Incomplete evidence never counts toward status.
    pub fn is_complete(&self) -> bool {
        if self.method.requires_digest() {
            self.resource
                .as_ref()
                .and_then(|r| r.digest.as_ref())
                .is_some()
        } else {
            true
        }
    }
}

define_object!(Policy, type_str = "policy", name_field = required, {
    pub status: DocumentStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adopted: Option<NaiveDate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed: Option<NaiveDate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_interval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<Resource>,
});

define_object!(Procedure, type_str = "procedure", name_field = required, {
    pub status: DocumentStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<Resource>,
});

define_object!(Risk, type_str = "risk", name_field = required, {
    pub statement: String,
    pub likelihood: u8,
    pub impact: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residual_likelihood: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residual_impact: Option<u8>,
    pub treatment: Treatment,
    pub status: RiskStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_refs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_on: Option<NaiveDate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub milestones: Option<Vec<Milestone>>,
});

define_object!(ExceptionObj, type_str = "exception", name_field = optional, {
    pub implementation_ref: String,
    pub justification: String,
    pub expires: NaiveDate,
    pub approver_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_ref: Option<String>,
});

define_object!(MappingReview, type_str = "mapping_review", name_field = optional, {
    pub mapping_ref: String,
    pub library_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_opt_timestamp")]
    pub mapping_modified: Option<DateTime<Utc>>,
    pub review_status: MappingReviewStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
});

/// Any of the 19 closed RFC 0001 / RFC 0002 OGRL objects.
#[derive(Debug, Clone, PartialEq)]
pub enum OgrlObject {
    Framework(Framework),
    Requirement(Requirement),
    Control(Control),
    Mapping(Mapping),
    Baseline(Baseline),
    Test(Test),
    Party(Party),
    Component(Component),
    System(System),
    Program(Program),
    Implementation(Implementation),
    Result(TestResult),
    Finding(Finding),
    Evidence(Evidence),
    Policy(Policy),
    Procedure(Procedure),
    Risk(Risk),
    Exception(ExceptionObj),
    MappingReview(MappingReview),
}

impl OgrlObject {
    /// Parse and validate any RFC 0001 object from a `serde_json::Value`.
    pub fn from_value(value: Value) -> Result<Self, ModelError> {
        let Some(map) = value.as_object() else {
            return Err(ModelError::NotAMapping);
        };
        let type_str = map
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| ModelError::UnknownType("<missing>".into()))?;
        let obj_type = ObjectType::from_str_opt(type_str)
            .ok_or_else(|| ModelError::UnknownType(type_str.to_string()))?;

        let obj = match obj_type {
            ObjectType::Framework => Self::Framework(serde_json::from_value(value)?),
            ObjectType::Requirement => Self::Requirement(serde_json::from_value(value)?),
            ObjectType::Control => Self::Control(serde_json::from_value(value)?),
            ObjectType::Mapping => Self::Mapping(serde_json::from_value(value)?),
            ObjectType::Baseline => Self::Baseline(serde_json::from_value(value)?),
            ObjectType::Test => Self::Test(serde_json::from_value(value)?),
            ObjectType::Party => Self::Party(serde_json::from_value(value)?),
            ObjectType::Component => Self::Component(serde_json::from_value(value)?),
            ObjectType::System => Self::System(serde_json::from_value(value)?),
            ObjectType::Program => Self::Program(serde_json::from_value(value)?),
            ObjectType::Implementation => Self::Implementation(serde_json::from_value(value)?),
            ObjectType::Result => Self::Result(serde_json::from_value(value)?),
            ObjectType::Finding => Self::Finding(serde_json::from_value(value)?),
            ObjectType::Evidence => Self::Evidence(serde_json::from_value(value)?),
            ObjectType::Policy => Self::Policy(serde_json::from_value(value)?),
            ObjectType::Procedure => Self::Procedure(serde_json::from_value(value)?),
            ObjectType::Risk => Self::Risk(serde_json::from_value(value)?),
            ObjectType::Exception => Self::Exception(serde_json::from_value(value)?),
            ObjectType::MappingReview => Self::MappingReview(serde_json::from_value(value)?),
        };

        // Envelope invariants: readable spec_version, valid id matching type, valid Risk scores.
        if !readable_spec_version(obj.spec_version()) {
            return Err(ModelError::UnsupportedSpecVersion(
                obj.spec_version().to_string(),
                readable_spec_version_label(),
            ));
        }
        let (id_type, _) = ids::split(obj.id())?;
        if id_type != obj.object_type().as_str() {
            return Err(ModelError::IdTypeMismatch {
                id: obj.id().to_string(),
                id_type: id_type.to_string(),
                obj_type: obj.object_type().to_string(),
            });
        }
        if let Self::Risk(r) = &obj {
            for score in [
                Some(r.likelihood),
                Some(r.impact),
                r.residual_likelihood,
                r.residual_impact,
            ]
            .into_iter()
            .flatten()
            {
                if !(1..=5).contains(&score) {
                    return Err(ModelError::InvalidScore(score));
                }
            }
        }
        Ok(obj)
    }

    pub fn to_json_value(&self) -> Value {
        let mut val = match self {
            Self::Framework(x) => serde_json::to_value(x),
            Self::Requirement(x) => serde_json::to_value(x),
            Self::Control(x) => serde_json::to_value(x),
            Self::Mapping(x) => serde_json::to_value(x),
            Self::Baseline(x) => serde_json::to_value(x),
            Self::Test(x) => serde_json::to_value(x),
            Self::Party(x) => serde_json::to_value(x),
            Self::Component(x) => serde_json::to_value(x),
            Self::System(x) => serde_json::to_value(x),
            Self::Program(x) => serde_json::to_value(x),
            Self::Implementation(x) => serde_json::to_value(x),
            Self::Result(x) => serde_json::to_value(x),
            Self::Finding(x) => serde_json::to_value(x),
            Self::Evidence(x) => serde_json::to_value(x),
            Self::Policy(x) => serde_json::to_value(x),
            Self::Procedure(x) => serde_json::to_value(x),
            Self::Risk(x) => serde_json::to_value(x),
            Self::Exception(x) => serde_json::to_value(x),
            Self::MappingReview(x) => serde_json::to_value(x),
        }
        .expect("OGRL object serialization cannot fail");
        if let Some(map) = val.as_object_mut() {
            map.insert(
                "type".to_string(),
                Value::String(self.object_type().as_str().to_string()),
            );
        }
        val
    }

    pub const fn object_type(&self) -> ObjectType {
        match self {
            Self::Framework(_) => ObjectType::Framework,
            Self::Requirement(_) => ObjectType::Requirement,
            Self::Control(_) => ObjectType::Control,
            Self::Mapping(_) => ObjectType::Mapping,
            Self::Baseline(_) => ObjectType::Baseline,
            Self::Test(_) => ObjectType::Test,
            Self::Party(_) => ObjectType::Party,
            Self::Component(_) => ObjectType::Component,
            Self::System(_) => ObjectType::System,
            Self::Program(_) => ObjectType::Program,
            Self::Implementation(_) => ObjectType::Implementation,
            Self::Result(_) => ObjectType::Result,
            Self::Finding(_) => ObjectType::Finding,
            Self::Evidence(_) => ObjectType::Evidence,
            Self::Policy(_) => ObjectType::Policy,
            Self::Procedure(_) => ObjectType::Procedure,
            Self::Risk(_) => ObjectType::Risk,
            Self::Exception(_) => ObjectType::Exception,
            Self::MappingReview(_) => ObjectType::MappingReview,
        }
    }

    pub fn id(&self) -> &str {
        match self {
            Self::Framework(x) => &x.id,
            Self::Requirement(x) => &x.id,
            Self::Control(x) => &x.id,
            Self::Mapping(x) => &x.id,
            Self::Baseline(x) => &x.id,
            Self::Test(x) => &x.id,
            Self::Party(x) => &x.id,
            Self::Component(x) => &x.id,
            Self::System(x) => &x.id,
            Self::Program(x) => &x.id,
            Self::Implementation(x) => &x.id,
            Self::Result(x) => &x.id,
            Self::Finding(x) => &x.id,
            Self::Evidence(x) => &x.id,
            Self::Policy(x) => &x.id,
            Self::Procedure(x) => &x.id,
            Self::Risk(x) => &x.id,
            Self::Exception(x) => &x.id,
            Self::MappingReview(x) => &x.id,
        }
    }

    pub fn spec_version(&self) -> &str {
        match self {
            Self::Framework(x) => &x.spec_version,
            Self::Requirement(x) => &x.spec_version,
            Self::Control(x) => &x.spec_version,
            Self::Mapping(x) => &x.spec_version,
            Self::Baseline(x) => &x.spec_version,
            Self::Test(x) => &x.spec_version,
            Self::Party(x) => &x.spec_version,
            Self::Component(x) => &x.spec_version,
            Self::System(x) => &x.spec_version,
            Self::Program(x) => &x.spec_version,
            Self::Implementation(x) => &x.spec_version,
            Self::Result(x) => &x.spec_version,
            Self::Finding(x) => &x.spec_version,
            Self::Evidence(x) => &x.spec_version,
            Self::Policy(x) => &x.spec_version,
            Self::Procedure(x) => &x.spec_version,
            Self::Risk(x) => &x.spec_version,
            Self::Exception(x) => &x.spec_version,
            Self::MappingReview(x) => &x.spec_version,
        }
    }

    pub fn created(&self) -> DateTime<Utc> {
        match self {
            Self::Framework(x) => x.created,
            Self::Requirement(x) => x.created,
            Self::Control(x) => x.created,
            Self::Mapping(x) => x.created,
            Self::Baseline(x) => x.created,
            Self::Test(x) => x.created,
            Self::Party(x) => x.created,
            Self::Component(x) => x.created,
            Self::System(x) => x.created,
            Self::Program(x) => x.created,
            Self::Implementation(x) => x.created,
            Self::Result(x) => x.created,
            Self::Finding(x) => x.created,
            Self::Evidence(x) => x.created,
            Self::Policy(x) => x.created,
            Self::Procedure(x) => x.created,
            Self::Risk(x) => x.created,
            Self::Exception(x) => x.created,
            Self::MappingReview(x) => x.created,
        }
    }

    pub fn modified(&self) -> DateTime<Utc> {
        match self {
            Self::Framework(x) => x.modified,
            Self::Requirement(x) => x.modified,
            Self::Control(x) => x.modified,
            Self::Mapping(x) => x.modified,
            Self::Baseline(x) => x.modified,
            Self::Test(x) => x.modified,
            Self::Party(x) => x.modified,
            Self::Component(x) => x.modified,
            Self::System(x) => x.modified,
            Self::Program(x) => x.modified,
            Self::Implementation(x) => x.modified,
            Self::Result(x) => x.modified,
            Self::Finding(x) => x.modified,
            Self::Evidence(x) => x.modified,
            Self::Policy(x) => x.modified,
            Self::Procedure(x) => x.modified,
            Self::Risk(x) => x.modified,
            Self::Exception(x) => x.modified,
            Self::MappingReview(x) => x.modified,
        }
    }

    pub fn is_revoked(&self) -> bool {
        match self {
            Self::Framework(x) => x.is_revoked(),
            Self::Requirement(x) => x.is_revoked(),
            Self::Control(x) => x.is_revoked(),
            Self::Mapping(x) => x.is_revoked(),
            Self::Baseline(x) => x.is_revoked(),
            Self::Test(x) => x.is_revoked(),
            Self::Party(x) => x.is_revoked(),
            Self::Component(x) => x.is_revoked(),
            Self::System(x) => x.is_revoked(),
            Self::Program(x) => x.is_revoked(),
            Self::Implementation(x) => x.is_revoked(),
            Self::Result(x) => x.is_revoked(),
            Self::Finding(x) => x.is_revoked(),
            Self::Evidence(x) => x.is_revoked(),
            Self::Policy(x) => x.is_revoked(),
            Self::Procedure(x) => x.is_revoked(),
            Self::Risk(x) => x.is_revoked(),
            Self::Exception(x) => x.is_revoked(),
            Self::MappingReview(x) => x.is_revoked(),
        }
    }

    pub fn with_revoked(&self, revoked: bool) -> Self {
        let mut cloned = self.clone();
        match &mut cloned {
            Self::Framework(x) => x.revoked = Some(revoked),
            Self::Requirement(x) => x.revoked = Some(revoked),
            Self::Control(x) => x.revoked = Some(revoked),
            Self::Mapping(x) => x.revoked = Some(revoked),
            Self::Baseline(x) => x.revoked = Some(revoked),
            Self::Test(x) => x.revoked = Some(revoked),
            Self::Party(x) => x.revoked = Some(revoked),
            Self::Component(x) => x.revoked = Some(revoked),
            Self::System(x) => x.revoked = Some(revoked),
            Self::Program(x) => x.revoked = Some(revoked),
            Self::Implementation(x) => x.revoked = Some(revoked),
            Self::Result(x) => x.revoked = Some(revoked),
            Self::Finding(x) => x.revoked = Some(revoked),
            Self::Evidence(x) => x.revoked = Some(revoked),
            Self::Policy(x) => x.revoked = Some(revoked),
            Self::Procedure(x) => x.revoked = Some(revoked),
            Self::Risk(x) => x.revoked = Some(revoked),
            Self::Exception(x) => x.revoked = Some(revoked),
            Self::MappingReview(x) => x.revoked = Some(revoked),
        }
        cloned
    }
}

impl Serialize for OgrlObject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_json_value().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OgrlObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Self::from_value(value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod spec_version_tests {
    use super::*;

    #[test]
    fn readable_spec_version_accepts_implemented_major_minor() {
        assert!(readable_spec_version("0.1.0"));
        assert!(readable_spec_version("0.1.99"));
        assert!(readable_spec_version("0.2.0"));
        assert!(readable_spec_version("0.2.3"));
        assert!(!readable_spec_version("0.3.0"));
        assert!(!readable_spec_version("1.0.0"));
        assert!(!readable_spec_version("0.2"));
        assert!(!readable_spec_version("0.2.0.0"));
    }

    #[test]
    fn detects_spec_0_2_family() {
        assert!(super::spec_is_0_2("0.2.0"));
        assert!(!super::spec_is_0_2("0.1.0"));
    }
}
