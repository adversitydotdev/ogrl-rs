//! Object identifiers and references, RFC 0001 sections 6.3 and 6.4.

use std::sync::LazyLock;

use regex::Regex;
use thiserror::Error;
use uuid::Uuid;

static TYPE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z_]+$").unwrap());
static REMAINDER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$").unwrap());
static DOMAIN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z]{2,63}\.[a-z0-9-]*[a-z][a-z0-9-]*(?:\.|$)").unwrap());

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdError {
    #[error("not an OGRL id: {0:?}")]
    Malformed(String),
    #[error("the type part is lowercase ASCII letters and underscores: {0:?}")]
    InvalidType(String),
    #[error(
        "the remainder is lowercase letters, digits, hyphen, dot, and underscore, starts and ends with a letter or a digit, and contains no --: {0:?}"
    )]
    InvalidRemainder(String),
}

/// Split `type--remainder` on the first `--`.
pub fn split(object_id: &str) -> Result<(&str, &str), IdError> {
    let Some((object_type, remainder)) = object_id.split_once("--") else {
        return Err(IdError::Malformed(object_id.to_string()));
    };
    if object_type.is_empty() || remainder.is_empty() {
        return Err(IdError::Malformed(object_id.to_string()));
    }
    if !TYPE_RE.is_match(object_type) {
        return Err(IdError::InvalidType(object_id.to_string()));
    }
    if remainder.contains("--") || !REMAINDER_RE.is_match(remainder) {
        return Err(IdError::InvalidRemainder(object_id.to_string()));
    }
    Ok((object_type, remainder))
}

/// Mint a new UUID-backed object id for `object_type`.
pub fn mint(object_type: &str) -> String {
    format!("{object_type}--{}", Uuid::new_v4())
}

/// True when the id is in the reserved standard-library slug space (RFC 0001 §6.3).
///
/// Organizations and providers use a UUID or a slug prefixed by a domain they control
/// (`control--com.acme.badge-access`). Bare slugs belong to the standard library.
pub fn is_reserved(object_id: &str) -> Result<bool, IdError> {
    let (_, remainder) = split(object_id)?;
    if Uuid::parse_str(remainder).is_ok() {
        return Ok(false);
    }
    if remainder.contains('_') {
        // `_to_` and `_part_` are library mapping joins.
        return Ok(true);
    }
    Ok(!DOMAIN_RE.is_match(remainder))
}

/// The object id portion of a reference, without any `#fragment`.
pub fn base(reference: &str) -> &str {
    reference.split_once('#').map_or(reference, |(b, _)| b)
}

/// The fragment portion of a reference after `#`, if present.
pub fn fragment(reference: &str) -> Option<&str> {
    reference.split_once('#').map(|(_, f)| f)
}

/// Extract the type prefix of a reference if it is a valid OGRL id.
pub fn type_of(reference: &str) -> Option<&str> {
    split(base(reference)).ok().map(|(kind, _)| kind)
}

/// `requirement--x#obj.a` -> `Some("a")`. `None` for any other reference.
pub fn objective_of(reference: &str) -> Option<&str> {
    let frag = fragment(reference)?;
    let obj = frag.strip_prefix("obj.")?;
    if obj.is_empty() { None } else { Some(obj) }
}

/// Conventional repository-form relative file path: `{type}/{remainder}.yaml`.
pub fn object_path(object_id: &str) -> Result<String, IdError> {
    let (kind, remainder) = split(object_id)?;
    Ok(format!("{kind}/{remainder}.yaml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_valid_and_invalid() {
        assert_eq!(
            split("control--ogrl-ac-01").unwrap(),
            ("control", "ogrl-ac-01")
        );
        assert_eq!(
            split("mapping_review--7c9e6679-7425-40de-944b-e07fc1f90ae7").unwrap(),
            ("mapping_review", "7c9e6679-7425-40de-944b-e07fc1f90ae7")
        );
        assert!(split("no-separator").is_err());
        assert!(split("Control--abc").is_err());
        assert!(split("control--a--b").is_err());
        assert!(split("control---leading").is_err());
        assert!(split("control--trailing.").is_err());
    }

    #[test]
    fn reserved_namespace() {
        assert!(is_reserved("control--ogrl-ac-01").unwrap());
        assert!(is_reserved("requirement--soc2-tsc-2017-cc6.1").unwrap());
        assert!(is_reserved("mapping--a_to_b").unwrap());
        assert!(!is_reserved("control--com.acme.badge-access").unwrap());
        assert!(!is_reserved("control--7c9e6679-7425-40de-944b-e07fc1f90ae7").unwrap());
    }

    #[test]
    fn fragments_and_objectives() {
        assert_eq!(base("requirement--x#a.1"), "requirement--x");
        assert_eq!(fragment("requirement--x#a.1"), Some("a.1"));
        assert_eq!(objective_of("requirement--x#obj.a"), Some("a"));
        assert_eq!(objective_of("requirement--x#obj."), None);
        assert_eq!(objective_of("requirement--x#a"), None);
    }
}
