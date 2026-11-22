//! Core OGRL (Open Governance Reference Language) implementation covering RFC 0001 and RFC 0002.

pub mod baselines;
pub mod bundle;
pub mod canonical;
pub mod constraints;
pub mod graph;
pub mod ids;
pub mod model;
pub mod parameters;
pub mod status;
pub mod time;
pub mod yaml;

pub use bundle::{BundleManifest, LoadedBundle, LoadedObject};
pub use constraints::{Diagnostic, Severity, StorageOrigin, Violation};
pub use graph::Graph;
pub use model::{ObjectType, OgrlObject, SPEC_VERSION};
