//! Pinned upstream NIST OSCAL catalogs (matching OGRL `internal/oscalimport/nist.go`).

use crate::catalog::ImportOptions;

/// The `usnistgov/oscal-content` commit pinned by OGRL.
pub const OSCAL_CONTENT_COMMIT: &str = "f0de6d8d8c059d374f15e0ae07508d82e370fc1d";

const OSCAL_CONTENT_RAW: &str = "https://raw.githubusercontent.com/usnistgov/oscal-content/f0de6d8d8c059d374f15e0ae07508d82e370fc1d/";

#[derive(Debug, Clone)]
pub struct NistCatalog {
    pub url: String,
    pub options: ImportOptions,
}

/// Official NIST catalogs in dependency order: SP 800-53 Rev 5 first, then SP 800-171 Rev 3
/// (which cross-references 800-53 by zero-padded control labels).
pub fn nist_catalogs() -> Vec<NistCatalog> {
    vec![
        NistCatalog {
            url: format!(
                "{OSCAL_CONTENT_RAW}nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
            ),
            options: ImportOptions {
                framework_id: "nist-sp-800-53-r5".into(),
                name: Some("NIST SP 800-53 Revision 5".into()),
                publisher: "NIST".into(),
                source_uri: Some("https://github.com/usnistgov/oscal-content".into()),
                source_path: Some(
                    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json".into(),
                ),
                commit: Some(OSCAL_CONTENT_COMMIT.into()),
                version: None,
            },
        },
        NistCatalog {
            url: format!(
                "{OSCAL_CONTENT_RAW}nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json"
            ),
            options: ImportOptions {
                framework_id: "nist-sp-800-171-r3".into(),
                name: Some("NIST SP 800-171 Revision 3".into()),
                publisher: "NIST".into(),
                source_uri: Some("https://github.com/usnistgov/oscal-content".into()),
                source_path: Some(
                    "nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json".into(),
                ),
                commit: Some(OSCAL_CONTENT_COMMIT.into()),
                version: None,
            },
        },
    ]
}
