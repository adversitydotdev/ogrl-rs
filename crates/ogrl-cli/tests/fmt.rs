//! CLI tests for `ogrl fmt` comment preservation and `--drop-comments`.

use std::fs;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

fn ogrl() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ogrl"))
}

fn write_file(dir: &Path, name: &str, body: &str) {
    fs::write(dir.join(name), body).unwrap();
}

const IMPL: &str = "\
---
# top comment
type: implementation
id: implementation--com.acme.x
spec_version: \"0.1.0\"
created: 2026-11-08T00:00:00Z
modified: 2026-11-08T00:00:00Z
status: implemented
responsibility: provider
# moves with component_ref
component_ref: component--dev.x.y
narrative: x  # trailing
";

#[test]
fn fmt_preserves_comments_and_is_idempotent() {
    let dir = TempDir::new().unwrap();
    write_file(dir.path(), "impl.yaml", IMPL);

    let out = ogrl()
        .args(["fmt", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let formatted = fs::read_to_string(dir.path().join("impl.yaml")).unwrap();
    assert!(formatted.starts_with("# top comment\n"), "{formatted}");
    assert!(formatted.contains("# moves with component_ref\ncomponent_ref:"));
    assert!(formatted.contains("narrative: x  # trailing"));
    assert!(!formatted.starts_with("---"));

    let check = ogrl()
        .args(["fmt", "--check", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
    assert!(String::from_utf8_lossy(&check.stdout).contains("ok:"));
}

#[test]
fn fmt_check_reports_would_reformat_without_dropping() {
    let dir = TempDir::new().unwrap();
    write_file(dir.path(), "impl.yaml", IMPL);
    let check = ogrl()
        .args([
            "fmt",
            "--check",
            dir.path().join("impl.yaml").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!check.status.success());
    let stdout = String::from_utf8_lossy(&check.stdout);
    assert!(stdout.contains("would reformat"), "{stdout}");
    assert!(!stdout.contains("would drop"), "{stdout}");
    // File is unchanged in check mode.
    assert_eq!(
        fs::read_to_string(dir.path().join("impl.yaml")).unwrap(),
        IMPL
    );
}

#[test]
fn fmt_drop_comments_strips_body_comments() {
    let dir = TempDir::new().unwrap();
    write_file(dir.path(), "impl.yaml", IMPL);
    let out = ogrl()
        .args([
            "fmt",
            "--drop-comments",
            dir.path().join("impl.yaml").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let formatted = fs::read_to_string(dir.path().join("impl.yaml")).unwrap();
    assert!(formatted.starts_with("# top comment\n"), "{formatted}");
    assert!(
        !formatted.contains("# moves with component_ref"),
        "{formatted}"
    );
    assert!(!formatted.contains("# trailing"), "{formatted}");
}
