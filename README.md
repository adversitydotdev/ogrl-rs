# ogrl-rs

High-performance Rust toolchain for **OGRL** (Open GRC Language — RFC 0001 & RFC 0002).

Designed to parse, lint, format, import, evaluate, diff, and render massive OGRL repositories and OSCAL 1.2.3 packages with parallel execution (`rayon`), span-aware strict YAML 1.2 parsing, and zero external runtime dependencies.

## Workspace layout

- `crates/ogrl-core` — Pure library implementing the 19 closed RFC 0001 object types (with unknown-field round-tripping), strict YAML 1.2 parser + canonical formatter, RFC 8785 canonical JSON & SHA-256 digests, parallel directory/exchange bundle I/O, indexed `Graph`, RFC 0001 §7.20 constraint validator, parameter resolver, §8 deterministic status evaluator, and RFC 0002 §5 library revision diff.
- `crates/ogrl-oscal` — OSCAL 1.2.3 (JSON & XML) catalog importer (including assessment `objectives` and `methods`), component-definition importer, 6-document OSCAL package renderer (JSON + XML), and narrative SSP renderer.
- `crates/ogrl-cli` — Standalone `ogrl` binary.
- `crates/ogrl-py` — Coarse-grained PyO3 / maturin Python bindings (`import ogrl_rs`) releasing the GIL for parallel Rust execution (`OgrlGraph`, `lint_path`, `read_directory`, `evaluate_program`, `compare_library_revisions`, `import_oscal_catalog`, `import_oscal_component`, `render_oscal`, `render_ssp`).

## Installation

Prebuilt `ogrl` CLI binaries and Python wheels are published on [GitHub Releases](https://github.com/adversitydotdev/ogrl-rs/releases):

```bash
# macOS (Apple Silicon)
curl -fsSL https://github.com/adversitydotdev/ogrl-rs/releases/latest/download/ogrl-aarch64-apple-darwin.tar.gz | tar -xz

# Linux (x86_64)
curl -fsSL https://github.com/adversitydotdev/ogrl-rs/releases/latest/download/ogrl-x86_64-unknown-linux-gnu.tar.gz | tar -xz

# Linux (aarch64)
curl -fsSL https://github.com/adversitydotdev/ogrl-rs/releases/latest/download/ogrl-aarch64-unknown-linux-gnu.tar.gz | tar -xz
```

Archives are also published for `x86_64-apple-darwin` (`.tar.gz`) and `x86_64-pc-windows-msvc` (`.zip`), along with `SHA256SUMS.txt`.

## Python bindings (`ogrl_rs`)

Build and install locally with [maturin](https://www.maturin.rs/) (or `uv pip install -e crates/ogrl-py`):

```bash
cd crates/ogrl-py
maturin develop --release
```

```python
import ogrl_rs

# Lint a repository in parallel (~70ms for 1,725 NIST files)
report = ogrl_rs.lint_path("../OGRL/library")

# Or load an indexed Rust graph once and run zero-reparse queries
graph = ogrl_rs.OgrlGraph.from_path("./my-org", library="../OGRL/library")
status = graph.evaluate("program--com.acme.prod", "2026-11-09T00:00:00Z")
oscal_files = graph.render_oscal(
    "program--com.acme.prod",
    "framework--nist-sp-800-53-r5",
    "2026-11-09T00:00:00Z",
    include_xml=True,
)
```

## Usage

```bash
# Lint a library, provider, or organization repository (text, json, or sarif)
cargo run --release -- lint ../OGRL/library
cargo run --release -- lint ./my-org --library ../OGRL/library --format sarif

# Check or apply canonical YAML 1.2 formatting
cargo run --release -- fmt ../OGRL/library --check

# Import pinned NIST SP 800-53 r5 + SP 800-171 r3 OSCAL catalogs (with assessment objectives)
cargo run --release -- import nist --out library

# Import any local OSCAL catalog (JSON or XML)
cargo run --release -- import oscal --catalog catalog.json --framework-id nist-sp-800-53-r5 --out library

# Import an OSCAL component definition as a provider bundle
cargo run --release -- import oscal-component --input component.json --library ../OGRL/library --out provider/django

# Pack / unpack / digest bundles
cargo run --release -- bundle pack ../OGRL/library --out library.json
cargo run --release -- bundle digest ../OGRL/library

# Evaluate program compliance status or readiness summary
cargo run --release -- eval ./my-org --library ../OGRL/library --summary

# Preview status & stale mapping review impact across library revisions
cargo run --release -- diff --before ./lib-v1 --after ./lib-v2 --org ./my-org

# Render 6-document OSCAL 1.2.3 package (JSON + XML) or narrative SSP
cargo run --release -- render oscal ./my-org --library ../OGRL/library --framework framework--nist-sp-800-53-r5 --out ./oscal --xml
cargo run --release -- render ssp ./my-org --library ../OGRL/library --out ./ssp
```
