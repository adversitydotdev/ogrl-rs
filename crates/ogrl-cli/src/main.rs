use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use rayon::prelude::*;
use serde_json::{Value, json};
use walkdir::WalkDir;

use ogrl_core::bundle::{
    BundleManifest, LoadedBundle, pack_exchange, read_directory, read_path, write_directory,
};
use ogrl_core::canonical::{canonical_json, projection_digest};
use ogrl_core::constraints::{Diagnostic, Severity, StorageOrigin, check_graph_parallel};
use ogrl_core::graph::Graph;
use ogrl_core::model::{OgrlObject, SPEC_VERSION};
use ogrl_core::status::{self, compare_revisions};
use ogrl_core::time::{format_timestamp, parse_timestamp};
use ogrl_core::yaml::{self, ParseOptions};
use ogrl_oscal::{
    ImportOptions, SP800_171A_CSV_URL, import_catalog_bytes, import_component_definition,
    index_only, nist_catalogs, render_oscal_package, render_ssp, sp800_171a_csv_to_oscal,
    sp800_171r2_options, sp800_171r2_source, verify_sp800_171a_csv, write_library_bundle,
    write_library_output,
};

#[derive(Parser)]
#[command(
    name = "ogrl",
    version,
    about = "High-performance parser, linter, formatter, evaluator, and OSCAL bridge for OGRL."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate YAML 1.2 authoring rules, RFC 0001 schemas, and §7.20 graph constraints.
    Lint {
        /// Repository directory, exchange bundle, or single object YAML/JSON file.
        path: PathBuf,
        /// Optional standard-library directory to resolve references against.
        #[arg(long)]
        library: Option<PathBuf>,
        /// Origin profile for validation rules.
        #[arg(long, value_enum, default_value_t = ProfileArg::Auto)]
        profile: ProfileArg,
        /// Output format.
        #[arg(long, value_enum, default_value_t = LintFormat::Text)]
        format: LintFormat,
        /// Relax RFC 0001 §6.1 strict YAML 1.2 checks (allow anchors/nulls).
        #[arg(long)]
        lenient_yaml: bool,
    },
    /// Format OGRL YAML files in deterministic canonical key order (RFC 0001 §6.1).
    Fmt {
        /// File or directory to format.
        path: PathBuf,
        /// Check formatting without modifying files (exits non-zero if changes are needed).
        #[arg(long)]
        check: bool,
    },
    /// Import upstream OSCAL catalogs or component definitions into OGRL objects.
    Import {
        #[command(subcommand)]
        target: ImportCommands,
    },
    /// Pack, unpack, or hash OGRL bundles.
    Bundle {
        #[command(subcommand)]
        action: BundleCommands,
    },
    /// Evaluate RFC 0001 §8 program status or summary at a point in time.
    Eval {
        /// Repository directory or exchange bundle containing organization objects.
        path: PathBuf,
        /// Optional standard-library directory if separate from `path`.
        #[arg(long)]
        library: Option<PathBuf>,
        /// Program ID to evaluate (defaults to the sole program if only one exists).
        #[arg(long)]
        program: Option<String>,
        /// Evaluation RFC 3339 timestamp (defaults to current UTC time).
        #[arg(long)]
        at: Option<String>,
        /// Filter requirement coverage to one framework ID.
        #[arg(long)]
        framework: Option<String>,
        /// Emit the readiness summary counts instead of per-control/requirement detail.
        #[arg(long)]
        summary: bool,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Diff two library revisions (RFC 0002 §5) and preview status impact on programs.
    Diff {
        /// Baseline ("before") library directory or bundle.
        #[arg(long)]
        before: PathBuf,
        /// Candidate ("after") library directory or bundle.
        #[arg(long)]
        after: PathBuf,
        /// Optional organization directory/bundle to compute program status & stale review impact.
        #[arg(long)]
        org: Option<PathBuf>,
        /// Evaluation RFC 3339 timestamp (defaults to current UTC time).
        #[arg(long)]
        at: Option<String>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Render a program to an OSCAL 1.2.3 package or narrative SSP.
    Render {
        #[command(subcommand)]
        view: RenderCommands,
    },
}

#[derive(Subcommand)]
enum ImportCommands {
    /// Fetch and import pinned NIST SP 800-53 r5, SP 800-171 r3 (OSCAL), and SP 800-171 r2
    /// (SP 800-171A CSV) catalogs.
    Nist {
        /// Output directory for the generated library.
        #[arg(long, default_value = "library")]
        out: PathBuf,
    },
    /// Import a single OSCAL 1.2.3 catalog (JSON or XML) from disk.
    Oscal {
        /// Path to the OSCAL catalog JSON or XML file.
        #[arg(long)]
        catalog: PathBuf,
        /// OGRL framework slug, e.g. `nist-sp-800-53-r5`.
        #[arg(long)]
        framework_id: String,
        /// Framework display title (defaults to catalog metadata.title).
        #[arg(long)]
        name: Option<String>,
        /// Publisher stored on the framework.
        #[arg(long, default_value = "NIST")]
        publisher: String,
        /// Output directory for the generated library.
        #[arg(long, default_value = "library")]
        out: PathBuf,
        /// Upstream source URI.
        #[arg(long)]
        source_uri: Option<String>,
        /// Path inside upstream source repository.
        #[arg(long)]
        source_path: Option<String>,
        /// Upstream commit hash.
        #[arg(long)]
        commit: Option<String>,
        /// Optional secondary OSCAL catalog to resolve cross-framework control references.
        #[arg(long)]
        resolve_catalog: Option<PathBuf>,
        /// Framework ID corresponding to `--resolve-catalog`.
        #[arg(long)]
        resolve_framework: Option<String>,
        /// Also write/update `bundle.yaml` in `--out`.
        #[arg(long)]
        write_bundle: bool,
    },
    /// Import an OSCAL 1.2.3 component definition (JSON or XML) as an OGRL provider bundle.
    OscalComponent {
        /// Path to the OSCAL component-definition JSON or XML file.
        #[arg(long)]
        input: PathBuf,
        /// Path to the pinned OGRL library directory or bundle for resolving control IDs.
        #[arg(long)]
        library: PathBuf,
        /// Output directory (repository-form) or file path (with `--exchange`).
        #[arg(long)]
        out: PathBuf,
        /// Write a single exchange-form JSON bundle instead of a directory tree.
        #[arg(long)]
        exchange: bool,
    },
}

#[derive(Subcommand)]
enum BundleCommands {
    /// Pack a repository-form directory into a single exchange-form JSON or YAML bundle.
    Pack {
        dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, value_enum, default_value_t = PackFormat::Json)]
        format: PackFormat,
    },
    /// Unpack an exchange-form bundle file into a repository-form directory tree.
    Unpack {
        file: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Compute the deterministic RFC 8785 SHA-256 projection digest of a bundle or directory.
    Digest { path: PathBuf },
}

#[derive(Subcommand)]
enum RenderCommands {
    /// Render the 6-document OSCAL 1.2.3 package (profile, ssp, mapping-collection, component-definition, assessment-results, poam).
    Oscal {
        path: PathBuf,
        #[arg(long)]
        library: Option<PathBuf>,
        #[arg(long)]
        program: Option<String>,
        #[arg(long)]
        framework: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        at: Option<String>,
        /// Also emit OSCAL 1.2.3 `.xml` files alongside `.json` (RFC 0002 §9).
        #[arg(long)]
        xml: bool,
    },
    /// Render a narrative System Security Plan (`ssp.md` and `ssp.json`).
    Ssp {
        path: PathBuf,
        #[arg(long)]
        library: Option<PathBuf>,
        #[arg(long)]
        program: Option<String>,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        at: Option<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ProfileArg {
    Auto,
    Library,
    Provider,
    Organization,
}

impl ProfileArg {
    fn to_override(self) -> Option<StorageOrigin> {
        match self {
            Self::Auto => None,
            Self::Library => Some(StorageOrigin::Library),
            Self::Provider => Some(StorageOrigin::Provider),
            Self::Organization => Some(StorageOrigin::Organization),
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum LintFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Clone, Copy, ValueEnum)]
enum PackFormat {
    Json,
    Yaml,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("ogrl: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.command {
        Commands::Lint {
            path,
            library,
            profile,
            format,
            lenient_yaml,
        } => cmd_lint(&path, library.as_deref(), profile, format, !lenient_yaml),
        Commands::Fmt { path, check } => cmd_fmt(&path, check),
        Commands::Import { target } => cmd_import(target),
        Commands::Bundle { action } => cmd_bundle(action),
        Commands::Eval {
            path,
            library,
            program,
            at,
            framework,
            summary,
            format,
        } => cmd_eval(
            &path,
            library.as_deref(),
            program.as_deref(),
            at.as_deref(),
            framework.as_deref(),
            summary,
            format,
        ),
        Commands::Diff {
            before,
            after,
            org,
            at,
            format,
        } => cmd_diff(&before, &after, org.as_deref(), at.as_deref(), format),
        Commands::Render { view } => cmd_render(view),
    }
}

// --- lint -------------------------------------------------------------------

fn cmd_lint(
    path: &Path,
    library_path: Option<&Path>,
    profile: ProfileArg,
    format: LintFormat,
    strict_yaml: bool,
) -> Result<ExitCode, String> {
    let start = Instant::now();
    let opts = ParseOptions {
        strict: strict_yaml,
    };

    let mut target = read_path(path, opts, profile.to_override()).map_err(|e| e.to_string())?;
    let mut diagnostics = std::mem::take(&mut target.diagnostics);

    // Combine with optional external library for graph resolution.
    let combined_graph = if let Some(lib_path) = library_path {
        let lib = read_path(lib_path, opts, Some(StorageOrigin::Library))
            .map_err(|e| format!("library {}: {e}", lib_path.display()))?;
        let mut all_objs: Vec<OgrlObject> =
            Vec::with_capacity(lib.objects.len() + target.objects.len());
        let mut lib_ids = Vec::new();
        let mut prov_ids = Vec::new();
        for lo in &lib.objects {
            lib_ids.push(lo.object.id().to_string());
            all_objs.push(lo.object.clone());
        }
        for lo in &target.objects {
            match lo.origin {
                StorageOrigin::Library => lib_ids.push(lo.object.id().to_string()),
                StorageOrigin::Provider => prov_ids.push(lo.object.id().to_string()),
                StorageOrigin::Organization => {}
            }
            all_objs.push(lo.object.clone());
        }
        Graph::new(all_objs, lib_ids, prov_ids)
    } else {
        target.to_graph()
    };

    let meta = target.metadata_index();
    let target_ids: std::collections::HashSet<&str> =
        target.objects.iter().map(|lo| lo.object.id()).collect();

    // Only report constraint diagnostics for objects in `path` (not the external `--library`).
    let mut graph_diags = check_graph_parallel(
        &combined_graph,
        |id| {
            meta.get(id)
                .map(|(_, _, origin)| *origin)
                .unwrap_or(StorageOrigin::Library)
        },
        |id| match meta.get(id) {
            Some((f, spans, _)) => (f.clone(), *spans),
            None => (None, None),
        },
    );
    graph_diags.retain(|d| {
        d.object_id
            .as_deref()
            .is_none_or(|id| target_ids.contains(id))
    });
    diagnostics.extend(graph_diags);

    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    let error_count = diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .count();

    match format {
        LintFormat::Text => {
            for d in &diagnostics {
                let loc = match (&d.file, d.line, d.col) {
                    (Some(f), Some(l), Some(c)) => format!("{}:{l}:{c}", f.display()),
                    (Some(f), Some(l), None) => format!("{}:{l}", f.display()),
                    (Some(f), None, _) => format!("{}", f.display()),
                    _ => d.object_id.clone().unwrap_or_else(|| "<input>".into()),
                };
                let ptr = if d.pointer.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", d.pointer)
                };
                let level = match d.severity {
                    Severity::Error => "error",
                    Severity::Warning => "warning",
                };
                eprintln!("{loc}: {level}[{}]{ptr}: {}", d.code, d.detail);
            }
            if error_count == 0 {
                println!(
                    "ok: {} objects validated in {:.1}ms (0 errors)",
                    target.objects.len(),
                    elapsed_ms
                );
            } else {
                eprintln!(
                    "failed: {} error(s) across {} objects in {:.1}ms",
                    error_count,
                    target.objects.len(),
                    elapsed_ms
                );
            }
        }
        LintFormat::Json => {
            let out = json!({
                "ok": error_count == 0,
                "objects": target.objects.len(),
                "errors": error_count,
                "elapsed_ms": elapsed_ms,
                "diagnostics": diagnostics,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        LintFormat::Sarif => {
            let sarif = to_sarif(&diagnostics);
            println!("{}", serde_json::to_string_pretty(&sarif).unwrap());
        }
    }

    Ok(if error_count == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn to_sarif(diagnostics: &[Diagnostic]) -> Value {
    let results: Vec<Value> = diagnostics
        .iter()
        .map(|d| {
            let uri = d
                .file
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| d.object_id.clone().unwrap_or_default());
            json!({
                "ruleId": d.code,
                "level": match d.severity {
                    Severity::Error => "error",
                    Severity::Warning => "warning",
                },
                "message": { "text": format!("{}{}", d.detail, if d.pointer.is_empty() { String::new() } else { format!(" ({})", d.pointer) }) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri },
                        "region": {
                            "startLine": d.line.unwrap_or(1),
                            "startColumn": d.col.unwrap_or(1),
                        }
                    }
                }]
            })
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ogrl",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://ogrl.adversity.dev"
                }
            },
            "results": results,
        }]
    })
}

// --- fmt --------------------------------------------------------------------

fn cmd_fmt(path: &Path, check_only: bool) -> Result<ExitCode, String> {
    let start = Instant::now();
    let files: Vec<PathBuf> = if path.is_file() {
        vec![path.to_path_buf()]
    } else if path.is_dir() {
        WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
            .map(|e| e.into_path())
            .filter(|p| {
                p.is_file()
                    && !p.strip_prefix(path).ok().is_some_and(|rel| {
                        rel.components()
                            .any(|c| c.as_os_str().to_string_lossy().starts_with('.'))
                    })
                    && p.extension().and_then(|e| e.to_str()).is_some_and(|e| {
                        e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml")
                    })
            })
            .collect()
    } else {
        return Err(format!("{} does not exist", path.display()));
    };

    let results: Vec<Result<(PathBuf, bool), String>> = files
        .par_iter()
        .map(|file| {
            let original =
                fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
            let header = leading_comment_header(&original);
            let (val, _) = yaml::parse_yaml_with_spans(&original, ParseOptions { strict: true })
                .map_err(|errs| {
                    format!(
                        "{}: {}",
                        file.display(),
                        errs.into_iter()
                            .map(|e| e.to_string())
                            .collect::<Vec<_>>()
                            .join("; ")
                    )
                })?;
            let formatted = format_with_header(&val, header.as_deref());
            let changed = formatted != original;
            if changed && !check_only {
                fs::write(file, &formatted).map_err(|e| format!("{}: {e}", file.display()))?;
            }
            Ok((file.clone(), changed))
        })
        .collect();

    let mut changed_files = Vec::new();
    for res in results {
        let (file, changed) = res?;
        if changed {
            changed_files.push(file);
        }
    }
    changed_files.sort();

    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    if check_only {
        for f in &changed_files {
            println!("would reformat {}", f.display());
        }
        if changed_files.is_empty() {
            println!(
                "ok: {} files formatted canonically ({:.1}ms)",
                files.len(),
                elapsed_ms
            );
            Ok(ExitCode::SUCCESS)
        } else {
            eprintln!(
                "{} of {} file(s) need formatting",
                changed_files.len(),
                files.len()
            );
            Ok(ExitCode::FAILURE)
        }
    } else {
        println!(
            "formatted {} of {} file(s) in {:.1}ms",
            changed_files.len(),
            files.len(),
            elapsed_ms
        );
        Ok(ExitCode::SUCCESS)
    }
}

fn leading_comment_header(text: &str) -> Option<String> {
    let mut lines = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            lines.push(line);
        } else {
            break;
        }
    }
    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

fn format_with_header(val: &Value, header: Option<&str>) -> String {
    let body = yaml::format_yaml(val, None);
    match header {
        Some(h) => format!("{h}\n{body}"),
        None => body,
    }
}

// --- import -----------------------------------------------------------------

fn cmd_import(target: ImportCommands) -> Result<ExitCode, String> {
    match target {
        ImportCommands::Nist { out } => {
            let mut resolve_idx = None;
            let mut newest: Option<DateTime<Utc>> = None;
            for cat in nist_catalogs() {
                let body = http_get(&cat.url)?;
                let output = import_catalog_bytes(&body, &cat.options, resolve_idx.as_ref())
                    .map_err(|e| e.to_string())?;
                write_library_output(&out, &output).map_err(|e| e.to_string())?;
                println!(
                    "{}: {} requirements ({} withdrawn, {} objectives), {} mappings",
                    output.framework_id,
                    output.requirements.len(),
                    output.withdrawn_count,
                    output.objectives_count,
                    output.mappings.len()
                );
                if output.framework_id == "nist-sp-800-53-r5" {
                    resolve_idx = Some(output.index);
                }
                if newest.is_none_or(|n| output.modified > n) {
                    newest = Some(output.modified);
                }
            }

            // SP 800-171 Rev 2 has no NIST OSCAL; compile it from the pinned SP 800-171A CSV.
            let csv = http_get(SP800_171A_CSV_URL)?;
            verify_sp800_171a_csv(&csv)?;
            let catalog = sp800_171a_csv_to_oscal(&csv)?;
            let mut output = import_catalog_bytes(&catalog, &sp800_171r2_options(), None)
                .map_err(|e| e.to_string())?;
            output.framework.source = Some(sp800_171r2_source());
            write_library_output(&out, &output).map_err(|e| e.to_string())?;
            println!(
                "{}: {} requirements ({} objectives) from SP 800-171A CSV",
                output.framework_id,
                output.requirements.len(),
                output.objectives_count
            );

            if let Some(stamp) = newest {
                write_library_bundle(&out, stamp, stamp).map_err(|e| e.to_string())?;
            }
            Ok(ExitCode::SUCCESS)
        }
        ImportCommands::Oscal {
            catalog,
            framework_id,
            name,
            publisher,
            out,
            source_uri,
            source_path,
            commit,
            resolve_catalog,
            resolve_framework,
            write_bundle,
        } => {
            let body = fs::read(&catalog).map_err(|e| format!("{}: {e}", catalog.display()))?;
            let resolve_idx = match (resolve_catalog, resolve_framework) {
                (Some(rc), Some(rf)) => {
                    let raw = fs::read(&rc).map_err(|e| format!("{}: {e}", rc.display()))?;
                    Some(index_only(&raw, &rf).map_err(|e| e.to_string())?)
                }
                (Some(_), None) => {
                    return Err("--resolve-framework is required with --resolve-catalog".into());
                }
                _ => None,
            };
            let opt = ImportOptions {
                framework_id,
                name,
                publisher,
                source_uri,
                source_path,
                commit,
                version: None,
            };
            let output = import_catalog_bytes(&body, &opt, resolve_idx.as_ref())
                .map_err(|e| e.to_string())?;
            write_library_output(&out, &output).map_err(|e| e.to_string())?;
            if write_bundle {
                write_library_bundle(&out, output.modified, output.modified)
                    .map_err(|e| e.to_string())?;
            }
            println!(
                "{}: {} requirements ({} withdrawn, {} objectives), {} mappings",
                output.framework_id,
                output.requirements.len(),
                output.withdrawn_count,
                output.objectives_count,
                output.mappings.len()
            );
            Ok(ExitCode::SUCCESS)
        }
        ImportCommands::OscalComponent {
            input,
            library,
            out,
            exchange,
        } => {
            let lib = read_path(
                &library,
                ParseOptions::default(),
                Some(StorageOrigin::Library),
            )
            .map_err(|e| format!("library {}: {e}", library.display()))?;
            let lib_graph = lib.to_graph();
            let content = fs::read(&input).map_err(|e| format!("{}: {e}", input.display()))?;
            let imported =
                import_component_definition(&content, &lib_graph).map_err(|e| e.to_string())?;
            for w in &imported.warnings {
                eprintln!("warning: {w}");
            }
            if exchange {
                let packed = pack_exchange(&imported.manifest, &imported.objects);
                if let Some(parent) = out.parent() {
                    if !parent.as_os_str().is_empty() {
                        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                    }
                }
                fs::write(&out, serde_json::to_vec_pretty(&packed).unwrap())
                    .map_err(|e| format!("{}: {e}", out.display()))?;
            } else {
                write_directory(&out, Some(&imported.manifest), &imported.objects, None)
                    .map_err(|e| e.to_string())?;
            }
            println!(
                "{}: {} objects ({} warnings)",
                imported.manifest.id,
                imported.objects.len(),
                imported.warnings.len()
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn http_get(url: &str) -> Result<Vec<u8>, String> {
    let resp = ureq::get(url)
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?;
    let mut reader = resp.into_reader();
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut bytes).map_err(|e| format!("read {url}: {e}"))?;
    Ok(bytes)
}

// --- bundle -----------------------------------------------------------------

fn cmd_bundle(action: BundleCommands) -> Result<ExitCode, String> {
    match action {
        BundleCommands::Pack { dir, out, format } => {
            let loaded =
                read_directory(&dir, ParseOptions::default(), None).map_err(|e| e.to_string())?;
            if !loaded.diagnostics.is_empty() {
                return Err(format!(
                    "refusing to pack: {} parse/schema error(s) in {}",
                    loaded.diagnostics.len(),
                    dir.display()
                ));
            }
            let manifest = loaded.manifest.unwrap_or_else(|| {
                let now = format_timestamp(&Utc::now());
                BundleManifest {
                    object_type: "bundle".into(),
                    id: ogrl_core::ids::mint("bundle"),
                    spec_version: SPEC_VERSION.into(),
                    created: Some(now.clone()),
                    modified: Some(now),
                    name: Some("Packed bundle".into()),
                    version: Some("0.1.0".into()),
                    library: None,
                    providers: None,
                    extra: Default::default(),
                }
            });
            let objects: Vec<OgrlObject> = loaded.objects.into_iter().map(|lo| lo.object).collect();
            let packed = pack_exchange(&manifest, &objects);
            if let Some(parent) = out.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
            }
            match format {
                PackFormat::Json => {
                    fs::write(&out, canonical_json(&packed))
                        .map_err(|e| format!("{}: {e}", out.display()))?;
                }
                PackFormat::Yaml => {
                    fs::write(&out, yaml::format_yaml(&packed, None))
                        .map_err(|e| format!("{}: {e}", out.display()))?;
                }
            }
            println!(
                "packed {} objects into {} ({})",
                objects.len(),
                out.display(),
                projection_digest(&objects)
            );
            Ok(ExitCode::SUCCESS)
        }
        BundleCommands::Unpack { file, out } => {
            let loaded =
                read_path(&file, ParseOptions::default(), None).map_err(|e| e.to_string())?;
            if !loaded.diagnostics.is_empty() {
                return Err(format!(
                    "refusing to unpack: {} error(s) in {}",
                    loaded.diagnostics.len(),
                    file.display()
                ));
            }
            let objects: Vec<OgrlObject> = loaded.objects.into_iter().map(|lo| lo.object).collect();
            write_directory(&out, loaded.manifest.as_ref(), &objects, None)
                .map_err(|e| e.to_string())?;
            println!("unpacked {} objects into {}", objects.len(), out.display());
            Ok(ExitCode::SUCCESS)
        }
        BundleCommands::Digest { path } => {
            let loaded =
                read_path(&path, ParseOptions::default(), None).map_err(|e| e.to_string())?;
            let objects: Vec<OgrlObject> = loaded.objects.into_iter().map(|lo| lo.object).collect();
            println!("{}", projection_digest(&objects));
            Ok(ExitCode::SUCCESS)
        }
    }
}

// --- eval -------------------------------------------------------------------

fn load_combined_graph(path: &Path, library: Option<&Path>) -> Result<Graph, String> {
    let opts = ParseOptions::default();
    let main_bundle = read_path(path, opts, None).map_err(|e| e.to_string())?;
    if !main_bundle.diagnostics.is_empty() {
        return Err(format!(
            "{} has {} parse/schema error(s); run `ogrl lint` for details",
            path.display(),
            main_bundle.diagnostics.len()
        ));
    }
    if let Some(lib_path) = library {
        let lib = read_path(lib_path, opts, Some(StorageOrigin::Library))
            .map_err(|e| format!("library {}: {e}", lib_path.display()))?;
        return Ok(merge_bundles(&lib, &main_bundle));
    }
    Ok(main_bundle.to_graph())
}

fn merge_bundles(lib: &LoadedBundle, org: &LoadedBundle) -> Graph {
    let mut objs = Vec::with_capacity(lib.objects.len() + org.objects.len());
    let mut lib_ids = Vec::new();
    let mut prov_ids = Vec::new();
    for lo in &lib.objects {
        lib_ids.push(lo.object.id().to_string());
        objs.push(lo.object.clone());
    }
    for lo in &org.objects {
        match lo.origin {
            StorageOrigin::Library => lib_ids.push(lo.object.id().to_string()),
            StorageOrigin::Provider => prov_ids.push(lo.object.id().to_string()),
            StorageOrigin::Organization => {}
        }
        objs.push(lo.object.clone());
    }
    Graph::new(objs, lib_ids, prov_ids)
}

fn resolve_program<'a>(
    graph: &'a Graph,
    program_id: Option<&str>,
) -> Result<&'a ogrl_core::model::Program, String> {
    if let Some(pid) = program_id {
        return graph
            .program(pid)
            .ok_or_else(|| format!("program {pid} not found in graph"));
    }
    let programs = graph.programs();
    match programs.as_slice() {
        [only] => Ok(only),
        [] => Err("no program object found in graph".into()),
        many => Err(format!(
            "multiple programs found ({}); pass --program <id>",
            many.iter()
                .map(|p| p.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn resolve_at(at: Option<&str>) -> Result<DateTime<Utc>, String> {
    match at {
        Some(s) => parse_timestamp(s).map_err(|e| e.to_string()),
        None => Ok(Utc::now()),
    }
}

fn cmd_eval(
    path: &Path,
    library: Option<&Path>,
    program_id: Option<&str>,
    at: Option<&str>,
    framework: Option<&str>,
    summary: bool,
    format: OutputFormat,
) -> Result<ExitCode, String> {
    let graph = load_combined_graph(path, library)?;
    let program = resolve_program(&graph, program_id)?;
    let instant = resolve_at(at)?;

    if summary {
        let sum = status::summarize(&graph, program, instant);
        match format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&sum).unwrap()),
            OutputFormat::Text => {
                println!("Program: {} ({})", program.name, program.id);
                println!("At: {}", format_timestamp(&sum.at));
                println!(
                    "Controls:     met={} gap={} waived={} out_of_scope={}",
                    sum.controls.get("met").copied().unwrap_or(0),
                    sum.controls.get("gap").copied().unwrap_or(0),
                    sum.controls.get("waived").copied().unwrap_or(0),
                    sum.controls.get("out_of_scope").copied().unwrap_or(0),
                );
                println!(
                    "Requirements: covered={} contribution={} unmapped={} gap={}",
                    sum.requirements.get("covered").copied().unwrap_or(0),
                    sum.requirements.get("contribution").copied().unwrap_or(0),
                    sum.requirements.get("unmapped").copied().unwrap_or(0),
                    sum.requirements.get("gap").copied().unwrap_or(0),
                );
                println!(
                    "Alerts:       failing_tests={} open_risks={} expiring_evidence={} expiring_exceptions={} open_findings={}",
                    sum.failing_tests,
                    sum.open_risks,
                    sum.expiring_evidence,
                    sum.expiring_exceptions,
                    sum.open_findings,
                );
            }
        }
        return Ok(ExitCode::SUCCESS);
    }

    let st = status::evaluate(&graph, program, instant, framework);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&st).unwrap()),
        OutputFormat::Text => {
            println!("Program: {} ({})", program.name, program.id);
            println!("At: {}", format_timestamp(&st.at));
            println!("\nControls ({}):", st.controls.len());
            for c in &st.controls {
                println!("  [{}] {}", c.state, c.control_id);
                for f in &c.failed {
                    println!("      - {f}");
                }
            }
            println!("\nRequirements ({}):", st.requirements.len());
            for r in &st.requirements {
                if r.unmet_control_ids.is_empty() {
                    println!("  [{}] {}", r.state, r.requirement_id);
                } else {
                    println!(
                        "  [{}] {} (unmet: {})",
                        r.state,
                        r.requirement_id,
                        r.unmet_control_ids.join(", ")
                    );
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

// --- diff -------------------------------------------------------------------

fn cmd_diff(
    before_path: &Path,
    after_path: &Path,
    org_path: Option<&Path>,
    at: Option<&str>,
    format: OutputFormat,
) -> Result<ExitCode, String> {
    let opts = ParseOptions::default();
    let before_lib = read_path(before_path, opts, Some(StorageOrigin::Library))
        .map_err(|e| format!("before {}: {e}", before_path.display()))?;
    let after_lib = read_path(after_path, opts, Some(StorageOrigin::Library))
        .map_err(|e| format!("after {}: {e}", after_path.display()))?;
    let instant = resolve_at(at)?;

    let (before_graph, after_graph) = if let Some(org_p) = org_path {
        let org =
            read_path(org_p, opts, None).map_err(|e| format!("org {}: {e}", org_p.display()))?;
        let bg = merge_bundles(&before_lib, &org);
        let ag = bg.with_library(after_lib.objects.into_iter().map(|lo| lo.object).collect());
        (bg, ag)
    } else {
        let bg = before_lib.to_graph();
        let ag = bg.with_library(after_lib.objects.into_iter().map(|lo| lo.object).collect());
        (bg, ag)
    };

    let diff = compare_revisions(&before_graph, &after_graph, instant);
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&diff).unwrap()),
        OutputFormat::Text => {
            println!("Library diff at {}", format_timestamp(&diff.at));
            println!(
                "Objects: +{} added, ~{} modified, -{} removed",
                diff.added_objects, diff.modified_objects, diff.removed_objects
            );
            println!("Stale mapping reviews: {}", diff.stale_reviews.len());
            for id in &diff.stale_reviews {
                println!("  - {id}");
            }
            println!(
                "Newly withdrawn baseline requirements: {}",
                diff.withdrawn.len()
            );
            for w in &diff.withdrawn {
                println!("  - {} in {}", w.requirement_id, w.baseline_id);
            }
            println!("Affected programs: {}", diff.programs.len());
            for p in &diff.programs {
                println!("  Program {}:", p.program_id);
                for c in &p.controls {
                    println!(
                        "    control {}: {} -> {}",
                        c.id,
                        c.before.as_deref().unwrap_or("<none>"),
                        c.after.as_deref().unwrap_or("<none>")
                    );
                }
                for r in &p.requirements {
                    println!(
                        "    requirement {}: {} -> {}",
                        r.id,
                        r.before.as_deref().unwrap_or("<none>"),
                        r.after.as_deref().unwrap_or("<none>")
                    );
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

// --- render -----------------------------------------------------------------

fn cmd_render(view: RenderCommands) -> Result<ExitCode, String> {
    match view {
        RenderCommands::Oscal {
            path,
            library,
            program,
            framework,
            out,
            at,
            xml,
        } => {
            let graph = load_combined_graph(&path, library.as_deref())?;
            let prog = resolve_program(&graph, program.as_deref())?;
            let instant = resolve_at(at.as_deref())?;
            let files = render_oscal_package(&graph, prog, &framework, instant, xml)
                .map_err(|e| e.to_string())?;
            fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
            for f in &files {
                let dest = out.join(&f.name);
                fs::write(&dest, &f.content).map_err(|e| format!("{}: {e}", dest.display()))?;
            }
            println!(
                "rendered {} OSCAL file(s) into {}",
                files.len(),
                out.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        RenderCommands::Ssp {
            path,
            library,
            program,
            out,
            at,
        } => {
            let graph = load_combined_graph(&path, library.as_deref())?;
            let prog = resolve_program(&graph, program.as_deref())?;
            let instant = resolve_at(at.as_deref())?;
            let files = render_ssp(&graph, prog, instant);
            fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
            for f in &files {
                let dest = out.join(&f.name);
                fs::write(&dest, &f.content).map_err(|e| format!("{}: {e}", dest.display()))?;
            }
            println!(
                "rendered {} SSP file(s) into {}",
                files.len(),
                out.display()
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}
