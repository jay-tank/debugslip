//! debugslip: static analysis flagging a `#[derive(Debug)]` struct/enum
//! with a sensitive-named field (`password`, `secret`, `token`,
//! `api_key`, `ssn`, `credit_card`, ...) typed as a plain `String`/`&str`/
//! `Vec<u8>` — not already wrapped in a known-safe redacting type
//! (`SecretString`, `Secret<T>`, `Redacted<T>`, ...).
//!
//! Rust's std `Debug` derive has no built-in field-skipping (unlike
//! serde's `#[serde(skip)]`): every derived field is printed verbatim, so
//! a config/credentials/request struct with a plain derived `Debug` leaks
//! its secret field into logs, crash reports, or error messages the
//! moment anyone debug-prints it via `{:?}`/`{:#?}` — `tracing::debug!`,
//! `log::debug!`, `println!`, a panic message, an `anyhow` `.context()`,
//! or an `Err` variant's own `Debug` impl.
//!
//! See DETAILS.md in the package root for the full rationale and exactly
//! what this tool does and does not check.

pub mod model;
pub mod parse;
pub mod report;
pub mod rules;

use anyhow::{Context, Result};
use model::Finding;
use std::path::{Path, PathBuf};

/// Collects every `.rs` file under `path` (recursively, if it's a
/// directory), or just that one file if `path` is itself a file
/// regardless of extension.
pub fn collect_rs_files(path: &Path) -> Result<Vec<PathBuf>> {
    if !path.exists() {
        anyhow::bail!("path does not exist: {}", path.display());
    }
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(path)
        .into_iter()
        .filter_entry(|e| e.file_name() != "target" && e.file_name() != ".git")
        .filter_map(|e| e.ok())
    {
        let p = entry.path();
        if p.is_file()
            && let Some(ext) = p.extension().and_then(|e| e.to_str())
            && ext.eq_ignore_ascii_case("rs")
        {
            files.push(p.to_path_buf());
        }
    }
    files.sort();
    Ok(files)
}

/// Runs the full pipeline (parse every file, then evaluate each one
/// independently) over one or more input paths. debugslip's analysis is
/// entirely per-item (struct/enum definitions), so, like sibling package
/// `lockwindow`, each file is evaluated on its own with no cross-file
/// information needed.
pub fn scan(paths: &[PathBuf]) -> Result<Vec<Finding>> {
    let mut files = Vec::new();
    for path in paths {
        files.extend(collect_rs_files(path)?);
    }

    let mut findings = Vec::new();
    for file in &files {
        let src = std::fs::read_to_string(file)
            .with_context(|| format!("failed to read {}", file.display()))?;
        let items = parse::parse_source(&src)
            .with_context(|| format!("failed to parse {}", file.display()))?;
        findings.extend(rules::evaluate(&file.display().to_string(), &items));
    }
    findings.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    Ok(findings)
}
