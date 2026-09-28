//! Parses Rust source with `syn` (never compiles/executes it). All of the
//! interesting per-item traversal lives in `rules.rs`; this module is just
//! the `syn::parse_str` entry point plus the top-level item list, kept as
//! its own module for the same reason sibling packages split parsing from
//! rule evaluation.

use anyhow::{Context, Result};
use syn::Item;

pub fn parse_source(src: &str) -> Result<Vec<Item>> {
    let file: syn::File = syn::parse_str(src).context("failed to parse Rust source")?;
    Ok(file.items)
}
