//! Rule evaluation.
//!
//! Rule ID:
//! - DS001 (High) — a `struct` or `enum` whose `#[derive(...)]` attribute
//!   list includes `Debug`, with a field (directly on the deriving struct,
//!   or on a struct-shaped enum variant) whose name matches a sensitive-
//!   shaped heuristic (`password`, `secret`, `token`, `api_key`, `ssn`,
//!   `credit_card`, ...) and whose type is a plain `String`/`&str`/
//!   `Vec<u8>` — not already wrapped in a known-safe redacting type by
//!   name (`SecretString`, `Secret<T>`, `Redacted<T>`, ...). See
//!   DETAILS.md for the full rationale, the exact name-matching
//!   heuristic, and every documented false-positive/false-negative
//!   tradeoff.

use crate::model::{Finding, Severity};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{Attribute, Field, Fields, GenericArgument, Item, Meta, Path, PathArguments, Token, Type};

pub fn evaluate(file: &str, items: &[Item]) -> Vec<Finding> {
    let mut findings = Vec::new();
    collect_items(items, file, &mut findings);
    findings.sort_by_key(|f| f.line);
    findings
}

/// Walks every top-level `struct`/`enum` (recursing into inline `mod { }`
/// blocks). Unlike sibling package `lockwindow`, this pass never looks at
/// function bodies at all — the whole check is item- and field-shape
/// level, so `impl` blocks are irrelevant here.
fn collect_items(items: &[Item], file: &str, findings: &mut Vec<Finding>) {
    for item in items {
        match item {
            Item::Struct(s) => {
                if has_derive_debug(&s.attrs) {
                    check_fields(&s.fields, &s.ident.to_string(), file, findings);
                }
            }
            Item::Enum(e) => {
                if has_derive_debug(&e.attrs) {
                    // A sensitive field inside just ONE variant is still
                    // in scope — deriving Debug on the enum generates one
                    // Debug impl covering every variant, so the leak risk
                    // is identical to a struct field. See DETAILS.md.
                    for variant in &e.variants {
                        let container = format!("{}::{}", e.ident, variant.ident);
                        check_fields(&variant.fields, &container, file, findings);
                    }
                }
            }
            Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    collect_items(inner, file, findings);
                }
            }
            _ => {}
        }
    }
}

/// True if `attrs` contains a `#[derive(...)]` attribute whose
/// comma-separated path list includes `Debug` — correctly handling both a
/// single combined list (`#[derive(Debug, Clone)]`) and multiple separate
/// `#[derive(...)]` attributes on the same item.
fn has_derive_debug(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("derive") {
            return false;
        }
        let Meta::List(list) = &attr.meta else {
            return false;
        };
        list.parse_args_with(Punctuated::<Path, Token![,]>::parse_terminated)
            .map(|paths| paths.iter().any(|p| p.is_ident("Debug")))
            .unwrap_or(false)
    })
}

fn check_fields(fields: &Fields, container: &str, file: &str, findings: &mut Vec<Finding>) {
    let Fields::Named(named) = fields else {
        // Tuple (`Foo(String)`) and unit (`Foo`) variants/structs have no
        // field *name* to run the sensitive-name heuristic against — out
        // of scope by construction, not an oversight. See DETAILS.md.
        return;
    };
    for f in &named.named {
        let Some(ident) = &f.ident else { continue };
        let name = ident.to_string();
        if !is_sensitive_field_name(&name) {
            continue;
        }
        let Some(type_label) = sensitive_type_label(&f.ty) else {
            continue;
        };
        findings.push(Finding {
            rule: "DS001",
            severity: Severity::High,
            file: file.to_string(),
            line: field_line(f),
            field: name.clone(),
            message: format!(
                "`{container}` derives Debug and has field `{name}: {type_label}` with no redacting wrapper — #[derive(Debug)] prints every field verbatim, so any debug!()/println!(\"{{:?}}\", ...)/tracing::debug!(?value)/anyhow .context(...) of this value leaks `{name}`'s raw contents into logs, crash reports, or error messages; wrap it in a redacting type (e.g. `secrecy::SecretString`) or write a manual `impl Debug for {container}` that redacts this field instead of deriving it"
            ),
        });
    }
}

fn field_line(f: &Field) -> usize {
    f.span().start().line
}

/// Metadata-suffix exclusions: a field describing something *about* a
/// secret (which hashing algorithm was used, say) rather than holding the
/// secret's own value. Deliberately narrow — see DETAILS.md's discussion
/// of `password_hash_algorithm` (excluded here) vs.
/// `password_reset_token_expiry` (still flagged, an accepted tradeoff).
const METADATA_SUFFIXES: &[&str] = &["_hash_algorithm", "_hash", "_algorithm"];

/// Sensitive-shaped term list (case-insensitive substring match against
/// the field's name).
const SENSITIVE_TERMS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "ssn",
    "credit_card",
    "card_number",
];

fn is_sensitive_field_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    if METADATA_SUFFIXES.iter().any(|suffix| lower.ends_with(suffix)) {
        return false;
    }
    SENSITIVE_TERMS.iter().any(|term| lower.contains(term))
}

/// If `ty` is a plain `String`, `&str`, or `Vec<u8>` — the only shapes
/// this tool considers capable of holding a raw secret value the same
/// syntactic way a `#[derive(Debug)]` would print it verbatim — returns a
/// short label for the finding message. Any other type (a numeric ID, an
/// `Option<String>`, a `DateTime`, or a type whose name text contains
/// `Secret`/`Redacted`) returns `None`: the type gate is authoritative,
/// not merely a tiebreaker on top of the name heuristic — see DETAILS.md.
fn sensitive_type_label(ty: &Type) -> Option<&'static str> {
    // Known-safe redacting wrapper types, matched by name text alone (no
    // full type resolution) — `SecretString`, `Secret<T>`, `Redacted<T>`,
    // and anything else whose rendered type text contains either word.
    let text = quote::quote!(#ty).to_string();
    if text.contains("Secret") || text.contains("Redacted") {
        return None;
    }

    match ty {
        Type::Path(tp) => {
            let seg = tp.path.segments.last()?;
            if seg.ident == "String" && matches!(seg.arguments, PathArguments::None) {
                return Some("String");
            }
            if seg.ident == "Vec"
                && let PathArguments::AngleBracketed(ab) = &seg.arguments
                && ab.args.len() == 1
                && let Some(GenericArgument::Type(Type::Path(inner))) = ab.args.first()
                && inner.path.is_ident("u8")
            {
                return Some("Vec<u8>");
            }
            None
        }
        Type::Reference(r) => match &*r.elem {
            Type::Path(inner) if inner.path.is_ident("str") => Some("&str"),
            _ => None,
        },
        _ => None,
    }
}
