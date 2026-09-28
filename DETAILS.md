# Design details

## The gap

`Mutex<T>`/`RwLock<T>` aren't the only place Rust's compile-time
guarantees quietly stop covering a whole class of correctness. `#[derive
(Debug)]` is another: it is completely safe from the compiler's point of
view — it always compiles, it always produces valid output — and it is
also the single easiest way to leak a secret into a log line without
anyone noticing.

```rust
#[derive(Debug)]
struct DbConfig {
    host: String,
    port: u16,
    password: String,
}
```

This looks completely ordinary. It's also extremely common — a config
struct, a credentials struct, an incoming request struct, gets `Debug`
derived on it as a matter of course, usually before anyone's thought
about what fields it will eventually hold. And Rust code debug-prints
structs *constantly*, for entirely legitimate reasons: `tracing::debug!
(?cfg)` while chasing a startup bug, `println!("{cfg:?}")` during local
development, an `anyhow` `.context(format!("failed with config {cfg:?}"))`
on an error path, a panic message that interpolates `{:?}` on the value
it was holding, or an `Err` variant whose own derived `Debug` impl
recursively prints every field of everything it wraps. None of these
call sites are doing anything wrong on their own — `{:?}` is exactly
what `Debug` is *for*. The bug is entirely upstream, in the derive: it
has no concept of "this field shouldn't be printed." Every single field
declared on the struct is rendered, verbatim, every time.

Unlike `serde`, which ships `#[serde(skip)]` and `#[serde(skip_serializing)]`
specifically because "not every field belongs in the wire format" is an
expected, common need, `Debug`'s derive has never grown an equivalent
skip attribute. The only real mitigations are:

- A **hand-written `impl Debug for T`** that explicitly redacts or omits
  the field (writing `"[REDACTED]"` in its place).
- A **field-level newtype wrapper** whose own `Debug` impl redacts itself
  (a small hand-rolled `struct SecretString(String)` with its own
  redacting `impl Debug`, or the `secrecy`/`redact` crates' ready-made
  wrapper types).

Neither of these happens automatically. Both require someone to have
already noticed the field was sensitive — which, in practice, often
happens well after the struct was first written, once it's grown a
`password`/`token`/`api_key` field nobody went back to re-audit the
existing `#[derive(Debug)]` against.

## What debugslip actually checks

debugslip is a `syn`/`proc-macro2`-based static analyzer. It never
compiles or runs the scanned code, and does no type inference — it
inspects each `struct`/`enum` item's attribute list and field
declarations directly:

1. **Derive check.** The item's `#[derive(...)]` attribute list (which
   may be one combined list, `#[derive(Debug, Clone)]`, or several
   separate `#[derive(...)]` attributes on the same item) must contain
   `Debug`, matched as an exact path segment via `syn`'s own parsed
   `Punctuated<Path, Comma>` derive-argument list — not a raw substring
   search on the attribute's token text, so a hypothetical
   `#[derive(MyDebugMacro)]` does not false-positive.
2. **Field name.** For a struct, every named field; for an enum, every
   named field of every struct-shaped variant (`Foo::Bar { field: ... }`)
   — independently, so a sensitive field in just one variant is enough
   to flag that variant. Tuple (`Foo(String)`) and unit (`Foo`)
   variants/structs have no field *name*, so they fall outside this
   heuristic by construction: there is nothing to match a sensitive term
   against.
3. **Name heuristic.** The field's identifier, lowercased, is checked
   for a case-insensitive substring match against a fixed term list:
   `password`, `passwd`, `secret`, `token`, `api_key`, `apikey`,
   `access_key`, `private_key`, `ssn`, `credit_card`, `card_number`.
4. **Metadata-suffix exclusion.** Before the term check runs, a small
   fixed suffix denylist (`_hash`, `_hash_algorithm`, `_algorithm`) is
   checked first: a field name *ending* in one of these is excluded
   outright, regardless of which term it might otherwise match. This
   exists specifically for fields that describe something *about* a
   secret rather than holding the secret's own value —
   `password_hash_algorithm` (the name of a KDF, e.g. `"argon2id"`, not a
   password) is the canonical example.
5. **Type gate.** The field's type must be exactly a plain `String`,
   `&str` (any lifetime), or `Vec<u8>` — matched structurally via `syn`'s
   parsed `Type`, not string comparison. Any other type (`u64`, `bool`,
   `Option<String>`, a custom `DateTime`, ...) is out of scope, *even if*
   the field's name matches the sensitive-term list. This is a hard
   requirement, not a secondary tiebreaker layered on top of the name
   heuristic — see "Why the type gate is authoritative" below.
6. **Wrapper-type exclusion.** Before the type-shape check runs, the
   field's rendered type text (`quote!(#ty).to_string()`) is checked for
   the substrings `Secret` or `Redacted` — covering `SecretString`,
   `Secret<T>`, `Redacted<T>`, and any similarly-named wrapper, without
   needing full type resolution (which `syn`, operating on a single file
   with no crate graph, cannot do anyway). A field of exactly this shape
   is treated as already mitigated and is not flagged.

If a field passes all of the above, debugslip reports it: rule `DS001`,
always High severity (a genuine derived-Debug leak of a secret field is
always a real, load-bearing correctness/security concern when it fires,
never a stylistic nit).

## Exact name-heuristic tradeoffs (documented honestly)

- **`password_hash_algorithm` — excluded.** Ends in `_hash_algorithm`,
  caught by the metadata-suffix denylist. This field holds the *name* of
  a hashing algorithm (`"argon2id"`, `"bcrypt"`), never the password
  itself — flagging it would be a pure false positive with no
  corresponding real leak.
- **`password_hash` — excluded.** Same suffix rule (`_hash`). A password
  hash is, by definition, not printable-in-plaintext-and-therefore-
  sensitive-the-same-way; debugslip treats it as out of scope even though
  it is `Vec<u8>`-typed and would otherwise match. This is a deliberate,
  narrow exclusion, not a claim that a password hash is safe to log in
  general (rainbow-table/offline-cracking risk is a separate, real
  concern this tool does not attempt to model).
- **`password_reset_token_expiry` (typed `String`) — still flagged.**
  Contains `token` as a substring and does not end in any of the
  metadata-suffix denylist entries, so the name heuristic matches. This
  is an accepted, documented false-positive tradeoff: distinguishing
  every possible "sensitive-shaped word used as part of a compound,
  non-secret field name" would require a much larger, more fragile
  exclusion list (or real semantic understanding this tool doesn't have)
  for comparatively little gain — a missed real `token: String` field is
  a worse outcome than an occasional over-flagged expiry timestamp.
- **`password_reset_token_expiry` (typed `DateTime`) — *not* flagged.**
  Same name, different (non-`String`/`&str`/`Vec<u8>`) type. Here the
  type gate, not the name heuristic, is what excludes it — see below.

## Why the type gate is authoritative

It would be tempting to treat the type gate as a mere secondary
tiebreaker layered on top of an already-sensitive name — "if the name
matches, flag it regardless of type, unless the type is obviously safe."
debugslip deliberately does *not* work this way: the type must be
exactly `String`/`&str`/`Vec<u8>` (or a known wrapper), full stop,
independent of how sensitive-shaped the name is. Two reasons:

- The overwhelming majority of non-string types that could carry a
  sensitive-shaped name (`u64`, `bool`, a numeric ID, a timestamp, an
  enum) genuinely cannot hold a raw secret *value* the same
  print-it-verbatim way a `String`/`Vec<u8>` can — `#[derive(Debug)]`
  printing a `DateTime` value is not remotely the same class of leak as
  printing a raw password string, even if the field happens to be named
  `password_reset_token_expiry`.
- Expanding the type check to "any type, if the name looks sensitive
  enough" would multiply false positives across every timestamp/ID/enum
  field with a passing resemblance to a sensitive term, without
  reliably catching any additional *real* secret leak in return — the
  actual secret-carrying case is essentially always a `String`/`&str`/
  `Vec<u8>` in real Rust code.

The accepted cost of this choice: a hypothetical custom type literally
named `Token` that itself wraps a raw secret string (`struct Token(String)`
with no name containing "Secret"/"Redacted") would be missed, the same
way a custom wrapper is missed by the wrapper-exclusion allowlist working
in the opposite direction. Both are the same underlying limitation —
debugslip works from type-name text and field-name text, never real type
resolution — and both are accepted for the same reason: a much larger,
fuzzier heuristic would trade a modest reduction in false negatives for
a much larger increase in false positives across this entire portfolio's
"small, sharp tool" design goal.

## Deliberate non-goals

- **No nested/transitive struct tracing.** If struct `Outer` derives
  `Debug` and has a field `inner: Inner`, where `Inner` itself has a
  sensitive field but does *not* derive `Debug` on its own, debugslip
  does **not** flag `Outer`. This is a real, documented limitation: when
  `Outer`'s derived `Debug` impl runs, it *does* invoke `Inner`'s own
  `Debug` impl to render that field — so if `Inner` also derives `Debug`
  (which it would have to, for `Outer`'s own derive to even compile),
  the exact same verbatim-printing leak happens, just one level down.
  debugslip only ever inspects the field list of the struct/enum whose
  *own* `#[derive(Debug)]` it found — it does not resolve a field's type
  to that type's own definition elsewhere in the file (or in another
  file/crate entirely, which `syn`'s single-file, no-type-inference
  model cannot do anyway) and recurse into its fields. Out of scope for
  v0.1; a real limitation worth fixing in a later version with proper
  same-crate cross-item resolution, not a currently-solved problem.
- **No `#[serde(skip)]`/`#[serde(skip_serializing)]` awareness.** A field
  correctly excluded from *serialization* via serde attributes is not
  thereby excluded from `Debug` — the two derives are unrelated, and
  debugslip does not treat a `#[serde(skip)]`-annotated field as
  mitigated, because it genuinely isn't: `Debug` still prints it.
- **No cross-field/method awareness of a custom redaction helper.** A
  struct that separately exposes a `fn redacted_debug_string(&self) ->
  String` helper method, but still derives `Debug` normally on the raw
  fields, is still flagged — the existence of an *opt-in* alternative
  formatting method does nothing to stop the derived, always-available
  `Debug` impl from also existing and leaking the field to anyone who
  calls `{:?}` on the value directly instead of the helper.
- **No real type checking of the wrapper-exclusion allowlist.** A type
  merely *named* `SecretFoo` or `RedactedBar` that does *not* actually
  implement a redacting `Debug` (e.g. someone derived `Debug` on their
  own `struct SecretString(String);` without writing a manual redacting
  impl) is treated as safe anyway, purely by name-text match — the same
  syntactic-first-pass tradeoff sibling packages make throughout this
  portfolio.

## Prior art check

`clippy` has no lint targeting this. Its closest-sounding lint,
`clippy::missing_debug_implementations`, checks the *opposite* thing
entirely — it warns when a public type does **not** implement `Debug`,
to help crate authors avoid an unhelpfully opaque public API. There is no
existing clippy lint (or, to the best of this project's research, any
other widely-used Rust static-analysis tool) that flags the case
debugslip targets: a type that *does* derive `Debug`, and holds a field
whose name and type together look like a secret with no redaction. This
is the same kind of narrow, currently-unfilled gap the rest of this
portfolio targets: a real, everyday mistake with no existing static tool
flagging it specifically.

## Data model

`parse.rs` is a thin `syn::parse_str` wrapper returning the file's
top-level `Item`s. `rules.rs` does all of the real work: `collect_items`
recurses into every top-level `struct`/`enum`/inline `mod { }` block (no
function-body traversal at all, unlike sibling package `lockwindow` — the
whole check is item- and field-shape level), `has_derive_debug` parses
each `#[derive(...)]` attribute's argument list as a real
`Punctuated<Path, Comma>` rather than doing a raw substring search, and
`check_fields` runs the name heuristic (`is_sensitive_field_name`,
including the metadata-suffix denylist) and the type gate
(`sensitive_type_label`) against every named field. Every finding is High
severity — a genuine derived-Debug secret leak is always a real
correctness/security concern when it fires.
