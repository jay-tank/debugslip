# debugslip usage

## Synopsis

```
debugslip <path>... [--json] [--fail-on <medium|high|never>]
```

## Arguments

- `<path>...` (required, one or more) — a `.rs` file or a directory. A
  directory is walked recursively; every `.rs` file found is parsed
  (`target/` and `.git/` are skipped). A file argument is read
  regardless of its extension. Like sibling package `lockwindow`,
  debugslip's analysis never needs cross-file information — each file is
  evaluated entirely on its own, since the pattern it targets is scoped
  to a single struct/enum item's own field declarations.

## Flags

- `--json` — emit findings as a JSON array instead of the default
  human-readable text. Each element has `rule`, `severity`, `file`,
  `line`, `field`, and `message`.
- `--fail-on <medium|high|never>` (default: `medium`) — controls the
  process exit code:
  - `medium` — exit non-zero if any finding exists (default). Every
    debugslip finding is currently High severity, so `medium` and `high`
    behave identically today; the flag is kept for parity with sibling
    tools and to leave room for a future lower-severity variant.
  - `high` — exit non-zero only if a High-severity finding exists
    (currently: any finding at all).
  - `never` — always exit 0 regardless of findings (useful for a
    report-only CI step that shouldn't block the pipeline).
- `-h`, `--help` / `-V`, `--version` — standard clap-generated help/version.

## Exit codes

- `0` — scan completed; no finding met the `--fail-on` threshold.
- `1` — scan completed; at least one finding met the `--fail-on`
  threshold, or a path didn't exist/wasn't readable, or a file failed to
  parse as Rust source.

## Rule reference

| Rule  | Severity | Trigger |
| :---- | :------- | :------ |
| DS001 | High | A `struct` or `enum` whose `#[derive(...)]` attribute list includes `Debug`, with a named field (directly on the deriving struct, or on a struct-shaped enum variant) whose name case-insensitively matches a sensitive-shaped term (`password`, `passwd`, `secret`, `token`, `api_key`, `apikey`, `access_key`, `private_key`, `ssn`, `credit_card`, `card_number`) and whose type is exactly a plain `String`, `&str`, or `Vec<u8>` — not a known-safe redacting wrapper (`SecretString`, `Secret<T>`, `Redacted<T>`, matched by type-name text). |

## Examples

Scan a single file:

```sh
debugslip src/lib.rs
```

Scan an entire crate, machine-readable:

```sh
debugslip src/ --json
```

Report findings without failing the CI job (informational dashboard step):

```sh
debugslip src/ --fail-on never
```

## What counts as an acquisition (derive + field + type)

1. **Derive.** `#[derive(Debug)]`, `#[derive(Debug, Clone)]` (any
   combined list containing `Debug`), or several separate
   `#[derive(...)]` attributes on the same item where at least one lists
   `Debug` — matched as a real parsed path, not a raw text search.
2. **Field.** A *named* field (struct field, or a field inside a
   struct-shaped `enum` variant like `Foo::Bar { field: ... }`). Tuple
   (`Foo(String)`) and unit (`Foo`) variants/structs have no field name
   to match against and are out of scope by construction.
3. **Name.** The field identifier, lowercased, contains one of the
   sensitive terms above as a substring — *unless* it ends with `_hash`,
   `_hash_algorithm`, or `_algorithm`, which is excluded outright (a
   field describing something *about* a secret, e.g. which hashing
   algorithm was used, rather than holding the secret's own value).
4. **Type.** Exactly `String`, `&str` (any lifetime), or `Vec<u8>`,
   matched structurally, not a looser "looks stringy" match — a
   sensitive-shaped name on any other type (`u64`, `Option<String>`, a
   custom `DateTime`, ...) is **not** flagged; the type check is a hard
   gate, not a secondary tiebreaker on top of the name heuristic.
5. **Wrapper exclusion.** Runs before the type-shape check: if the
   field's rendered type text contains `Secret` or `Redacted`
   (`SecretString`, `Secret<T>`, `Redacted<T>`, ...), it is treated as
   already mitigated and excluded.

See [../DETAILS.md](../DETAILS.md) for the full rationale and every
documented false-positive/false-negative tradeoff, including the
worked-through `password_hash_algorithm` vs. `password_reset_token_expiry`
comparison.

## Scope

debugslip is a static, `syn`-based, per-item analyzer. It never compiles
or runs the scanned code, never resolves a field's type to that type's
own definition elsewhere (so a sensitive field nested inside a
non-deriving sub-struct field is invisible to it — see DETAILS.md's
nested-struct limitation), and treats a wrapper type as safe purely by
matching its name text, with no real type-level verification that the
wrapper's own `Debug` impl actually redacts anything.
