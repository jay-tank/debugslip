# debugslip

Flags a `#[derive(Debug)]` struct/enum with a sensitive-named field
(`password`, `secret`, `token`, `api_key`, `ssn`, `credit_card`, ...)
typed as a plain `String`/`&str`/`Vec<u8>` — not already wrapped in a
known-safe redacting type (`SecretString`, `Secret<T>`, `Redacted<T>`,
...).

```rust
// flagged — every field is printed verbatim by the derived Debug impl
#[derive(Debug)]
struct DbConfig {
    host: String,
    port: u16,
    password: String,
}
```

```rust
// not flagged — a manual Debug impl that explicitly redacts the field
impl std::fmt::Debug for DbConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("password", &"[REDACTED]")
            .finish()
    }
}
```

Rust's std `Debug` derive has no built-in field-skipping (unlike serde's
`#[serde(skip)]` for serialization): every declared field is rendered
verbatim, every time. And Rust code debug-prints structs constantly, for
entirely ordinary reasons — `tracing::debug!(?cfg)`, `println!("{cfg:?}")`
during local dev, an `anyhow` `.context(format!("{cfg:?}"))`, a panic
message, or an `Err` variant's own recursive `Debug` impl. None of those
call sites are wrong; the derive is what has no concept of "don't print
this one." A config/credentials/request struct that picks up a
`password`/`token`/`api_key` field well after `#[derive(Debug)]` was
already on it — the common order of events — leaks that field into logs,
crash reports, or error messages the first time anyone debug-prints it.
See [DETAILS.md](DETAILS.md) for the full rationale, the exact
name-matching heuristic and its documented tradeoffs, and this tool's
scope limits.

## Install

Not yet published to crates.io. Once published:

```sh
cargo install debugslip
```

Until then, build from source:

```sh
git clone https://github.com/jay-tank/debugslip
cd debugslip
cargo install --path .
```

## Usage

```sh
debugslip <path>... [--json] [--fail-on <medium|high|never>]
```

`<path>` may be a single `.rs` file or a directory (scanned recursively
for `.rs` files). Multiple paths may be given. Analysis is entirely
per-item (struct/enum field declarations), so each file is evaluated
independently — no cross-file information is needed.

```sh
$ debugslip examples/vulnerable.rs
[HIGH] DS001 examples/vulnerable.rs:14 (password): `DbConfig` derives Debug and has field `password: String` with no redacting wrapper — #[derive(Debug)] prints every field verbatim, so any debug!()/println!("{:?}", ...)/tracing::debug!(?value)/anyhow .context(...) of this value leaks `password`'s raw contents into logs, crash reports, or error messages; wrap it in a redacting type (e.g. `secrecy::SecretString`) or write a manual `impl Debug for DbConfig` that redacts this field instead of deriving it
...
debugslip: 9 finding(s)
$ echo $?
1
```

```sh
$ debugslip examples/clean.rs
debugslip: no derived-Debug secret leaks found
$ echo $?
0
```

Full CLI reference (flags, exit codes, the exact name/type heuristics):
[docs/USAGE.md](docs/USAGE.md).

## What it checks

- **DS001** — a `struct` or `enum` whose `#[derive(...)]` list includes
  `Debug`, with a named field (directly on the deriving struct, or on a
  struct-shaped enum variant) whose name matches a sensitive-shaped
  heuristic and whose type is a plain `String`/`&str`/`Vec<u8>`.

Not flagged: the same field with no `#[derive(Debug)]` at all (a manual
`impl Debug` is the accepted mitigation); a field already typed as
`SecretString`/`Secret<T>`/`Redacted<T>`; a field name ending in
`_hash`/`_hash_algorithm`/`_algorithm` (metadata about a secret, not the
secret itself); a sensitive-shaped name on a non-`String`/`&str`/`Vec<u8>`
type (the type gate is authoritative — see DETAILS.md); a sensitive field
buried inside a nested sub-struct field's own definition (out of scope
for v0.1 — see DETAILS.md).

## Not yet pushed

This package is built and tested locally but **not yet pushed to
GitHub** and **not yet published to crates.io**. The `cargo install
debugslip` command above will not work until that happens.

## License

MIT — see [LICENSE](LICENSE).
