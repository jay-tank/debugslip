use assert_cmd::Command;
use predicates::prelude::*;

fn bin() -> Command {
    Command::cargo_bin("debugslip").unwrap()
}

fn write_fixture(name: &str, contents: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "debugslip-test-{}-{}",
        std::process::id(),
        name.replace(['/', '\\'], "_")
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("fixture.rs");
    std::fs::write(&file, contents).unwrap();
    file
}

// --- Positive cases: must be flagged -----------------------------------

#[test]
fn flags_plain_derive_debug_with_password_string_field() {
    let f = write_fixture(
        "plain-password",
        r#"
#[derive(Debug)]
struct Config {
    password: String,
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .failure()
        .stdout(predicate::str::contains("DS001"))
        .stdout(predicate::str::contains("password"));
}

#[test]
fn flags_multi_derive_list_with_debug_present() {
    // #[derive(Debug, Clone)] — must correctly parse a multi-item derive
    // attribute and still recognize Debug within it.
    let f = write_fixture(
        "multi-derive",
        r#"
#[derive(Debug, Clone)]
struct Config {
    password: String,
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .failure()
        .stdout(predicate::str::contains("DS001"));
}

#[test]
fn flags_debug_present_among_two_separate_derive_attributes() {
    let f = write_fixture(
        "two-derive-attrs",
        r#"
#[derive(Clone)]
#[derive(Debug)]
struct Session {
    token: String,
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .failure()
        .stdout(predicate::str::contains("DS001"))
        .stdout(predicate::str::contains("token"));
}

#[test]
fn flags_token_named_field() {
    let f = write_fixture(
        "token-field",
        r#"
#[derive(Debug)]
struct Session {
    token: String,
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .failure()
        .stdout(predicate::str::contains("DS001"));
}

#[test]
fn flags_api_key_field() {
    let f = write_fixture(
        "api-key-field",
        r#"
#[derive(Debug)]
struct ApiClient {
    api_key: String,
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .failure()
        .stdout(predicate::str::contains("DS001"));
}

#[test]
fn flags_vec_u8_private_key_field() {
    let f = write_fixture(
        "vec-u8-private-key",
        r#"
#[derive(Debug)]
struct SigningMaterial {
    private_key: Vec<u8>,
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .failure()
        .stdout(predicate::str::contains("DS001"))
        .stdout(predicate::str::contains("Vec<u8>"));
}

#[test]
fn flags_str_reference_field() {
    let f = write_fixture(
        "str-ref-field",
        r#"
#[derive(Debug)]
struct LoginAttempt<'a> {
    passwd: &'a str,
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .failure()
        .stdout(predicate::str::contains("DS001"));
}

#[test]
fn flags_password_reset_token_string_field_conservative_tradeoff() {
    // "token" appears as a substring in a compound name that isn't
    // itself a bare token — accepted, documented false-positive
    // tradeoff (see DETAILS.md), still flagged because the type is a
    // plain String.
    let f = write_fixture(
        "password-reset-token",
        r#"
#[derive(Debug)]
struct PasswordReset {
    password_reset_token: String,
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .failure()
        .stdout(predicate::str::contains("DS001"));
}

#[test]
fn flags_enum_with_sensitive_field_in_one_variant_only() {
    let f = write_fixture(
        "enum-one-variant",
        r#"
#[derive(Debug)]
enum AuthEvent {
    LoginFailed { reason: String },
    LoginSucceeded { user_id: u64, access_key: String },
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .failure()
        .stdout(predicate::str::contains("DS001"))
        .stdout(predicate::str::contains("access_key"));
}

#[test]
fn vulnerable_example_reports_nine_findings() {
    let out = bin().arg("examples/vulnerable.rs").output().unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let count = stdout.lines().filter(|l| l.contains("DS001")).count();
    assert_eq!(count, 9, "expected 9 findings, got:\n{stdout}");
}

// --- Negative cases: must NOT be flagged --------------------------------

#[test]
fn does_not_flag_secret_string_wrapper_type() {
    let f = write_fixture(
        "secret-string-wrapper",
        r#"
struct SecretString(String);
#[derive(Debug)]
struct Config {
    password: SecretString,
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .success()
        .stdout(predicate::str::contains("no derived-Debug"));
}

#[test]
fn does_not_flag_generic_secret_wrapper_type() {
    let f = write_fixture(
        "generic-secret-wrapper",
        r#"
struct Secret<T>(T);
#[derive(Debug)]
struct Session {
    token: Secret<String>,
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .success()
        .stdout(predicate::str::contains("no derived-Debug"));
}

#[test]
fn does_not_flag_redacted_wrapper_type() {
    let f = write_fixture(
        "redacted-wrapper",
        r#"
struct Redacted<T>(T);
#[derive(Debug)]
struct Config {
    secret: Redacted<String>,
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .success()
        .stdout(predicate::str::contains("no derived-Debug"));
}

#[test]
fn does_not_flag_manual_debug_impl_with_no_derive() {
    // A hand-written impl Debug for Config, no #[derive(Debug)] at all —
    // the presence of derive is the trigger; a hand-rolled impl is
    // exactly the accepted mitigation.
    let f = write_fixture(
        "manual-debug-impl",
        r#"
struct Config {
    password: String,
}
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config").field("password", &"[REDACTED]").finish()
    }
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .success()
        .stdout(predicate::str::contains("no derived-Debug"));
}

#[test]
fn does_not_flag_struct_with_no_sensitive_field() {
    let f = write_fixture(
        "no-sensitive-field",
        r#"
#[derive(Debug)]
struct Metrics {
    requests_total: u64,
    errors_total: u64,
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .success()
        .stdout(predicate::str::contains("no derived-Debug"));
}

#[test]
fn does_not_flag_password_hash_algorithm_metadata_field() {
    let f = write_fixture(
        "password-hash-algorithm",
        r#"
#[derive(Debug)]
struct StoredCredential {
    password_hash_algorithm: String,
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .success()
        .stdout(predicate::str::contains("no derived-Debug"));
}

#[test]
fn does_not_flag_password_hash_field() {
    let f = write_fixture(
        "password-hash",
        r#"
#[derive(Debug)]
struct StoredCredential {
    password_hash: Vec<u8>,
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .success()
        .stdout(predicate::str::contains("no derived-Debug"));
}

#[test]
fn does_not_flag_sensitive_name_on_non_string_type() {
    // "token" appears in the name, but the type is not a plain
    // String/&str/Vec<u8> — the type gate is authoritative (see
    // DETAILS.md's discussion of this exact case).
    let f = write_fixture(
        "non-string-type",
        r#"
struct DateTime;
#[derive(Debug)]
struct PasswordReset {
    password_reset_token_expiry: DateTime,
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .success()
        .stdout(predicate::str::contains("no derived-Debug"));
}

#[test]
fn does_not_flag_nested_substruct_without_its_own_derive() {
    // Outer derives Debug and includes Inner as a field; Inner has a
    // sensitive field but no #[derive(Debug)] of its own. Out of scope
    // for v0.1 (see DETAILS.md) — only the sensitive field directly on
    // the deriving struct is flagged.
    let f = write_fixture(
        "nested-substruct",
        r#"
struct Inner {
    api_key: String,
}
#[derive(Debug)]
struct Outer {
    name: String,
    inner: Inner,
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .success()
        .stdout(predicate::str::contains("no derived-Debug"));
}

#[test]
fn does_not_flag_tuple_variant_with_no_field_name() {
    let f = write_fixture(
        "tuple-variant",
        r#"
#[derive(Debug)]
enum Credential {
    Password(String),
}
"#,
    );
    bin()
        .arg(&f)
        .assert()
        .success()
        .stdout(predicate::str::contains("no derived-Debug"));
}

#[test]
fn clean_example_reports_zero_findings() {
    bin()
        .arg("examples/clean.rs")
        .assert()
        .success()
        .stdout(predicate::str::contains("no derived-Debug"));
}

// --- CLI plumbing --------------------------------------------------------

#[test]
fn json_output_is_valid_and_matches_text_finding_count() {
    let text_out = bin().arg("examples/vulnerable.rs").output().unwrap();
    let text_findings = String::from_utf8(text_out.stdout)
        .unwrap()
        .lines()
        .filter(|l| l.contains("DS001"))
        .count();

    let json_out = bin()
        .arg("examples/vulnerable.rs")
        .arg("--json")
        .output()
        .unwrap();
    let stdout = String::from_utf8(json_out.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");
    assert!(parsed.is_array());
    assert_eq!(parsed.as_array().unwrap().len(), text_findings);
    assert!(text_findings > 0);
}

#[test]
fn fail_on_never_always_exits_zero() {
    bin()
        .arg("examples/vulnerable.rs")
        .arg("--fail-on")
        .arg("never")
        .assert()
        .success();
}

#[test]
fn fail_on_high_still_catches_ds001() {
    let f = write_fixture(
        "fail-on-high",
        r#"
#[derive(Debug)]
struct Config {
    password: String,
}
"#,
    );
    bin()
        .arg(&f)
        .arg("--fail-on")
        .arg("high")
        .assert()
        .failure()
        .stdout(predicate::str::contains("DS001"));
}

#[test]
fn scans_a_directory_recursively() {
    bin()
        .arg("examples")
        .assert()
        .failure()
        .stdout(predicate::str::contains("DS001"));
}

#[test]
fn missing_path_errors_cleanly() {
    bin().arg("examples/does-not-exist.rs").assert().failure();
}
