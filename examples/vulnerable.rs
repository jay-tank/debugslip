// Example crate slice demonstrating debugslip's core positive case: a
// #[derive(Debug)] struct/enum with a sensitive-named field typed as a
// plain String/&str/Vec<u8> — every field is printed verbatim the moment
// anyone debug-prints the value.

use std::collections::HashMap;

// Classic case: a config struct someone will inevitably `println!("{:?}",
// cfg)` or `tracing::debug!(?cfg)` while chasing down a startup bug.
#[derive(Debug)]
struct DbConfig {
    host: String,
    port: u16,
    password: String,
}

// Multiple derives on the same attribute — Debug is present among others,
// which must still be recognized.
#[derive(Debug, Clone)]
struct ApiClient {
    base_url: String,
    api_key: String,
}

// Different derive-attribute spelling: two separate #[derive(...)]
// attributes rather than one combined list — Debug still present.
#[derive(Clone)]
#[derive(Debug)]
struct Session {
    user_id: u64,
    token: String,
}

// Raw bytes, not just String — the same leak shape applies to Vec<u8>.
#[derive(Debug)]
struct SigningMaterial {
    key_id: String,
    private_key: Vec<u8>,
}

// &str field, not an owned String.
#[derive(Debug)]
struct LoginAttempt<'a> {
    username: &'a str,
    passwd: &'a str,
}

// PII-shaped terms beyond credential-shaped ones.
#[derive(Debug)]
struct Applicant {
    name: String,
    ssn: String,
    credit_card: String,
}

// enum with a sensitive field inside just ONE variant — deriving Debug on
// the enum still generates a single Debug impl covering every variant, so
// this is in scope exactly like a struct field.
#[derive(Debug)]
enum AuthEvent {
    LoginFailed { reason: String },
    LoginSucceeded { user_id: u64, access_key: String },
}

// A struct whose field name contains "token" as a plain substring but
// which is not itself a secret value — the accepted, documented
// false-positive tradeoff (see DETAILS.md): the type is still a plain
// String, so the name heuristic alone is enough to flag it.
#[derive(Debug)]
struct PasswordReset {
    email: String,
    password_reset_token: String,
}

fn log_everything(cfg: &DbConfig, client: &ApiClient, extra: &HashMap<String, String>) {
    println!("{cfg:?} {client:?} {extra:?}");
}
