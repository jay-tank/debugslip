// Example crate slice with no derived-Debug secret leaks — debugslip
// should report zero findings against this file.

// Correct fix #1: a manual Debug impl that redacts the field, so there is
// no #[derive(Debug)] at all for debugslip to key off of.
struct DbConfig {
    host: String,
    port: u16,
    password: String,
}

impl std::fmt::Debug for DbConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

// Correct fix #2: a redacting wrapper type whose OWN Debug impl redacts
// itself — safe to derive Debug on the struct that holds it.
struct SecretString(String);

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

#[derive(Debug)]
struct ApiClient {
    base_url: String,
    api_key: SecretString,
}

// A `secrecy`/`redact`-style wrapper referenced generically — matched by
// type-name text alone (no full type resolution needed).
struct Secret<T>(T);

#[derive(Debug)]
struct Session {
    user_id: u64,
    token: Secret<String>,
}

// No sensitive-named field at all.
#[derive(Debug)]
struct Metrics {
    requests_total: u64,
    errors_total: u64,
}

// Field name contains a sensitive term but is metadata *about* a secret,
// not the secret's own value — excluded by the metadata-suffix rule (see
// DETAILS.md): `password_hash_algorithm` ends with `_hash_algorithm`.
#[derive(Debug)]
struct StoredCredential {
    username: String,
    password_hash: Vec<u8>,
    password_hash_algorithm: String,
}

// Sensitive-shaped name, but the type isn't a plain String/&str/Vec<u8> —
// the type gate is authoritative, so a timestamp field is out of scope
// even though "token" appears in its name (see DETAILS.md).
struct DateTime;

#[derive(Debug)]
struct PasswordReset {
    email: String,
    password_reset_token_expiry: DateTime,
}

// Nested struct: the outer struct derives Debug and includes a sub-struct
// as a field; the sub-struct itself has a sensitive field but does NOT
// derive Debug on its own. Out of scope for v0.1 — debugslip only flags
// when the sensitive field is directly on the deriving struct, not
// transitively through a nested type's own fields (see DETAILS.md).
struct Inner {
    api_key: String,
}

#[derive(Debug)]
struct Outer {
    name: String,
    inner: Inner,
}
