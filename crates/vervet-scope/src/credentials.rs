//! Operator-supplied credential material for credential-access techniques.

/// One username/password pair, for per-account validation (T1078).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

/// Credential material. Carries both shapes a technique might need: a spray set
/// (one password across many usernames) and explicit per-account `pairs`. A
/// technique reads whichever it requires; passwords are never written to
/// evidence — techniques redact them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
    pub usernames: Vec<String>,
    pub password: String,
    pub pairs: Vec<Credential>,
}
