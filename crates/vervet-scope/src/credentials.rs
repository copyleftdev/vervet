//! Operator-supplied credential material for credential-access techniques.

/// A spray credential set: one password tried across many accounts. The
/// password is never written into evidence — techniques redact it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
    pub usernames: Vec<String>,
    pub password: String,
}
