//! The ATT&CK tactic a technique advances.

use serde::Serialize;

/// The adversary goal a technique serves, mirroring ATT&CK tactic columns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tactic {
    Discovery,
    CredentialAccess,
    LateralMovement,
}
