//! The dense, read-first summary of an engagement.

use serde::Serialize;

/// The dense summary an AI consumer reads before pulling any handle. Carries
/// enough identity (name, attack id, tactic) that a receipt is self-describing
/// for reporting, with no registry lookup required.
#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub name: String,
    pub attack_id: String,
    pub tactic: String,
    pub engagement_id: String,
    pub observation_count: usize,
}
