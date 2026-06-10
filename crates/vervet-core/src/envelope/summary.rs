//! The dense, read-first summary of an engagement.

use serde::Serialize;

/// The dense summary an AI consumer reads before pulling any handle.
#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub technique: String,
    pub attack_id: String,
    pub engagement_id: String,
    pub observation_count: usize,
}
