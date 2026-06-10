//! The typed result of one technique engagement.

use serde::Serialize;

use crate::attack::{Tactic, TechniqueId};

/// A single fact observed while emulating a technique against one target.
#[derive(Clone, Debug, Serialize)]
pub struct Observation {
    /// The in-scope target the observation concerns.
    pub target: String,
    /// Short machine token, e.g. `port_open`.
    pub kind: String,
    /// Human/LLM-readable detail, e.g. `tcp/445`.
    pub detail: String,
}

/// The typed evidence produced by one technique engagement.
#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    pub technique: TechniqueId,
    pub tactic: Tactic,
    pub name: &'static str,
    pub engagement_id: String,
    pub observations: Vec<Observation>,
}

impl Evidence {
    /// Begin evidence for a technique engagement with no observations yet.
    /// `name` is the technique's human label, carried so receipts are
    /// self-describing for reporting.
    pub fn new(
        technique: TechniqueId,
        tactic: Tactic,
        name: &'static str,
        engagement_id: impl Into<String>,
    ) -> Self {
        Self {
            technique,
            tactic,
            name,
            engagement_id: engagement_id.into(),
            observations: Vec::new(),
        }
    }

    /// Record one observation.
    pub fn observe(
        &mut self,
        kind: impl Into<String>,
        target: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.observations.push(Observation {
            target: target.into(),
            kind: kind.into(),
            detail: detail.into(),
        });
    }
}
