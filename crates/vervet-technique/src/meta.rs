//! Self-describing technique metadata.

use serde::Serialize;
use vervet_core::attack::{Tactic, TechniqueId};

/// What footprint a technique leaves, surfaced in `describe` so an operator and
/// the AI can reason about blast radius before engaging.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffect {
    /// Observes only; opens no connections that mutate target state.
    ReadOnly,
    /// Establishes connections a target may log or alert on.
    Observable,
}

/// Static description of a technique, declared as a `const` in each technique
/// file and emitted verbatim by `describe`.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct TechniqueMeta {
    pub id: TechniqueId,
    pub tactic: Tactic,
    pub name: &'static str,
    pub summary: &'static str,
    pub side_effect: SideEffect,
}
