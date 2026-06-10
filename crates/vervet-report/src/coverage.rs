//! The coverage map types emitted by a report.

use std::collections::BTreeMap;

use serde::Serialize;

/// Per-technique rollup across all receipts that exercised it.
#[derive(Clone, Debug, Serialize)]
pub struct TechniqueCoverage {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub engagements: u64,
    pub observations: u64,
    /// Always `unobserved` in v0: vervet fires techniques but does not see the
    /// defender, so it never claims a technique was detected or missed.
    pub detection: &'static str,
}

/// Workspace-wide totals.
#[derive(Clone, Debug, Serialize)]
pub struct Totals {
    pub engagements: u64,
    pub techniques: usize,
    pub observations: u64,
}

/// An ATT&CK coverage map: techniques grouped under the tactics they advance.
#[derive(Clone, Debug, Serialize)]
pub struct Coverage {
    pub schema: &'static str,
    pub version: &'static str,
    /// tactic -> the technique ids exercised under it.
    pub tactics: BTreeMap<String, Vec<String>>,
    pub techniques: Vec<TechniqueCoverage>,
    pub totals: Totals,
    pub detection_note: &'static str,
}

impl Coverage {
    /// Stamp the protocol identity and honest detection note onto a rollup.
    pub fn new(
        techniques: Vec<TechniqueCoverage>,
        tactics: BTreeMap<String, Vec<String>>,
        totals: Totals,
    ) -> Self {
        Coverage {
            schema: "vq1-coverage",
            version: "0.1.0",
            tactics,
            techniques,
            totals,
            detection_note: "detection is unobserved — vervet does not see your \
blue team; feed SIEM evidence to populate",
        }
    }
}
