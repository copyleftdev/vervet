//! Assembly of a complete vq1 envelope from technique evidence.

use serde::Serialize;

use super::{HandleMap, Header, Summary};
use crate::evidence::{Evidence, Handle};

/// A complete vq1 envelope: protocol header, dense summary, and a handle map of
/// every observation for drill-down.
#[derive(Clone, Debug, Serialize)]
pub struct Envelope {
    pub header: Header,
    pub summary: Summary,
    pub handles: HandleMap,
}

impl Envelope {
    /// Assemble an envelope from technique evidence. Each observation is hashed
    /// to a content-addressed handle and recorded for drill-down.
    pub fn from_evidence(ev: &Evidence) -> Result<Self, crate::Error> {
        let mut handles = HandleMap::default();
        for obs in &ev.observations {
            let handle = Handle::of(obs)?;
            handles.insert(handle.to_string(), serde_json::to_value(obs)?);
        }
        let summary = Summary {
            technique: ev.technique.to_string(),
            attack_id: ev.technique.as_str().to_string(),
            engagement_id: ev.engagement_id.clone(),
            observation_count: ev.observations.len(),
        };
        Ok(Envelope {
            header: Header::VQ1,
            summary,
            handles,
        })
    }
}
