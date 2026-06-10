//! `vervet schema` — the vq1 envelope contract as JSON Schema.

use std::process::ExitCode;

use serde_json::json;

/// Emit the vq1 envelope contract, pinned to the protocol version. Consumers
/// validate against it or generate typed bindings from it.
pub fn run() -> ExitCode {
    let schema = json!({
        "$id": "https://vervet.tools/schema/vq1/0.1.0",
        "title": "vq1 evidence envelope",
        "type": "object",
        "required": ["header", "summary", "handles"],
        "properties": {
            "header": {
                "type": "object",
                "properties": {
                    "schema": { "const": "vq1" },
                    "version": { "const": "0.1.0" }
                }
            },
            "summary": {
                "type": "object",
                "properties": {
                    "technique": { "type": "string" },
                    "attack_id": { "type": "string" },
                    "engagement_id": { "type": "string" },
                    "observation_count": { "type": "integer" }
                }
            },
            "handles": {
                "type": "object",
                "description": "map of ev:<hash> to one observation record"
            }
        }
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&schema).expect("schema serialize")
    );
    ExitCode::SUCCESS
}
