//! `vervet explain` — resolve one handle from a previously emitted envelope.

use std::process::ExitCode;

use crate::args;

/// `vervet explain --run <envelope.json> --handle <ev:...>`
pub fn run(argv: &[String]) -> ExitCode {
    let (Some(run), Some(handle)) = (args::value(argv, "--run"), args::value(argv, "--handle"))
    else {
        eprintln!("usage: vervet explain --run <envelope.json> --handle <ev:...>");
        return ExitCode::FAILURE;
    };

    let text = match std::fs::read_to_string(run) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: reading {run}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let doc: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: parsing {run}: {e}");
            return ExitCode::FAILURE;
        }
    };

    match doc.get("handles").and_then(|h| h.get(handle)) {
        Some(record) => {
            println!(
                "{}",
                serde_json::to_string_pretty(record).expect("record serialize")
            );
            ExitCode::SUCCESS
        }
        None => {
            eprintln!("error: handle '{handle}' not found in {run}");
            ExitCode::FAILURE
        }
    }
}
