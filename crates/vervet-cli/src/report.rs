//! `vervet report` — synthesize receipts into an ATT&CK coverage map.

use std::process::ExitCode;

use serde_json::Value;
use vervet_report::coverage;

/// `vervet report <receipt.json> [receipt2.json ...]`
pub fn run_cmd(argv: &[String]) -> ExitCode {
    let paths: Vec<&String> = argv.iter().filter(|a| !a.starts_with('-')).collect();
    if paths.is_empty() {
        eprintln!("usage: vervet report <receipt.json> [receipt2.json ...]");
        return ExitCode::FAILURE;
    }

    let mut receipts = Vec::with_capacity(paths.len());
    for path in paths {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("error: reading {path}: {e}");
                return ExitCode::FAILURE;
            }
        };
        match serde_json::from_str::<Value>(&text) {
            Ok(v) => receipts.push(v),
            Err(e) => {
                eprintln!("error: parsing {path}: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    let cov = coverage(&receipts);
    println!(
        "{}",
        serde_json::to_string_pretty(&cov).expect("coverage serialize")
    );
    ExitCode::SUCCESS
}
