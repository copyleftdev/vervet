//! `vervet recon` — authorize T1046 through the gate, engage, emit a receipt.

use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use vervet_engage::{EngageError, run};
use vervet_scope::{Gate, Manifest, Request};
use vervet_technique::find;

use crate::args;

/// `vervet recon --manifest <f> --authority <hex> --target <ipv4> [--ports a,b]`
///
/// Emits an audited engagement receipt. A denial prints the typed reason and
/// exits 2; usage/IO errors exit 1.
pub fn run_cmd(argv: &[String]) -> ExitCode {
    let (Some(manifest_path), Some(authority), Some(target)) = (
        args::value(argv, "--manifest"),
        args::value(argv, "--authority"),
        args::value(argv, "--target"),
    ) else {
        eprintln!(
            "usage: vervet recon --manifest <f> --authority <hex> --target <ipv4> [--ports a,b]"
        );
        return ExitCode::FAILURE;
    };

    let Ok(target) = target.parse::<Ipv4Addr>() else {
        eprintln!("error: --target must be an IPv4 address");
        return ExitCode::FAILURE;
    };
    let ports = args::value(argv, "--ports")
        .map(parse_ports)
        .unwrap_or_default();

    let manifest = match load_manifest(manifest_path) {
        Ok(m) => m,
        Err(e) => return fail(&e),
    };
    let gate = match Gate::new(authority) {
        Ok(g) => g,
        Err(d) => return deny(&d.to_string()),
    };
    let Some(technique) = find("T1046") else {
        return fail("T1046 is not registered");
    };

    let request = Request { target, ports };
    match run(&gate, &manifest, technique, request, now()) {
        Ok(receipt) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&receipt).expect("receipt serialize")
            );
            ExitCode::SUCCESS
        }
        Err(EngageError::Denied(d)) => deny(&d.to_string()),
        Err(EngageError::Assembly(e)) => fail(&e.to_string()),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_ports(s: &str) -> Vec<u16> {
    s.split(',').filter_map(|p| p.trim().parse().ok()).collect()
}

fn load_manifest(path: &str) -> Result<Manifest, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("parsing {path}: {e}"))
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("error: {msg}");
    ExitCode::FAILURE
}

fn deny(msg: &str) -> ExitCode {
    eprintln!("denied: {msg}");
    ExitCode::from(2)
}
