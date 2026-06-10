//! `vervet emulate <ATTACK_ID>` — authorize and fire any registered technique.

use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use vervet_engage::{EngageError, run};
use vervet_scope::{Credentials, Gate, Manifest, Request};
use vervet_technique::find;

use crate::args;

const USAGE: &str = "usage: vervet emulate <ATTACK_ID> --manifest <f> --authority <hex> \
--target <ipv4> [--ports a,b] [--users u1,u2] [--password p]";

/// Emits an audited engagement receipt for the named technique. A denial prints
/// the typed reason and exits 2; usage/IO errors exit 1.
pub fn run_cmd(argv: &[String]) -> ExitCode {
    let Some(attack_id) = argv.first().filter(|a| !a.starts_with('-')) else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };
    let rest = &argv[1..];

    let (Some(manifest_path), Some(authority), Some(target)) = (
        args::value(rest, "--manifest"),
        args::value(rest, "--authority"),
        args::value(rest, "--target"),
    ) else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };
    let Ok(target) = target.parse::<Ipv4Addr>() else {
        eprintln!("error: --target must be an IPv4 address");
        return ExitCode::FAILURE;
    };
    let ports = args::value(rest, "--ports")
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
    let Some(technique) = find(attack_id) else {
        return fail(&format!("{attack_id} is not a registered technique"));
    };

    let mut request = Request::new(target, ports);
    if let Some(creds) = credentials(rest) {
        request = request.with_credentials(creds);
    }

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

/// Build credentials from `--password` (required) and `--users` (comma list).
fn credentials(args: &[String]) -> Option<Credentials> {
    let password = args::value(args, "--password")?.to_string();
    let usernames = args::value(args, "--users")
        .map(|s| {
            s.split(',')
                .map(|u| u.trim().to_string())
                .filter(|u| !u.is_empty())
                .collect()
        })
        .unwrap_or_default();
    Some(Credentials {
        usernames,
        password,
    })
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
