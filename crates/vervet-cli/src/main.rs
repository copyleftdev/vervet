//! The vervet binary. Parses the verb and hands off to one focused module.

use std::process::ExitCode;

mod args;
mod describe;
mod emulate;
mod explain;
mod schema;

// Force-link the technique crate so its `inventory::submit!` entries register.
use vervet_techniques as _;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match argv.first().map(String::as_str) {
        Some("describe") => describe::run(),
        Some("schema") => schema::run(),
        Some("emulate") => emulate::run_cmd(&argv[1..]),
        Some("explain") => explain::run(&argv[1..]),
        Some("--version") => {
            println!("vervet {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: vervet <describe|schema|emulate|explain> [args]");
            ExitCode::FAILURE
        }
    }
}
