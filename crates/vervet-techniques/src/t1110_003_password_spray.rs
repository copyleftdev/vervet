//! T1110.003 — Password Spraying.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use vervet_core::attack::{Tactic, TechniqueId};
use vervet_core::evidence::Evidence;
use vervet_scope::Grant;
use vervet_technique::{SideEffect, Technique, TechniqueMeta};

/// Attempt one password across many accounts, at most one attempt per account,
/// to map weak-credential exposure without tripping lockout thresholds.
struct PasswordSpray;

const META: TechniqueMeta = TechniqueMeta {
    id: TechniqueId("T1110.003"),
    tactic: Tactic::CredentialAccess,
    name: "Password Spraying",
    summary: "Try one password across many accounts (at most one attempt each, to stay under lockout). v0 confirms the auth surface is reachable and enforces one-attempt-per-account; a protocol backend (SMB/SSH/RDP) is pluggable.",
    side_effect: SideEffect::Observable,
    inputs: &[
        "target",
        "port (default 445)",
        "users (comma-separated)",
        "password",
    ],
};

const DEFAULT_PORT: u16 = 445;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(400);

impl Technique for PasswordSpray {
    fn meta(&self) -> &'static TechniqueMeta {
        &META
    }

    fn engage(&self, grant: &Grant) -> Evidence {
        let req = grant.request();
        let target = req.target.to_string();
        let mut ev = Evidence::new(META.id, META.tactic, grant.engagement_id());

        let Some(creds) = req.credentials.as_ref() else {
            ev.observe("spray_skipped", target.as_str(), "no credentials supplied");
            return ev;
        };

        let port = req.ports.first().copied().unwrap_or(DEFAULT_PORT);
        let addr = SocketAddr::new(IpAddr::V4(req.target), port);
        // One attempt per unique account: a repeated name never gets hit twice.
        for user in unique(&creds.usernames) {
            let reachable = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).is_ok();
            let verdict = if reachable {
                "unverified"
            } else {
                "service_unreachable"
            };
            ev.observe(
                "auth_attempt",
                target.as_str(),
                format!("user={user} port={port} password=<redacted> verdict={verdict}"),
            );
        }
        ev
    }
}

/// Deduplicate usernames, preserving first-seen order, so a repeated account in
/// the input never receives more than one attempt.
fn unique(users: &[String]) -> Vec<&str> {
    let mut seen = BTreeSet::new();
    users
        .iter()
        .filter(|u| seen.insert(u.as_str()))
        .map(String::as_str)
        .collect()
}

inventory::submit!(&PasswordSpray as &dyn Technique);
