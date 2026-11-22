//! GitHub App webhook verification, event routing, and persistent installation state.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use ring::hmac;

/// Incoming GitHub webhook event parsed from `X-GitHub-Event` + JSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookEvent {
    /// App installed on an account with initial repositories.
    InstallationCreated {
        installation_id: u64,
        account: String,
        repos: Vec<String>,
    },
    /// App uninstalled or suspended.
    InstallationRemoved { installation_id: u64 },
    /// Repositories added to an installation.
    ReposAdded {
        installation_id: u64,
        repos: Vec<String>,
    },
    /// Repositories removed from an installation.
    ReposRemoved {
        installation_id: u64,
        repos: Vec<String>,
    },
    /// Comment posted on a CargoScope pull request (`/cargoscope ...` or `@cargoscope ...`).
    PrComment {
        installation_id: u64,
        repo: String,
        pr_number: u64,
        comment_body: String,
        commenter: String,
    },
    /// Push to a branch (triggers rebase checks for open CargoScope PRs).
    Push {
        installation_id: u64,
        repo: String,
        git_ref: String,
    },
    /// Pull request merged or closed cleanly (triggers capacity replenishment if needed).
    PullRequestClosed {
        installation_id: u64,
        repo: String,
        pr_number: u64,
        merged: bool,
    },
    /// Delivery does not require action.
    Ignored,
}

/// Verifies GitHub's `X-Hub-Signature-256: sha256=<hex>` HMAC signature.
#[must_use]
pub fn verify_github_signature(
    secret: &str,
    payload: &[u8],
    signature_header: Option<&str>,
) -> bool {
    let Some(header) = signature_header else {
        return false;
    };
    let Some(hex_sig) = header.trim().strip_prefix("sha256=") else {
        return false;
    };
    let Some(sig_bytes) = decode_hex_32(hex_sig) else {
        return false;
    };
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    hmac::verify(&key, payload, &sig_bytes).is_ok()
}

fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (idx, chunk) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[idx] = (hi << 4) | lo;
    }
    Some(out)
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parses a GitHub webhook event payload.
///
/// # Errors
/// Returns an error if the JSON payload cannot be parsed.
pub fn parse_webhook_event(event_name: &str, payload: &[u8]) -> Result<WebhookEvent, String> {
    let v: serde_json::Value =
        serde_json::from_slice(payload).map_err(|err| format!("Invalid webhook JSON: {err}"))?;
    let installation_id = v
        .get("installation")
        .and_then(|i| i.get("id"))
        .and_then(serde_json::Value::as_u64);
    let action = v.get("action").and_then(serde_json::Value::as_str);

    match event_name {
        "installation" => {
            let Some(inst_id) = installation_id else {
                return Ok(WebhookEvent::Ignored);
            };
            match action {
                Some("created" | "unsuspend") => {
                    let account = v["installation"]["account"]["login"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_owned();
                    let repos = extract_repo_names(v.get("repositories"));
                    Ok(WebhookEvent::InstallationCreated {
                        installation_id: inst_id,
                        account,
                        repos,
                    })
                }
                Some("deleted" | "suspend") => Ok(WebhookEvent::InstallationRemoved {
                    installation_id: inst_id,
                }),
                _ => Ok(WebhookEvent::Ignored),
            }
        }
        "installation_repositories" => {
            let Some(inst_id) = installation_id else {
                return Ok(WebhookEvent::Ignored);
            };
            let added = extract_repo_names(v.get("repositories_added"));
            let removed = extract_repo_names(v.get("repositories_removed"));
            if !added.is_empty() {
                return Ok(WebhookEvent::ReposAdded {
                    installation_id: inst_id,
                    repos: added,
                });
            }
            if !removed.is_empty() {
                return Ok(WebhookEvent::ReposRemoved {
                    installation_id: inst_id,
                    repos: removed,
                });
            }
            Ok(WebhookEvent::Ignored)
        }
        "issue_comment" => {
            if action != Some("created") {
                return Ok(WebhookEvent::Ignored);
            }
            let Some(inst_id) = installation_id else {
                return Ok(WebhookEvent::Ignored);
            };
            if v["issue"].get("pull_request").is_none() {
                return Ok(WebhookEvent::Ignored);
            }
            let Some(repo) = v["repository"]["full_name"].as_str() else {
                return Ok(WebhookEvent::Ignored);
            };
            let Some(pr_number) = v["issue"]["number"].as_u64() else {
                return Ok(WebhookEvent::Ignored);
            };
            let Some(body) = v["comment"]["body"].as_str() else {
                return Ok(WebhookEvent::Ignored);
            };
            if !contains_cargoscope_command(body) {
                return Ok(WebhookEvent::Ignored);
            }
            let commenter = v["comment"]["user"]["login"]
                .as_str()
                .unwrap_or("unknown")
                .to_owned();
            Ok(WebhookEvent::PrComment {
                installation_id: inst_id,
                repo: repo.to_owned(),
                pr_number,
                comment_body: body.to_owned(),
                commenter,
            })
        }
        "push" => {
            let Some(inst_id) = installation_id else {
                return Ok(WebhookEvent::Ignored);
            };
            let Some(repo) = v["repository"]["full_name"].as_str() else {
                return Ok(WebhookEvent::Ignored);
            };
            let git_ref = v["ref"].as_str().unwrap_or("").to_owned();
            Ok(WebhookEvent::Push {
                installation_id: inst_id,
                repo: repo.to_owned(),
                git_ref,
            })
        }
        "pull_request" => {
            if action != Some("closed") {
                return Ok(WebhookEvent::Ignored);
            }
            let Some(inst_id) = installation_id else {
                return Ok(WebhookEvent::Ignored);
            };
            let Some(repo) = v["repository"]["full_name"].as_str() else {
                return Ok(WebhookEvent::Ignored);
            };
            let Some(pr_number) = v["number"].as_u64() else {
                return Ok(WebhookEvent::Ignored);
            };
            let merged = v["pull_request"]["merged"].as_bool().unwrap_or(false);
            Ok(WebhookEvent::PullRequestClosed {
                installation_id: inst_id,
                repo: repo.to_owned(),
                pr_number,
                merged,
            })
        }
        _ => Ok(WebhookEvent::Ignored),
    }
}

fn contains_cargoscope_command(body: &str) -> bool {
    body.lines().any(|line| {
        let lower = line.trim().to_ascii_lowercase();
        lower.starts_with("/cargoscope") || lower.starts_with("@cargoscope")
    })
}

fn extract_repo_names(val: Option<&serde_json::Value>) -> Vec<String> {
    val.and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("full_name").and_then(serde_json::Value::as_str))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Installation record stored on disk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstallationRecord {
    /// GitHub account or org login.
    pub account: String,
    /// Full `owner/repo` names enabled for this installation.
    pub repos: BTreeSet<String>,
    /// Unix timestamp of the last scheduled run per `owner/repo`.
    pub last_run_unix: BTreeMap<String, u64>,
}

/// Atomic JSON state tracking installations and last scheduled update timestamps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BotState {
    pub installations: BTreeMap<u64, InstallationRecord>,
}

impl BotState {
    /// Loads state from `path`, returning an empty state if the file does not exist yet.
    ///
    /// # Errors
    /// Returns an error if the existing state file cannot be read or contains invalid JSON.
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = fs::read_to_string(path)
            .map_err(|err| format!("Failed reading {}: {err}", path.display()))?;
        let root: serde_json::Value = serde_json::from_str(&text)
            .map_err(|err| format!("Invalid state JSON in {}: {err}", path.display()))?;
        let mut installations = BTreeMap::new();
        if let Some(map) = root
            .get("installations")
            .and_then(serde_json::Value::as_object)
        {
            for (id_str, entry) in map {
                let Ok(id) = id_str.parse::<u64>() else {
                    continue;
                };
                let account = entry["account"].as_str().unwrap_or("unknown").to_owned();
                let repos = entry["repos"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(serde_json::Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default();
                let last_run_unix = entry["last_run_unix"]
                    .as_object()
                    .map(|obj| {
                        obj.iter()
                            .filter_map(|(k, v)| v.as_u64().map(|ts| (k.clone(), ts)))
                            .collect()
                    })
                    .unwrap_or_default();
                installations.insert(
                    id,
                    InstallationRecord {
                        account,
                        repos,
                        last_run_unix,
                    },
                );
            }
        }
        Ok(Self { installations })
    }

    /// Saves state atomically via sibling temp file rename.
    ///
    /// # Errors
    /// Returns an error if parent creation or file writing fails.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("Failed creating {}: {err}", parent.display()))?;
        }
        let mut installations_json = serde_json::Map::new();
        for (id, rec) in &self.installations {
            let repos: Vec<serde_json::Value> = rec
                .repos
                .iter()
                .map(|r| serde_json::Value::String(r.clone()))
                .collect();
            let last_run: serde_json::Map<String, serde_json::Value> = rec
                .last_run_unix
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::from(*v)))
                .collect();
            installations_json.insert(
                id.to_string(),
                serde_json::json!({
                    "account": rec.account,
                    "repos": repos,
                    "last_run_unix": last_run,
                }),
            );
        }
        let json = serde_json::to_string_pretty(&serde_json::json!({
            "installations": installations_json,
        }))
        .map_err(|err| format!("Failed serializing bot state: {err}"))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json).map_err(|err| format!("Failed writing {}: {err}", tmp.display()))?;
        fs::rename(&tmp, path).map_err(|err| format!("Failed renaming state file: {err}"))?;
        Ok(())
    }

    /// Registers an installation and its initial repositories.
    pub fn upsert_installation(&mut self, id: u64, account: &str, repos: &[String]) {
        let entry = self.installations.entry(id).or_default();
        entry.account = account.to_owned();
        for repo in repos {
            entry.repos.insert(repo.clone());
        }
    }

    /// Removes an uninstalled/suspended installation.
    pub fn remove_installation(&mut self, id: u64) {
        self.installations.remove(&id);
    }

    /// Adds repositories to an existing installation.
    pub fn add_repos(&mut self, id: u64, repos: &[String]) {
        let entry = self.installations.entry(id).or_default();
        for repo in repos {
            entry.repos.insert(repo.clone());
        }
    }

    /// Removes repositories from an installation.
    pub fn remove_repos(&mut self, id: u64, repos: &[String]) {
        if let Some(entry) = self.installations.get_mut(&id) {
            for repo in repos {
                entry.repos.remove(repo);
                entry.last_run_unix.remove(repo);
            }
        }
    }

    /// Records completion timestamp for a repository.
    pub fn mark_repo_ran(&mut self, id: u64, repo: &str, now_unix: u64) {
        if let Some(entry) = self.installations.get_mut(&id) {
            entry.last_run_unix.insert(repo.to_owned(), now_unix);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign_hex(secret: &str, body: &[u8]) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let tag = hmac::sign(&key, body);
        let mut s = String::from("sha256=");
        for b in tag.as_ref() {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    #[test]
    fn verifies_github_hmac_sha256_signatures() {
        let body = br#"{"action":"created"}"#;
        let sig = sign_hex("top-secret", body);
        assert!(verify_github_signature("top-secret", body, Some(&sig)));
        assert!(!verify_github_signature("wrong", body, Some(&sig)));
        assert!(!verify_github_signature("top-secret", b"{}", Some(&sig)));
        assert!(!verify_github_signature("top-secret", body, None));
        assert!(!verify_github_signature(
            "top-secret",
            body,
            Some("sha1=deadbeef")
        ));
    }

    #[test]
    fn parses_installation_and_pr_comment_webhooks() {
        let install_payload = serde_json::json!({
            "action": "created",
            "installation": { "id": 42, "account": { "login": "acme" } },
            "repositories": [{ "full_name": "acme/widget" }]
        });
        assert_eq!(
            parse_webhook_event("installation", install_payload.to_string().as_bytes())
                .expect("parsed"),
            WebhookEvent::InstallationCreated {
                installation_id: 42,
                account: "acme".to_owned(),
                repos: vec!["acme/widget".to_owned()],
            }
        );

        let comment_payload = serde_json::json!({
            "action": "created",
            "installation": { "id": 42 },
            "repository": { "full_name": "acme/widget" },
            "issue": { "number": 7, "pull_request": { "url": "https://api.github.com/..." } },
            "comment": { "body": "/cargoscope rebase", "user": { "login": "alice" } }
        });
        assert_eq!(
            parse_webhook_event("issue_comment", comment_payload.to_string().as_bytes())
                .expect("parsed"),
            WebhookEvent::PrComment {
                installation_id: 42,
                repo: "acme/widget".to_owned(),
                pr_number: 7,
                comment_body: "/cargoscope rebase".to_owned(),
                commenter: "alice".to_owned(),
            }
        );

        let issue_only = serde_json::json!({
            "action": "created",
            "installation": { "id": 42 },
            "repository": { "full_name": "acme/widget" },
            "issue": { "number": 8 },
            "comment": { "body": "/cargoscope rebase", "user": { "login": "alice" } }
        });
        assert_eq!(
            parse_webhook_event("issue_comment", issue_only.to_string().as_bytes())
                .expect("parsed"),
            WebhookEvent::Ignored
        );
    }

    #[test]
    fn bot_state_persists_round_trip() {
        let dir = std::env::temp_dir().join(format!("cargoscope-bot-state-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("state.json");

        let mut state = BotState::default();
        state.upsert_installation(99, "harpe", &["harpe/app".to_owned()]);
        state.mark_repo_ran(99, "harpe/app", 1_700_000_000);
        state.save(&path).expect("save");

        let loaded = BotState::load(&path).expect("load");
        assert_eq!(loaded, state);
        let _ = fs::remove_dir_all(&dir);
    }
}
