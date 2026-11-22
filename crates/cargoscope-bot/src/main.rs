//! `cargoscope-bot`: hosted 1-click GitHub App (`cargoscope-bot[bot]`) backend.
//!
//! Eliminates copied `.github/workflows/*.yml` files, unlocks native CI triggers
//! on dependency PRs via GitHub App installation tokens, reads
//! `.github/dependabot.yml` + `cargoscope.toml` (`cargo`, `github-actions`,
//! `docker`), enforces a 7-day anti-supply-chain cooldown, and handles
//! `/cargoscope rebase|recreate|ignore` PR comments.

mod auth;
mod runner;
mod server;
mod webhook;

use std::process::ExitCode;

use crate::auth::GitHubAppAuth;
use crate::runner::{BotConfig, sync_repository};

fn print_usage() {
    eprintln!(
        "\
cargoscope-bot: hosted GitHub App backend for CargoScope

USAGE:
  cargoscope-bot serve                  Run HTTP webhook server + background scheduler
  cargoscope-bot run-once               Sync every repository recorded in state.json
  cargoscope-bot sync <INST_ID> <REPO>  Immediately sync one owner/repo with installation ID

ENVIRONMENT:
  CARGOSCOPE_APP_ID                     GitHub App numeric ID (required)
  CARGOSCOPE_PRIVATE_KEY                PEM private key text (or CARGOSCOPE_PRIVATE_KEY_PATH)
  CARGOSCOPE_WEBHOOK_SECRET             GitHub webhook HMAC-SHA256 secret (recommended)
  CARGOSCOPE_BOT_LISTEN                 HTTP listen address (default 0.0.0.0:8080)
  CARGOSCOPE_BOT_WORK_DIR               Clone/cache directory (default /var/lib/cargoscope-bot)
  CARGOSCOPE_BOT_STATE                  Installation state JSON path
  CARGOSCOPE_BOT_POLL_SECS              Scheduler check interval in seconds (default 900)
  CARGOSCOPE_APP_SLUG                   GitHub App slug (default cargoscope-bot)
"
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print_usage();
        return ExitCode::SUCCESS;
    }

    let config = match BotConfig::from_env() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("Configuration error: {err}");
            return ExitCode::from(2);
        }
    };
    let auth =
        match GitHubAppAuth::from_pem(&config.app_id, &config.private_key_pem, &config.api_base) {
            Ok(a) => a,
            Err(err) => {
                eprintln!("Auth initialization failed: {err}");
                return ExitCode::from(2);
            }
        };

    match args[0].as_str() {
        "serve" => match server::serve(config, auth) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("Server error: {err}");
                ExitCode::FAILURE
            }
        },
        "run-once" => match server::run_once(&config, &auth) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("Run error: {err}");
                ExitCode::FAILURE
            }
        },
        "sync" if args.len() == 3 => {
            let Ok(inst_id) = args[1].parse::<u64>() else {
                eprintln!("Invalid installation ID: {}", args[1]);
                return ExitCode::from(2);
            };
            match sync_repository(&config, &auth, inst_id, &args[2]) {
                Ok(rep) => {
                    println!(
                        "{}: opened={:?} updated={:?} closed={:?} skip={:?}",
                        rep.repo,
                        rep.opened_prs,
                        rep.updated_prs,
                        rep.closed_prs,
                        rep.skipped_reason
                    );
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("Sync failed: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        other => {
            eprintln!("Unknown subcommand: {other}");
            print_usage();
            ExitCode::from(2)
        }
    }
}
