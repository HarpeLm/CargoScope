//! Multi-repository CargoScope update runner driven by GitHub App installation tokens.
//!
//! Because commits and branches are pushed using GitHub App installation
//! credentials (`x-access-token`), GitHub dispatches native `pull_request`
//! events that run every CI check on the target repository without custom PATs
//! or copied workflow YAML files.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use cargoscope_cargo::dependabot::{DependabotConfigs, load_all};
use cargoscope_cargo::updates::UpdatesConfig;

use crate::auth::{GitHubAppAuth, base64_encode};

const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
const USER_AGENT: &str = "cargoscope-bot (+https://github.com/HarpeLm/CargoScope)";
const DEFAULT_OPEN_PR_LIMIT: usize = 5;
const BRANCH_PREFIX: &str = "cargoscope/";

/// Runtime configuration for `cargoscope-bot`.
#[derive(Debug, Clone)]
pub struct BotConfig {
    /// Numeric GitHub App ID (`CARGOSCOPE_APP_ID`).
    pub app_id: String,
    /// PEM-encoded GitHub App private key (`CARGOSCOPE_PRIVATE_KEY` or `_PATH`).
    pub private_key_pem: String,
    /// Optional webhook HMAC-SHA256 secret (`CARGOSCOPE_WEBHOOK_SECRET`).
    pub webhook_secret: Option<String>,
    /// GitHub REST API base URL (default `https://api.github.com`).
    pub api_base: String,
    /// Git HTTPS host base URL (default `https://github.com`).
    pub git_host: String,
    /// Path to `cargoscope` CLI binary (default sibling or `cargoscope` in `PATH`).
    pub cargoscope_bin: PathBuf,
    /// Scratch directory where repository clones are cached.
    pub work_root: PathBuf,
    /// Persistent installation/schedule state JSON file.
    pub state_file: PathBuf,
    /// Bind address for HTTP server (`CARGOSCOPE_BOT_LISTEN`).
    pub listen_addr: String,
    /// Background scheduler tick interval in seconds.
    pub poll_interval_secs: u64,
    /// GitHub App Marketplace / install slug.
    pub app_slug: String,
    /// Public webhook/app URL for the landing page.
    pub public_url: Option<String>,
    /// Whether major/breaking updates are also proposed by default.
    pub include_breaking: bool,
}

impl BotConfig {
    /// Loads configuration from process environment variables.
    ///
    /// # Errors
    /// Returns an error if `CARGOSCOPE_APP_ID` or the private key PEM is missing or unreadable.
    pub fn from_env() -> Result<Self, String> {
        let app_id = env_non_empty("CARGOSCOPE_APP_ID")
            .ok_or_else(|| "Missing CARGOSCOPE_APP_ID environment variable.".to_owned())?;
        let private_key_pem = if let Some(inline) = env_non_empty("CARGOSCOPE_PRIVATE_KEY") {
            inline.replace("\\n", "\n")
        } else if let Some(path) = env_non_empty("CARGOSCOPE_PRIVATE_KEY_PATH") {
            fs::read_to_string(&path).map_err(|err| {
                format!("Failed reading CARGOSCOPE_PRIVATE_KEY_PATH {path}: {err}")
            })?
        } else {
            return Err(
                "Set CARGOSCOPE_PRIVATE_KEY (PEM text) or CARGOSCOPE_PRIVATE_KEY_PATH.".to_owned(),
            );
        };
        let work_root = env_non_empty("CARGOSCOPE_BOT_WORK_DIR")
            .map_or_else(|| PathBuf::from("/var/lib/cargoscope-bot"), PathBuf::from);
        let state_file = env_non_empty("CARGOSCOPE_BOT_STATE")
            .map_or_else(|| work_root.join("state.json"), PathBuf::from);
        let cargoscope_bin = env_non_empty("CARGOSCOPE_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(default_cargoscope_bin);
        let poll_interval_secs = env_non_empty("CARGOSCOPE_BOT_POLL_SECS")
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&s| s >= 30)
            .unwrap_or(900);

        Ok(Self {
            app_id,
            private_key_pem,
            webhook_secret: env_non_empty("CARGOSCOPE_WEBHOOK_SECRET"),
            api_base: env_non_empty("CARGOSCOPE_API_BASE")
                .unwrap_or_else(|| "https://api.github.com".to_owned()),
            git_host: env_non_empty("CARGOSCOPE_GIT_HOST")
                .unwrap_or_else(|| "https://github.com".to_owned()),
            cargoscope_bin,
            work_root,
            state_file,
            listen_addr: env_non_empty("CARGOSCOPE_BOT_LISTEN")
                .unwrap_or_else(|| "0.0.0.0:8080".to_owned()),
            poll_interval_secs,
            app_slug: env_non_empty("CARGOSCOPE_APP_SLUG")
                .unwrap_or_else(|| "cargoscope-bot".to_owned()),
            public_url: env_non_empty("CARGOSCOPE_BOT_PUBLIC_URL"),
            include_breaking: env_non_empty("CARGOSCOPE_BOT_BREAKING")
                .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true")),
        })
    }
}

fn env_non_empty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn default_cargoscope_bin() -> PathBuf {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join("cargoscope");
        if sibling.is_file() {
            return sibling;
        }
    }
    PathBuf::from("cargoscope")
}

/// Summary of actions taken when syncing one repository.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub repo: String,
    pub opened_prs: Vec<u64>,
    pub updated_prs: Vec<u64>,
    pub closed_prs: Vec<u64>,
    pub skipped_reason: Option<String>,
}

/// Maps Dependabot `schedule.interval` strings to seconds between automatic runs.
#[must_use]
pub fn schedule_interval_secs(interval: Option<&str>) -> u64 {
    match interval
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("daily") => 86_400,
        Some("monthly") => 30 * 86_400,
        _ => 7 * 86_400,
    }
}

/// Converts a PR grouping key into a safe Git branch name (`cargoscope/<slug>`).
#[must_use]
pub fn branch_name_for_key(key: &str) -> String {
    let sanitized: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = sanitized.trim_matches(['-', '.']);
    let leaf = if trimmed.is_empty() {
        "updates"
    } else {
        trimmed
    };
    format!("{BRANCH_PREFIX}{leaf}")
}

/// Lists all repositories visible to a GitHub App installation (`owner/repo`).
///
/// # Errors
/// Returns an error on token exchange or API failure.
pub fn list_installation_repos(
    config: &BotConfig,
    auth: &GitHubAppAuth,
    installation_id: u64,
) -> Result<Vec<String>, String> {
    let token = auth.installation_token(installation_id)?;
    let gh = GitHubClient::new(&config.api_base, &token);
    gh.list_installation_repos()
}

/// Synchronizes dependency updates for `repo` (`owner/repo`) using an installation token.
///
/// # Errors
/// Returns an error on GitHub API, git, or CargoScope CLI invocation failure.
pub fn sync_repository(
    config: &BotConfig,
    auth: &GitHubAppAuth,
    installation_id: u64,
    repo: &str,
) -> Result<SyncReport, String> {
    let token = auth.installation_token(installation_id)?;
    let gh = GitHubClient::new(&config.api_base, &token);
    let mut report = SyncReport {
        repo: repo.to_owned(),
        ..SyncReport::default()
    };

    let meta = gh.get_repo(repo)?;
    let default_branch = meta
        .get("default_branch")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("main")
        .to_owned();

    let repo_dir = ensure_repo_clone(config, &token, repo, &default_branch)?;
    let policy = load_repo_policy(&repo_dir);
    if policy.ecosystems.is_empty() {
        report.skipped_reason =
            Some("No Cargo, GitHub Actions, or Docker manifests found".to_owned());
        return Ok(report);
    }

    if policy.ecosystems.iter().any(|e| e == "cargo") && repo_dir.join("Cargo.lock").is_file() {
        let _ = run_cargoscope(config, &repo_dir, &["update", "--fast"]);
    }

    let eco_arg = policy.ecosystems.join(",");
    let plan = run_update_plan(config, &repo_dir, &eco_arg, policy.breaking)?;
    let open_prs = gh.list_open_bot_prs(repo)?;

    let mut open_by_branch: BTreeMap<String, OpenPr> = BTreeMap::new();
    for pr in open_prs {
        open_by_branch.insert(pr.head_ref.clone(), pr);
    }

    let planned_branches: BTreeSet<String> = plan
        .pull_requests
        .iter()
        .map(|p| branch_name_for_key(&p.key))
        .collect();

    // Close obsolete open CargoScope PRs when their package is already updated on default branch.
    for (branch, pr) in &open_by_branch {
        if !planned_branches.contains(branch) {
            let msg = format!(
                "Closing this PR because `{}` is now up to date on `{default_branch}`.",
                pr.head_ref
            );
            gh.close_pr(repo, pr.number, Some(&msg))?;
            report.closed_prs.push(pr.number);
        }
    }

    let active_open_count = open_by_branch
        .keys()
        .filter(|b| planned_branches.contains(*b))
        .count();
    let max_prs = policy.open_pr_limit.unwrap_or(DEFAULT_OPEN_PR_LIMIT);
    let mut remaining_slots = max_prs.saturating_sub(active_open_count);

    for pull in &plan.pull_requests {
        let branch = branch_name_for_key(&pull.key);
        let existing = open_by_branch.get(&branch);
        if existing.is_none() && remaining_slots == 0 {
            continue;
        }

        // Reset clean branch from default branch and apply just this PR's package/ecosystem slice.
        run_git_auth(
            &repo_dir,
            &token,
            &[
                "checkout",
                "-B",
                &branch,
                &format!("origin/{default_branch}"),
            ],
        )?;

        let pkgs_arg = pull.packages.join(",");
        let md_body = render_pr_markdown(config, &repo_dir, &eco_arg, &pkgs_arg, policy.breaking)?;
        let apply_res = apply_slice_update(config, &repo_dir, &eco_arg, &pkgs_arg, policy.breaking);
        if apply_res.is_err() {
            reset_working_tree(&repo_dir, &default_branch)?;
            continue;
        }

        if !git_has_changes(&repo_dir)? {
            reset_working_tree(&repo_dir, &default_branch)?;
            continue;
        }

        let commit_title = format!(
            "{}{}",
            policy.commit_prefix.as_deref().unwrap_or(""),
            pull.title
        );
        commit_and_push(&repo_dir, &token, &branch, &commit_title)?;

        let full_body = append_bot_footer(&md_body, &config.app_slug);
        if let Some(pr) = existing {
            gh.update_pr(repo, pr.number, &commit_title, &full_body)?;
            report.updated_prs.push(pr.number);
        } else {
            let pr_number =
                gh.create_pr(repo, &branch, &default_branch, &commit_title, &full_body)?;
            apply_pr_metadata(&gh, repo, pr_number, &policy.labels, &policy.reviewers);
            report.opened_prs.push(pr_number);
            remaining_slots = remaining_slots.saturating_sub(1);
        }

        reset_working_tree(&repo_dir, &default_branch)?;
    }

    Ok(report)
}

/// Re-rebases open `cargoscope/*` PR branches after a push to the repository's default branch.
///
/// # Errors
/// Returns an error if GitHub API or git rebase operations fail.
pub fn rebase_open_prs_on_push(
    config: &BotConfig,
    auth: &GitHubAppAuth,
    installation_id: u64,
    repo: &str,
    git_ref: &str,
) -> Result<Vec<u64>, String> {
    let token = auth.installation_token(installation_id)?;
    let gh = GitHubClient::new(&config.api_base, &token);
    let meta = gh.get_repo(repo)?;
    let default_branch = meta
        .get("default_branch")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("main")
        .to_owned();
    if git_ref != format!("refs/heads/{default_branch}") {
        return Ok(Vec::new());
    }
    let open_prs = gh.list_open_bot_prs(repo)?;
    if open_prs.is_empty() {
        return Ok(Vec::new());
    }
    let mut touched = Vec::new();
    for pr in open_prs {
        if pr.mergeable_state == "dirty" || pr.mergeable_state == "behind" {
            let repo_dir = ensure_repo_clone(config, &token, repo, &default_branch)?;
            if rebase_single_pr(config, &repo_dir, &token, &default_branch, &pr).is_ok() {
                touched.push(pr.number);
            }
        }
    }
    Ok(touched)
}

/// Executes a `/cargoscope ...` or `@cargoscope ...` comment command on PR `#pr_number`.
///
/// # Errors
/// Returns an error if the PR details, clone, command execution, or comment reply fail.
pub fn handle_pr_comment(
    config: &BotConfig,
    auth: &GitHubAppAuth,
    installation_id: u64,
    repo: &str,
    pr_number: u64,
    comment_body: &str,
    commenter: &str,
) -> Result<String, String> {
    let token = auth.installation_token(installation_id)?;
    let gh = GitHubClient::new(&config.api_base, &token);
    let pr = gh.get_pr(repo, pr_number)?;
    if !pr.head_ref.starts_with(BRANCH_PREFIX) {
        return Ok("Ignored command on non-CargoScope branch.".to_owned());
    }
    let meta = gh.get_repo(repo)?;
    let default_branch = meta
        .get("default_branch")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("main")
        .to_owned();
    let repo_dir = ensure_repo_clone(config, &token, repo, &default_branch)?;
    let lower = comment_body.to_ascii_lowercase();

    if lower.contains("rebase") {
        rebase_single_pr(config, &repo_dir, &token, &default_branch, &pr)?;
        let ack = format!(
            "Rebased `{}` onto `{default_branch}` for @{commenter}.",
            pr.head_ref
        );
        gh.post_comment(repo, pr_number, &ack)?;
        return Ok(ack);
    }

    if lower.contains("recreate") {
        sync_repository(config, auth, installation_id, repo)?;
        let ack = format!(
            "Regenerated PR #{pr_number} from current dependency metadata for @{commenter}."
        );
        gh.post_comment(repo, pr_number, &ack)?;
        return Ok(ack);
    }

    if lower.contains("ignore") {
        let body_tmp = repo_dir.join(".cargoscope-pr-body.tmp.md");
        fs::write(&body_tmp, &pr.body)
            .map_err(|err| format!("Failed writing temporary PR body: {err}"))?;
        run_git_auth(
            &repo_dir,
            &token,
            &[
                "checkout",
                "-B",
                &default_branch,
                &format!("origin/{default_branch}"),
            ],
        )?;
        let cmd_out = run_cargoscope_in_args(
            config,
            &repo_dir,
            &[
                "fix",
                "--updates",
                "--comment-command",
                comment_body.trim(),
                "--pr-body",
                body_tmp.to_str().unwrap_or(".cargoscope-pr-body.tmp.md"),
                "--apply",
            ],
        );
        let _ = fs::remove_file(&body_tmp);
        let stdout = cmd_out?;
        if git_has_changes(&repo_dir)? {
            let ignore_branch = format!("cargoscope/ignore-pr-{pr_number}");
            run_git_auth(&repo_dir, &token, &["checkout", "-B", &ignore_branch])?;
            commit_and_push(
                &repo_dir,
                &token,
                &ignore_branch,
                &format!("chore(deps): ignore update from PR #{pr_number}"),
            )?;
            let ignore_pr = gh.create_pr(
                repo,
                &ignore_branch,
                &default_branch,
                &format!("chore(deps): record CargoScope ignore rule from PR #{pr_number}"),
                &format!(
                    "Requested by @{commenter} in #{pr_number}:\n\n> {}\n\n{stdout}",
                    comment_body.trim()
                ),
            )?;
            gh.close_pr(
                repo,
                pr_number,
                Some(&format!(
                    "Ignore rule opened in #{ignore_pr}; closing this PR."
                )),
            )?;
            let _ = reset_working_tree(&repo_dir, &default_branch);
            return Ok(format!(
                "Opened ignore rule PR #{ignore_pr} and closed #{pr_number}."
            ));
        }
        let ack = format!("@{commenter}: `{}` processed.", comment_body.trim());
        gh.post_comment(repo, pr_number, &ack)?;
        return Ok(ack);
    }

    Ok("No actionable /cargoscope command found.".to_owned())
}

fn rebase_single_pr(
    config: &BotConfig,
    repo_dir: &Path,
    token: &str,
    default_branch: &str,
    pr: &OpenPr,
) -> Result<(), String> {
    let packages = extract_packages_from_pr(&pr.title, &pr.body);
    let policy = load_repo_policy(repo_dir);
    let eco_arg = if policy.ecosystems.is_empty() {
        "cargo,github-actions,docker".to_owned()
    } else {
        policy.ecosystems.join(",")
    };
    run_git_auth(
        repo_dir,
        token,
        &[
            "checkout",
            "-B",
            &pr.head_ref,
            &format!("origin/{default_branch}"),
        ],
    )?;
    if !packages.is_empty() {
        let pkgs_arg = packages.join(",");
        apply_slice_update(config, repo_dir, &eco_arg, &pkgs_arg, policy.breaking)?;
    } else {
        let _ = run_git_auth(repo_dir, token, &["fetch", "origin", &pr.head_ref]);
        let _ = run_git_auth(
            repo_dir,
            token,
            &["rebase", &format!("origin/{default_branch}"), "FETCH_HEAD"],
        );
    }
    if git_has_changes(repo_dir)? {
        commit_and_push(repo_dir, token, &pr.head_ref, &pr.title)?;
    }
    reset_working_tree(repo_dir, default_branch)?;
    Ok(())
}

fn extract_packages_from_pr(title: &str, body: &str) -> Vec<String> {
    // Parse package names from PR diff table rows: `| name | from | to |` or fallback from title.
    let mut pkgs = BTreeSet::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("| `")
            && let Some((name, _)) = rest.split_once('`')
            && !name.eq_ignore_ascii_case("package")
        {
            pkgs.insert(name.to_owned());
        }
    }
    if pkgs.is_empty()
        && let Some(after_bump) = title.split("Bump ").nth(1)
        && let Some(pkg) = after_bump.split_whitespace().next()
    {
        pkgs.insert(pkg.trim_end_matches(':').to_owned());
    }
    pkgs.into_iter().collect()
}

struct RepoPolicy {
    ecosystems: Vec<String>,
    open_pr_limit: Option<usize>,
    labels: Vec<String>,
    reviewers: Vec<String>,
    commit_prefix: Option<String>,
    breaking: bool,
}

fn load_repo_policy(repo_dir: &Path) -> RepoPolicy {
    let dep_configs: DependabotConfigs = load_all(repo_dir);
    let toml_cfg = cargoscope_cargo::updates::load(repo_dir).unwrap_or_default();

    let mut ecosystems = Vec::new();
    if dep_configs.cargo.is_some() || repo_dir.join("Cargo.toml").is_file() {
        ecosystems.push("cargo".to_owned());
    }
    if dep_configs.github_actions.is_some() || repo_dir.join(".github/workflows").is_dir() {
        ecosystems.push("github-actions".to_owned());
    }
    if dep_configs.docker.is_some() || has_dockerfiles(repo_dir) {
        ecosystems.push("docker".to_owned());
    }

    let merged_cfg: Option<&UpdatesConfig> = dep_configs
        .cargo
        .as_ref()
        .or(dep_configs.github_actions.as_ref())
        .or(dep_configs.docker.as_ref());

    let open_pr_limit = toml_cfg
        .open_pull_requests_limit
        .or_else(|| merged_cfg.and_then(|c| c.open_pull_requests_limit));
    let labels = if !toml_cfg.labels.is_empty() {
        toml_cfg.labels
    } else {
        merged_cfg.map_or_else(Vec::new, |c| c.labels.clone())
    };
    let reviewers = if !toml_cfg.reviewers.is_empty() {
        toml_cfg.reviewers
    } else {
        merged_cfg.map_or_else(Vec::new, |c| c.reviewers.clone())
    };
    let commit_prefix = toml_cfg
        .commit_prefix
        .or_else(|| merged_cfg.and_then(|c| c.commit_prefix.clone()));

    RepoPolicy {
        ecosystems,
        open_pr_limit,
        labels,
        reviewers,
        commit_prefix,
        breaking: false,
    }
}

fn has_dockerfiles(root: &Path) -> bool {
    let Ok(entries) = fs::read_dir(root) else {
        return false;
    };
    entries.flatten().any(|entry| {
        entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with("Dockerfile") || n.starts_with("Containerfile"))
    })
}

/// Computes the shortest automatic cadence across `.github/dependabot.yml` blocks.
#[must_use]
pub fn repo_schedule_secs(repo_dir: &Path) -> u64 {
    let dep = load_all(repo_dir);
    [
        dep.cargo
            .as_ref()
            .and_then(|c| c.schedule_interval.as_deref()),
        dep.github_actions
            .as_ref()
            .and_then(|c| c.schedule_interval.as_deref()),
        dep.docker
            .as_ref()
            .and_then(|c| c.schedule_interval.as_deref()),
    ]
    .into_iter()
    .flatten()
    .map(|interval| schedule_interval_secs(Some(interval)))
    .min()
    .unwrap_or(7 * 86_400)
}

#[derive(Debug)]
struct PlannedPr {
    key: String,
    title: String,
    packages: Vec<String>,
}

#[derive(Debug)]
struct UpdatePlan {
    pull_requests: Vec<PlannedPr>,
}

fn run_update_plan(
    config: &BotConfig,
    repo_dir: &Path,
    ecosystems: &str,
    breaking: bool,
) -> Result<UpdatePlan, String> {
    let effective_breaking = breaking || config.include_breaking;
    let mut args = vec![
        "fix",
        "--updates",
        "--ecosystems",
        ecosystems,
        "--format",
        "json",
    ];
    if effective_breaking {
        args.push("--breaking");
    }
    let stdout = run_cargoscope_in_args(config, repo_dir, &args)?;
    let v: serde_json::Value =
        serde_json::from_str(&stdout).map_err(|err| format!("Invalid plan JSON: {err}"))?;
    let mut pull_requests = Vec::new();
    if let Some(items) = v.get("pull_requests").and_then(serde_json::Value::as_array) {
        for item in items {
            let Some(key) = item.get("key").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let title = item
                .get("title")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(key)
                .to_owned();
            let packages: Vec<String> = item
                .get("packages")
                .and_then(serde_json::Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            if !packages.is_empty() {
                pull_requests.push(PlannedPr {
                    key: key.to_owned(),
                    title,
                    packages,
                });
            }
        }
    }
    Ok(UpdatePlan { pull_requests })
}

fn render_pr_markdown(
    config: &BotConfig,
    repo_dir: &Path,
    ecosystems: &str,
    only_pkgs: &str,
    breaking: bool,
) -> Result<String, String> {
    let effective_breaking = breaking || config.include_breaking;
    let mut args = vec![
        "fix",
        "--updates",
        "--ecosystems",
        ecosystems,
        "--only",
        only_pkgs,
        "--format",
        "markdown",
    ];
    if effective_breaking {
        args.push("--breaking");
    }
    run_cargoscope_in_args(config, repo_dir, &args)
}

fn apply_slice_update(
    config: &BotConfig,
    repo_dir: &Path,
    ecosystems: &str,
    only_pkgs: &str,
    breaking: bool,
) -> Result<String, String> {
    let effective_breaking = breaking || config.include_breaking;
    let mut args = vec![
        "fix",
        "--updates",
        "--ecosystems",
        ecosystems,
        "--only",
        only_pkgs,
        "--apply",
    ];
    if effective_breaking {
        args.push("--breaking");
    }
    run_cargoscope_in_args(config, repo_dir, &args)
}

fn append_bot_footer(body: &str, app_slug: &str) -> String {
    format!(
        "{}\n\n---\n<sub>Opened by **{app_slug}[bot]** · Commands: `/cargoscope rebase`, `/cargoscope recreate`, `/cargoscope ignore this version|major version|minor version|dependency`</sub>\n",
        body.trim_end()
    )
}

fn run_cargoscope(config: &BotConfig, repo_dir: &Path, args: &[&str]) -> Result<String, String> {
    run_cargoscope_in_args(config, repo_dir, args)
}

fn run_cargoscope_in_args(
    config: &BotConfig,
    repo_dir: &Path,
    args: &[&str],
) -> Result<String, String> {
    let out = Command::new(&config.cargoscope_bin)
        .current_dir(repo_dir)
        .args(args)
        .arg(".")
        .output()
        .map_err(|err| format!("Failed executing {:?}: {err}", config.cargoscope_bin))?;
    if !out.status.success() {
        return Err(format!(
            "cargoscope {:?} failed ({}): {}",
            args,
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn ensure_repo_clone(
    config: &BotConfig,
    token: &str,
    repo: &str,
    default_branch: &str,
) -> Result<PathBuf, String> {
    let slug = repo.replace('/', "__");
    let repo_dir = config.work_root.join("repos").join(slug);
    let remote_url = format!("{}/{repo}.git", config.git_host.trim_end_matches('/'));
    if repo_dir.join(".git").is_dir() {
        run_git_auth(&repo_dir, token, &["fetch", "--prune", "origin"])?;
        reset_working_tree(&repo_dir, default_branch)?;
    } else {
        if let Some(parent) = repo_dir.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("Failed creating {}: {err}", parent.display()))?;
        }
        let parent = repo_dir.parent().unwrap_or_else(|| Path::new("."));
        let dir_name = repo_dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| "Invalid repo clone directory name.".to_owned())?;
        run_git_auth(parent, token, &["clone", &remote_url, dir_name])?;
    }
    run_git_auth(
        &repo_dir,
        token,
        &["config", "user.name", "cargoscope-bot[bot]"],
    )?;
    run_git_auth(
        &repo_dir,
        token,
        &[
            "config",
            "user.email",
            "cargoscope-bot[bot]@users.noreply.github.com",
        ],
    )?;
    Ok(repo_dir)
}

fn reset_working_tree(repo_dir: &Path, default_branch: &str) -> Result<(), String> {
    let _ = run_git_plain(repo_dir, &["rebase", "--abort"]);
    run_git_plain(
        repo_dir,
        &[
            "checkout",
            "-B",
            default_branch,
            &format!("origin/{default_branch}"),
        ],
    )?;
    run_git_plain(
        repo_dir,
        &["reset", "--hard", &format!("origin/{default_branch}")],
    )?;
    run_git_plain(repo_dir, &["clean", "-fd"])?;
    Ok(())
}

fn git_has_changes(repo_dir: &Path) -> Result<bool, String> {
    let out = run_git_plain(repo_dir, &["status", "--porcelain"])?;
    Ok(!out.trim().is_empty())
}

fn commit_and_push(
    repo_dir: &Path,
    token: &str,
    branch: &str,
    message: &str,
) -> Result<(), String> {
    run_git_plain(repo_dir, &["add", "-A"])?;
    run_git_plain(repo_dir, &["commit", "-m", message])?;
    run_git_auth(
        repo_dir,
        token,
        &[
            "push",
            "--force-with-lease",
            "origin",
            &format!("HEAD:refs/heads/{branch}"),
        ],
    )?;
    Ok(())
}

fn run_git_plain(cwd: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(args)
        .output()
        .map_err(|err| format!("Failed executing git {:?}: {err}", args))?;
    if !out.status.success() {
        return Err(format!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn run_git_auth(cwd: &Path, token: &str, args: &[&str]) -> Result<String, String> {
    let creds = base64_encode(format!("x-access-token:{token}").as_bytes());
    let header = format!("http.extraheader=AUTHORIZATION: basic {creds}");
    let out = Command::new("git")
        .current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .arg("-c")
        .arg(header)
        .args(args)
        .output()
        .map_err(|err| format!("Failed executing authenticated git {:?}: {err}", args))?;
    if !out.status.success() {
        return Err(format!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn apply_pr_metadata(
    gh: &GitHubClient<'_>,
    repo: &str,
    pr_number: u64,
    labels: &[String],
    reviewers: &[String],
) {
    if !labels.is_empty() {
        let _ = gh.add_labels(repo, pr_number, labels);
    }
    if !reviewers.is_empty() {
        let _ = gh.request_reviewers(repo, pr_number, reviewers);
    }
}

#[derive(Debug, Clone)]
struct OpenPr {
    number: u64,
    head_ref: String,
    title: String,
    body: String,
    mergeable_state: String,
}

struct GitHubClient<'a> {
    api_base: &'a str,
    token: &'a str,
}

impl<'a> GitHubClient<'a> {
    fn new(api_base: &'a str, token: &'a str) -> Self {
        Self {
            api_base: api_base.trim_end_matches('/'),
            token,
        }
    }

    fn get_json(&self, path: &str) -> Result<serde_json::Value, String> {
        let url = format!("{}{path}", self.api_base);
        let resp = ureq::get(&url)
            .timeout(HTTP_TIMEOUT)
            .set("Accept", "application/vnd.github+json")
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("User-Agent", USER_AGENT)
            .set("X-GitHub-Api-Version", "2022-11-28")
            .call()
            .map_err(|err| format!("GET {path} failed: {err}"))?;
        serde_json::from_reader(resp.into_reader())
            .map_err(|err| format!("GET {path} invalid JSON: {err}"))
    }

    fn send_json(
        &self,
        method: &str,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let url = format!("{}{path}", self.api_base);
        let req = match method {
            "POST" => ureq::post(&url),
            "PATCH" => ureq::patch(&url),
            other => return Err(format!("Unsupported HTTP method: {other}")),
        };
        let payload = body.to_string();
        let resp = req
            .timeout(HTTP_TIMEOUT)
            .set("Accept", "application/vnd.github+json")
            .set("Content-Type", "application/json")
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("User-Agent", USER_AGENT)
            .set("X-GitHub-Api-Version", "2022-11-28")
            .send_string(&payload)
            .map_err(|err| format!("{method} {path} failed: {err}"))?;
        serde_json::from_reader(resp.into_reader())
            .map_err(|err| format!("{method} {path} invalid JSON: {err}"))
    }

    fn list_installation_repos(&self) -> Result<Vec<String>, String> {
        let v = self.get_json("/installation/repositories?per_page=100")?;
        Ok(v.get("repositories")
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter(|r| !r["archived"].as_bool().unwrap_or(false))
                    .filter_map(|r| r["full_name"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn get_repo(&self, repo: &str) -> Result<serde_json::Value, String> {
        self.get_json(&format!("/repos/{repo}"))
    }

    fn list_open_bot_prs(&self, repo: &str) -> Result<Vec<OpenPr>, String> {
        let v = self.get_json(&format!("/repos/{repo}/pulls?state=open&per_page=100"))?;
        let Some(arr) = v.as_array() else {
            return Ok(Vec::new());
        };
        Ok(arr
            .iter()
            .filter_map(|item| {
                let head_ref = item["head"]["ref"].as_str()?.to_owned();
                if !head_ref.starts_with(BRANCH_PREFIX) {
                    return None;
                }
                Some(OpenPr {
                    number: item["number"].as_u64()?,
                    head_ref,
                    title: item["title"].as_str().unwrap_or("").to_owned(),
                    body: item["body"].as_str().unwrap_or("").to_owned(),
                    mergeable_state: item["mergeable_state"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_owned(),
                })
            })
            .collect())
    }

    fn get_pr(&self, repo: &str, pr_number: u64) -> Result<OpenPr, String> {
        let item = self.get_json(&format!("/repos/{repo}/pulls/{pr_number}"))?;
        Ok(OpenPr {
            number: pr_number,
            head_ref: item["head"]["ref"].as_str().unwrap_or("").to_owned(),
            title: item["title"].as_str().unwrap_or("").to_owned(),
            body: item["body"].as_str().unwrap_or("").to_owned(),
            mergeable_state: item["mergeable_state"]
                .as_str()
                .unwrap_or("unknown")
                .to_owned(),
        })
    }

    fn create_pr(
        &self,
        repo: &str,
        head: &str,
        base: &str,
        title: &str,
        body: &str,
    ) -> Result<u64, String> {
        let created = self.send_json(
            "POST",
            &format!("/repos/{repo}/pulls"),
            &serde_json::json!({
                "title": title,
                "head": head,
                "base": base,
                "body": body,
            }),
        )?;
        created["number"]
            .as_u64()
            .ok_or_else(|| "GitHub create PR response omitted 'number'.".to_owned())
    }

    fn update_pr(&self, repo: &str, pr_number: u64, title: &str, body: &str) -> Result<(), String> {
        let _ = self.send_json(
            "PATCH",
            &format!("/repos/{repo}/pulls/{pr_number}"),
            &serde_json::json!({
                "title": title,
                "body": body,
            }),
        )?;
        Ok(())
    }

    fn close_pr(&self, repo: &str, pr_number: u64, comment: Option<&str>) -> Result<(), String> {
        if let Some(msg) = comment {
            let _ = self.post_comment(repo, pr_number, msg);
        }
        let _ = self.send_json(
            "PATCH",
            &format!("/repos/{repo}/pulls/{pr_number}"),
            &serde_json::json!({ "state": "closed" }),
        )?;
        Ok(())
    }

    fn post_comment(&self, repo: &str, pr_number: u64, body: &str) -> Result<(), String> {
        let _ = self.send_json(
            "POST",
            &format!("/repos/{repo}/issues/{pr_number}/comments"),
            &serde_json::json!({ "body": body }),
        )?;
        Ok(())
    }

    fn add_labels(&self, repo: &str, pr_number: u64, labels: &[String]) -> Result<(), String> {
        let _ = self.send_json(
            "POST",
            &format!("/repos/{repo}/issues/{pr_number}/labels"),
            &serde_json::json!({ "labels": labels }),
        )?;
        Ok(())
    }

    fn request_reviewers(
        &self,
        repo: &str,
        pr_number: u64,
        reviewers: &[String],
    ) -> Result<(), String> {
        let _ = self.send_json(
            "POST",
            &format!("/repos/{repo}/pulls/{pr_number}/requested_reviewers"),
            &serde_json::json!({ "reviewers": reviewers }),
        )?;
        Ok(())
    }
}

/// Checks if a local cached repo is due for its periodic update according to its config.
#[must_use]
pub fn is_repo_due(work_root: &Path, repo: &str, last_run_unix: u64, now_unix: u64) -> bool {
    let repo_dir = work_root.join("repos").join(repo.replace('/', "__"));
    let interval = if repo_dir.is_dir() {
        repo_schedule_secs(&repo_dir)
    } else {
        7 * 86_400
    };
    now_unix.saturating_sub(last_run_unix) >= interval
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_branch_names_from_keys() {
        assert_eq!(branch_name_for_key("serde"), "cargoscope/serde");
        assert_eq!(
            branch_name_for_key("actions/checkout"),
            "cargoscope/actions-checkout"
        );
        assert_eq!(
            branch_name_for_key("group:production-deps"),
            "cargoscope/group-production-deps"
        );
    }

    #[test]
    fn maps_schedule_intervals() {
        assert_eq!(schedule_interval_secs(Some("daily")), 86_400);
        assert_eq!(schedule_interval_secs(Some("weekly")), 7 * 86_400);
        assert_eq!(schedule_interval_secs(Some("monthly")), 30 * 86_400);
        assert_eq!(schedule_interval_secs(None), 7 * 86_400);
    }

    #[test]
    fn extracts_packages_from_markdown_diff_table() {
        let body = "| Package | From | To |\n| `actions/checkout` | `v4.1.0` | `v4.2.2` |\n";
        assert_eq!(
            extract_packages_from_pr("Bump actions/checkout", body),
            vec!["actions/checkout".to_owned()]
        );
    }
}
