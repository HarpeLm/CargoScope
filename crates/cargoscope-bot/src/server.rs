//! Minimal HTTP/1.1 webhook & 1-click install landing server + background scheduler.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::auth::{GitHubAppAuth, now_unix_secs};
use crate::runner::{
    BotConfig, handle_pr_comment, is_repo_due, list_installation_repos, rebase_open_prs_on_push,
    sync_repository,
};
use crate::webhook::{BotState, WebhookEvent, parse_webhook_event, verify_github_signature};

const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

struct AppContext {
    config: BotConfig,
    auth: GitHubAppAuth,
    state: Mutex<BotState>,
}

/// Starts the HTTP webhook server and background scheduler loop until process exit.
///
/// # Errors
/// Returns an error if the TCP listener cannot bind or initial state fails to load.
pub fn serve(config: BotConfig, auth: GitHubAppAuth) -> Result<(), String> {
    let initial_state = BotState::load(&config.state_file)?;
    let ctx = Arc::new(AppContext {
        config: config.clone(),
        auth,
        state: Mutex::new(initial_state),
    });

    // Background scheduler thread checks due repositories periodically.
    let sched_ctx = Arc::clone(&ctx);
    thread::spawn(move || {
        loop {
            run_scheduled_cycle(&sched_ctx);
            thread::sleep(Duration::from_secs(sched_ctx.config.poll_interval_secs));
        }
    });

    let listener = TcpListener::bind(&config.listen_addr)
        .map_err(|err| format!("Failed binding {}: {err}", config.listen_addr))?;
    eprintln!(
        "cargoscope-bot listening on http://{} (app_id={}, slug={})",
        config.listen_addr, config.app_id, config.app_slug
    );

    for stream in listener.incoming().flatten() {
        let req_ctx = Arc::clone(&ctx);
        thread::spawn(move || handle_connection(stream, &req_ctx));
    }
    Ok(())
}

/// Runs a single pass over all installations registered in local state.
///
/// # Errors
/// Returns an error if loading state or fetching installation repositories fails.
pub fn run_once(config: &BotConfig, auth: &GitHubAppAuth) -> Result<(), String> {
    let mut state = BotState::load(&config.state_file)?;
    let now = now_unix_secs();
    let pairs: Vec<(u64, Vec<String>)> = state
        .installations
        .iter()
        .map(|(&id, rec)| (id, rec.repos.iter().cloned().collect()))
        .collect();
    for (inst_id, cached_repos) in pairs {
        let repos = list_installation_repos(config, auth, inst_id).unwrap_or(cached_repos);
        state.upsert_installation(
            inst_id,
            &state.installations[&inst_id].account.clone(),
            &repos,
        );
        for repo in repos {
            match sync_repository(config, auth, inst_id, &repo) {
                Ok(report) => {
                    eprintln!(
                        "synced {repo}: opened={:?} updated={:?} closed={:?} skip={:?}",
                        report.opened_prs,
                        report.updated_prs,
                        report.closed_prs,
                        report.skipped_reason
                    );
                    state.mark_repo_ran(inst_id, &repo, now);
                }
                Err(err) => eprintln!("sync error for {repo}: {err}"),
            }
        }
    }
    state.save(&config.state_file)?;
    Ok(())
}

fn run_scheduled_cycle(ctx: &Arc<AppContext>) {
    let now = now_unix_secs();
    let due_list: Vec<(u64, String)> = {
        let Ok(guard) = ctx.state.lock() else {
            return;
        };
        let mut out = Vec::new();
        for (&inst_id, rec) in &guard.installations {
            for repo in &rec.repos {
                let last = rec.last_run_unix.get(repo).copied().unwrap_or(0);
                if is_repo_due(&ctx.config.work_root, repo, last, now) {
                    out.push((inst_id, repo.clone()));
                }
            }
        }
        out
    };

    for (inst_id, repo) in due_list {
        match sync_repository(&ctx.config, &ctx.auth, inst_id, &repo) {
            Ok(report) => {
                eprintln!(
                    "[scheduler] {repo}: opened={:?} updated={:?} closed={:?}",
                    report.opened_prs, report.updated_prs, report.closed_prs
                );
                if let Ok(mut guard) = ctx.state.lock() {
                    guard.mark_repo_ran(inst_id, &repo, now_unix_secs());
                    let _ = guard.save(&ctx.config.state_file);
                }
            }
            Err(err) => eprintln!("[scheduler] error on {repo}: {err}"),
        }
    }
}

struct HttpRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    let n = reader
        .read_line(&mut request_line)
        .map_err(|err| format!("read request line: {err}"))?;
    if n == 0 {
        return Err("empty connection".to_owned());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_owned();
    let path = parts
        .next()
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_owned();

    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        let bytes = reader
            .read_line(&mut line)
            .map_err(|err| format!("read header: {err}"))?;
        if bytes == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, val)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), val.trim().to_owned());
        }
    }

    let content_len = headers
        .get("content-length")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    if content_len > MAX_BODY_BYTES {
        return Err("payload too large".to_owned());
    }
    let mut body = vec![0u8; content_len];
    if content_len > 0 {
        reader
            .read_exact(&mut body)
            .map_err(|err| format!("read body: {err}"))?;
    }
    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn handle_connection(mut stream: TcpStream, ctx: &Arc<AppContext>) {
    let Ok(req) = read_http_request(&mut stream) else {
        return;
    };
    let (status, content_type, body) = route_request(&req, ctx);
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.write_all(&body);
}

fn route_request(
    req: &HttpRequest,
    ctx: &Arc<AppContext>,
) -> (&'static str, &'static str, Vec<u8>) {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/healthz") => {
            let count = ctx.state.lock().map_or(0, |s| s.installations.len());
            let json = serde_json::json!({
                "status": "ok",
                "app": ctx.config.app_slug,
                "installations": count,
            });
            ("200 OK", "application/json", json.to_string().into_bytes())
        }
        ("GET", "/") => {
            let install_url = format!(
                "https://github.com/apps/{}/installations/new",
                ctx.config.app_slug
            );
            let webhook_note = ctx
                .config
                .public_url
                .as_deref()
                .map_or_else(String::new, |u| format!("<p><code>{u}/webhook</code></p>"));
            let html = format!(
                "<!doctype html><html><head><meta charset='utf-8'><title>CargoScope Bot</title></head>\
                <body style='font-family:system-ui;max-width:640px;margin:3rem auto;line-height:1.5'>\
                <h1>cargoscope-bot[bot]</h1>\
                <p>1-click replacement for Dependabot Cargo, GitHub Actions, and Docker with 7-day supply-chain cooldown and native CI triggers.</p>\
                {webhook_note}\
                <p><a href='{install_url}' style='display:inline-block;padding:.75rem 1.25rem;background:#111;color:#fff;text-decoration:none;border-radius:6px'>Install CargoScope on GitHub</a></p>\
                </body></html>"
            );
            ("200 OK", "text/html; charset=utf-8", html.into_bytes())
        }
        ("POST", "/webhook") => handle_webhook(req, ctx),
        _ => ("404 Not Found", "text/plain", b"not found".to_vec()),
    }
}

fn handle_webhook(
    req: &HttpRequest,
    ctx: &Arc<AppContext>,
) -> (&'static str, &'static str, Vec<u8>) {
    if let Some(secret) = &ctx.config.webhook_secret {
        let sig = req.headers.get("x-hub-signature-256").map(String::as_str);
        if !verify_github_signature(secret, &req.body, sig) {
            return (
                "401 Unauthorized",
                "text/plain",
                b"invalid signature".to_vec(),
            );
        }
    }

    let event_name = req
        .headers
        .get("x-github-event")
        .map_or("ping", String::as_str);
    if event_name == "ping" {
        return (
            "200 OK",
            "application/json",
            br#"{"ok":true,"pong":true}"#.to_vec(),
        );
    }

    let event = match parse_webhook_event(event_name, &req.body) {
        Ok(ev) => ev,
        Err(err) => {
            return (
                "400 Bad Request",
                "text/plain",
                format!("bad webhook payload: {err}").into_bytes(),
            );
        }
    };

    match event {
        WebhookEvent::InstallationCreated {
            installation_id,
            account,
            repos,
        } => {
            if let Ok(mut guard) = ctx.state.lock() {
                guard.upsert_installation(installation_id, &account, &repos);
                let _ = guard.save(&ctx.config.state_file);
            }
            let bg = Arc::clone(ctx);
            thread::spawn(move || {
                for repo in repos {
                    if let Err(err) = sync_repository(&bg.config, &bg.auth, installation_id, &repo)
                    {
                        eprintln!("[install {installation_id}] sync {repo} failed: {err}");
                    } else if let Ok(mut guard) = bg.state.lock() {
                        guard.mark_repo_ran(installation_id, &repo, now_unix_secs());
                        let _ = guard.save(&bg.config.state_file);
                    }
                }
            });
        }
        WebhookEvent::InstallationRemoved { installation_id } => {
            if let Ok(mut guard) = ctx.state.lock() {
                guard.remove_installation(installation_id);
                let _ = guard.save(&ctx.config.state_file);
            }
        }
        WebhookEvent::ReposAdded {
            installation_id,
            repos,
        } => {
            if let Ok(mut guard) = ctx.state.lock() {
                guard.add_repos(installation_id, &repos);
                let _ = guard.save(&ctx.config.state_file);
            }
            let bg = Arc::clone(ctx);
            thread::spawn(move || {
                for repo in repos {
                    let _ = sync_repository(&bg.config, &bg.auth, installation_id, &repo);
                    if let Ok(mut guard) = bg.state.lock() {
                        guard.mark_repo_ran(installation_id, &repo, now_unix_secs());
                        let _ = guard.save(&bg.config.state_file);
                    }
                }
            });
        }
        WebhookEvent::ReposRemoved {
            installation_id,
            repos,
        } => {
            if let Ok(mut guard) = ctx.state.lock() {
                guard.remove_repos(installation_id, &repos);
                let _ = guard.save(&ctx.config.state_file);
            }
        }
        WebhookEvent::PrComment {
            installation_id,
            repo,
            pr_number,
            comment_body,
            commenter,
        } => {
            let bg = Arc::clone(ctx);
            thread::spawn(move || {
                if let Err(err) = handle_pr_comment(
                    &bg.config,
                    &bg.auth,
                    installation_id,
                    &repo,
                    pr_number,
                    &comment_body,
                    &commenter,
                ) {
                    eprintln!("[comment {repo}#{pr_number}] failed: {err}");
                }
            });
        }
        WebhookEvent::Push {
            installation_id,
            repo,
            git_ref,
        } => {
            let bg = Arc::clone(ctx);
            thread::spawn(move || {
                let _ =
                    rebase_open_prs_on_push(&bg.config, &bg.auth, installation_id, &repo, &git_ref);
            });
        }
        WebhookEvent::PullRequestClosed { .. } | WebhookEvent::Ignored => {}
    }

    (
        "202 Accepted",
        "application/json",
        br#"{"accepted":true}"#.to_vec(),
    )
}
