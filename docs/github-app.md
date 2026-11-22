# Hosted GitHub App (`cargoscope-bot[bot]`)

Install **CargoScope** in one click on a personal account or organization with **zero `.github/workflows/*.yml` files to copy** and **native CI execution** on every opened pull request.

## Why use the GitHub App instead of `action.yml`?

| Feature | GitHub Action (`action.yml`) | Hosted GitHub App (`cargoscope-bot[bot]`) |
| --- | --- | --- |
| Workflow YAML in repo | Required (`.github/workflows/cargoscope.yml`) | **0 YAML files needed** |
| Runs repo CI on bot PRs | Requires PAT (`CI_PAT`) or extra config | **Native** — GitHub App installation tokens fire `pull_request` CI directly |
| Multi-ecosystem updates | `cargo`, `github-actions`, `docker` | `cargo`, `github-actions`, `docker` |
| Reads existing config | `.github/dependabot.yml`, `deny.toml`, `cargoscope.toml` | `.github/dependabot.yml`, `deny.toml`, `cargoscope.toml` |
| PR chat commands | Needs second workflow trigger | Native webhooks (`/cargoscope rebase`, `recreate`, `ignore ...`) |

## Quick setup for users (1 click)

1. Keep your existing `.github/dependabot.yml` (or add a minimal `cargoscope.toml`) with `cargo`, `github-actions`, and/or `docker` blocks.
2. Disable GitHub Dependabot updates if desired (or remove Dependabot once CargoScope App is active).
3. Click **Install** on `https://github.com/apps/cargoscope-bot` and select all repositories or specific repos.
4. `cargoscope-bot[bot]` immediately syncs selected repositories and thereafter follows your `.github/dependabot.yml` schedule (`daily`, `weekly`, or `monthly`).

## Self-hosting / deploying the hosted service

`crates/cargoscope-bot` is included in this workspace and ships ready to deploy with **zero extra third-party crates** (RS256 JWT + HMAC-SHA256 webhook verification run directly on `ring`):

1. Register a GitHub App using [`deploy/github-app/app-manifest.json`](../deploy/github-app/app-manifest.json) and download its private key `.pem`.
2. Deploy [`deploy/github-app/fly.toml`](../deploy/github-app/fly.toml) (builds [`deploy/github-app/Dockerfile`](../deploy/github-app/Dockerfile)) with persistent `/data` storage and set secrets:
   - `CARGOSCOPE_APP_ID` — numeric GitHub App ID
   - `CARGOSCOPE_PRIVATE_KEY` — PEM key contents (`BEGIN RSA PRIVATE KEY` or `BEGIN PRIVATE KEY`)
   - `CARGOSCOPE_WEBHOOK_SECRET` — HMAC webhook secret
3. Health endpoint: `GET /healthz`, 1-click install landing page: `GET /`, GitHub webhook endpoint: `POST /webhook`.

### Publishing on GitHub Marketplace

Once deployed and verified on HTTPS, submit the GitHub App listing in GitHub Developer Settings -> **Marketplace** -> **List your tool** under Dependency Management, linking users to zero-config migration from Dependabot (`cargo`, `github-actions`, `docker`).
