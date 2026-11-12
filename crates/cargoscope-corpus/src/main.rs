//! Replays `tests/corpus/corpus.toml` and measures the precision of
//! unused-dependency detection (SPEC.md sections 5.2 and 12).
//!
//! Usage: `cargo run -p cargoscope-corpus -- [WORK_DIR] [--offline]`
//!
//! Each repository is fetched at its pinned commit with `git` into WORK_DIR
//! (default `target/corpus`). When a repository has no `Cargo.lock`, one is
//! created with `cargo generate-lockfile`, which only resolves versions: no
//! build script or project code runs. CargoScope itself never executes code.
//!
//! Exit code 1 when a `likely-unused` finding is unlabelled or wrong, or
//! when precision is below the 97% target.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use cargoscope_core::UnusedConfidence;

const TARGET_PRECISION: f64 = 0.97;

struct Label {
    manifest: String,
    section: String,
    dependency: String,
    unused: bool,
}

struct Repository {
    name: String,
    url: String,
    commit: String,
    set: String,
    labels: Vec<Label>,
}

fn string(value: &toml::Value, key: &str) -> Result<String, String> {
    value
        .get(key)
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("missing `{key}`"))
}

fn read_corpus(path: &Path) -> Result<Vec<Repository>, String> {
    let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    let value: toml::Value = toml::from_str(&text).map_err(|error| error.to_string())?;
    let repositories = value
        .get("repository")
        .and_then(toml::Value::as_array)
        .ok_or("no [[repository]]")?;
    repositories
        .iter()
        .map(|repository| {
            let labels = repository
                .get("labels")
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .map(|label| {
                    Ok(Label {
                        manifest: string(label, "manifest")?,
                        section: string(label, "section")?,
                        dependency: string(label, "dependency")?,
                        unused: match string(label, "truth")?.as_str() {
                            "unused" => true,
                            "used" => false,
                            other => return Err(format!("unknown truth `{other}`")),
                        },
                    })
                })
                .collect::<Result<_, String>>()?;
            Ok(Repository {
                name: string(repository, "name")?,
                url: string(repository, "url")?,
                commit: string(repository, "commit")?,
                set: string(repository, "set")?,
                labels,
            })
        })
        .collect()
}

fn run(command: &mut Command) -> Result<(), String> {
    let output = command.output().map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
    }
}

fn checkout(repository: &Repository, dir: &Path, offline: bool) -> Result<(), String> {
    let at_commit = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .is_some_and(|output| String::from_utf8_lossy(&output.stdout).trim() == repository.commit);
    if !at_commit {
        if offline {
            return Err("not fetched yet and --offline given".to_owned());
        }
        std::fs::create_dir_all(dir).map_err(|error| error.to_string())?;
        run(Command::new("git").arg("-C").arg(dir).arg("init").arg("-q"))?;
        run(Command::new("git").arg("-C").arg(dir).args([
            "fetch",
            "-q",
            "--depth",
            "1",
            &repository.url,
            &repository.commit,
        ]))?;
        run(Command::new("git").arg("-C").arg(dir).args([
            "checkout",
            "-q",
            "--detach",
            "FETCH_HEAD",
        ]))?;
    }
    if !dir.join("Cargo.lock").is_file() {
        let mut command = Command::new("cargo");
        // A repository's rust-toolchain file must not make rustup install a
        // toolchain: resolution works with the stable one.
        command
            .current_dir(dir)
            .env("RUSTUP_TOOLCHAIN", "stable")
            .env("RUSTUP_AUTO_INSTALL", "0")
            .args(["generate-lockfile", "-q"]);
        if offline {
            command.arg("--offline");
        }
        run(&mut command)?;
    }
    Ok(())
}

#[derive(Default)]
struct Tally {
    true_positives: usize,
    false_positives: Vec<String>,
    unlabelled: Vec<String>,
    missed: Vec<String>,
}

fn main() -> ExitCode {
    let mut work_dir = PathBuf::from("target/corpus");
    let mut offline = false;
    for argument in std::env::args().skip(1) {
        if argument == "--offline" {
            offline = true;
        } else {
            work_dir = PathBuf::from(argument);
        }
    }
    let corpus_file = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/corpus.toml");
    let repositories = match read_corpus(&corpus_file) {
        Ok(repositories) => repositories,
        Err(error) => {
            eprintln!("cannot read {}: {error}", corpus_file.display());
            return ExitCode::from(2);
        }
    };

    let mut tallies: BTreeMap<String, Tally> = BTreeMap::new();
    let mut failed = false;
    for repository in &repositories {
        let dir = work_dir.join(repository.name.replace('/', "_"));
        if let Err(error) = checkout(repository, &dir, offline) {
            eprintln!("{}: {error}", repository.name);
            failed = true;
            continue;
        }
        let result = cargoscope_cargo::scan_cargo_project(&dir)
            .and_then(|inventory| cargoscope_cargo::find_unused(&dir, &inventory));
        let findings = match result {
            Ok((findings, _)) => findings,
            Err(error) => {
                eprintln!("{}: {error}", repository.name);
                failed = true;
                continue;
            }
        };

        let tally = tallies.entry(repository.set.clone()).or_default();
        let label_of = |manifest: &str, section: &str, dependency: &str| {
            repository.labels.iter().find(|label| {
                label.manifest == manifest
                    && label.section == section
                    && label.dependency == dependency
            })
        };
        let mut reported = Vec::new();
        for finding in findings
            .iter()
            .filter(|finding| finding.confidence == UnusedConfidence::Likely)
            .filter(|finding| finding.ignored.is_none())
        {
            let id = format!(
                "{} {} [{}] {}",
                repository.name,
                finding.manifest,
                finding.kind.section(),
                finding.dependency
            );
            reported.push((
                finding.manifest.clone(),
                finding.kind.section(),
                finding.dependency.clone(),
            ));
            match label_of(
                &finding.manifest,
                finding.kind.section(),
                &finding.dependency,
            ) {
                Some(label) if label.unused => tally.true_positives += 1,
                Some(_) => tally.false_positives.push(id),
                None => tally.unlabelled.push(id),
            }
        }
        for label in repository.labels.iter().filter(|label| label.unused) {
            let found = reported.iter().any(|(manifest, section, dependency)| {
                *manifest == label.manifest
                    && *section == label.section
                    && *dependency == label.dependency
            });
            if !found {
                tally.missed.push(format!(
                    "{} {} [{}] {}",
                    repository.name, label.manifest, label.section, label.dependency
                ));
            }
        }
    }

    for (set, tally) in &tallies {
        let reported = tally.true_positives + tally.false_positives.len() + tally.unlabelled.len();
        let labelled = tally.true_positives + tally.false_positives.len();
        let precision = if labelled == 0 {
            1.0
        } else {
            #[allow(clippy::cast_precision_loss)]
            let ratio = tally.true_positives as f64 / labelled as f64;
            ratio
        };
        println!(
            "{set}: {reported} likely-unused reported, {} correct, {} wrong, {} unlabelled; precision {:.1}%; {} labelled unused dependencies not reported as likely",
            tally.true_positives,
            tally.false_positives.len(),
            tally.unlabelled.len(),
            precision * 100.0,
            tally.missed.len()
        );
        for item in &tally.false_positives {
            println!("  wrong: {item}");
        }
        for item in &tally.unlabelled {
            println!("  unlabelled: {item}");
        }
        for item in &tally.missed {
            println!("  not reported as likely: {item}");
        }
        failed |= !tally.false_positives.is_empty()
            || !tally.unlabelled.is_empty()
            || precision < TARGET_PRECISION;
    }

    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
