//! `[bans.build]` inspection: executables and scripts shipped inside the
//! crates that run code at build time, as cargo-deny 0.20 checks them.
//!
//! Inspected: the crates with a build script or a proc-macro (and, with
//! `include-dependencies`, what they depend on), from the unpacked registry
//! sources; workspace members only with `include-workspace`; git sources
//! never (cargo-deny skips them too). In each crate, every file is checked in
//! this order:
//!
//! 1. a `bypass` entry of the crate allows it (exact path, optionally with a
//!    SHA-256 that must match, or an `allow-globs` pattern);
//! 2. its name matches `script-extensions` (and cargo-deny's built-in list
//!    with `enable-builtin-globs`): an error;
//! 3. its first bytes are a native executable (ELF, PE, Mach-O, and static
//!    archives with `include-archives`): an error; a `#!` script: the
//!    `interpreted` level.
//!
//! A `bypass` with a matching `build-script` SHA-256 skips the whole crate
//! unless one of its `required-features` is enabled.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use cargoscope_core::Inventory;
use cargoscope_core::policy::{
    ActivePackages, BuildBypass, BuildInspection, EnabledFeatures, LintLevel, Policy, Rule,
    Violation, ViolationLevel,
};
use sha2::{Digest, Sha256};

use crate::crate_sources::{has_build_script, resolve_package_dirs};

/// cargo-deny's built-in script extensions (`enable-builtin-globs`).
const BUILTIN_GLOBS: &[&str] = &[
    "*.bat", "*.cmd", "*.go", "*.java", "*.js", "*._js", "*.es", "*.es6", "*.pl", "*.perl", "*.pm",
    "*.6pl", "*.6pm", "*.p6", "*.p6l", "*.p6m", "*.pl6", "*.pm6", "*.t", "*.ps1", "*.psd1",
    "*.psm1", "*.py", "*.rb", "*.sh", "*.bash", "*.zsh",
];

/// What the first bytes of a file say.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Native(&'static str),
    Script(String),
}

/// Reads the start of a file as cargo-deny (goblin) does: files shorter than
/// 16 bytes are never executables.
fn executable_kind(path: &Path, include_archives: bool) -> std::io::Result<Option<Kind>> {
    let mut file = fs::File::open(path)?;
    let mut header = [0u8; 256];
    let mut read = 0;
    while read < 16 {
        let n = file.read(&mut header[read..16])?;
        if n == 0 {
            return Ok(None);
        }
        read += n;
    }
    let head = &header[..16];
    if head.starts_with(b"\x7fELF") {
        return Ok(Some(Kind::Native("elf")));
    }
    if head.starts_with(b"!<arch>\n") {
        return Ok(include_archives.then_some(Kind::Native("archive")));
    }
    match u16::from_le_bytes([head[0], head[1]]) {
        0x5a4d => return Ok(Some(Kind::Native("pe"))),
        // TE images and COFF objects: not reported by cargo-deny.
        0x5a56 | 0x014c | 0x8664 | 0xaa64 => return Ok(None),
        _ => {}
    }
    match u32::from_be_bytes([head[0], head[1], head[2], head[3]]) {
        0xfeed_face | 0xfeed_facf | 0xcefa_edfe | 0xcffa_edfe | 0xcafe_babe => {
            return Ok(Some(Kind::Native("mach")));
        }
        _ => {}
    }
    if &head[..2] != b"#!" {
        return Ok(None);
    }
    let mut end = 16;
    if !head.contains(&b'\n') {
        end += file.read(&mut header[16..])?;
    }
    let bytes = &header[..end];
    let Some(line_end) = bytes.iter().position(|b| *b == b'\n') else {
        return Ok(None);
    };
    let Ok(line) = std::str::from_utf8(&bytes[..line_end]) else {
        return Ok(None);
    };
    // `#![attribute]` at the top of a Rust file is not a shebang.
    if path.extension().is_some_and(|ext| ext == "rs") && line.starts_with("#![") {
        return Ok(None);
    }
    let mut items = line.split(' ');
    let Some(first) = items.next() else {
        return Ok(None);
    };
    let interpreter = if first.ends_with("#!") {
        items.next()
    } else {
        Some(first)
    };
    let Some(interpreter) = interpreter else {
        return Ok(None);
    };
    let name = if interpreter.ends_with("/env") {
        items.next()
    } else {
        Some(
            interpreter
                .rsplit_once('/')
                .map_or(interpreter, |(_, bin)| bin),
        )
    };
    Ok(name.map(|name| Kind::Script(name.trim_start_matches("#!").to_owned())))
}

/// Glob matching as globset does by default: `*` and `**` match any text
/// (separators included), `?` one character, `[...]` a class, `{a,b}` an
/// alternative.
fn glob_match(pattern: &str, text: &str) -> bool {
    if let (Some(open), Some(close)) = (pattern.find('{'), pattern.find('}'))
        && open < close
    {
        let (head, rest) = pattern.split_at(open);
        let tail = &rest[close - open + 1..];
        return rest[1..close - open]
            .split(',')
            .any(|alternative| glob_match(&format!("{head}{alternative}{tail}"), text));
    }
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    fn inner(p: &[char], t: &[char]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some('*') => {
                let rest = &p[p.iter().take_while(|c| **c == '*').count()..];
                (0..=t.len()).any(|skip| inner(rest, &t[skip..]))
            }
            Some('?') => !t.is_empty() && inner(&p[1..], &t[1..]),
            Some('[') => {
                let Some(close) = p.iter().skip(1).position(|c| *c == ']') else {
                    return t.first() == Some(&'[') && inner(&p[1..], &t[1..]);
                };
                let class = &p[1..=close];
                let Some(c) = t.first() else {
                    return false;
                };
                let (negated, class) = match class.first() {
                    Some('!' | '^') => (true, &class[1..]),
                    _ => (false, class),
                };
                let mut hit = false;
                let mut i = 0;
                while i < class.len() {
                    if i + 2 < class.len() && class[i + 1] == '-' {
                        hit |= (class[i]..=class[i + 2]).contains(c);
                        i += 3;
                    } else {
                        hit |= class[i] == *c;
                        i += 1;
                    }
                }
                hit != negated && inner(&p[close + 2..], &t[1..])
            }
            Some(c) => t.first() == Some(c) && inner(&p[1..], &t[1..]),
        }
    }
    inner(&pattern, &text)
}

fn sha256(path: &Path) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut file = fs::File::open(path)?;
    let mut chunk = [0u8; 8192];
    loop {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Files under `root`, as `/`-separated relative paths, sorted.
fn files(root: &Path) -> Vec<(String, PathBuf)> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                stack.push(path);
            } else if kind.is_file()
                && let Ok(relative) = path.strip_prefix(root)
            {
                let label = relative
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                found.push((label, path));
            }
        }
    }
    found.sort();
    found
}

/// The build script of the crate in `dir`, when it has one.
fn build_script_path(dir: &Path) -> Option<PathBuf> {
    if has_build_script(dir) != Some(true) {
        return None;
    }
    let manifest: toml::Value =
        toml::from_str(&fs::read_to_string(dir.join("Cargo.toml")).ok()?).ok()?;
    let declared = manifest
        .get("package")
        .and_then(|package| package.get("build"))
        .and_then(toml::Value::as_str);
    Some(dir.join(declared.unwrap_or("build.rs")))
}

fn is_proc_macro(dir: &Path) -> bool {
    fs::read_to_string(dir.join("Cargo.toml"))
        .ok()
        .and_then(|text| toml::from_str::<toml::Value>(&text).ok())
        .and_then(|manifest| {
            let lib = manifest.get("lib")?;
            lib.get("proc-macro")
                .or_else(|| lib.get("proc_macro"))?
                .as_bool()
        })
        == Some(true)
}

fn version_matches(requirement: Option<&str>, version: &str) -> bool {
    match requirement {
        None => true,
        Some(requirement) => match (
            semver::VersionReq::parse(requirement),
            semver::Version::parse(version),
        ) {
            (Ok(requirement), Ok(version)) => requirement.matches(&version),
            _ => true,
        },
    }
}

/// Findings of the inspection: violations, and warnings for the report.
#[derive(Debug, Default)]
pub struct Inspected {
    /// Executables, scripts and checksum mismatches.
    pub violations: Vec<Violation>,
    /// `bypass` entries that matched no crate.
    pub warnings: Vec<String>,
}

/// Inspects the build-time crates of `inventory` (limited to `active` when
/// given) as `policy`'s `[bans.build]` asks.
#[must_use]
pub fn inspect(
    project_root: &Path,
    inventory: &Inventory,
    policy: &Policy,
    active: Option<&ActivePackages>,
    enabled_features: Option<&EnabledFeatures>,
) -> Inspected {
    let mut found = Inspected::default();
    let Some(config) = &policy.build_inspection else {
        return found;
    };
    if config.executables == LintLevel::Allow {
        return found;
    }
    let is_active = |index: usize| {
        let package = &inventory.packages[index];
        active.is_none_or(|set| set.contains(&(package.name.clone(), package.version.clone())))
    };
    let dirs = resolve_package_dirs(project_root, inventory);
    let build_time: BTreeSet<usize> = (0..inventory.packages.len())
        .filter(|&index| is_active(index))
        .filter(|&index| {
            dirs[index]
                .as_deref()
                .is_some_and(|dir| has_build_script(dir) == Some(true) || is_proc_macro(dir))
        })
        .collect();
    let mut selected = build_time.clone();
    if config.include_dependencies {
        let mut stack: Vec<usize> = build_time.iter().copied().collect();
        while let Some(index) = stack.pop() {
            for &dependency in &inventory.packages[index].dependencies {
                if is_active(dependency) && selected.insert(dependency) {
                    stack.push(dependency);
                }
            }
        }
    }
    let mut used_bypass = vec![false; config.bypass.len()];
    for index in selected {
        let package = &inventory.packages[index];
        if package
            .source
            .as_deref()
            .is_some_and(|source| source.starts_with("git+"))
            || (package.root && !policy.build_include_workspace)
        {
            continue;
        }
        let Some(dir) = dirs[index].as_deref() else {
            continue;
        };
        let build_script = build_script_path(dir);
        // A build script outside allow-build-scripts is reported by the
        // policy itself; its files are not looked at (as in cargo-deny).
        if build_script.is_some()
            && policy.allow_build_scripts.as_ref().is_some_and(|allowed| {
                !allowed.iter().any(|entry| {
                    entry.name == package.name
                        && version_matches(entry.version.as_deref(), &package.version)
                })
            })
        {
            continue;
        }
        let bypass = config.bypass.iter().enumerate().find(|(_, entry)| {
            entry.name == package.name
                && version_matches(entry.version.as_deref(), &package.version)
        });
        if let Some((position, _)) = bypass {
            used_bypass[position] = true;
        }
        let bypass = bypass.map(|(_, entry)| entry);
        let mut push = |level: ViolationLevel, message: String| {
            found.violations.push(Violation {
                package: index,
                rule: Rule::Ban,
                level,
                message,
            });
        };
        if let Some(entry) = bypass
            && let Some(expected) = &entry.build_script
            && let Some(script) = &build_script
        {
            match sha256(script) {
                Ok(actual) if actual == *expected => {
                    let enabled = enabled_features.and_then(|features| {
                        features.get(&(package.name.clone(), package.version.clone()))
                    });
                    if !entry
                        .required_features
                        .iter()
                        .any(|feature| enabled.is_some_and(|set| set.contains(feature)))
                    {
                        continue;
                    }
                }
                Ok(actual) => push(
                    ViolationLevel::Warning,
                    format!(
                        "the build script of `{}` changed: its SHA-256 is {actual}, [bans.build] bypass expects {expected}",
                        package.name
                    ),
                ),
                Err(error) => push(
                    ViolationLevel::Warning,
                    format!(
                        "the build script of `{}` could not be read: {error}",
                        package.name
                    ),
                ),
            }
        }
        inspect_files(dir, &package.name, config, bypass, &mut push);
    }
    for (entry, used) in config.bypass.iter().zip(used_bypass) {
        if !used {
            found.warnings.push(format!(
                "[bans.build] bypass for `{}` matches no inspected crate: remove it if it is no longer needed",
                entry.name
            ));
        }
    }
    found
}

fn inspect_files(
    dir: &Path,
    name: &str,
    config: &BuildInspection,
    bypass: Option<&BuildBypass>,
    push: &mut impl FnMut(ViolationLevel, String),
) {
    let extensions: Vec<String> = config
        .script_extensions
        .iter()
        .map(|extension| format!("*.{extension}"))
        .chain(
            config
                .enable_builtin_globs
                .then_some(BUILTIN_GLOBS)
                .into_iter()
                .flatten()
                .map(|glob| (*glob).to_owned()),
        )
        .collect();
    let mut allow_hit: BTreeMap<&str, bool> = bypass
        .map(|entry| {
            entry
                .allow
                .iter()
                .map(|(path, _)| (path.as_str(), false))
                .collect()
        })
        .unwrap_or_default();
    let mut glob_hit: BTreeMap<&str, bool> = bypass
        .map(|entry| {
            entry
                .allow_globs
                .iter()
                .map(|glob| (glob.as_str(), false))
                .collect()
        })
        .unwrap_or_default();
    for (relative, path) in files(dir) {
        if let Some(entry) = bypass {
            let allowed = entry.allow.iter().find(|(allowed, _)| *allowed == relative);
            if let Some((allowed, None)) = allowed {
                allow_hit.insert(allowed.as_str(), true);
                continue;
            }
            let globs: Vec<&String> = entry
                .allow_globs
                .iter()
                .filter(|glob| glob_match(glob, &relative))
                .collect();
            if !globs.is_empty() {
                for glob in globs {
                    glob_hit.insert(glob.as_str(), true);
                }
                continue;
            }
            if let Some((allowed, Some(expected))) = allowed {
                allow_hit.insert(allowed.as_str(), true);
                match sha256(&path) {
                    Ok(actual) if actual == *expected => {}
                    Ok(actual) => push(
                        ViolationLevel::Error,
                        format!(
                            "`{relative}` in `{name}` changed: its SHA-256 is {actual}, [bans.build] bypass expects {expected}"
                        ),
                    ),
                    Err(error) => push(
                        ViolationLevel::Error,
                        format!("`{relative}` in `{name}` could not be read: {error}"),
                    ),
                }
                continue;
            }
        }
        if let Some(glob) = extensions.iter().find(|glob| glob_match(glob, &relative)) {
            push(
                ViolationLevel::Error,
                format!(
                    "`{relative}` in `{name}` matches the script extension `{glob}` of [bans.build]"
                ),
            );
            continue;
        }
        match executable_kind(&path, config.include_archives) {
            Ok(Some(Kind::Native(kind))) => push(
                ViolationLevel::Error,
                format!(
                    "`{relative}` in `{name}` is an executable ({kind}), and `{name}` runs code at build time"
                ),
            ),
            Ok(Some(Kind::Script(interpreter))) => {
                if let Some(level) = config.interpreted.to_violation_level() {
                    push(
                        level,
                        format!(
                            "`{relative}` in `{name}` is a {interpreter} script, and `{name}` runs code at build time"
                        ),
                    );
                }
            }
            Ok(None) => {}
            Err(error) => push(
                ViolationLevel::Warning,
                format!("`{relative}` in `{name}` could not be read: {error}"),
            ),
        }
    }
    for (path, hit) in allow_hit {
        if !hit {
            push(
                ViolationLevel::Warning,
                format!(
                    "[bans.build] bypass of `{name}` allows `{path}`, which is not in the crate"
                ),
            );
        }
    }
    for (glob, hit) in glob_hit {
        if !hit {
            push(
                ViolationLevel::Warning,
                format!("[bans.build] bypass of `{name}`: allow-globs `{glob}` matches no file"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{Kind, executable_kind, glob_match, sha256};

    #[test]
    fn globs_match_like_globset() {
        assert!(glob_match("*.sh", "scripts/build.sh"));
        assert!(glob_match("tests/**", "tests/data/x.bin"));
        assert!(glob_match("src/*.{c,h}", "src/a.h"));
        assert!(glob_match("lib?.so", "lib1.so"));
        assert!(glob_match("[a-c]x", "bx"));
        assert!(!glob_match("[!a-c]x", "bx"));
        assert!(!glob_match("*.sh", "build.shx"));
    }

    #[test]
    fn recognises_executables_and_scripts() {
        let dir = std::env::temp_dir().join(format!("cargoscope-exe-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("dir");
        let write = |name: &str, bytes: &[u8]| {
            let path = dir.join(name);
            fs::write(&path, bytes).expect("write");
            path
        };
        let pad = |head: &[u8]| {
            let mut bytes = head.to_vec();
            bytes.resize(64, 0);
            bytes
        };
        let kind =
            |path: &std::path::Path, archives| executable_kind(path, archives).expect("read");
        assert_eq!(
            kind(&write("a.so", &pad(b"\x7fELF\x02\x01")), false),
            Some(Kind::Native("elf"))
        );
        assert_eq!(
            kind(&write("a.exe", &pad(b"MZ\x90\x00")), false),
            Some(Kind::Native("pe"))
        );
        assert_eq!(
            kind(&write("a.dylib", &pad(&[0xcf, 0xfa, 0xed, 0xfe])), false),
            Some(Kind::Native("mach"))
        );
        let archive = write("a.a", &pad(b"!<arch>\n"));
        assert_eq!(kind(&archive, false), None);
        assert_eq!(kind(&archive, true), Some(Kind::Native("archive")));
        assert_eq!(
            kind(
                &write("run", b"#!/usr/bin/env python3\nprint('hi')\n"),
                false
            ),
            Some(Kind::Script("python3".to_owned()))
        );
        assert_eq!(
            kind(&write("x.sh", b"#! /bin/bash\necho hello world\n"), false),
            Some(Kind::Script("bash".to_owned()))
        );
        assert_eq!(
            kind(&write("lib.rs", b"#![no_std]\npub fn f() {}\n"), false),
            None
        );
        assert_eq!(
            kind(&write("short", b"#!/bin/sh\n"), false),
            None,
            "under 16 bytes"
        );
        assert_eq!(
            kind(&write("text.txt", b"just some text, nothing else\n"), false),
            None
        );
        assert_eq!(
            sha256(&write("empty", b"")).expect("hash"),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
