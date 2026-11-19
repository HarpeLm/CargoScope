//! Data model shared by all CargoScope crates.

pub mod license;
pub mod policy;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// The current application version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A package resolved in a Cargo lockfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// Crate name.
    pub name: String,
    /// Resolved crate version.
    pub version: String,
    /// Optional Cargo source, such as a registry URL. `None` for local packages.
    pub source: Option<String>,
    /// Whether this package belongs to the scanned project (root package or workspace member).
    pub root: bool,
    /// Whether a root package depends on this package directly.
    pub direct: bool,
    /// Indices, in [`Inventory::packages`], of the packages this one depends on.
    pub dependencies: Vec<usize>,
}

/// The resolved Cargo packages found in a project, with their dependency edges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    /// Packages sorted by name and version.
    pub packages: Vec<Package>,
}

impl Inventory {
    /// Returns the shortest dependency chain from a root package to `target`,
    /// as package indices starting with the root and ending with `target`.
    ///
    /// Ties are broken by package order, so the result is deterministic.
    /// Returns `None` when no root reaches `target`.
    #[must_use]
    pub fn path_to(&self, target: usize) -> Option<Vec<usize>> {
        let count = self.packages.len();
        if target >= count {
            return None;
        }

        let mut previous: Vec<Option<usize>> = vec![None; count];
        let mut visited = vec![false; count];
        let mut queue = VecDeque::new();

        for (index, package) in self.packages.iter().enumerate() {
            if package.root {
                visited[index] = true;
                queue.push_back(index);
            }
        }

        while let Some(current) = queue.pop_front() {
            if current == target {
                let mut path = vec![current];
                let mut node = current;
                while let Some(parent) = previous[node] {
                    path.push(parent);
                    node = parent;
                }
                path.reverse();
                return Some(path);
            }
            for &next in &self.packages[current].dependencies {
                if next < count && !visited[next] {
                    visited[next] = true;
                    previous[next] = Some(current);
                    queue.push_back(next);
                }
            }
        }

        None
    }

    /// Indices of packages in [`Inventory::packages`] that depend directly on `target`,
    /// sorted by package order.
    #[must_use]
    pub fn dependents_of(&self, target: usize) -> Vec<usize> {
        if target >= self.packages.len() {
            return Vec::new();
        }
        self.packages
            .iter()
            .enumerate()
            .filter_map(|(index, package)| package.dependencies.contains(&target).then_some(index))
            .collect()
    }

    /// Returns up to `limit` simple dependency chains from root packages to
    /// `target`, shortest first, ties broken by package order.
    #[must_use]
    pub fn paths_to(&self, target: usize, limit: usize) -> Vec<Vec<usize>> {
        let count = self.packages.len();
        if target >= count || limit == 0 {
            return Vec::new();
        }

        let mut reverse = vec![Vec::new(); count];
        for (index, package) in self.packages.iter().enumerate() {
            for &dep in &package.dependencies {
                if dep < count {
                    reverse[dep].push(index);
                }
            }
        }
        let mut can_reach = vec![false; count];
        can_reach[target] = true;
        let mut rev_queue = VecDeque::from([target]);
        while let Some(node) = rev_queue.pop_front() {
            for &parent in &reverse[node] {
                if !can_reach[parent] {
                    can_reach[parent] = true;
                    rev_queue.push_back(parent);
                }
            }
        }

        let mut queue = VecDeque::new();
        for (index, package) in self.packages.iter().enumerate() {
            if package.root && can_reach[index] {
                queue.push_back(vec![index]);
            }
        }
        if queue.is_empty() {
            return Vec::new();
        }

        let mut results = Vec::new();
        let mut visits = vec![0usize; count];
        while let Some(path) = queue.pop_front() {
            let last = *path.last().expect("path is non-empty");
            if last == target {
                results.push(path);
                if results.len() == limit {
                    break;
                }
                continue;
            }
            for &next in &self.packages[last].dependencies {
                if next < count && can_reach[next] && !path.contains(&next) && visits[next] < limit
                {
                    if next != target {
                        visits[next] += 1;
                    }
                    let mut extended = path.clone();
                    extended.push(next);
                    queue.push_back(extended);
                }
            }
        }
        results
    }

    /// Marks the packages reachable from the root packages. With `cut`,
    /// edges from a root package to `cut` are ignored, as if every member
    /// stopped depending on it directly.
    fn reachable(&self, cut: Option<usize>) -> Vec<bool> {
        let count = self.packages.len();
        let mut seen = vec![false; count];
        let mut stack: Vec<usize> = (0..count).filter(|&i| self.packages[i].root).collect();
        for &root in &stack {
            seen[root] = true;
        }
        while let Some(current) = stack.pop() {
            let from_root = self.packages[current].root;
            for &next in &self.packages[current].dependencies {
                if next < count && !seen[next] && !(from_root && Some(next) == cut) {
                    seen[next] = true;
                    stack.push(next);
                }
            }
        }
        seen
    }

    fn reachable_without(&self, removed: Option<usize>) -> Vec<bool> {
        let count = self.packages.len();
        let mut seen = vec![false; count];
        let mut stack: Vec<usize> = (0..count)
            .filter(|&i| self.packages[i].root && Some(i) != removed)
            .collect();
        for &root in &stack {
            seen[root] = true;
        }
        while let Some(current) = stack.pop() {
            for &next in &self.packages[current].dependencies {
                if next < count && !seen[next] && Some(next) != removed {
                    seen[next] = true;
                    stack.push(next);
                }
            }
        }
        seen
    }

    fn subtree_non_root_count(&self, start: usize) -> usize {
        let count = self.packages.len();
        if start >= count {
            return 0;
        }
        let mut seen = vec![false; count];
        seen[start] = true;
        let mut stack = vec![start];
        while let Some(current) = stack.pop() {
            for &next in &self.packages[current].dependencies {
                if next < count && !seen[next] && !self.packages[next].root {
                    seen[next] = true;
                    stack.push(next);
                }
            }
        }
        seen.iter()
            .enumerate()
            .filter(|&(index, &in_tree)| in_tree && !self.packages[index].root)
            .count()
    }

    /// Marks the packages reachable from root packages without traversing
    /// direct `[dev-dependencies]` edges (edges leaving a root package to a
    /// non-root package that has only `DependencyKind::Dev` in `direct_kinds`).
    #[must_use]
    pub fn non_dev_reachable(
        &self,
        direct_kinds: &BTreeMap<String, BTreeSet<DependencyKind>>,
    ) -> Vec<bool> {
        let count = self.packages.len();
        let mut seen = vec![false; count];
        let mut stack: Vec<usize> = (0..count).filter(|&i| self.packages[i].root).collect();
        for &root in &stack {
            seen[root] = true;
        }
        while let Some(current) = stack.pop() {
            let from_root = self.packages[current].root;
            for &next in &self.packages[current].dependencies {
                if next >= count || seen[next] {
                    continue;
                }
                if from_root
                    && !self.packages[next].root
                    && let Some(kinds) = direct_kinds.get(&self.packages[next].name)
                    && !kinds.is_empty()
                    && !kinds.contains(&DependencyKind::Normal)
                    && !kinds.contains(&DependencyKind::Build)
                {
                    continue;
                }
                seen[next] = true;
                stack.push(next);
            }
        }
        seen
    }

    /// Returns `(exclusive, tree)` for `target`: how many non-root packages
    /// would leave the dependency tree if `target` were removed (`exclusive`),
    /// and how many non-root packages `target` transitively pulls in (`tree`).
    #[must_use]
    pub fn package_weight(&self, target: usize) -> (usize, usize) {
        if target >= self.packages.len() {
            return (0, 0);
        }
        let all = self.reachable_without(None);
        let without = self.reachable_without(Some(target));
        let exclusive = all
            .iter()
            .zip(&without)
            .enumerate()
            .filter(|&(index, (before, after))| !self.packages[index].root && *before && !*after)
            .count();
        let tree = self.subtree_non_root_count(target);
        (exclusive, tree)
    }

    /// Weight of each direct dependency: `(index, exclusive, tree)`, where
    /// `exclusive` counts the packages that would leave the dependency tree
    /// if no member depended on it directly (itself included), and `tree`
    /// the packages it pulls in (itself included, project packages excluded).
    ///
    /// Sorted by `exclusive`, heaviest first, then by package order.
    #[must_use]
    pub fn direct_weights(&self) -> Vec<(usize, usize, usize)> {
        let all = self.reachable(None);
        let mut weights: Vec<(usize, usize, usize)> = (0..self.packages.len())
            .filter(|&index| self.packages[index].direct && !self.packages[index].root)
            .map(|index| {
                let without = self.reachable(Some(index));
                let exclusive = all
                    .iter()
                    .zip(&without)
                    .filter(|(before, after)| **before && !**after)
                    .count();
                let mut tree = vec![false; self.packages.len()];
                tree[index] = true;
                let mut stack = vec![index];
                while let Some(current) = stack.pop() {
                    for &next in &self.packages[current].dependencies {
                        if next < tree.len() && !tree[next] && !self.packages[next].root {
                            tree[next] = true;
                            stack.push(next);
                        }
                    }
                }
                (
                    index,
                    exclusive,
                    tree.iter().filter(|&&in_tree| in_tree).count(),
                )
            })
            .collect();
        weights.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
        weights
    }

    /// Crates resolved in more than one version, which Cargo compiles once
    /// per version. Packages of the scanned project are left out.
    ///
    /// Each entry is a crate name and the indices of its versions, oldest
    /// first (semantic version order); entries are sorted by name.
    #[must_use]
    pub fn duplicates(&self) -> Vec<(String, Vec<usize>)> {
        let mut by_name: std::collections::BTreeMap<&str, Vec<usize>> =
            std::collections::BTreeMap::new();
        for (index, package) in self.packages.iter().enumerate() {
            if !package.root {
                by_name.entry(&package.name).or_default().push(index);
            }
        }
        by_name
            .into_iter()
            .filter(|(_, indices)| {
                let versions: std::collections::BTreeSet<&str> = indices
                    .iter()
                    .map(|&index| self.packages[index].version.as_str())
                    .collect();
                versions.len() > 1
            })
            .map(|(name, mut indices)| {
                indices.sort_by(|&left, &right| {
                    let (left, right) =
                        (&self.packages[left].version, &self.packages[right].version);
                    match (semver::Version::parse(left), semver::Version::parse(right)) {
                        (Ok(left), Ok(right)) => left.cmp(&right),
                        _ => left.cmp(right),
                    }
                });
                (name.to_owned(), indices)
            })
            .collect()
    }
}

/// Severity of a finding, on the CVSS qualitative scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// CVSS score 0.0.
    None,
    /// CVSS score 0.1 to 3.9.
    Low,
    /// CVSS score 4.0 to 6.9.
    Medium,
    /// CVSS score 7.0 to 8.9.
    High,
    /// CVSS score 9.0 to 10.0.
    Critical,
}

impl Severity {
    /// Lowercase name used in reports and on the command line.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// What kind of advisory a finding comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvisoryKind {
    /// A security vulnerability.
    Vulnerability,
    /// An informational advisory, such as `unmaintained` or `unsound`.
    Informational(String),
}

/// How likely an advisory is to affect the scanned project's shipped code.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdvisoryRelevance {
    /// No signal rules the advisory out.
    #[default]
    AffectsYou,
    /// The advisory is restricted (for example to a target OS/arch or an
    /// uncalled function on a transitive dependency) and may not apply.
    Possibly,
    /// A concrete signal shows the advisory does not affect the shipped build
    /// (not built, dev-only, non-matching target, or uncalled function on a
    /// direct dependency).
    Unlikely,
}

impl AdvisoryRelevance {
    /// Machine-readable name (`"affects-you"`, `"possibly"`, `"unlikely"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AffectsYou => "affects-you",
            Self::Possibly => "possibly",
            Self::Unlikely => "unlikely",
        }
    }
}

/// A known advisory affecting a resolved package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryFinding {
    /// Index of the affected package in [`Inventory::packages`].
    pub package: usize,
    /// Advisory identifier, such as a `RUSTSEC-` ID, taken from the data.
    pub id: String,
    /// Other identifiers (CVE, GHSA) listed by the advisory.
    pub aliases: Vec<String>,
    /// Advisory title.
    pub title: String,
    /// Publication date of the advisory (`YYYY-MM-DD`).
    pub date: String,
    /// Link to the original report, if any.
    pub url: Option<String>,
    /// Kind of advisory.
    pub kind: AdvisoryKind,
    /// Severity computed from the advisory's CVSS vector; `None` when it has none.
    pub severity: Option<Severity>,
    /// Version requirements that fix the advisory; empty when no fix exists.
    pub patched: Vec<String>,
    /// Architectures declared under `[affected] arch` (empty if unrestricted).
    pub affected_arch: Vec<String>,
    /// Operating systems declared under `[affected] os` (empty if unrestricted).
    pub affected_os: Vec<String>,
    /// Function paths declared under `[affected.functions]` that apply to the
    /// resolved package version.
    pub affected_functions: Vec<String>,
    /// Evaluated likelihood that the advisory affects the project's build.
    pub relevance: AdvisoryRelevance,
    /// Human-readable reason when [`Self::relevance`] is not `AffectsYou`.
    pub relevance_reason: Option<String>,
    /// Reason given in `cargoscope.toml` when this advisory is ignored.
    /// Ignored advisories stay in the report but never fail the scan.
    pub ignored: Option<String>,
}

/// Manifest section a dependency is declared in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DependencyKind {
    /// `[dependencies]`.
    Normal,
    /// `[dev-dependencies]`.
    Dev,
    /// `[build-dependencies]`.
    Build,
}

impl DependencyKind {
    /// Manifest section name.
    #[must_use]
    pub fn section(self) -> &'static str {
        match self {
            Self::Normal => "dependencies",
            Self::Dev => "dev-dependencies",
            Self::Build => "build-dependencies",
        }
    }
}

/// How sure CargoScope is that a dependency is unused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnusedConfidence {
    /// No reference found and no known exception applies.
    Likely,
    /// No reference found, but a known pattern could explain the usage.
    Possibly,
}

impl UnusedConfidence {
    /// Name used in reports.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Likely => "likely-unused",
            Self::Possibly => "possibly-unused",
        }
    }
}

/// A declared dependency for which no usage was found in the sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnusedFinding {
    /// Name of the project package (root or workspace member) declaring it.
    pub declared_by: String,
    /// Manifest of that package, relative to the scanned directory.
    pub manifest: String,
    /// Key used in the manifest, which is also the name used in code.
    pub dependency: String,
    /// Real crate name when the dependency is renamed with `package = "..."`.
    pub package: String,
    /// Manifest section.
    pub kind: DependencyKind,
    /// Confidence level.
    pub confidence: UnusedConfidence,
    /// Evidence: what was searched, and why the confidence is lowered if it is.
    pub evidence: Vec<String>,
    /// Reason given by the user when this finding is ignored in configuration.
    pub ignored: Option<String>,
}

/// Whether an available update stays within SemVer compatibility or breaks it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutdatedKind {
    /// No newer non-yanked version is known.
    #[default]
    None,
    /// Only a SemVer-compatible update (`^current`) is available.
    Compatible,
    /// Only a SemVer-breaking update is available.
    Breaking,
    /// Both a newer SemVer-compatible update and a newer breaking version exist.
    Both,
}

impl OutdatedKind {
    /// Machine-readable name (`"none"`, `"compatible"`, `"breaking"`, `"both"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Compatible => "compatible",
            Self::Breaking => "breaking",
            Self::Both => "both",
        }
    }
}

/// Returns whether `candidate` stays within Cargo's SemVer-compatible caret
/// range (`^current`).
#[must_use]
pub fn is_semver_compatible(current: &semver::Version, candidate: &semver::Version) -> bool {
    if current.major > 0 {
        candidate.major == current.major
    } else if current.minor > 0 {
        candidate.major == 0 && candidate.minor == current.minor
    } else {
        candidate.major == 0 && candidate.minor == 0 && candidate.patch == current.patch
    }
}

/// Registry data about one resolved package, from the local crates.io cache.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageInfo {
    /// SPDX license expression, or `None` when unknown.
    pub license: Option<String>,
    /// Latest published version that is not yanked (stable, unless only
    /// pre-releases exist). `None` when no registry data is cached.
    pub latest_version: Option<String>,
    /// Publication date (`YYYY-MM-DD`) of `latest_version`, when known.
    pub latest_published: Option<String>,
    /// Latest published non-yanked version that is SemVer-compatible with the
    /// resolved version (`^current`), when known.
    pub latest_compatible: Option<String>,
    /// Publication date (`YYYY-MM-DD`) of `latest_compatible`, when known.
    pub compatible_published: Option<String>,
    /// Publication time of the resolved version (RFC 3339, UTC), when known.
    pub published: Option<String>,
    /// Whether the resolved version has been yanked. `None` when unknown.
    pub yanked: Option<bool>,
    /// Whether `latest_version` is newer than the resolved version.
    pub outdated: bool,
    /// Publication date (`YYYY-MM-DD`) of the most recent non-yanked release
    /// of any version, when known.
    pub last_release: Option<String>,
    /// Whether the crate has had no release for [`STALE_YEARS`] years or more
    /// before the registry data was downloaded.
    pub stale: bool,
    /// crates.io owners (user logins, `github:org:team` for teams), when known.
    pub owners: Option<Vec<String>>,
    /// Repository URL declared by the crate, when known.
    pub repository: Option<String>,
    /// Whether the repository is archived on GitHub. `None` when unknown or
    /// not hosted on GitHub.
    pub archived: Option<bool>,
}

/// Whether a crates.io owner stands for a group: a team (`github:org:team`)
/// or the account of the Rust project's organisation.
fn is_shared_account(login: &str) -> bool {
    login.contains(':') || login == "rust-lang-owner"
}

/// Unix seconds of an RFC 3339 UTC timestamp (`2026-11-19T08:30:00Z`, with
/// optional fractional seconds) or of a bare `YYYY-MM-DD` date (midnight).
#[must_use]
pub fn unix_seconds(stamp: &str) -> Option<u64> {
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let text = stamp.get(range)?;
        text.bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| text.parse().ok())?
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    if stamp.get(4..5) != Some("-") || stamp.get(7..8) != Some("-") || !(1..=12).contains(&month) {
        return None;
    }
    let (hour, minute, second) = if stamp.len() == 10 {
        (0, 0, 0)
    } else {
        if !matches!(stamp.get(10..11), Some("T" | " ")) {
            return None;
        }
        let rest = &stamp[19.min(stamp.len())..];
        let utc = rest.ends_with('Z') || rest.ends_with("+00:00") || rest.is_empty();
        if !utc {
            return None;
        }
        (number(11..13)?, number(14..16)?, number(17..19)?)
    };
    // Days from civil (Howard Hinnant's algorithm), the inverse of `utc_date`.
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = shifted_year.div_euclid(400);
    let year_of_era = shifted_year - era * 400;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    u64::try_from(days * 86_400 + hour * 3_600 + minute * 60 + second).ok()
}

/// A resolved version published less than this many hours before the scan
/// is a recent release: compromised releases are usually caught within days.
pub const RECENT_RELEASE_HOURS: u64 = 72;

/// A crate without a release for this many years counts as stale.
pub const STALE_YEARS: u32 = 2;

/// A sign that a dependency may be fragile, from crates.io and GitHub data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintenanceConcern {
    /// No release for [`STALE_YEARS`] years or more.
    Stale,
    /// A single crates.io owner, and no team.
    SingleOwner,
    /// The repository is archived (read-only).
    Archived,
}

impl MaintenanceConcern {
    /// Stable identifier used in JSON and SARIF.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stale => "stale",
            Self::SingleOwner => "single-owner",
            Self::Archived => "archived",
        }
    }
}

impl PackageInfo {
    /// Maintenance concerns, in a fixed order: archived, stale, single owner.
    #[must_use]
    pub fn maintenance_concerns(&self) -> Vec<MaintenanceConcern> {
        let mut concerns = Vec::new();
        if self.archived == Some(true) {
            concerns.push(MaintenanceConcern::Archived);
        }
        if self.stale {
            concerns.push(MaintenanceConcern::Stale);
        }
        if self
            .owners
            .as_ref()
            .is_some_and(|owners| owners.len() == 1 && !is_shared_account(&owners[0]))
        {
            concerns.push(MaintenanceConcern::SingleOwner);
        }
        concerns
    }

    /// Classifies whether newer cached versions for `current_version` are
    /// SemVer-compatible, SemVer-breaking, or both.
    #[must_use]
    pub fn outdated_kind(&self, current_version: &str) -> OutdatedKind {
        if !self.outdated {
            return OutdatedKind::None;
        }
        let Ok(current) = semver::Version::parse(current_version) else {
            return OutdatedKind::None;
        };
        let has_compat = self
            .latest_compatible
            .as_deref()
            .and_then(|v| semver::Version::parse(v).ok())
            .is_some_and(|compat| compat > current && is_semver_compatible(&current, &compat));
        let latest_parsed = self
            .latest_version
            .as_deref()
            .and_then(|v| semver::Version::parse(v).ok())
            .filter(|latest| *latest > current);
        let has_breaking = latest_parsed
            .as_ref()
            .is_some_and(|latest| !is_semver_compatible(&current, latest));
        let latest_is_compat = latest_parsed
            .as_ref()
            .is_some_and(|latest| is_semver_compatible(&current, latest));
        match (has_compat || latest_is_compat, has_breaking) {
            (true, true) => OutdatedKind::Both,
            (true, false) => OutdatedKind::Compatible,
            (false, true) => OutdatedKind::Breaking,
            (false, false) => OutdatedKind::None,
        }
    }

    /// Returns the newest SemVer-compatible upgrade if strictly newer than
    /// `current_version`.
    #[must_use]
    pub fn compatible_upgrade(&self, current_version: &str) -> Option<&str> {
        let current = semver::Version::parse(current_version).ok()?;
        if let Some(compat) = self.latest_compatible.as_deref() {
            let parsed = semver::Version::parse(compat).ok()?;
            if parsed > current && is_semver_compatible(&current, &parsed) {
                return Some(compat);
            }
        }
        if self.outdated
            && let Some(latest) = self.latest_version.as_deref()
        {
            let parsed = semver::Version::parse(latest).ok()?;
            if parsed > current && is_semver_compatible(&current, &parsed) {
                return Some(latest);
            }
        }
        None
    }
}

/// Which checks a scan runs. The inventory is always built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Checks {
    /// Match packages against the RustSec advisory database.
    pub advisories: bool,
    /// Look for likely-unused dependencies.
    pub unused: bool,
    /// Report licenses from the crates.io cache.
    pub licenses: bool,
    /// Report latest and yanked versions from the crates.io cache.
    pub versions: bool,
    /// Check the policy of `cargoscope.toml`, when the file defines one.
    pub policy: bool,
}

impl Checks {
    /// Every check, the default.
    pub const ALL: Self = Self {
        advisories: true,
        unused: true,
        licenses: true,
        versions: true,
        policy: true,
    };

    /// Names accepted by `--checks`, in report order.
    pub const NAMES: [&'static str; 6] = [
        "inventory",
        "advisories",
        "unused",
        "licenses",
        "versions",
        "policy",
    ];

    /// Parses a comma-separated list such as `inventory,advisories`.
    ///
    /// # Errors
    ///
    /// Returns the first unknown name.
    pub fn parse(list: &str) -> Result<Self, String> {
        let mut checks = Self {
            advisories: false,
            unused: false,
            licenses: false,
            versions: false,
            policy: false,
        };
        for name in list
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            match name {
                "inventory" => {}
                "advisories" => checks.advisories = true,
                "unused" => checks.unused = true,
                "licenses" => checks.licenses = true,
                "versions" => checks.versions = true,
                "policy" => checks.policy = true,
                other => return Err(other.to_owned()),
            }
        }
        Ok(checks)
    }

    /// Names of the enabled checks, `inventory` included.
    #[must_use]
    pub fn enabled(self) -> Vec<&'static str> {
        let flags = [
            true,
            self.advisories,
            self.unused,
            self.licenses,
            self.versions,
            self.policy,
        ];
        Self::NAMES
            .iter()
            .zip(flags)
            .filter_map(|(name, enabled)| enabled.then_some(*name))
            .collect()
    }
}

impl Default for Checks {
    fn default() -> Self {
        Self::ALL
    }
}

/// How much `unsafe` code a package contains, counted from its sources.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnsafeCount {
    /// `unsafe { … }` blocks.
    pub blocks: usize,
    /// `unsafe fn` items and `unsafe extern` blocks.
    pub functions: usize,
    /// `unsafe impl` items.
    pub impls: usize,
    /// `unsafe trait` items.
    pub traits: usize,
    /// Other uses of the keyword, such as `#[unsafe(no_mangle)]` or inside macros.
    pub other: usize,
    /// Source files the lexer could not read, so not counted.
    pub unreadable_files: usize,
}

impl UnsafeCount {
    /// Every use of `unsafe`.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.blocks + self.functions + self.impls + self.traits + self.other
    }
}

/// Everything a scan produced, ready to be rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Checks that ran; data for the others is empty.
    pub checks: Checks,
    /// Resolved packages and their dependency graph.
    pub inventory: Inventory,
    /// Advisories affecting resolved packages.
    pub advisories: Vec<AdvisoryFinding>,
    /// Registry data, one entry per package of `inventory`, in the same order.
    pub package_info: Vec<PackageInfo>,
    /// Date the crates.io data was downloaded (`YYYY-MM-DD`), if any.
    pub registry_date: Option<String>,
    /// Dependencies with no usage found, including ignored ones.
    pub unused: Vec<UnusedFinding>,
    /// Date the RustSec database was downloaded (`YYYY-MM-DD`), if known.
    pub advisory_db_date: Option<String>,
    /// Whether unused dependencies were checked with the compiler
    /// (`scan --precise`) in addition to the static analysis.
    pub unused_precise: bool,
    /// Policy violations; `None` when no policy is configured or checked.
    pub policy: Option<Vec<policy::Violation>>,
    /// Non-fatal problems to show the user, such as unreadable advisory files.
    pub warnings: Vec<String>,
    /// Sections under which the project's packages declare each direct
    /// dependency, by crate name (empty when the manifests were not read).
    pub direct_kinds:
        std::collections::BTreeMap<String, std::collections::BTreeSet<DependencyKind>>,
    /// `unsafe` code of each package, by package index (empty when not
    /// counted; `None` for packages whose sources are not on disk).
    pub unsafe_code: Vec<Option<UnsafeCount>>,
}

#[cfg(test)]
mod tests {
    use super::{Checks, Inventory, Package};

    #[test]
    fn parses_check_lists() {
        let checks = Checks::parse("inventory, advisories,versions").expect("valid");
        assert!(checks.advisories && checks.versions && !checks.unused && !checks.licenses);
        assert_eq!(
            checks.enabled(),
            vec!["inventory", "advisories", "versions"]
        );
        assert_eq!(Checks::parse("inventory,typo"), Err("typo".to_owned()));
        assert_eq!(Checks::default().enabled(), Checks::NAMES.to_vec());
    }

    fn package(name: &str, root: bool, dependencies: Vec<usize>) -> Package {
        Package {
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            source: None,
            root,
            direct: false,
            dependencies,
        }
    }

    #[test]
    fn finds_shortest_path_from_a_root() {
        // 0 app -> 1 a -> 2 b -> 3 target ; 0 app -> 4 c -> 3 target
        let inventory = Inventory {
            packages: vec![
                package("app", true, vec![1, 4]),
                package("a", false, vec![2]),
                package("b", false, vec![3]),
                package("target", false, vec![]),
                package("c", false, vec![3]),
            ],
        };
        assert_eq!(inventory.path_to(3), Some(vec![0, 4, 3]));
        assert_eq!(inventory.path_to(0), Some(vec![0]));
    }

    #[test]
    fn weighs_direct_dependencies_by_what_only_they_pull_in() {
        // app -> heavy -> {a, shared}; app -> light -> shared; app -> shared
        // tool (member) -> b ; b is not direct of app but reached from tool.
        let direct = |name: &str, dependencies: Vec<usize>| Package {
            direct: true,
            ..package(name, false, dependencies)
        };
        let inventory = Inventory {
            packages: vec![
                package("app", true, vec![1, 2, 4]),
                direct("heavy", vec![3, 4]),
                direct("light", vec![4]),
                package("a", false, vec![]),
                direct("shared", vec![]),
                package("tool", true, vec![6]),
                direct("b", vec![]),
            ],
        };
        let weights = inventory.direct_weights();
        // heavy: removing it drops heavy and a (shared stays): 2, tree 3.
        assert_eq!(weights[0], (1, 2, 3));
        // light: 1 (itself), tree 2; b: 1; shared: still reached via heavy, 0.
        assert!(weights.contains(&(2, 1, 2)));
        assert!(weights.contains(&(6, 1, 1)));
        assert_eq!(weights.last(), Some(&(4, 0, 1)));
    }

    #[test]
    fn finds_crates_resolved_in_several_versions() {
        let versioned = |name: &str, version: &str, root: bool| Package {
            version: version.to_owned(),
            ..package(name, root, vec![])
        };
        let inventory = Inventory {
            packages: vec![
                versioned("app", "0.1.0", true),
                versioned("app", "0.2.0", false),
                versioned("syn", "1.10.0", false),
                versioned("syn", "1.9.0", false),
                versioned("serde", "1.0.0", false),
                versioned("member", "0.1.0", true),
                versioned("member", "0.2.0", true),
            ],
        };
        // A registry crate with the name of a member counts only once;
        // members themselves are never duplicates.
        // Oldest first, in semantic version order: 1.9.0 before 1.10.0.
        assert_eq!(inventory.duplicates(), vec![("syn".to_owned(), vec![3, 2])]);
    }

    #[test]
    fn unreachable_package_has_no_path() {
        let inventory = Inventory {
            packages: vec![
                package("app", true, vec![]),
                package("orphan", false, vec![]),
            ],
        };
        assert_eq!(inventory.path_to(1), None);
        assert_eq!(inventory.path_to(9), None);
    }

    #[test]
    fn survives_dependency_cycles() {
        let inventory = Inventory {
            packages: vec![
                package("app", true, vec![1]),
                package("a", false, vec![2]),
                package("b", false, vec![1]),
            ],
        };
        assert_eq!(inventory.path_to(2), Some(vec![0, 1, 2]));
    }

    #[test]
    fn finds_dependents_all_paths_and_package_weight() {
        // 0 app -> {1 a, 2 b, 5 d}; 1 a -> {3 target, 4 c}; 2 b -> {3 target}; 3 target -> {4 c}
        let inventory = Inventory {
            packages: vec![
                package("app", true, vec![1, 2, 5]),
                package("a", false, vec![3, 4]),
                package("b", false, vec![3]),
                package("target", false, vec![4]),
                package("c", false, vec![]),
                package("d", false, vec![1]),
            ],
        };
        assert_eq!(inventory.dependents_of(3), vec![1, 2]);
        assert_eq!(
            inventory.paths_to(3, 10),
            vec![vec![0, 1, 3], vec![0, 2, 3], vec![0, 5, 1, 3]]
        );
        assert_eq!(inventory.paths_to(3, 2), vec![vec![0, 1, 3], vec![0, 2, 3]]);
        // Removing `target` only drops `target` itself (since `a` also depends on `c`): exclusive = 1, tree = 2.
        assert_eq!(inventory.package_weight(3), (1, 2));
        // Removing `d` drops `d` only (since `app` also depends on `a`): exclusive = 1, tree = 4 ({d, a, target, c}).
        assert_eq!(inventory.package_weight(5), (1, 4));
    }

    #[test]
    fn classifies_semver_compatible_and_breaking_updates() {
        let compat = super::PackageInfo {
            latest_version: Some("1.4.0".to_owned()),
            latest_compatible: Some("1.4.0".to_owned()),
            outdated: true,
            ..Default::default()
        };
        assert_eq!(
            compat.outdated_kind("1.2.0"),
            super::OutdatedKind::Compatible
        );
        assert_eq!(compat.compatible_upgrade("1.2.0"), Some("1.4.0"));

        let both = super::PackageInfo {
            latest_version: Some("0.9.0".to_owned()),
            latest_compatible: Some("0.8.5".to_owned()),
            outdated: true,
            ..Default::default()
        };
        assert_eq!(both.outdated_kind("0.8.1"), super::OutdatedKind::Both);
        assert_eq!(both.compatible_upgrade("0.8.1"), Some("0.8.5"));

        let breaking = super::PackageInfo {
            latest_version: Some("0.0.4".to_owned()),
            latest_compatible: Some("0.0.3".to_owned()),
            outdated: true,
            ..Default::default()
        };
        assert_eq!(
            breaking.outdated_kind("0.0.3"),
            super::OutdatedKind::Breaking
        );
        assert_eq!(breaking.compatible_upgrade("0.0.3"), None);
    }

    #[test]
    fn lists_maintenance_concerns_and_treats_teams_as_shared_ownership() {
        use super::MaintenanceConcern::{Archived, SingleOwner, Stale};
        let owners = |logins: &[&str]| Some(logins.iter().map(|&l| l.to_owned()).collect());
        let info = super::PackageInfo {
            stale: true,
            archived: Some(true),
            owners: owners(&["alice"]),
            ..Default::default()
        };
        assert_eq!(
            info.maintenance_concerns(),
            vec![Archived, Stale, SingleOwner]
        );
        let team = super::PackageInfo {
            owners: owners(&["github:rust-lang:libs"]),
            ..Default::default()
        };
        assert!(team.maintenance_concerns().is_empty());
        let rust_lang = super::PackageInfo {
            owners: owners(&["rust-lang-owner"]),
            ..Default::default()
        };
        assert!(rust_lang.maintenance_concerns().is_empty());
        let two = super::PackageInfo {
            owners: owners(&["alice", "bob"]),
            archived: Some(false),
            ..Default::default()
        };
        assert!(two.maintenance_concerns().is_empty());
        assert!(
            super::PackageInfo::default()
                .maintenance_concerns()
                .is_empty()
        );
    }
}
