//! Data model shared by all CargoScope crates.

use std::collections::VecDeque;

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
}

/// Everything a scan produced, ready to be rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Resolved packages and their dependency graph.
    pub inventory: Inventory,
    /// Advisories affecting resolved packages.
    pub advisories: Vec<AdvisoryFinding>,
    /// Date the RustSec database was downloaded (`YYYY-MM-DD`), if known.
    pub advisory_db_date: Option<String>,
    /// Non-fatal problems to show the user, such as unreadable advisory files.
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::{Inventory, Package};

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
}
