//! Data model shared by all CargoScope crates.

/// The current application version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A package resolved in a Cargo lockfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// Crate name.
    pub name: String,
    /// Resolved crate version.
    pub version: String,
    /// Optional Cargo source, such as a registry URL.
    pub source: Option<String>,
    /// Whether this package is declared directly by the scanned manifest.
    pub direct: bool,
}

/// The resolved Cargo packages found in a project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    /// Packages sorted by name and version.
    pub packages: Vec<Package>,
}
