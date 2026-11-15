//! Dependencies of a compiled Rust binary (`cargoscope audit-bin`).
//!
//! Two sources, best first:
//!
//! 1. **cargo-auditable data**: `cargo auditable build` embeds the exact
//!    dependency tree as zlib-compressed JSON in a `.dep-v0` section. It is
//!    found by scanning the file for zlib streams that decompress to
//!    `{"packages":`, so ELF, Mach-O and PE binaries need no parser.
//! 2. **Registry paths**: without that data, the paths that panic messages
//!    keep (`.../registry/src/index.crates.io-.../serde-1.0.200/src/de.rs`)
//!    name some crates and their versions. The list is incomplete: crates with
//!    no panic message in the binary are missing, and there is no tree.
//!
//! Nothing is executed: the file is only read.

use std::collections::BTreeSet;
use std::io::Read;

use cargoscope_core::{Inventory, Package};
use serde_json::Value;

/// crates.io, as Cargo.lock names it.
const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// Largest decompressed cargo-auditable data accepted.
const MAX_AUDIT_DATA: u64 = 16 * 1024 * 1024;

/// Where the dependency list of a binary comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinarySource {
    /// Exact tree embedded by cargo-auditable.
    Auditable,
    /// Crates named by registry paths in the binary: incomplete, no tree.
    RegistryPaths,
}

/// The dependencies found in a binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryInventory {
    /// The packages, with the binary itself as root.
    pub inventory: Inventory,
    /// Where they come from.
    pub source: BinarySource,
}

/// Reads the dependencies of a binary from its bytes. `name` labels the root
/// package when the data has none (registry paths).
///
/// Returns `None` when the binary has neither cargo-auditable data nor
/// registry paths (not a Rust binary, or stripped of both).
#[must_use]
pub fn inventory_of(bytes: &[u8], name: &str) -> Option<BinaryInventory> {
    if let Some(inventory) = auditable_inventory(bytes) {
        return Some(BinaryInventory {
            inventory,
            source: BinarySource::Auditable,
        });
    }
    let crates = registry_paths(bytes);
    if crates.is_empty() {
        return None;
    }
    let mut packages = vec![Package {
        name: name.to_owned(),
        version: "0.0.0".to_owned(),
        source: None,
        root: true,
        direct: false,
        dependencies: (1..=crates.len()).collect(),
    }];
    packages.extend(crates.into_iter().map(|(name, version)| Package {
        name,
        version,
        source: Some(CRATES_IO.to_owned()),
        root: false,
        direct: false,
        dependencies: Vec::new(),
    }));
    Some(BinaryInventory {
        inventory: Inventory { packages },
        source: BinarySource::RegistryPaths,
    })
}

/// Finds and decodes cargo-auditable data: a zlib stream (compression level
/// header `78 01`, `78 5E`, `78 9C` or `78 DA`) whose content starts with
/// `{"packages":`.
fn auditable_inventory(bytes: &[u8]) -> Option<Inventory> {
    bytes.windows(2).enumerate().find_map(|(start, header)| {
        if header[0] != 0x78 || ![0x01, 0x5E, 0x9C, 0xDA].contains(&header[1]) {
            return None;
        }
        let mut decoder = flate2::read::ZlibDecoder::new(&bytes[start..]);
        let mut prefix = [0u8; 12];
        decoder.read_exact(&mut prefix).ok()?;
        if &prefix != b"{\"packages\":" {
            return None;
        }
        let mut text = prefix.to_vec();
        decoder.take(MAX_AUDIT_DATA).read_to_end(&mut text).ok()?;
        parse_auditable(&serde_json::from_slice(&text).ok()?)
    })
}

/// Converts cargo-auditable JSON (`{"packages": [{"name", "version",
/// "source", "kind", "dependencies", "root"}]}`) into an inventory.
fn parse_auditable(data: &Value) -> Option<Inventory> {
    let entries = data.get("packages")?.as_array()?;
    let mut packages: Vec<Package> = entries
        .iter()
        .map(|entry| {
            let text = |key: &str| entry.get(key).and_then(Value::as_str).unwrap_or_default();
            let source = match text("source") {
                "crates.io" => Some(CRATES_IO.to_owned()),
                "local" | "" => None,
                other => Some(other.to_owned()),
            };
            Package {
                name: text("name").to_owned(),
                version: text("version").to_owned(),
                source,
                root: entry.get("root").and_then(Value::as_bool).unwrap_or(false),
                direct: false,
                dependencies: entry
                    .get("dependencies")
                    .and_then(Value::as_array)
                    .map(|indices| {
                        indices
                            .iter()
                            .filter_map(Value::as_u64)
                            .filter_map(|index| usize::try_from(index).ok())
                            .filter(|&index| index < entries.len())
                            .collect()
                    })
                    .unwrap_or_default(),
            }
        })
        .collect();
    if packages.iter().any(|package| package.name.is_empty()) {
        return None;
    }
    let direct: BTreeSet<usize> = packages
        .iter()
        .filter(|package| package.root)
        .flat_map(|package| package.dependencies.iter().copied())
        .collect();
    for index in direct {
        packages[index].direct = !packages[index].root;
    }
    Some(Inventory { packages })
}

/// `(name, version)` of the crates named by registry source paths:
/// `registry/src/<index>/<name>-<version>/`, with `/` or `\` separators.
fn registry_paths(bytes: &[u8]) -> BTreeSet<(String, String)> {
    let mut crates = BTreeSet::new();
    for marker in [&b"registry/src/"[..], &b"registry\\src\\"[..]] {
        let mut rest = bytes;
        while let Some(position) = find(rest, marker) {
            rest = &rest[position + marker.len()..];
            // Skip the index directory (`index.crates.io-1949cf8c6b5b557f`).
            let Some(separator) = rest.iter().position(|&b| b == b'/' || b == b'\\') else {
                break;
            };
            let after = &rest[separator + 1..];
            let end = after
                .iter()
                .position(|&b| b == b'/' || b == b'\\' || !b.is_ascii_graphic())
                .unwrap_or(after.len());
            if let Ok(directory) = std::str::from_utf8(&after[..end])
                && let Some(found) = split_name_version(directory)
            {
                crates.insert(found);
            }
        }
    }
    crates
}

/// `serde-1.0.200` -> `("serde", "1.0.200")`: the version starts after the
/// last `-` followed by a digit and parses as semver.
fn split_name_version(directory: &str) -> Option<(String, String)> {
    let split = directory
        .char_indices()
        .filter(|&(index, c)| {
            c == '-' && directory[index + 1..].starts_with(|d: char| d.is_ascii_digit())
        })
        .map(|(index, _)| index)
        .find(|&index| semver::Version::parse(&directory[index + 1..]).is_ok())?;
    let name = &directory[..split];
    let valid = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    valid.then(|| (name.to_owned(), directory[split + 1..].to_owned()))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::{BinarySource, inventory_of, split_name_version};
    use std::io::Write;

    fn compress(text: &str) -> Vec<u8> {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(text.as_bytes()).expect("compress");
        encoder.finish().expect("compress")
    }

    #[test]
    fn reads_cargo_auditable_data_anywhere_in_the_file() {
        let json = r#"{"packages":[{"name":"app","version":"0.1.0","source":"local","dependencies":[1,2],"root":true},{"name":"serde_json","version":"1.0.128","source":"crates.io","dependencies":[2]},{"name":"itoa","version":"1.0.11","source":"crates.io"},{"name":"cc","version":"1.1.0","source":"crates.io","kind":"build"}]}"#;
        // A false zlib header before the real stream must be skipped.
        let mut bytes = b"\x7fELF....\x78\xda not zlib ...".to_vec();
        bytes.extend(compress(json));
        bytes.extend(b"...trailing section data");
        let found = inventory_of(&bytes, "ignored").expect("found");
        assert_eq!(found.source, BinarySource::Auditable);
        let packages = &found.inventory.packages;
        assert_eq!(packages.len(), 4);
        assert!(packages[0].root && packages[0].source.is_none());
        assert_eq!(packages[1].name, "serde_json");
        assert!(packages[1].direct && packages[2].direct && !packages[3].direct);
        assert_eq!(
            packages[1].source.as_deref(),
            Some("registry+https://github.com/rust-lang/crates.io-index")
        );
        assert_eq!(packages[1].dependencies, vec![2]);
    }

    #[test]
    fn falls_back_to_registry_paths_of_panic_messages() {
        let bytes = b"\x00called `Option::unwrap()` on a `None` value\x00/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde_json-1.0.128/src/de.rs\x00C:\\Users\\u\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\proc-macro2-1.0.86\\src\\lib.rs\x00/x/registry/src/index.crates.io-1949cf8c6b5b557f/serde_json-1.0.128/src/ser.rs\x00";
        let found = inventory_of(bytes, "tool").expect("found");
        assert_eq!(found.source, BinarySource::RegistryPaths);
        let names: Vec<(&str, &str)> = found
            .inventory
            .packages
            .iter()
            .map(|package| (package.name.as_str(), package.version.as_str()))
            .collect();
        assert_eq!(
            names,
            vec![
                ("tool", "0.0.0"),
                ("proc-macro2", "1.0.86"),
                ("serde_json", "1.0.128")
            ]
        );
        assert_eq!(found.inventory.path_to(2), Some(vec![0, 2]));
        assert_eq!(inventory_of(b"not a rust binary", "x"), None);
    }

    #[test]
    fn splits_crate_directories_into_name_and_version() {
        assert_eq!(
            split_name_version("wasi-0.11.0+wasi-snapshot-preview1"),
            Some((
                "wasi".to_owned(),
                "0.11.0+wasi-snapshot-preview1".to_owned()
            ))
        );
        assert_eq!(
            split_name_version("windows-sys-0.52.0"),
            Some(("windows-sys".to_owned(), "0.52.0".to_owned()))
        );
        assert_eq!(split_name_version("no-version"), None);
    }
}
