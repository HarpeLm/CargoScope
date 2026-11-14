"""Compiler judge for unused dependencies, independent of CargoScope's code.

Input: Cargo's --message-format=json output of
  RUSTFLAGS="-W unused-crate-dependencies" cargo check --workspace --all-targets [--all-features]
and `cargo metadata --no-deps` of the same workspace.

A declared dependency of a workspace member is:
  - "unused" when rustc reports it unused in every compiled target of the
    member that receives that kind of dependency;
  - "used" when at least one such target uses it;
  - "unknown" when the member or the dependency was not compiled (another
    platform, a failed build): excluded from the measure.
"""
import json
import os
import sys


def receives(artifact):
    kinds = artifact["target"]["kind"]
    test = artifact.get("profile", {}).get("test", False)
    if "custom-build" in kinds:
        return "build"
    if test or any(kind in ("test", "bench", "example") for kind in kinds):
        return "normal+dev"
    return "normal"


def judge(messages_path, metadata_path, root, skip_dev=False):
    metadata = json.load(open(metadata_path))
    members = {p["id"]: p for p in metadata["packages"] if p["id"] in set(metadata["workspace_members"])}
    by_manifest = {os.path.realpath(p["manifest_path"]): p for p in members.values()}

    targets = {}   # manifest -> (kind, name) -> {"receives": set, "unused": set}
    built = set()  # names of every compiled package
    for line in open(messages_path, errors="ignore"):
        try:
            message = json.loads(line)
        except ValueError:
            continue
        reason = message.get("reason")
        if reason == "compiler-artifact":
            built.add(message["package_id"].split("#")[-1].split("@")[0].split("/")[-1])
            built.add(message["target"]["name"].replace("-", "_"))
        if reason not in ("compiler-artifact", "compiler-message"):
            continue
        # Messages come from the container, where the repository is /src.
        manifest = message["manifest_path"]
        if manifest.startswith("/src/"):
            manifest = os.path.join(root, manifest[len("/src/"):])
        manifest = os.path.realpath(manifest)
        if manifest not in by_manifest:
            continue
        key = (json.dumps(message["target"]["kind"]), message["target"]["name"])
        entry = targets.setdefault(manifest, {}).setdefault(key, {"receives": set(), "unused": set()})
        if reason == "compiler-artifact":
            entry["receives"].add(receives(message))
        else:
            inner = message.get("message", {})
            if (inner.get("code") or {}).get("code") == "unused_crate_dependencies":
                text = inner.get("message", "")
                parts = text.split("`")
                if len(parts) > 1:
                    entry["unused"].add(parts[1])

    verdicts = {}
    for manifest, package in by_manifest.items():
        label = os.path.relpath(manifest, root)
        package_targets = targets.get(manifest, {})
        for dependency in package["dependencies"]:
            kind = dependency.get("kind") or "normal"
            section = {"normal": "dependencies", "dev": "dev-dependencies", "build": "build-dependencies"}[kind]
            key_name = dependency.get("rename") or dependency["name"]
            ident = key_name.replace("-", "_")
            wanted = {"normal": ("normal", "normal+dev"), "dev": ("normal+dev",), "build": ("build",)}[kind]
            relevant = [t for t in package_targets.values() if t["receives"] & set(wanted)]
            compiled = dependency["name"] in built or dependency["name"].replace("-", "_") in built
            if not relevant or not compiled or (skip_dev and kind == "dev"):
                verdict = "unknown"
            elif all(ident in t["unused"] for t in relevant):
                verdict = "unused"
            else:
                verdict = "used"
            verdicts[f"{label}|{section}|{key_name}"] = verdict
    return verdicts


if __name__ == "__main__":
    messages, metadata, root, out = sys.argv[1:5]
    skip_dev = len(sys.argv) > 5 and sys.argv[5] == "skip-dev"
    json.dump(judge(messages, metadata, os.path.realpath(root), skip_dev), open(out, "w"), indent=1, sort_keys=True)
