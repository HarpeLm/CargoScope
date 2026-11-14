#!/bin/sh
# Compiles each repository in a network-less container with rustc's
# unused_crate_dependencies lint, then runs the independent judge.
# Usage: run-judge.sh ORACLE_DIR
set -u
O="$1"
mkdir -p "$O/judge" "$O/targets"
for repo in "$O"/repos/*; do
  d=$(basename "$repo")
  [ -f "$O/judge/$d.verdicts.json" ] && continue
  mode=all-features
  for features in "--all-features" ""; do
    python3 "$O/timeout.py" 1200 docker run --rm --network none \
      -v "$O/cargo-home:/cargo" -v "$repo:/src" -v "$O/targets:/targets" \
      -e CARGO_HOME=/cargo -e RUSTFLAGS="-W unused-crate-dependencies" \
      -w /src rust:1 \
      cargo check --offline --workspace --all-targets $features \
        --message-format=json --target-dir "/targets/$d" \
      > "$O/judge/$d.messages.json" 2> "$O/judge/$d.stderr.txt"
    status=$?
    [ "$status" = 0 ] && break
    mode=default-features
  done
  [ "$status" = 0 ] || mode=failed
  echo "$d $mode $status" >> "$O/judge/status.txt"
  [ "$mode" = failed ] && continue
  (cd "$repo" && CARGO_HOME="$O/cargo-home" RUSTUP_TOOLCHAIN=stable RUSTUP_AUTO_INSTALL=0 \
    cargo metadata --no-deps --offline --format-version 1 > "$O/judge/$d.metadata.json" 2>/dev/null)
  python3 "$O/judge.py" "$O/judge/$d.messages.json" "$O/judge/$d.metadata.json" "$repo" "$O/judge/$d.verdicts.json"
done
