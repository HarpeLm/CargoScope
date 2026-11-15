#!/bin/sh
# Judges one repository for the blind benchmark, on a disposable CI machine.
#
# Usage: judge-one.sh OWNER/NAME COMMIT OUT_DIR
#
# 1. Runs the frozen tools (cargoscope, cargo-machete, cargo-shear must be on
#    the PATH) on the repository: static analysis only.
# 2. Compiles it with Rust 1.99.1 and rustc's unused_crate_dependencies lint
#    (from 1.100, Cargo reports unused dependencies itself and rustc's JSON
#    messages no longer carry them): all targets and features first, then
#    without benches (dev-dependencies are then not judged). A repository
#    that compiles neither way is dropped.
# 3. Turns the compiler messages into verdicts with ../compiler-judge/judge.py.
set -u
repo="$1"; commit="$2"; out="$3"
here=$(cd "$(dirname "$0")" && pwd)
d=$(echo "$repo" | tr / _)
mkdir -p "$out/judge" "$out/tools"
work=$(mktemp -d)
src="$work/src"

git init -q "$src"
git -C "$src" fetch -q --depth 1 "https://github.com/$repo" "$commit" || { echo "$d clone-failed" > "$out/judge/$d.status"; exit 0; }
git -C "$src" checkout -q FETCH_HEAD
cd "$src" || exit 0
cargo fetch -q > /dev/null 2>&1

# Frozen tools, before any compilation.
cargoscope scan . --checks inventory,unused --format json --fail-on none > "$out/tools/cs-$d.json" 2> "$out/tools/cs-$d.err"
cargo machete > "$out/tools/machete-$d.txt" 2>&1
cargo shear --format json --color never > "$out/tools/shear-$d.json" 2> "$out/tools/shear-$d.err"

# The compiler as judge.
mode=failed; skip=""
for targets in "--all-targets" "--lib --bins --tests --examples"; do
  # shellcheck disable=SC2086
  RUSTFLAGS="-W unused-crate-dependencies" timeout 1800 \
    cargo check --workspace $targets --all-features --message-format=json \
      --target-dir "$work/target" > "$work/messages.json" 2> "$out/judge/$d.stderr.txt"
  if [ $? = 0 ]; then
    if [ "$targets" = "--all-targets" ]; then
      mode="all-features"
    else
      mode="no-benches all-features"; skip="skip-dev"
    fi
    break
  fi
done
echo "$d $mode" > "$out/judge/$d.status"
tail -n 30 "$out/judge/$d.stderr.txt" > "$out/judge/$d.stderr.tail" && rm "$out/judge/$d.stderr.txt"
[ "$mode" = failed ] && exit 0
cargo metadata --no-deps --format-version 1 > "$work/metadata.json" 2> /dev/null
# shellcheck disable=SC2086
python3 "$here/../compiler-judge/judge.py" "$work/messages.json" "$work/metadata.json" "$src" "$out/judge/$d.verdicts.json" $skip
