#!/bin/sh
# Second pass for repositories whose benches need nightly: libraries,
# binaries, tests and examples only; dev-dependencies are then judged unknown.
set -u
O="$1"
TOOLCHAIN=$(docker run --rm --network none rust:1 rustup default | cut -d' ' -f1)
for d in $(awk '$2=="failed"{print $1}' "$O/judge/status.txt"); do
  [ "$d" = servo_rust-smallvec ] && continue
  repo="$O/repos/$d"
  mode=failed
  for features in "--all-features" ""; do
    python3 "$O/timeout.py" 1200 docker run --rm --network none \
      -v "$O/cargo-home:/cargo" -v "$repo:/src" -v "$O/targets:/targets" \
      -e CARGO_HOME=/cargo -e RUSTUP_TOOLCHAIN="$TOOLCHAIN" -e RUSTFLAGS="-W unused-crate-dependencies" \
      -w /src rust:1 \
      cargo check --offline --workspace --lib --bins --tests --examples $features \
        --message-format=json --target-dir "/targets/$d" \
      > "$O/judge/$d.messages.json" 2> "$O/judge/$d.stderr.txt"
    if [ $? = 0 ]; then mode="no-benches${features:+ all-features}"; break; fi
  done
  echo "$d $mode" >> "$O/judge/retry-status.txt"
  [ "$mode" = failed ] && continue
  (cd "$repo" && CARGO_HOME="$O/cargo-home" RUSTUP_TOOLCHAIN=stable RUSTUP_AUTO_INSTALL=0 \
    cargo metadata --no-deps --offline --format-version 1 > "$O/judge/$d.metadata.json" 2>/dev/null)
  python3 "$O/judge.py" "$O/judge/$d.messages.json" "$O/judge/$d.metadata.json" "$repo" "$O/judge/$d.verdicts.json" skip-dev
done
