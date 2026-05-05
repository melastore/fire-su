#!/usr/bin/env sh
set -eu

ROOT="${0%/*}"
[ "$ROOT" = "$0" ] && ROOT="."
CRATE="$ROOT/fire-su-v3/backend/fire-su"
OUT="$ROOT/dist/android"

mkdir -p "$OUT"

targets="
aarch64-linux-android
armv7-linux-androideabi
x86_64-linux-android
i686-linux-android
"

for target in $targets; do
	if ! rustup target list --installed | grep -qx "$target"; then
		echo "skip $target: rust target not installed"
		continue
	fi
	echo "building $target"
	(cd "$CRATE" && cargo build --release --target "$target")
	cp "$CRATE/target/$target/release/fire-su" "$OUT/fire-su-$target"
done

echo "artifacts: $OUT"
