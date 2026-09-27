#!/bin/sh
# Regenerates the differential test vectors in ff1/testdata:
#
#   differential_fpe-rs.json         Rust fpe crate (pinned in fpe-rs/Cargo.toml
#                                    and fpe-rs/Cargo.lock), radix 2..65536
#   differential_bouncycastle.json   Bouncy Castle bcprov-jdk18on (pinned below),
#                                    radix 2..65535
#
# Needs cargo (Rust 1.80+) and a JDK 17+ (javac/java on PATH or JAVA_HOME).
# Run from the repository root. Outputs are deterministic: re-running with
# the same pinned versions reproduces the files byte for byte.
#
# Usage: tools/differential/generate.sh [fpe-rs|bouncycastle]...
set -eu

ROOT=$(pwd)
OUT="$ROOT/ff1/testdata"
DIR="$ROOT/tools/differential"

BC_VERSION=1.86
BC_JAR="bcprov-jdk18on-$BC_VERSION.jar"
BC_URL="https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/$BC_VERSION/$BC_JAR"
BC_SHA256=2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/scrambler-differential"

sha256() {
	if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

gen_fpe_rs() {
	(cd "$DIR/fpe-rs" && cargo run --locked --release --quiet) >"$OUT/differential_fpe-rs.json.tmp"
	mv "$OUT/differential_fpe-rs.json.tmp" "$OUT/differential_fpe-rs.json"
	echo "wrote ff1/testdata/differential_fpe-rs.json"
}

gen_bouncycastle() {
	java=java
	javac=javac
	if [ -n "${JAVA_HOME:-}" ]; then
		java="$JAVA_HOME/bin/java"
		javac="$JAVA_HOME/bin/javac"
	fi
	mkdir -p "$CACHE"
	if [ ! -f "$CACHE/$BC_JAR" ] || [ "$(sha256 "$CACHE/$BC_JAR")" != "$BC_SHA256" ]; then
		curl -sSfL -o "$CACHE/$BC_JAR.tmp" "$BC_URL"
		got=$(sha256 "$CACHE/$BC_JAR.tmp")
		[ "$got" = "$BC_SHA256" ] || { echo "$BC_JAR: sha256 $got, want $BC_SHA256" >&2; exit 1; }
		mv "$CACHE/$BC_JAR.tmp" "$CACHE/$BC_JAR"
	fi
	classes=$(mktemp -d)
	"$javac" -encoding UTF-8 --release 17 -cp "$CACHE/$BC_JAR" -d "$classes" "$DIR/bouncycastle/GenerateVectors.java"
	"$java" -cp "$classes:$CACHE/$BC_JAR" GenerateVectors "$BC_VERSION" >"$OUT/differential_bouncycastle.json.tmp"
	rm -rf "$classes"
	mv "$OUT/differential_bouncycastle.json.tmp" "$OUT/differential_bouncycastle.json"
	echo "wrote ff1/testdata/differential_bouncycastle.json"
}

[ $# -gt 0 ] || set -- fpe-rs bouncycastle
for g in "$@"; do
	case $g in
	fpe-rs) gen_fpe_rs ;;
	bouncycastle) gen_bouncycastle ;;
	*) echo "unknown generator $g" >&2; exit 2 ;;
	esac
done
