#!/bin/sh
# Re-download the Wycheproof AES-FF1 vector files into
# ff1/testdata/wycheproof and verify them against SHA256SUMS. Run from the
# repository root.
set -eu

COMMIT=3fa63dd0344abb611f1fb1d77e119938603ea230
BASE="https://raw.githubusercontent.com/C2SP/wycheproof/$COMMIT/testvectors_v1"
DIR=ff1/testdata/wycheproof

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cut -d' ' -f3 "$DIR/SHA256SUMS" | while read -r f; do
	curl -sSfL -o "$tmp/$f" "$BASE/$f"
done
cp "$DIR/SHA256SUMS" "$tmp/"
if command -v sha256sum >/dev/null; then
	(cd "$tmp" && sha256sum -c --quiet SHA256SUMS)
else
	(cd "$tmp" && shasum -a 256 -c --quiet SHA256SUMS)
fi
cp "$tmp"/aes_ff1_*_test.json "$DIR/"
echo "verified and wrote $(ls "$tmp"/aes_ff1_*_test.json | wc -l | tr -d ' ') files to $DIR"
