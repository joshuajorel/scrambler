#!/bin/sh
# Re-download the NIST ACVP FF1 vector set into ff1/testdata/acvp and verify
# it against the pinned hashes. Run from the repository root.
set -eu

COMMIT=975de31eb83d87039ec88934fdc47d8c312b892d
URL="https://raw.githubusercontent.com/usnistgov/ACVP-Server/$COMMIT/gen-val/json-files/ACVP-AES-FF1-1.0/internalProjection.json"
SHA256=63cd6642095fbb1ce7af3fa53d7d720d725a58fe331d35ced1540b5e433668ee
BLOB=39faea241274305417050ac2b75f599d89ff1334
OUT=ff1/testdata/acvp/internalProjection.json

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl -sSfL -o "$tmp" "$URL"

got=$( (command -v sha256sum >/dev/null && sha256sum "$tmp" || shasum -a 256 "$tmp") | cut -d' ' -f1)
[ "$got" = "$SHA256" ] || { echo "sha256 mismatch: got $got, want $SHA256" >&2; exit 1; }
blob=$(git hash-object "$tmp")
[ "$blob" = "$BLOB" ] || { echo "git blob mismatch: got $blob, want $BLOB" >&2; exit 1; }

cp "$tmp" "$OUT"
echo "wrote $OUT (sha256 $got)"
