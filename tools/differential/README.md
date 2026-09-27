# Differential vector generators

Two independent FF1 implementations compute ciphertexts for the same kinds
of inputs; `TestDifferential` (`ff1/vectors_test.go`) checks that this
package produces exactly the same results in both directions.

| Output | Generator | Library (pinned) | Radix | Vectors |
|---|---|---|---|---|
| `ff1/testdata/differential_fpe-rs.json` | `fpe-rs/` (Rust) | [`fpe`](https://crates.io/crates/fpe) 0.6.1 (str4d/fpe), `aes` 0.8.4; the rest of the tree in `fpe-rs/Cargo.lock` | 2..65536 | 846 |
| `ff1/testdata/differential_bouncycastle.json` | `bouncycastle/GenerateVectors.java` | `org.bouncycastle:bcprov-jdk18on` 1.86, SHA-256 `2af190b3…5b4cb371f` (checked by `generate.sh`) | 2..65535 | 634 |

The committed files were produced with rustc 1.98.1 and Temurin
OpenJDK 21.0.12.1 (recorded in each file's `pinned` field).

Both generators start with fixed edge cases — edge radixes (2, 3, 10, 16, 36,
62, 64, 255–257, 999, 1000, 1023–1025, 32767–32769, 65535, and 65536 for
Rust) at the minimum length with all-zero and all-maximum numerals; radix 2
with v = 232; radix 10 with d = 20; radix 256 with n = 57; the largest
radix (65536 for Rust, 65535 for Bouncy Castle) at lengths 2, 3, 12, 13, 29,
30, and 64 and with digits around 32767/32768 and the maximum; every tweak
length 0–40 plus 255, 256, and 1000 bytes — followed by pseudorandom
parameters from a SplitMix64 generator with a fixed seed (random key size,
radix, length up to minlen + 600, tweak up to 600 bytes). Each generator
checks its library against NIST sample 1 and that decryption inverts
encryption before writing anything.

Two library quirks are handled explicitly:

- **Bouncy Castle mis-encodes radix 65536.** `SP80038G.calculateP_FF1`
  hardcodes `P[3] = 0`, so radix 65536 becomes `00 00 00` in P instead of
  `01 00 00`. The Java generator never emits radix 65536; it records Bouncy
  Castle's output for one such input in `radix65536_excluded`
  (`[6653, 42184]`, where the correct answer is `[18476, 48157]`), and the Go
  test asserts that this record really is wrong.
- **The Rust crate computes b with floating point** for radixes that are not
  powers of two (`ceil(v * log2(radix) / 8)`). The generator compares that
  formula with the exact `ceil(BITLEN(radix^v - 1) / 8)` for every case and
  would skip any mismatch (`skipped_float_b_mismatch`); with the committed
  seed there are none.

## Regenerating

From the repository root, with cargo and a JDK 17+ (`java`/`javac` on `PATH`
or `JAVA_HOME` set):

```sh
tools/differential/generate.sh               # both
tools/differential/generate.sh fpe-rs        # just one
```

The Bouncy Castle jar is downloaded from Maven Central into
`${XDG_CACHE_HOME:-~/.cache}/scrambler-differential` and verified against
the pinned SHA-256 before use. Output is deterministic; apart from the
recorded toolchain versions, re-running reproduces the committed files
exactly, which the `vectors` CI job checks.
