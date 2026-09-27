# scrambler

Format-preserving encryption (FPE) for Go: **FF1** from NIST SP 800-38G,
following the stricter requirements of the SP 800-38G Rev. 1 second public
draft (February 2025).

- FF1 only. FF3 and FF3-1 are intentionally not provided (Rev. 1 removes FF3).
- Always enforces a domain of at least one million values
  (`radix^minlen >= 1,000,000`); there is no legacy "≥ 100" mode.
- Radix 2 through 65,536, over Unicode rune alphabets, byte alphabets, or raw
  `[]uint16` numerals.
- AES-128/192/256 through Go's `crypto/aes`, forward direction only.
- Exact integer arithmetic (`math/big`), no floating point anywhere.
- Standard library only. Goroutine-safe, stateless ciphers; the tweak is passed
  on every call. Never panics on caller input.

> **Status:** new and not yet independently audited. SP 800-38G Rev. 1 is a
> draft; its requirements may change before it is final.

```sh
go get github.com/joshuajorel/scrambler/ff1
```

## Usage

```go
import "github.com/joshuajorel/scrambler/ff1"

key := ... // 16, 24, or 32 random bytes from your key management system

c, err := ff1.New(key, ff1.Digits)
if err != nil { ... }

// Encrypt the middle six digits of a card number. The digits that stay in
// the clear, plus a purpose label and version, form the tweak.
card := "4111119876541111"
tweak := []byte("card-middle-v1|" + card[:6] + "|" + card[12:])

ct, err := c.Encrypt(card[6:12], tweak) // "120431": six digits in, six out
pt, err := c.Decrypt(ct, tweak)         // "987654"
```

### Alphabets

An `Alphabet` maps symbols to numerals; the i-th symbol is numeral i and the
radix is the number of symbols.

| Constructor | Input is | Radix |
|---|---|---|
| `ff1.NewAlphabet("αβγδ…")`, `ff1.NewRuneAlphabet([]rune{…})` | UTF-8; one rune per symbol | rune count (not byte length), 2..65536 |
| `ff1.NewByteAlphabet([]byte{…})` | raw bytes; one byte per symbol | 2..256 |
| `ff1.RadixOnly(r)` | numerals only (`EncryptNumerals`) | 2..65536 |

Predefined: `Digits` (10), `HexLower`/`HexUpper` (16), `LowerAlphanumeric`
and `UpperAlphanumeric` (36; the NIST samples use `0-9a-z`), and
`Alphanumeric` (62, `0-9a-zA-Z`, the digit order of `math/big` and other FF1
libraries). Symbols must be distinct; U+FFFD and invalid code points are
rejected. Lengths are counted in symbols, so a Unicode alphabet counts runes.

### Numerals

```go
alpha, _ := ff1.RadixOnly(65536)
c, _ := ff1.New(key, alpha)
ct, err := c.EncryptNumerals([]uint16{35521, 37776}, tweak) // each < radix
```

`EncryptNumerals` / `DecryptNumerals` work with every cipher and return a new
slice; the input is not modified.

### Options and errors

```go
c, err := ff1.New(key, ff1.Digits,
	ff1.WithMinLength(8),        // default: smallest n with radix^n >= 10^6
	ff1.WithMaxLength(19),       // default: 2^32-1
	ff1.WithMaxTweakLength(64))  // default: 2^32-1 bytes
```

Every error wraps one sentinel, to be tested with `errors.Is`:
`ErrInvalidKeyLength`, `ErrInvalidRadix`, `ErrInvalidAlphabet`,
`ErrDomainTooSmall`, `ErrInvalidLength`, `ErrInvalidNumeral`,
`ErrInvalidSymbol`, `ErrTweakTooLong`, `ErrInvalidOption`, `ErrNoSymbols`, and
`ErrUninitialized` (zero-value `Cipher`). Messages never contain key, tweak,
plaintext, or ciphertext material.

## Security notes

References are to NIST SP 800-38G Rev. 1, second public draft
(<https://doi.org/10.6028/NIST.SP.800-38Gr1.2pd>).

- **Confidentiality only — no authentication.** FF1 has no integrity check.
  Decrypting with the wrong key or tweak, or decrypting a tampered ciphertext,
  returns a well-formed plaintext of the right length and alphabet, not an
  error. If you need to detect tampering or mismatched context, add a MAC or
  checksum elsewhere (for example in another column).
- **Deterministic.** The same key, tweak, and plaintext always give the same
  ciphertext, so equal values under the same tweak are visibly equal. This is
  inherent to FPE.
- **Tweaks.** The tweak is not secret, and the API requires one on every call,
  but that alone does not make tweaks vary — passing a constant is legal and
  common. Appendix C recommends a tweak that varies with each instance, taken
  from information statically associated with the plaintext, so that
  equal plaintexts in different contexts encrypt differently and one
  compromised value does not reveal others. Encode that context
  unambiguously, for example as length-prefixed fields for tenant, table and
  field, record identifier, purpose, and a version: `"a|b" + "c"` and
  `"a" + "|bc"` must not collide.
- **Small domains.** Rev. 1 requires `radix^minlen >= 1,000,000` in response
  to message-recovery and round-function-recovery attacks on small domains
  (Appendix A.2 and Appendix G, citing Bellare–Hoang–Tessaro, Durak–Vaudenay,
  and Hoang–Tessaro–Trieu). This package enforces it for every input and
  configuration, with no override. The original 2016 minimum of 100 is not
  offered.
- **The minimum is still small.** 10^6 values is about 20 bits. Anyone with
  access to an encryption or decryption oracle can enumerate a domain that
  small, and an attacker can guess a plaintext with probability
  `g / radix^n` after `g` guesses (Appendix A.1). Treat encryption and
  decryption endpoints as sensitive: authorize callers, rate-limit, and
  monitor them. Prefer longer inputs (or padding) where the format allows.
- **What the 2^77 figure means.** Appendix A.2 estimates that, at the 10^6
  domain size, the known attacks need a data complexity of at least 2^77 to
  recover a single target message. That is an estimate for the published
  message-recovery attacks, not a general security guarantee for FF1.
- **Length leakage.** Ciphertexts have the plaintext's length. Pad to a fixed
  length if lengths are sensitive (Section 2).
- **Timing.** `math/big` is not constant-time, so the running time can depend
  on the values being processed. `crypto/aes` is constant-time only on
  platforms with hardware AES (for example AES-NI or the ARMv8 crypto
  extensions). Do not use this package where a local timing side channel is
  a concern.
- **Keys.** Use uniformly random 128-, 192-, or 256-bit keys, keep them
  secret, and consider separate keys per data type or purpose. Key management
  is out of scope.
- **Validation.** This is not a CAVP/CMVP-validated module.

## Testing and provenance

`go test -race ./...` runs every suite below. Test vectors come from
published sources and are vendored byte-for-byte with their provenance; none
are typed in by hand except the nine NIST samples and single cross-checks
quoted from published sources.

| Suite | Cases | Source |
|---|---|---|
| NIST FF1 samples (`kat_test.go`) | 9, both directions, string and numeral API | NIST CSRC FF1 examples (samples 1–9) |
| NIST ACVP (`vectors_test.go`, `TestACVP`) | 750 (30 groups × 25), subtests `tg%d/tc%d` | `usnistgov/ACVP-Server` `ACVP-AES-FF1-1.0/internalProjection.json` @ `975de31` ([testdata/acvp](ff1/testdata/acvp/README.md)) |
| Wycheproof (`wycheproof_test.go`) | 57,246 in 22 files, incl. radix 65535 (965) and 65536 (1,049) | `C2SP/wycheproof` `testvectors_v1/aes_ff1_*` @ `3fa63dd` ([testdata/wycheproof](ff1/testdata/wycheproof/README.md)) |
| Other libraries (`TestThirdPartyVectors`) | 69: 60 known answers, 3 round-trip, 6 rejections | Bouncy Castle `SP80038GTest.java` (incl. radix 1024 and radix 256/n = 57), Rust `str4d/fpe`, `capitalone/fpe`, `ubiq-fpe-go`, at pinned commits ([extract.py](tools/extract_vectors/extract.py)) |
| Differential (`TestDifferential`) | 846 from the Rust `fpe` crate 0.6.1 (radix 2..65536), 634 from Bouncy Castle 1.86 (radix ≤ 65535) | [tools/differential](tools/differential/README.md), deterministic seeds |
| Reference cross-check | boundary, parity, tweak, and fuzz inputs | `reference_test.go`: a literal transcription of the spec |
| Full permutation | all 10^6 inputs of radix 10, n = 6 | `permutation_test.go` |
| Fuzzing | `FuzzRoundTrip`, `FuzzNoPanic` | `fuzz_test.go` |

How the Wycheproof cases resolve: 49,102 valid cases match; 138 cases that
are valid under the 2016 rule but have `radix^n < 10^6` are rejected with
`ErrDomainTooSmall` by design; all 7,819 invalid cases are rejected (110 bad
key sizes, 132 short messages, 5,577 out-of-range digits or symbols, and
2,187 digits such as −1 or 65536 that cannot be represented in the `[]uint16`
numeral API at all).

**Bouncy Castle and radix 65536.** Bouncy Castle's `SP80038G.calculateP_FF1`
hardcodes `P[3] = 0`, so it encodes radix 65536 as `00 00 00` instead of
`01 00 00` and returns wrong ciphertexts at that radix (for a zero key, zero
8-byte tweak, and input `[0, 1]` it returns `[6653, 42184]`; the correct
answer, computed identically by the Rust crate and by this package, which
also passes all 918 valid Wycheproof radix-65536 cases, is `[18476, 48157]`).
It is therefore used as an oracle only up to radix 65535, and
`TestRadix65536Regression` pins the correct value.

Other checks cover the parameter boundaries (radix 1 and 65537 rejected; 2, 3,
10, 64, 255–257, 999–1025, 32767–32769, 65535, 65536 accepted; exact minimum
lengths; odd and even n; radix 2 with v = 232, where b must be 29; radix 65536
n = 12 → 13, where S grows to two blocks; tweaks of 0, maximum, and maximum+1
bytes; all-zero and all-maximum inputs), every error path, determinism, key
and tweak sensitivity, and concurrent use under the race detector.

```sh
go test -race ./...
go test -run '^$' -fuzz FuzzRoundTrip -fuzztime 30s ./ff1
go test -run '^$' -fuzz FuzzNoPanic -fuzztime 30s ./ff1
go test -run '^$' -bench . ./ff1
```

To re-derive the vendored data: `python3 tools/extract_vectors/extract.py`,
`sh tools/acvp/fetch.sh`, `sh tools/wycheproof/fetch.sh`, and
`tools/differential/generate.sh`. CI re-runs all four and fails on any
difference.

## Performance

Apple M5 Pro, Go 1.26.1 (`go test -bench . ./ff1`):

| Operation | Time | Allocations |
|---|---|---|
| Encrypt, radix 10, n = 16 | 0.67 µs | 42 |
| Encrypt, radix 10, n = 9 | 0.69 µs | 45 |
| Encrypt, radix 36, n = 19 | 0.94 µs | 45 |
| Encrypt, radix 2, n = 512 | 4.0 µs | 46 |
| EncryptNumerals, radix 65536, n = 16 | 1.5 µs | 42 |
| New (AES key expansion) | 0.16 µs | 7 |

## License

Apache-2.0 — see [LICENSE](LICENSE). Vendored test vectors keep their own
terms (NIST public-domain notice; Wycheproof Apache-2.0); see the READMEs
under `ff1/testdata`.
