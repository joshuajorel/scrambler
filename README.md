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
	ff1.WithMaxLength(19),       // default: 2^32-1 (2^27-1 on 32-bit platforms)
	ff1.WithMaxTweakLength(64))  // default: 2^32-1 bytes (2^30-1 on 32-bit)
```

**Cap lengths for untrusted input.** The defaults are the largest lengths
FF1 allows (on 32-bit platforms, the largest for which every internal size
fits in an `int`), so one call can be asked to process gigabytes, and the
cost of a call grows faster than linearly with the input length. When
plaintexts, ciphertexts, or tweaks come from untrusted callers, set
`WithMaxLength` and `WithMaxTweakLength` to what the data needs — for
example 19 digits and a 64-byte tweak for card numbers — so oversized
requests fail fast with `ErrInvalidLength` or `ErrTweakTooLong`. Lengths are
checked before anything proportional to the input is allocated.

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
  error. To detect tampering or a mismatched context, store a keyed MAC —
  for example HMAC-SHA-256 under a separate key — computed over the
  ciphertext *and* its context (the tweak, or the fields it is derived from),
  for example in another column, and verify it before trusting a decryption.
  An unkeyed checksum (a CRC, a Luhn check digit, or a plain hash) only
  catches accidental corruption: anyone who can change the ciphertext can
  recompute it, so it authenticates nothing.
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

### Deterministic masking of join keys across databases

The `mask` package compiles a fixed-width policy for each logical data domain.
It supplies a stable, versioned tweak encoding and a registry that holds one
configuration per domain ID and rejects any different one, including a
different policy version. Location names used in the registry never enter a
join-domain tweak.

```go
key := ... // 16, 24, or 32 bytes from your key manager
policy, err := mask.Compile(mask.Spec{
	DomainID: "account-number", Version: "v1",
	Alphabet: "0123456789", Width: 12, Scope: mask.JoinDomain,
}, mask.KeyRef{ID: "accounts-key", Version: "2026-09"}, key)
if err != nil { ... }

var locations mask.Registry
parent, err := locations.Bind("accounts.id", policy)
if err != nil { ... }
foreignKey, err := locations.Bind("orders.account_id", policy)
if err != nil { ... }
a, err := parent.Mask("000123456789", mask.Context{})
if err != nil { ... }
b, err := foreignKey.Mask("000123456789", mask.Context{})
if err != nil { ... }
// a == b, including across independent processes with the same policy and key.
```

Import `github.com/joshuajorel/scrambler/mask` for this example. A policy's
`Fingerprint` is a stable digest of its declared rules and key reference; it
does not contain key bytes. The caller must resolve the same versioned key
reference to the same key in every process. Rotate a key with a new policy
version. A registry accepts one version per domain ID, so every location bound
in that registry moves to the new version together. Each process has its own
registry and separate processes are not coordinated by it, so deploy a new
version to every process that masks the domain together. The package exposes
masking only; it has no unmask operation.

`JoinDomain` is for business keys that must join across locations. Use
`TenantDomain` only when cross-tenant joins are deliberately excluded, and
`Record` when per-record variation is needed. The tweak uses length-prefixed
domain ID, policy version, and the applicable logical context. It does not
derive context from table or column names. For join keys, bind every parent
and foreign-key location to the same compiled policy.

Plain policies accept one exact symbol width and an ordered Unicode alphabet.
Invalid symbols, wrong widths, malformed UTF-8, and oversized input are
errors. FF1's minimum domain of one million values is enforced at compile
time. Empty input is rejected by default; `PreserveEmpty` is an explicit
missing-value rule and never encrypts the empty string. Custom canonicalizers
need a stable ID that changes when their behavior changes. By default
(`RejectAliases`) input must already be in canonical form, preventing two raw
spellings from collapsing to one masked value without keeping process-local
history. `AllowAliases` is an explicit opt-in to intentional aliasing: choose
it only when a canonicalizer deliberately normalizes different representations
of the same logical value, such as zero padding, so that they mask alike.

**Equal canonical inputs producing equal outputs under one join-domain policy
is intentional.** Anyone who sees the masked datasets can observe equality,
join records, and count repeated values. Masking is pseudonymization, not
anonymization. Keep keys and masking access controlled, and do not treat a
masked copy as public data.

Structured policies use `Spec.Layout` instead of `Alphabet` and `Width`. A
layout is a sequence of exact literals, encrypted segments, validated but
retained segments, and optionally a final Luhn digit. Every encrypted position
is combined into one domain, even across separators or different alphabets.
The product of their alphabet sizes must be at least 1,000,000; retained
characters and the check digit do not count. The implementation uses FF1 over
a binary domain and cycle walking to permute exactly that combined domain.
The layout, including each literal, width, alphabet order, and check-digit
rule, enters the policy fingerprint.

Literal and retained parts are bound into the tweak: after the plain policy
fields, the tweak appends each such part's rune position and its actual
text, length-prefixed. Values that differ only in clear text therefore mask
their encrypted positions differently. Two cards with different first six
digits and the same middle nine do not share masked middle digits, and two
email layouts with separators in different positions do not share masked
letters. The check digit is not bound; it is recomputed. Plain policies'
tweaks are unchanged.

```go
customer, err := mask.Compile(mask.Spec{
	DomainID: "customer-number", Version: "v1", Scope: mask.JoinDomain,
	Layout: []mask.Part{
		{Kind: mask.LiteralPart, Literal: "C"},
		{Kind: mask.EncryptedPart, Width: 6, Alphabet: "0123456789"},
	},
}, mask.KeyRef{ID: "customer-key", Version: "2026-09"}, key)
if err != nil { ... }
masked, err := customer.Mask("C000123", mask.Context{})
// "C" stays fixed; the six digits have exactly 10^6 possible values.
```

The same pieces express these other fixed formats:

| Format | Layout | Example input |
|---|---|---|
| Card | 6 retained digits, 9 encrypted digits, final `LuhnDigit` | `4111111111111111` |
| US phone | `+1-`, 3 encrypted digits, `-`, 3 encrypted digits, `-`, 4 encrypted digits | `+1-202-555-0001` |
| Email local part | 3 encrypted lowercase letters, `.`, 6 encrypted lowercase letters, `.`, 6 encrypted digits, `@example.test` | `ava.nguyen.000001@example.test` |

For the card, the first six digits are checked against their declared
alphabet and copied; the incoming Luhn digit must be valid, and a new digit
is calculated from the masked payload. `LuhnDigit` requires an all-digit
payload and must be the last part. Literal text must match exactly, and all
segment widths count Unicode runes. Malformed values return errors. A
different email local-part length needs a separate fixed layout and domain ID;
short lengths with a combined domain below one million are rejected. These
policies do not parse arbitrary email syntax or provide a regex language.
Bind each location that represents the same business key to the same policy.

### Shareable policy manifests and streaming rows

The `manifest` package loads a versioned, non-secret JSON file. It compiles
`mask` policies and registry bindings using key bytes supplied by the caller;
the file contains only key reference IDs and versions. See
[`manifest/testdata/banking.json`](manifest/testdata/banking.json) for a
complete v1 example matching the private banking demo's actual tables:
PostgreSQL `public.customers`, Oracle `BANK.ACCOUNTS`, and SQL Server
`dbo.payments`. Names, holder name, dates of birth, and non-target columns
are explicit `clear` bindings with a reason. There are no database drivers or
KMS clients in this package.

The top-level object has `version: 1`, `policies`, `bindings`, `edges`, and
`goldens`. Each policy has one `domain`, policy `version`, `key` (`id` and
`version`), `scope` (`join_domain`, `tenant_domain`, or `record`), and either
`alphabet` plus `width` or `layout` parts (`literal`, `encrypted`, `retained`,
`luhn`). Layout syntax follows `mask.Part`. One policy is allowed per domain;
the manifest does not expose custom canonicalizers or aliasing. A binding
identifies `database`, `schema`, `table`, `column`, and `mode`. Masked bindings
also name `policy` and `codec` (`kind` and `width`); `unique: true` enables
duplicate-output detection. Clear bindings have `reason` and no masking
settings. Binding IDs are `database.schema.table.column`. Each `edge` names
two binding IDs in `from` and `to`. Each golden pins one synthetic canonical
`input`, its masked `output`, and policy `fingerprint` for a binding; an
optional `context` supplies tenant or record tweak fields. Every policy needs
at least one golden. Keep fixture inputs synthetic and safe to share.

The three codecs have explicit storage contracts:

| Codec | Input and output Go type | `width` | Conversion |
|---|---|---|---|
| `text` | `string` | Maximum UTF-8 bytes | Canonical string unchanged; rejects overflow. |
| `blank_padded_text` | `string` | Exact UTF-8 byte width | Strips right-side ASCII spaces before masking and pads output back; rejects a policy whose output could end in a space. |
| `zero_padded_numeric` | `int64` | Maximum decimal digits | Pads nonnegative input on the left to canonical width, then converts masked digits back to `int64`; at most 18 canonical digits are allowed. |

The codec width is checked against **every possible output** of the policy,
including retained and literal parts. Numeric codecs require an all-digit
layout. The banking demo stores its join fields as `VARCHAR`/`VARCHAR2`, so
its fixture uses `text`; the numeric and blank-padded codecs are also tested
with synthetic in-memory rows. A driver adapter should turn its database
values into these exact Go types and preserve SQL `NULL` as `nil`.

```go
manifestFile, err := os.Open("manifest/testdata/banking.json")
if err != nil { ... }
defer manifestFile.Close()
keys := resolveVersionedKeys() // map[mask.KeyRef][]byte; all references
set, err := manifest.Load(manifestFile, keys)
if err != nil { ... }
var duplicates manifest.Detector // share across the whole target dataset
for nextRow() {
    // Complete row keyed by IDs such as "postgresql.public.customers.email".
    row := readRow()
    masked, nulls, err := set.MaskRow(row, mask.Context{}, &duplicates)
    if err != nil { ... } // binding ID appears in the diagnostic
    reportNulls(nulls)
    writeRow(masked)
}
```

Load validates the full graph before masking: every masked binding resolves to
one defined policy, all equality edges connect masked bindings of the same
domain policy and version under `join_domain`, codec capacity covers all
outputs, and golden values match the supplied key. `MaskRow` requires every
declared column of one table, passes `nil` through unchanged and reports its
binding ID, and fails on malformed or over-width values. A `Detector` rejects
repeated masked outputs in columns marked `unique`; create a new one for each
target dataset. It keeps prior outputs in memory, so a very large stream may
need an application-owned database uniqueness check instead. The library
does not coordinate transactions or writes across the three databases.

Policy fingerprints include the key reference label and version, but not key
bytes. Thus two processes resolving one reference to different keys pass the
fingerprint divergence check. The required golden fixtures catch disagreement
for their listed inputs when each process loads the manifest, but they are not
a general key-consistency protocol. An optional one-way key check value could
be added in a future format version; doing so would let holders compare key
equality without sharing the key, while exposing equality of keys across
manifests. This remains an open design choice for the banking demo rollout.

The rest of this section describes a manual recipe that calls `ff1` directly.
Its tweak encoding differs from the `mask` package's, so the two produce
different outputs for the same value and cannot be mixed for one domain: every
location of a domain must use the same approach.

A common use of FF1 is to pseudonymize an identifier, such as an account
number, so that masked copies in different databases, services, or files can
still be joined on the masked value. That needs every system to turn the same
value into exactly the same ciphertext, which deliberately inverts the
per-record tweak advice above:

- **One key and one logical-domain tweak everywhere.** Every system uses the
  same key (the same KMS entry) and the same constant tweak naming the logical
  domain and a version, for example `[]byte("account-number:v1")`. Do not put
  table or column names, record IDs, or other per-location data in the tweak:
  they make the same account number mask differently in different places and
  break the joins.
- **One alphabet with a fixed symbol order.** Use the same alphabet everywhere
  (for example `ff1.Digits`); a different symbol order is a different
  permutation.
- **One representation and normalization policy.** Apply the same canonical
  form before masking in every system: the same character set and case,
  separators and whitespace stripped the same way, and the same width or zero
  padding (`"0042"` and `"42"` are different inputs). Decide up front what
  happens to values that fail validation, rather than masking them
  inconsistently.
- **Masking needs only `Encrypt`.** If no system needs the original values
  back, never call `Decrypt`, and keep the key where only the masking service
  can use it: whoever holds the key can reverse every masked value.
- **Keep golden ciphertexts.** Record a few fixed inputs with their expected
  masked outputs and check them in each system's tests and after every
  library upgrade; any change in output silently breaks joins with data masked
  earlier. This package pins such values for its built-in alphabets in
  `ff1/golden_test.go`, and changing them would be a breaking change.

The trade-off is intended but real: under one key and tweak, equal values are
equal everywhere, so anyone who sees masked data can link records across
datasets and count repeated values, and each value still has only the domain
size of its format.

```go
// The same key, alphabet, tweak, and normalization in every service.
masker, err := ff1.New(key, ff1.Digits, ff1.WithMaxLength(12), ff1.WithMaxTweakLength(32))
if err != nil { ... }
var accountTweak = []byte("account-number:v1")

func maskAccount(raw string) (string, error) {
	acct, err := normalizeAccount(raw) // e.g. strip spaces and dashes, left-pad to 12 digits
	if err != nil {
		return "", err
	}
	return masker.Encrypt(acct, accountTweak)
}
```

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
| Golden outputs | 16 fixed inputs over every built-in alphabet, a Unicode alphabet, and radix 65536; changing them is a breaking change | `golden_test.go`, cross-checked against the reference |
| Length arithmetic | the largest accepted n and t for 32- and 64-bit ints, without allocating them | `limits_test.go`; CI also runs the whole suite as a 32-bit (`GOARCH=386`) program |
| Fuzzing | `FuzzRoundTrip`, `FuzzNoPanic` | `fuzz_test.go` |

How the Wycheproof cases resolve: 49,102 valid cases match; 138 cases that
are valid under the 2016 rule but have `radix^n < 10^6` are rejected with
`ErrDomainTooSmall` by design; all 8,006 invalid cases are rejected (110 bad
key sizes, 132 short messages, 5,577 out-of-range digits or symbols, and
2,187 digits such as −1 or 65536 that cannot be represented in the `[]uint16`
numeral API at all). `TestREADMECounts` checks that every count quoted here
matches what the tests assert.

**Bouncy Castle and radix 65536.** Bouncy Castle's `SP80038G.calculateP_FF1`
hardcodes `P[3] = 0`, so it encodes radix 65536 as `00 00 00` instead of
`01 00 00` and returns wrong ciphertexts at that radix (for a zero key, zero
8-byte tweak, and input `[0, 1]` it returns `[6653, 42184]`; the correct
answer, computed identically by the Rust crate and by this package, which
also passes all 918 valid Wycheproof radix-65536 cases, is `[18476, 48157]`).
It is therefore used as an oracle only up to radix 65535, and
`TestRadix65536Regression` pins the correct value.

Other checks cover the parameter boundaries (radix 1 and 65537 rejected; 2, 3,
10, 36, 64, 255–257, 999, 1000, 1023–1025, 32767–32769, 65535, 65536
accepted; exact minimum lengths; odd and even n; radix 2 with v = 232, where b
must be 29; radix 65536 n = 12 → 13, where S grows to two blocks; tweaks of 0,
maximum, and maximum+1 bytes; all-zero and all-maximum inputs), every error
path, determinism, key and tweak sensitivity, and concurrent use under the race
detector.

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
