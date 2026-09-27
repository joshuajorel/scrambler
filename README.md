# scrambler

scrambler is a Go library for masking sensitive production data before copying
it to development or test environments. Its `mask` package uses NIST FF1
format-preserving encryption to keep values in a declared format while making
the same business key mask to the same value in every table, file, or service
that carries it. This keeps foreign-key joins usable in masked copies.

Use it when you need consistent, fixed-width pseudonyms for identifiers. Do
not use masked data as anonymous or public data: equal values remain linkable,
and someone with the key can reverse them. FF1 also provides no authentication;
use a separate integrity check if you need to detect tampering. The library is
new and has not been independently audited. The NIST SP 800-38G Rev. 1 second
public draft (February 2025) that it follows may change before publication.

```sh
go get github.com/joshuajorel/scrambler/mask
```

## Quick start: mask a business key

Supply the AES key from your key manager and identify it with a versioned
`KeyRef`. Compile one policy for the logical account number, bind both columns
to it, and mask each value through its binding:

```go
package example

import "github.com/joshuajorel/scrambler/mask"

func maskAccountIDs(key []byte) (string, string, error) {
    policy, err := mask.Compile(mask.Spec{
        DomainID: "account-number", Version: "v1",
        Alphabet: "0123456789", Width: 12, Scope: mask.JoinDomain,
    }, mask.KeyRef{ID: "accounts-key", Version: "2026-09"}, key)
    if err != nil { return "", "", err }

    var registry mask.Registry
    parent, err := registry.Bind("accounts.id", policy)
    if err != nil { return "", "", err }
    foreignKey, err := registry.Bind("orders.account_id", policy)
    if err != nil { return "", "", err }

    a, err := parent.Mask("000123456789", mask.Context{})
    if err != nil { return "", "", err }
    b, err := foreignKey.Mask("000123456789", mask.Context{})
    return a, b, err // a == b when err is nil
}
```

The same policy and key produce the same mask in independent processes too.
The registry checks that every binding of a domain ID uses the same declared
policy; it does not coordinate processes. The `mask` package exposes masking
only, with no unmask operation.

## Core concepts

### Share one policy per business key

A domain ID names a *logical* value, such as `account-number`. Bind every
parent and foreign-key column that contains that value to the same policy,
including across databases. Keep the alphabet and its symbol order, width,
canonical form, scope, policy version, and key consistent. For example,
`"0042"` and `"42"` are different inputs unless you deliberately normalize
them. Each process must resolve the same key reference to the same key bytes.
A policy's `Fingerprint` is a stable digest of its declared rules and key
reference; it contains no key bytes. A registry rejects a different policy or
version for an already-bound domain ID.

Plain policies accept an exact width in Unicode symbols and an ordered Unicode
alphabet. Invalid symbols, wrong widths, malformed UTF-8, and oversized input
return errors. Empty input is rejected by default. `PreserveEmpty` is an
explicit rule for a known missing-value sentinel and does not encrypt it.
A custom canonicalizer needs a stable ID that changes when its rules change.
The default `RejectAliases` requires raw input to be canonical; choose
`AllowAliases` only when different spellings intentionally mean the same
logical value and should mask alike, such as a deliberate zero-padding rule.

### Tweaks and scopes

The tweak is a non-secret input to FF1 that selects a permutation alongside
the key. `mask` constructs a length-prefixed tweak from the domain ID, policy
version, and scope context. For `JoinDomain`, it is constant for the logical
business key. **Do not put table names, column names, or row IDs in a join-key
tweak**: the same real key would then mask differently at each location and
break joins. Registry location names never enter the tweak.

| Scope | Context required | Effect |
|---|---|---|
| `JoinDomain` | Empty `mask.Context{}` | Same canonical value masks alike across all bound locations. |
| `TenantDomain` | `mask.Context{TenantID: tenant}` | Values can join within a tenant; equal values in different tenants mask differently. |
| `Record` | `mask.Context{RecordID: record}`; `TenantID` is optional | Each record gets its own context when per-record variation is needed. |

`TenantDomain` excludes cross-tenant joins by design. `Record` is unsuitable
for a key that must join across records. For structured layouts, the literal
and retained text also enters the tweak, so different clear parts select
different permutations. The check digit does not enter it.

### Versions and key rotation

The policy version and key reference are explicit. To rotate a key, use a new
key reference and a new policy version, then deploy that version to every
process masking the domain. One registry accepts only one version of a domain
ID at a time; separate registries do not coordinate a rollout. Re-masking
existing copies or preserving joins across versions requires a planned data
migration. Keep fixed input/output examples in your own tests: a changed
output can silently break joins with earlier masked data.

### Domain size and short fields

FF1 requires at least **one million possible values** in the encrypted domain;
`mask.Compile` rejects smaller domains. Six decimal digits are the minimum
plain decimal width. A two-digit status, four-digit PIN, or other short field
cannot be masked alone with this library. Where the data model permits,
combine encrypted positions into a larger structured layout or use a wider
canonical field. Otherwise choose a different masking design for that field;
do not bypass the minimum. Retained text and a check digit do not count toward
the encrypted domain.

### Structured layouts and Luhn

Use `Spec.Layout` in place of `Alphabet` and `Width` for a fixed format. Parts
can be exact literals, encrypted segments, validated but retained segments,
and an optional final `LuhnDigit`. All encrypted positions form one domain,
even across separators and different alphabets; the product of their alphabet
sizes must reach one million. The implementation uses FF1 over a binary domain
and cycle walking to permute exactly that combined domain. The layout's
literals, widths, alphabet order, and check-digit rule enter its fingerprint.

```go
package example

import "github.com/joshuajorel/scrambler/mask"

func maskCustomerNumber(key []byte, raw string) (string, error) {
    policy, err := mask.Compile(mask.Spec{
        DomainID: "customer-number", Version: "v1", Scope: mask.JoinDomain,
        Layout: []mask.Part{
            {Kind: mask.LiteralPart, Literal: "C"},
            {Kind: mask.EncryptedPart, Width: 6, Alphabet: "0123456789"},
        },
    }, mask.KeyRef{ID: "customer-key", Version: "2026-09"}, key)
    if err != nil { return "", err }
    return policy.Mask(raw, mask.Context{}) // e.g. raw == "C000123"
}
```

| Format | Layout | Example input |
|---|---|---|
| Card | 6 retained digits, 9 encrypted digits, final `LuhnDigit` | `4111111111111111` |
| US phone | `+1-`, 3 encrypted digits, `-`, 3 encrypted digits, `-`, 4 encrypted digits | `+1-202-555-0001` |
| Email local part | 3 encrypted lowercase letters, `.`, 6 encrypted lowercase letters, `.`, 6 encrypted digits, `@example.test` | `ava.nguyen.000001@example.test` |

For a card layout, retained digits are checked and copied. The incoming Luhn
digit must be valid; a new one is calculated after masking. `LuhnDigit` must
be last and requires an all-digit payload. Literals must match exactly, and
segment widths count Unicode runes. Malformed values return errors. A
different email local-part length needs its own fixed layout and domain ID;
layouts do not parse arbitrary email syntax or provide a regex language.
Literal and retained parts are bound to the tweak with their rune position
and actual text, length-prefixed. Two cards with different retained first six
digits and the same middle nine therefore need not share masked middle digits.

## Shareable policy manifests and streaming rows

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
    // Each binding uses only the fields its scope needs: none for join_domain,
    // TenantID for tenant_domain, and both for record.
    ctx := mask.Context{TenantID: tenantID, RecordID: recordID(row)}
    masked, nulls, err := set.MaskRow(row, ctx, &duplicates)
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
binding ID, and fails on malformed or over-width values. It passes each masked
binding only the context fields its policy scope uses, so one row can mix
`join_domain`, `tenant_domain`, and `record` columns. A `tenant_domain`
binding fails without a tenant ID, and a `record` binding without a record
ID. A `Detector` rejects repeated masked outputs in columns marked `unique`;
create a new one for each target dataset. It keeps prior outputs in memory, so
a very large stream may need an application-owned database uniqueness check
instead. The library does not coordinate transactions or writes across the
three databases.

Policy fingerprints include the key reference label and version, but not key
bytes. Thus two processes resolving one reference to different keys pass the
fingerprint divergence check. The required golden fixtures catch disagreement
for their listed inputs when each process loads the manifest, but they are not
a general key-consistency protocol. An optional one-way key check value could
be added in a future format version; doing so would let holders compare key
equality without sharing the key, while exposing equality of keys across
manifests. This remains an open design choice for the banking demo rollout.

## Operating guidance

Keep keys and masking access in a controlled production-side service or key
manager, outside the non-production environment. Whoever holds the key can
reverse FF1 output, even though `mask` has no unmask method. Use uniformly
random 128-, 192-, or 256-bit AES keys. Decide which users and jobs may call
masking, and rate-limit and monitor endpoints: a small enumerable domain can
be guessed even though its one-million-value minimum is enforced.

Treat validation and masking errors as failures. Do not pass the original value
through on error, since that would leak production data into a masked copy.
Define an explicit missing-value rule where needed and quarantine or reject
malformed rows. Preserve the same representation and normalization across all
systems that carry a business key.

Equality is visible by design. A reader of masked datasets can join rows and
count repeated values. This is **pseudonymization, not anonymization**; do not
publish masked copies as public data. FF1 retains length and format and offers
confidentiality without authentication. If tamper detection matters, verify a
keyed MAC over the ciphertext and its context before trusting decryption; a
Luhn digit or unkeyed checksum only detects accidental errors.

## Direct `ff1` API

Use `ff1` when you need the lower-level engine or a format outside the fixed
policy model. For production-to-non-production join keys, prefer `mask`: its
policy and registry make the shared tweak and format explicit. A direct FF1
join-key recipe uses a different tweak encoding from `mask`, so the two
approaches produce different outputs and must not be mixed for one domain.

`ff1` implements FF1 from NIST SP 800-38G under the stricter requirements of
the Rev. 1 second public draft. FF3 and FF3-1 are not provided; Rev. 1 removes
FF3. It uses AES-128/192/256 through Go's `crypto/aes`, forward direction only,
exact `math/big` arithmetic, and the standard library. Ciphers are stateless
and safe for concurrent goroutines; callers pass a tweak for each call.
Caller input returns errors rather than panics.

```sh
go get github.com/joshuajorel/scrambler/ff1
```

```go
package example

import "github.com/joshuajorel/scrambler/ff1"

func maskCardMiddle(key []byte) (string, error) {
    c, err := ff1.New(key, ff1.Digits)
    if err != nil { return "", err }
    card := "4111119876541111"
    // Encrypt the middle six digits; retain the first six and last four.
    tweak := []byte("card-middle-v1|" + card[:6] + "|" + card[12:])
    middle, err := c.Encrypt(card[6:12], tweak)
    if err != nil { return "", err }
    return card[:6] + middle + card[12:], nil
}
```

For a direct FF1 join-key recipe, use the same key, alphabet and symbol order,
normalization, and logical-domain tweak in every service. Do not add location
or record context to that tweak. Masking only requires `Encrypt`; if no system
needs originals, do not call `Decrypt`. Keep fixed ciphertexts in tests after
library upgrades. The built-in alphabet outputs are pinned in
`ff1/golden_test.go`.

### Alphabets and numerals

An `Alphabet` maps each symbol to a numeral in declaration order. Its radix
is the symbol count, and Unicode string lengths are counted in runes.

| Constructor | Input is | Radix |
|---|---|---|
| `ff1.NewAlphabet("αβγδ…")`, `ff1.NewRuneAlphabet([]rune{…})` | UTF-8; one rune per symbol | rune count (not byte length), 2..65536 |
| `ff1.NewByteAlphabet([]byte{…})` | raw bytes; one byte per symbol | 2..256 |
| `ff1.RadixOnly(r)` | numerals only (`EncryptNumerals`) | 2..65536 |

Predefined alphabets: `Digits` (10), `HexLower`/`HexUpper` (16),
`LowerAlphanumeric` and `UpperAlphanumeric` (36; NIST samples use `0-9a-z`),
and `Alphanumeric` (62, `0-9a-zA-Z`, the digit order of `math/big` and other
FF1 libraries). Symbols must be distinct; U+FFFD and invalid code points are
rejected. `EncryptNumerals` and `DecryptNumerals` take `[]uint16` and return a
new slice without modifying the input. They work with every cipher, including
`ff1.RadixOnly(65536)`; each numeral must be less than the radix.

### Options and errors

`ff1.New(key, alphabet, options...)` accepts `WithMinLength`, `WithMaxLength`,
and `WithMaxTweakLength`. The default minimum is the smallest length with
`radix^length >= 1,000,000`; there is no legacy 100-value mode. The default
maximum length is 2^32−1 symbols (2^27−1 on 32-bit platforms); the default
maximum tweak length is 2^32−1 bytes (2^30−1 on 32-bit platforms). Set caps
for untrusted input, for example 19 digits and a 64-byte tweak for a card,
because cost grows faster than linearly with length. Oversized requests fail
before proportional allocation with `ErrInvalidLength` or `ErrTweakTooLong`.

Errors wrap sentinels testable with `errors.Is`: `ErrInvalidKeyLength`,
`ErrInvalidRadix`, `ErrInvalidAlphabet`, `ErrDomainTooSmall`,
`ErrInvalidLength`, `ErrInvalidNumeral`, `ErrInvalidSymbol`,
`ErrTweakTooLong`, `ErrInvalidOption`, `ErrNoSymbols`, and `ErrUninitialized`
(for a zero-value `Cipher`). Error messages omit key, tweak, plaintext, and
ciphertext material.

### FF1 security details

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
- **Tweaks for direct FF1 use.** The tweak is not secret, and the API requires
  one on every call, but that alone does not make tweaks vary — passing a
  constant is legal and common. For values that do not need joins, Appendix C
  recommends a tweak that varies with each instance, taken from information
  statically associated with the plaintext, so that
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
