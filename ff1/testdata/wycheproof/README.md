# Wycheproof AES-FF1 vectors

The `aes_ff1_*_test.json` files here are unmodified copies of every AES-FF1
vector file in Project Wycheproof's `testvectors_v1` directory:

| | |
|---|---|
| Repository | <https://github.com/C2SP/wycheproof> |
| Commit | `3fa63dd0344abb611f1fb1d77e119938603ea230` (main, 2026-09-02) |
| Path | `testvectors_v1/aes_ff1_*_test.json` (22 files) |
| Generator | `google-wycheproof` 0.9rc5 (the `source` of every test group) |
| License | Apache License 2.0 — "Copyright 2016-2026 The Wycheproof Authors" (upstream has no NOTICE file) |

Each file can be fetched from
`https://raw.githubusercontent.com/C2SP/wycheproof/3fa63dd0344abb611f1fb1d77e119938603ea230/testvectors_v1/<name>`.
`SHA256SUMS` lists the SHA-256 of every file; `tools/wycheproof/fetch.sh`
re-downloads them and checks those sums, and `TestTestdataIntegrity` in
`ff1/vectors_test.go` fails if a committed copy changes. The git blob SHA-1
of each copy equals the upstream blob:

| File | Git blob | Cases |
|---|---|---|
| aes_ff1_base10_test.json | 4dd765eeab1ae67d54b02dda2c13180d2066a92c | 3845 |
| aes_ff1_base16_test.json | 60ba8ee186f511a4f5b8edc62a5328e769f4eddf | 3872 |
| aes_ff1_base26_test.json | 6bd5e823d61c29ca6e072c4dfd79bf6c5616312c | 3076 |
| aes_ff1_base32_test.json | bfac98c6e3f91bf2172ba321c8a1e6aca49aa0e0 | 2868 |
| aes_ff1_base36_test.json | 2567ff4ccb58155639b9fcf7195cbbe9af08eb5f | 2854 |
| aes_ff1_base45_test.json | 80148f2bdf0549cd9ef6ca82c64c9de555ed763b | 2421 |
| aes_ff1_base62_test.json | c25b836e72d314500aa7d43c9bdb50de17dbcc5c | 2474 |
| aes_ff1_base64_test.json | decb528737b1157d9bc9af4a4d394df7f208e572 | 2417 |
| aes_ff1_base85_test.json | bafe13f973a53a95c77cdece8005be7cf2a9dbd1 | 1852 |
| aes_ff1_radix10_test.json | e07f1af83edc3bf302f9bdb25d547557bb087a62 | 3845 |
| aes_ff1_radix16_test.json | 6edf143acef3d960d6e33f7e7905dbfb37ebcd82 | 3872 |
| aes_ff1_radix26_test.json | 63616a86b7e4b3fdc66b3a17c702dc2ab2acfebd | 3076 |
| aes_ff1_radix32_test.json | 120f2e766411c8f5d7578d83de40be377ca11046 | 2868 |
| aes_ff1_radix36_test.json | ef87390d386a2b37f3f323aa7be0f669856ffa85 | 2854 |
| aes_ff1_radix45_test.json | 47938f699b11f6186369e67bcbff0b06f8e7dacc | 2421 |
| aes_ff1_radix62_test.json | 989ef9d2f18df69c025a6fcc8c4a191f2abb5f99 | 2474 |
| aes_ff1_radix64_test.json | daf1fc40b9ab414902d5bf73170a6ae15de563de | 2417 |
| aes_ff1_radix85_test.json | a47f253aca704ec186b7199a016d792417444004 | 1852 |
| aes_ff1_radix255_test.json | 61325ed28d89a3ad534a0af38359d869646f1d22 | 1853 |
| aes_ff1_radix256_test.json | 71da1d997f957b27ad4ff06b5a41eece2b7bc331 | 2021 |
| aes_ff1_radix65535_test.json | f38261c709dcbf306e457c78a42931faf878c9bf | 965 |
| aes_ff1_radix65536_test.json | 03831ce749e04f4e30380a192f534418288bd23f | 1049 |

57,246 cases in total. The `base*` files encode messages as strings over the
group's alphabet (`fpe_str_test_schema.json`); the `radix*` files use lists of
digits (`fpe_list_test_schema.json`).

## How `TestWycheproof` treats them

* `valid`, radix^n ≥ 1,000,000: encryption and decryption must both match.
* `valid` but radix^n < 1,000,000 (flag `SmallMessageSize`, legal under the
  original 2016 rule of ≥ 100): this package's stricter Rev. 1 policy must
  reject them with `ErrDomainTooSmall`. Counted separately (138 cases).
* `invalid`: must return an error and never panic — `ErrInvalidKeyLength`
  (`InvalidKeySize`), `ErrDomainTooSmall` (`InvalidMessageSize`), or
  `ErrInvalidNumeral` / `ErrInvalidSymbol` (`InvalidPlaintext`). Decrypting the
  listed ciphertext must also not yield the invalid plaintext.
* `invalid` list cases whose plaintext holds a digit outside 0..65535 (−1 or
  65536) cannot be expressed as the `[]uint16` the numeral API takes; they are
  rejected at that type boundary and counted separately (2,187 cases).

The exact per-file counts are asserted in `wycheproofCounts` in
`ff1/wycheproof_test.go`.
