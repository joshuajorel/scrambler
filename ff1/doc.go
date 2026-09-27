// Package ff1 implements the FF1 format-preserving encryption mode of
// NIST SP 800-38G, following the SP 800-38G Rev. 1 second public draft
// (February 2025). FF3 and FF3-1 are deliberately not provided.
//
// FF1 encrypts a string of n numerals in a radix between 2 and 65536 to
// another string of n numerals in the same radix, under an AES key (128,
// 192, or 256 bits) and a tweak supplied on every call:
//
//	c, err := ff1.New(key, ff1.Digits)
//	...
//	tweak := []byte("ssn-v1|tenant=42|record=1001") // context, not secret
//	ct, err := c.Encrypt("123456789", tweak)        // 9 digits in, 9 digits out
//	pt, err := c.Decrypt(ct, tweak)
//
// # Alphabets
//
// An [Alphabet] maps symbols to numerals. [NewAlphabet] and
// [NewRuneAlphabet] build Unicode alphabets whose radix is the number of
// runes; [NewByteAlphabet] treats input as raw bytes; [RadixOnly] has no
// symbols and serves the numeral API ([Cipher.EncryptNumerals],
// [Cipher.DecryptNumerals]), which takes []uint16 numerals directly and
// supports every radix up to 65536. [Digits], [LowerAlphanumeric],
// [Alphanumeric], and a few others are predefined.
//
// # Domain size
//
// Every input must satisfy radix^n >= 1,000,000 ([MinDomainSize]), which
// Rev. 1 turns from a recommendation into a requirement because of attacks
// on small domains. Shorter inputs, and options that would allow them, fail
// with [ErrDomainTooSmall]. There is no way to relax this.
//
// # Errors
//
// All failures return errors wrapping one of the exported sentinels (for
// example [ErrInvalidKeyLength], [ErrDomainTooSmall], [ErrInvalidSymbol]);
// test for them with [errors.Is]. The package never panics on caller input.
//
// # Security considerations
//
// FF1 provides confidentiality only. It is deterministic: the same key,
// tweak, and plaintext always give the same ciphertext, so equal values are
// visible as equal. It has no integrity protection: decrypting with the
// wrong key or tweak, or decrypting a modified ciphertext, returns a
// well-formed but wrong plaintext rather than an error. Ciphertexts reveal
// the plaintext length.
//
// The tweak is not secret, but it should vary: SP 800-38G Rev. 1 Appendix C
// recommends deriving it from information associated with each plaintext.
// Encode that context unambiguously (for example tenant, field, record,
// purpose, and a version), because the package cannot check that tweaks
// actually differ.
//
// Even the minimum domain of 10^6 values is only about 20 bits, so anyone
// who can call encryption or decryption can enumerate a domain that small;
// applications must authorize and rate-limit such access.
//
// # Implementation notes
//
// All arithmetic is exact (math/big and integer loops; no floating point),
// only the forward AES direction is used, and a [Cipher] holds no mutable
// state, so it is safe for concurrent use. math/big is not constant-time, so
// the running time may depend on the values processed; crypto/aes is
// constant-time only with hardware AES support. See the repository README
// for the full security notes and the test-vector provenance.
package ff1
