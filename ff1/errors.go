package ff1

import "errors"

// Sentinel errors returned by this package. Returned errors usually wrap one
// of these with additional context, so compare them with [errors.Is].
//
// Error messages never include plaintext, ciphertext, key, or tweak
// material; at most they report lengths, the radix, and the position of an
// offending symbol or numeral.
var (
	// ErrInvalidKeyLength is returned by [New] when the key is not 16, 24,
	// or 32 bytes long (AES-128, AES-192, or AES-256).
	ErrInvalidKeyLength = errors.New("ff1: invalid key length")

	// ErrInvalidRadix is returned when an alphabet would have a radix
	// outside [2, 65536] (256 for byte alphabets), or when [New] is given a
	// zero-value [Alphabet].
	ErrInvalidRadix = errors.New("ff1: invalid radix")

	// ErrInvalidAlphabet is returned by the alphabet constructors when the
	// symbols contain duplicates, invalid UTF-8, or runes that are not
	// valid Unicode scalar values.
	ErrInvalidAlphabet = errors.New("ff1: invalid alphabet")

	// ErrDomainTooSmall is returned when radix^n < 1,000,000 for an input of
	// length n, or when [New] is configured with such a minimum or maximum
	// length. SP 800-38G Rev. 1 requires radix^minlen >= 1,000,000; this
	// package always enforces it.
	ErrDomainTooSmall = errors.New("ff1: domain too small (radix^length < 1000000)")

	// ErrInvalidLength is returned when an input's length lies outside the
	// cipher's configured [minimum, maximum] length range.
	ErrInvalidLength = errors.New("ff1: invalid input length")

	// ErrInvalidNumeral is returned by the numeral API when a numeral is
	// not less than the radix.
	ErrInvalidNumeral = errors.New("ff1: numeral out of range for radix")

	// ErrInvalidSymbol is returned by the string API when the input contains
	// a character (rune or byte) that is not in the cipher's alphabet,
	// including invalid UTF-8 for rune alphabets.
	ErrInvalidSymbol = errors.New("ff1: symbol not in alphabet")

	// ErrTweakTooLong is returned when a tweak exceeds the cipher's maximum
	// tweak length.
	ErrTweakTooLong = errors.New("ff1: tweak too long")

	// ErrInvalidOption is returned by [New] when an [Option] value is out of
	// range or the options are mutually inconsistent.
	ErrInvalidOption = errors.New("ff1: invalid option")

	// ErrNoSymbols is returned by the string methods of a [Cipher] whose
	// alphabet was created with [RadixOnly] and therefore has no symbols.
	ErrNoSymbols = errors.New("ff1: alphabet has no symbols; use the numeral API")

	// ErrUninitialized is returned by the methods of a zero-value or nil
	// [Cipher]. Use [New] to create a Cipher.
	ErrUninitialized = errors.New("ff1: Cipher not initialized; create it with New")
)
