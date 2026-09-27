package ff1

import (
	"fmt"
	"unicode/utf8"
)

// Radix limits from SP 800-38G: radix ∈ [2, 2^16].
const (
	// MinRadix is the smallest radix FF1 allows.
	MinRadix = 2
	// MaxRadix is the largest radix FF1 allows, 65536. Numerals in this
	// radix span the full uint16 range.
	MaxRadix = 1 << 16
)

type alphabetKind uint8

const (
	kindRunes alphabetKind = iota + 1
	kindBytes
	kindRadixOnly
)

// Alphabet maps between symbols and FF1 numerals. The radix of an alphabet
// is its number of distinct symbols, and the i-th symbol (counting from 0)
// represents numeral i.
//
// There are three kinds of alphabet:
//   - rune alphabets ([NewAlphabet], [NewRuneAlphabet]): strings are
//     interpreted as UTF-8 and each rune is one symbol, so the radix is the
//     rune count, not the byte length, and input and output lengths are
//     counted in runes;
//   - byte alphabets ([NewByteAlphabet]): strings are treated as raw bytes
//     and each byte is one symbol (radix <= 256);
//   - radix-only alphabets ([RadixOnly]): no symbols, only usable with the
//     numeral API ([Cipher.EncryptNumerals], [Cipher.DecryptNumerals]).
//
// Each rune is one symbol: combining sequences and other multi-rune
// graphemes are not treated as single symbols.
//
// Alphabet values are immutable and safe for concurrent use. The zero value
// has no symbols and radix 0; [New] rejects it with [ErrInvalidRadix].
type Alphabet struct {
	a *alphabet
}

type alphabet struct {
	kind    alphabetKind
	radix   int
	symbols []rune         // kindRunes: symbols; kindBytes: bytes widened to rune
	low     [256]int32     // numeral for symbols < 256, or -1
	high    map[rune]int32 // numeral for rune symbols >= 256
}

// Predefined alphabets.
var (
	// Digits is "0123456789" (radix 10).
	Digits = mustAlphabet("0123456789")
	// HexLower is "0123456789abcdef" (radix 16).
	HexLower = mustAlphabet("0123456789abcdef")
	// HexUpper is "0123456789ABCDEF" (radix 16).
	HexUpper = mustAlphabet("0123456789ABCDEF")
	// LowerAlphanumeric is "0-9a-z" (radix 36), the alphabet used by the
	// NIST radix-36 FF1 samples.
	LowerAlphanumeric = mustAlphabet("0123456789abcdefghijklmnopqrstuvwxyz")
	// UpperAlphanumeric is "0-9A-Z" (radix 36).
	UpperAlphanumeric = mustAlphabet("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	// Alphanumeric is "0-9a-zA-Z" (radix 62): digits, then lower-case, then
	// upper-case letters. This is the digit order of math/big and of the
	// radix-62 alphabets of other FF1 implementations.
	Alphanumeric = mustAlphabet("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
)

// mustAlphabet is only used for the package's own constant alphabets.
func mustAlphabet(s string) Alphabet {
	a, err := NewAlphabet(s)
	if err != nil {
		panic(err)
	}
	return a
}

// NewAlphabet returns a rune alphabet whose symbols are the runes of s, in
// order. s must be valid UTF-8 with 2..65536 distinct runes; the radix is
// utf8.RuneCountInString(s), not len(s). The rules of [NewRuneAlphabet]
// apply.
func NewAlphabet(s string) (Alphabet, error) {
	if !utf8.ValidString(s) {
		return Alphabet{}, fmt.Errorf("%w: invalid UTF-8", ErrInvalidAlphabet)
	}
	n := utf8.RuneCountInString(s)
	if n < MinRadix || n > MaxRadix {
		return Alphabet{}, fmt.Errorf("%w: alphabet has %d symbols, need %d..%d", ErrInvalidRadix, n, MinRadix, MaxRadix)
	}
	return NewRuneAlphabet([]rune(s))
}

// NewRuneAlphabet returns a rune alphabet with the given symbols, in order.
// Symbols must be distinct valid Unicode scalar values, and there must be
// 2..65536 of them. Surrogate halves and U+FFFD (utf8.RuneError) are
// rejected: U+FFFD is what lossy UTF-8 conversions substitute for invalid
// bytes, so accepting it as a symbol would let corrupted input encrypt
// silently. The slice is copied.
func NewRuneAlphabet(symbols []rune) (Alphabet, error) {
	n := len(symbols)
	if n < MinRadix || n > MaxRadix {
		return Alphabet{}, fmt.Errorf("%w: alphabet has %d symbols, need %d..%d", ErrInvalidRadix, n, MinRadix, MaxRadix)
	}
	a := newAlphabet(kindRunes, n)
	a.symbols = make([]rune, n)
	for i, r := range symbols {
		if !utf8.ValidRune(r) || r == utf8.RuneError {
			return Alphabet{}, fmt.Errorf("%w: symbol %d is not a valid Unicode scalar value", ErrInvalidAlphabet, i)
		}
		if a.lookup(r) >= 0 {
			return Alphabet{}, fmt.Errorf("%w: duplicate symbol at index %d", ErrInvalidAlphabet, i)
		}
		a.symbols[i] = r
		a.set(r, int32(i))
	}
	return Alphabet{a}, nil
}

// NewByteAlphabet returns a byte alphabet with the given symbols, in order.
// Strings encrypted with it are treated as raw bytes (not UTF-8). Symbols
// must be distinct and there must be 2..256 of them. The slice is copied.
func NewByteAlphabet(symbols []byte) (Alphabet, error) {
	n := len(symbols)
	if n < MinRadix || n > 256 {
		return Alphabet{}, fmt.Errorf("%w: byte alphabet has %d symbols, need %d..256", ErrInvalidRadix, n, MinRadix)
	}
	a := newAlphabet(kindBytes, n)
	a.symbols = make([]rune, n)
	for i, c := range symbols {
		if a.low[c] >= 0 {
			return Alphabet{}, fmt.Errorf("%w: duplicate symbol at index %d", ErrInvalidAlphabet, i)
		}
		a.symbols[i] = rune(c)
		a.low[c] = int32(i)
	}
	return Alphabet{a}, nil
}

// RadixOnly returns a symbol-less alphabet of the given radix (2..65536),
// for use with the numeral API only. The string methods of a [Cipher]
// built from it return [ErrNoSymbols].
func RadixOnly(radix int) (Alphabet, error) {
	if radix < MinRadix || radix > MaxRadix {
		return Alphabet{}, fmt.Errorf("%w: %d not in %d..%d", ErrInvalidRadix, radix, MinRadix, MaxRadix)
	}
	return Alphabet{newAlphabet(kindRadixOnly, radix)}, nil
}

func newAlphabet(kind alphabetKind, radix int) *alphabet {
	a := &alphabet{kind: kind, radix: radix}
	for i := range a.low {
		a.low[i] = -1
	}
	return a
}

func (a *alphabet) set(r rune, v int32) {
	if r >= 0 && r < 256 {
		a.low[r] = v
		return
	}
	if a.high == nil {
		a.high = make(map[rune]int32)
	}
	a.high[r] = v
}

func (a *alphabet) lookup(r rune) int32 {
	if r >= 0 && r < 256 {
		return a.low[r]
	}
	if v, ok := a.high[r]; ok {
		return v
	}
	return -1
}

// Radix returns the number of symbols in the alphabet, or 0 for the zero
// value.
func (a Alphabet) Radix() int {
	if a.a == nil {
		return 0
	}
	return a.a.radix
}

// String returns the alphabet's symbols as a string. For byte alphabets
// the result holds the raw symbol bytes; for radix-only and zero-value
// alphabets it is empty.
func (a Alphabet) String() string {
	if a.a == nil {
		return ""
	}
	switch a.a.kind {
	case kindRunes:
		return string(a.a.symbols)
	case kindBytes:
		b := make([]byte, len(a.a.symbols))
		for i, r := range a.a.symbols {
			b[i] = byte(r)
		}
		return string(b)
	}
	return ""
}

// symbolCount returns the number of symbols in s under this alphabet's
// encoding (runes or bytes).
func (a *alphabet) symbolCount(s string) int {
	if a.kind == kindBytes {
		return len(s)
	}
	return utf8.RuneCountInString(s)
}

// decode maps s to numerals. n must equal a.symbolCount(s), and the caller
// must already have checked n against the cipher's length limits
// (Cipher.checkParams), so the allocation below is bounded by the
// configured maximum length however long s is.
func (a *alphabet) decode(s string, n int) ([]uint16, error) {
	out := make([]uint16, n)
	if a.kind == kindBytes {
		for i := 0; i < len(s); i++ {
			v := a.low[s[i]]
			if v < 0 {
				return nil, fmt.Errorf("%w: at position %d", ErrInvalidSymbol, i)
			}
			out[i] = uint16(v)
		}
		return out, nil
	}
	i := 0
	for off := 0; off < len(s); {
		r, size := utf8.DecodeRuneInString(s[off:])
		v := int32(-1)
		if r != utf8.RuneError || size != 1 {
			v = a.lookup(r)
		}
		if v < 0 {
			return nil, fmt.Errorf("%w: at position %d", ErrInvalidSymbol, i)
		}
		out[i] = uint16(v)
		off += size
		i++
	}
	return out, nil
}

// encode maps numerals (all < radix) to a string.
func (a *alphabet) encode(x []uint16) string {
	if a.kind == kindBytes {
		b := make([]byte, len(x))
		for i, v := range x {
			b[i] = byte(a.symbols[v])
		}
		return string(b)
	}
	b := make([]byte, 0, len(x))
	for _, v := range x {
		b = utf8.AppendRune(b, a.symbols[v])
	}
	return string(b)
}
