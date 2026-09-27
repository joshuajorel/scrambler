package ff1_test

import (
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"testing"

	"github.com/joshuajorel/scrambler/ff1"
)

// allSentinels lists every exported sentinel error. Every error the package
// returns must wrap exactly one of them.
var allSentinels = []error{
	ff1.ErrInvalidKeyLength,
	ff1.ErrInvalidRadix,
	ff1.ErrInvalidAlphabet,
	ff1.ErrDomainTooSmall,
	ff1.ErrInvalidLength,
	ff1.ErrInvalidNumeral,
	ff1.ErrInvalidSymbol,
	ff1.ErrTweakTooLong,
	ff1.ErrInvalidOption,
	ff1.ErrNoSymbols,
	ff1.ErrUninitialized,
}

// sentinelCount returns how many exported sentinels err wraps.
func sentinelCount(err error) int {
	n := 0
	for _, s := range allSentinels {
		if errors.Is(err, s) {
			n++
		}
	}
	return n
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func mustNew(t testing.TB, key []byte, a ff1.Alphabet, opts ...ff1.Option) *ff1.Cipher {
	t.Helper()
	c, err := ff1.New(key, a, opts...)
	if err != nil {
		t.Fatalf("New(radix %d): %v", a.Radix(), err)
	}
	return c
}

func mustRadix(t testing.TB, radix int) ff1.Alphabet {
	t.Helper()
	a, err := ff1.RadixOnly(radix)
	if err != nil {
		t.Fatalf("RadixOnly(%d): %v", radix, err)
	}
	return a
}

func mustAlphabet(t testing.TB, s string) ff1.Alphabet {
	t.Helper()
	a, err := ff1.NewAlphabet(s)
	if err != nil {
		t.Fatalf("NewAlphabet(%q): %v", s, err)
	}
	return a
}

// toNumerals maps each rune of s to its index in alphabet.
func toNumerals(t testing.TB, alphabet, s string) []uint16 {
	t.Helper()
	syms := []rune(alphabet)
	var out []uint16
	for _, r := range s {
		i := slices.Index(syms, r)
		if i < 0 {
			t.Fatalf("%q not in alphabet %q", r, alphabet)
		}
		out = append(out, uint16(i))
	}
	return out
}

// testKey returns a deterministic key of the given length.
func testKey(n int) []byte {
	k := make([]byte, n)
	for i := range k {
		k[i] = byte(i*7 + 1)
	}
	return k
}

// defaultLimits returns the default (and largest accepted) input and tweak
// lengths: 2^32-1 for both on 64-bit platforms, 2^27-1 and 2^30-1 on 32-bit
// ones, where an int cannot hold every size derived from larger values.
func defaultLimits() (maxLen, maxTweak int64) {
	if strconv.IntSize == 64 {
		return 1<<32 - 1, 1<<32 - 1
	}
	return 1<<27 - 1, 1<<30 - 1
}
