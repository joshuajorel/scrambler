package ff1_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"slices"
	"strings"
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

func loadJSON(t testing.TB, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
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

// rng is a small deterministic xorshift64* generator so tests are
// reproducible without math/rand seeding concerns.
type rng uint64

func (r *rng) next() uint64 {
	x := uint64(*r)
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	*r = rng(x)
	return x * 0x2545F4914F6CDD1D
}

// intn returns a value in [0, n).
func (r *rng) intn(n int) int { return int(r.next() % uint64(n)) }

func (r *rng) bytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.next())
	}
	return b
}

func (r *rng) numerals(n, radix int) []uint16 {
	x := make([]uint16, n)
	for i := range x {
		x[i] = uint16(r.intn(radix))
	}
	return x
}

// domainOK reports whether radix^n >= 1,000,000, exactly.
func domainOK(radix, n int) bool {
	d := new(big.Int).Exp(big.NewInt(int64(radix)), big.NewInt(int64(n)), nil)
	return d.Cmp(big.NewInt(ff1.MinDomainSize)) >= 0
}

// encodeWith maps numerals to the runes of alphabet.
func encodeWith(alphabet string, x []uint16) string {
	syms := []rune(alphabet)
	var sb strings.Builder
	for _, d := range x {
		sb.WriteRune(syms[d])
	}
	return sb.String()
}
