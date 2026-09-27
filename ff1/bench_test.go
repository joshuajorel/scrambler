package ff1_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/joshuajorel/scrambler/ff1"
)

// T11 benchmarks. Run with: go test -run '^$' -bench . ./ff1

var benchTweak = []byte("benchmark-tweak")

// BenchmarkEncrypt measures the string API.
func BenchmarkEncrypt(b *testing.B) {
	for _, bc := range []struct {
		alphabet ff1.Alphabet
		n        int
	}{
		{ff1.Digits, 16},
		{ff1.Digits, 9},
		{ff1.LowerAlphanumeric, 19},
		{mustAlphabet(b, "01"), 512},
	} {
		syms := bc.alphabet.String()
		pt := strings.Repeat(syms, bc.n/len(syms)+1)[:bc.n]
		c := mustNew(b, testKey(16), bc.alphabet)
		b.Run(fmt.Sprintf("radix%d/n%d", bc.alphabet.Radix(), bc.n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := c.Encrypt(pt, benchTweak); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDecrypt measures the string API in the other direction.
func BenchmarkDecrypt(b *testing.B) {
	c := mustNew(b, testKey(16), ff1.Digits)
	ct, err := c.Encrypt("4111111111111111", benchTweak)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("radix10/n16", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := c.Decrypt(ct, benchTweak); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkEncryptNumerals measures the numeral API, including radix 65536.
func BenchmarkEncryptNumerals(b *testing.B) {
	for _, bc := range []struct{ radix, n int }{
		{10, 16},
		{10, 9},
		{36, 19},
		{2, 512},
		{65536, 2},
		{65536, 16},
		{65536, 256},
	} {
		c := mustNew(b, testKey(32), mustRadix(b, bc.radix))
		r := rng(uint64(bc.radix*1000 + bc.n))
		x := r.numerals(bc.n, bc.radix)
		b.Run(fmt.Sprintf("radix%d/n%d", bc.radix, bc.n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := c.EncryptNumerals(x, benchTweak); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("decrypt/radix%d/n%d", bc.radix, bc.n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := c.DecryptNumerals(x, benchTweak); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkNew measures cipher construction (AES key expansion plus
// parameter validation).
func BenchmarkNew(b *testing.B) {
	key := testKey(32)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ff1.New(key, ff1.Digits); err != nil {
			b.Fatal(err)
		}
	}
}
