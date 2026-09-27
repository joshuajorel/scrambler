package ff1_test

import (
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/joshuajorel/scrambler/ff1"
)

// TestDeterminism is part of T9: the same key, tweak, and plaintext always
// give the same ciphertext, across calls and across independently built
// ciphers.
func TestDeterminism(t *testing.T) {
	key := testKey(32)
	tweak := []byte("determinism")
	c1 := mustNew(t, key, ff1.Digits)
	c2 := mustNew(t, slices.Clone(key), mustAlphabet(t, "0123456789"))
	pt := "4111111111111111"
	first, err := c1.Encrypt(pt, tweak)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 100 {
		c := c1
		if i%2 == 1 {
			c = c2
		}
		if ct, err := c.Encrypt(pt, slices.Clone(tweak)); err != nil || ct != first {
			t.Fatalf("call %d: Encrypt = %q, %v; want %q", i, ct, err, first)
		}
	}
	// Inputs are not modified.
	x := []uint16{1, 2, 3, 4, 5, 6, 7, 8}
	orig := slices.Clone(x)
	tw := []byte{9, 9}
	nc := mustNew(t, key, mustRadix(t, 10))
	if _, err := nc.EncryptNumerals(x, tw); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(x, orig) || !slices.Equal(tw, []byte{9, 9}) {
		t.Fatal("EncryptNumerals modified its inputs")
	}
	// The key slice is not retained.
	k := slices.Clone(key)
	c3 := mustNew(t, k, ff1.Digits)
	clear(k)
	if ct, err := c3.Encrypt(pt, tweak); err != nil || ct != first {
		t.Fatalf("after clearing the key slice: %q, %v; want %q", ct, err, first)
	}
}

// TestKeySensitivity is part of T9: flipping any single key bit changes the
// ciphertext. radix 10, n = 16 makes a chance collision a 10^-16 event.
func TestKeySensitivity(t *testing.T) {
	pt := "0123456789012345"
	tweak := []byte("key-sensitivity")
	for _, klen := range []int{16, 24, 32} {
		key := testKey(klen)
		base, err := mustNew(t, key, ff1.Digits).Encrypt(pt, tweak)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{base: true}
		for bit := range klen * 8 {
			k := slices.Clone(key)
			k[bit/8] ^= 1 << (bit % 8)
			ct, err := mustNew(t, k, ff1.Digits).Encrypt(pt, tweak)
			if err != nil {
				t.Fatal(err)
			}
			if seen[ct] {
				t.Errorf("AES-%d: flipping key bit %d repeats ciphertext %q", klen*8, bit, ct)
			}
			seen[ct] = true
		}
	}
}

// TestTweakSensitivity is part of T9: every single-bit tweak change, and
// every change of tweak length (including trailing zero bytes, which change
// t in P), changes the ciphertext.
func TestTweakSensitivity(t *testing.T) {
	c := mustNew(t, testKey(16), ff1.Digits)
	pt := "0123456789012345"
	tweak := []byte("tweak-sensitivity-0123456789")
	seen := map[string]string{}
	record := func(name string, tw []byte) {
		ct, err := c.Encrypt(pt, tw)
		if err != nil {
			t.Fatal(err)
		}
		if prev, ok := seen[ct]; ok {
			t.Errorf("tweaks %s and %s give the same ciphertext %q", prev, name, ct)
		}
		seen[ct] = name
	}
	record("base", tweak)
	for bit := range len(tweak) * 8 {
		tw := slices.Clone(tweak)
		tw[bit/8] ^= 1 << (bit % 8)
		record(fmt.Sprintf("bit%d", bit), tw)
	}
	record("empty", nil)
	for n := 1; n <= 40; n++ {
		record(fmt.Sprintf("zeros%d", n), make([]byte, n))
	}
	record("base+00", append(slices.Clone(tweak), 0))
	record("base[:len-1]", tweak[:len(tweak)-1])
}

// TestPlaintextSensitivity: changing one plaintext digit changes the
// ciphertext in more than that position (diffusion across the Feistel
// halves).
func TestPlaintextSensitivity(t *testing.T) {
	c := mustNew(t, testKey(16), ff1.Digits)
	pt := []byte("0000000000000000")
	base, err := c.Encrypt(string(pt), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range pt {
		p := slices.Clone(pt)
		p[i] = '1'
		ct, err := c.Encrypt(string(p), nil)
		if err != nil {
			t.Fatal(err)
		}
		diff := 0
		for j := range ct {
			if ct[j] != base[j] {
				diff++
			}
		}
		if diff < 2 {
			t.Errorf("changing digit %d changed only %d ciphertext digits", i, diff)
		}
	}
}

// TestConcurrentUse is T10: one Cipher (and one Alphabet) shared by many
// goroutines gives the same results as sequential use. Run with -race.
func TestConcurrentUse(t *testing.T) {
	key := testKey(32)
	alpha := ff1.Alphanumeric
	c := mustNew(t, key, alpha)
	nc := mustNew(t, key, mustRadix(t, 65536))
	r := rng(10)

	type job struct {
		pt, ct string
		tweak  []byte
		x, y   []uint16
	}
	jobs := make([]job, 64)
	for i := range jobs {
		n := 4 + r.intn(40)
		syms := []rune(alpha.String())
		var pt []rune
		for range n {
			pt = append(pt, syms[r.intn(len(syms))])
		}
		j := job{pt: string(pt), tweak: r.bytes(r.intn(24)), x: r.numerals(2+r.intn(30), 65536)}
		var err error
		if j.ct, err = c.Encrypt(j.pt, j.tweak); err != nil {
			t.Fatal(err)
		}
		if j.y, err = nc.EncryptNumerals(j.x, j.tweak); err != nil {
			t.Fatal(err)
		}
		jobs[i] = j
	}

	var wg sync.WaitGroup
	for g := range 32 {
		wg.Go(func() {
			// A second cipher built concurrently from the same key and alphabet.
			local, err := ff1.New(key, alpha)
			if err != nil {
				t.Error(err)
				return
			}
			for k := range 4 * len(jobs) {
				j := jobs[(g*7+k)%len(jobs)]
				use := c
				if k%3 == 0 {
					use = local
				}
				if ct, err := use.Encrypt(j.pt, j.tweak); err != nil || ct != j.ct {
					t.Errorf("goroutine %d: Encrypt(%q) = %q, %v; want %q", g, j.pt, ct, err, j.ct)
					return
				}
				if pt, err := use.Decrypt(j.ct, j.tweak); err != nil || pt != j.pt {
					t.Errorf("goroutine %d: Decrypt = %q, %v; want %q", g, pt, err, j.pt)
					return
				}
				if y, err := nc.EncryptNumerals(j.x, j.tweak); err != nil || !slices.Equal(y, j.y) {
					t.Errorf("goroutine %d: EncryptNumerals mismatch", g)
					return
				}
				if x, err := nc.DecryptNumerals(j.y, j.tweak); err != nil || !slices.Equal(x, j.x) {
					t.Errorf("goroutine %d: DecryptNumerals mismatch", g)
					return
				}
			}
		})
	}
	wg.Wait()
}
