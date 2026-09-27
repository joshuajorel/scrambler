package ff1_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/joshuajorel/scrambler/ff1"
)

// checkAgainstRef encrypts and decrypts x and compares both directions with
// the reference implementation.
func checkAgainstRef(t *testing.T, c *ff1.Cipher, key []byte, x []uint16, tweak []byte) {
	t.Helper()
	ct, err := c.EncryptNumerals(x, tweak)
	if err != nil {
		t.Fatalf("EncryptNumerals(n=%d, t=%d): %v", len(x), len(tweak), err)
	}
	if want := refCrypt(key, c.Radix(), tweak, x, true); !slices.Equal(ct, want) {
		t.Fatalf("EncryptNumerals(n=%d, t=%d) = %v, reference %v", len(x), len(tweak), ct, want)
	}
	pt, err := c.DecryptNumerals(ct, tweak)
	if err != nil || !slices.Equal(pt, x) {
		t.Fatalf("DecryptNumerals(EncryptNumerals(x)) = %v, %v; want %v", pt, err, x)
	}
	if want := refCrypt(key, c.Radix(), tweak, x, false); !slices.Equal(mustDecrypt(t, c, x, tweak), want) {
		t.Fatalf("DecryptNumerals(n=%d) disagrees with the reference", len(x))
	}
}

func mustDecrypt(t *testing.T, c *ff1.Cipher, x []uint16, tweak []byte) []uint16 {
	t.Helper()
	y, err := c.DecryptNumerals(x, tweak)
	if err != nil {
		t.Fatal(err)
	}
	return y
}

// TestRadixBounds is part of T5: radix 1 and 65537 are rejected; the
// listed radixes between are accepted and agree with the reference.
func TestRadixBounds(t *testing.T) {
	for _, r := range []int{-1, 0, 1, 65537, 1 << 20} {
		if _, err := ff1.RadixOnly(r); !errors.Is(err, ff1.ErrInvalidRadix) {
			t.Errorf("RadixOnly(%d) error = %v, want ErrInvalidRadix", r, err)
		}
	}
	if _, err := ff1.NewAlphabet("a"); !errors.Is(err, ff1.ErrInvalidRadix) {
		t.Errorf("NewAlphabet(1 symbol) error = %v, want ErrInvalidRadix", err)
	}
	if _, err := ff1.NewRuneAlphabet(runeRange(0x100, 65537)); !errors.Is(err, ff1.ErrInvalidRadix) {
		t.Errorf("NewRuneAlphabet(65537 symbols) error = %v, want ErrInvalidRadix", err)
	}
	if _, err := ff1.NewByteAlphabet([]byte{7}); !errors.Is(err, ff1.ErrInvalidRadix) {
		t.Errorf("NewByteAlphabet(1 symbol) error = %v, want ErrInvalidRadix", err)
	}
	if _, err := ff1.NewByteAlphabet(make([]byte, 257)); !errors.Is(err, ff1.ErrInvalidRadix) {
		t.Errorf("NewByteAlphabet(257 symbols) error = %v, want ErrInvalidRadix", err)
	}

	key := testKey(16)
	r := rng(42)
	for _, radix := range []int{2, 3, 10, 36, 64, 255, 256, 257, 999, 1000, 1023, 1024, 1025, 32767, 32768, 32769, 65535, 65536} {
		t.Run(fmt.Sprintf("radix%d", radix), func(t *testing.T) {
			c := mustNew(t, key, mustRadix(t, radix))
			if c.Radix() != radix {
				t.Fatalf("Radix() = %d", c.Radix())
			}
			for _, n := range []int{c.MinLength(), c.MinLength() + 1, 33, 64} {
				checkAgainstRef(t, c, key, r.numerals(n, radix), r.bytes(r.intn(40)))
			}
		})
	}

	// The largest alphabets are accepted and encrypt through the string API.
	big, err := ff1.NewRuneAlphabet(runeRange(0x10000, 65536)) // supplementary planes: 4-byte UTF-8
	if err != nil || big.Radix() != 65536 {
		t.Fatalf("NewRuneAlphabet(65536 symbols) = radix %d, %v", big.Radix(), err)
	}
	c := mustNew(t, key, big)
	pt := string(runeRange(0x10000+65534, 2)) + string(runeRange(0x10000, 3))
	ct, err := c.Encrypt(pt, nil)
	if err != nil || len([]rune(ct)) != 5 {
		t.Fatalf("Encrypt over 65536 runes = %q, %v", ct, err)
	}
	if back, err := c.Decrypt(ct, nil); err != nil || back != pt {
		t.Fatalf("Decrypt = %q, %v; want %q", back, err, pt)
	}
	bytes256 := make([]byte, 256)
	for i := range bytes256 {
		bytes256[i] = byte(255 - i)
	}
	if a, err := ff1.NewByteAlphabet(bytes256); err != nil || a.Radix() != 256 {
		t.Fatalf("NewByteAlphabet(256 symbols) = radix %d, %v", a.Radix(), err)
	}
}

func runeRange(start rune, n int) []rune {
	rs := make([]rune, n)
	for i := range rs {
		rs[i] = start + rune(i)
	}
	return rs
}

// TestMinLengthBoundary is part of T5: exactly minlen is accepted and
// minlen-1 is rejected with ErrDomainTooSmall.
func TestMinLengthBoundary(t *testing.T) {
	key := testKey(32)
	for _, tc := range []struct{ radix, minLen int }{
		{10, 6}, {2, 20}, {65536, 2}, {3, 13}, {16, 5}, {36, 4}, {99, 4}, {100, 3}, {256, 3}, {999, 3}, {1000, 2},
	} {
		t.Run(fmt.Sprintf("radix%d", tc.radix), func(t *testing.T) {
			c := mustNew(t, key, mustRadix(t, tc.radix))
			if c.MinLength() != tc.minLen {
				t.Fatalf("MinLength() = %d, want %d", c.MinLength(), tc.minLen)
			}
			if !domainOK(tc.radix, tc.minLen) || domainOK(tc.radix, tc.minLen-1) {
				t.Fatalf("test table is wrong for radix %d", tc.radix)
			}
			ok := make([]uint16, tc.minLen)
			checkAgainstRef(t, c, key, ok, nil)
			for _, n := range []int{tc.minLen - 1, 1, 0} {
				if _, err := c.EncryptNumerals(make([]uint16, n), nil); !errors.Is(err, ff1.ErrDomainTooSmall) {
					t.Errorf("EncryptNumerals(n=%d) error = %v, want ErrDomainTooSmall", n, err)
				}
				if _, err := c.DecryptNumerals(make([]uint16, n), nil); !errors.Is(err, ff1.ErrDomainTooSmall) {
					t.Errorf("DecryptNumerals(n=%d) error = %v, want ErrDomainTooSmall", n, err)
				}
			}
			if tc.minLen-1 >= 2 {
				if _, err := ff1.New(key, mustRadix(t, tc.radix), ff1.WithMinLength(tc.minLen-1)); !errors.Is(err, ff1.ErrDomainTooSmall) {
					t.Errorf("New(WithMinLength(%d)) error = %v, want ErrDomainTooSmall", tc.minLen-1, err)
				}
			}
		})
	}

	// The same boundary through the string API.
	c := mustNew(t, key, ff1.Digits)
	if _, err := c.Encrypt("123456", nil); err != nil {
		t.Errorf("Encrypt(6 digits): %v", err)
	}
	if _, err := c.Encrypt("12345", nil); !errors.Is(err, ff1.ErrDomainTooSmall) {
		t.Errorf("Encrypt(5 digits) error = %v, want ErrDomainTooSmall", err)
	}
	bin := mustNew(t, key, mustAlphabet(t, "01"))
	if _, err := bin.Encrypt(strings.Repeat("1", 20), nil); err != nil {
		t.Errorf("Encrypt(20 bits): %v", err)
	}
	if _, err := bin.Decrypt(strings.Repeat("1", 19), nil); !errors.Is(err, ff1.ErrDomainTooSmall) {
		t.Errorf("Decrypt(19 bits) error = %v, want ErrDomainTooSmall", err)
	}
}

// TestLengthParity is part of T5: odd and even n (u != v and u == v).
func TestLengthParity(t *testing.T) {
	r := rng(7)
	for _, radix := range []int{2, 7, 10, 26, 64, 255, 256, 1000, 65536} {
		key := testKey(24)
		c := mustNew(t, key, mustRadix(t, radix))
		lo := c.MinLength()
		for n := lo; n < lo+8; n++ {
			checkAgainstRef(t, c, key, r.numerals(n, radix), r.bytes(n%20))
		}
		for _, n := range []int{99, 100, 101, 255, 256, 257, 511, 512, 513} {
			checkAgainstRef(t, c, key, r.numerals(n, radix), r.bytes(9))
		}
	}
}

// TestRadix2V232 is part of T5: radix 2 with v = 232 needs b = 29 bytes
// (232 bits exactly; see TestByteLengthsKnown). Both n = 463 (u = 231) and
// n = 464 (u = 232) have v = 232.
func TestRadix2V232(t *testing.T) {
	key := testKey(16)
	c := mustNew(t, key, mustRadix(t, 2))
	r := rng(232)
	for _, n := range []int{463, 464} {
		for range 4 {
			checkAgainstRef(t, c, key, r.numerals(n, 2), r.bytes(r.intn(30)))
		}
		checkAgainstRef(t, c, key, make([]uint16, n), nil)
	}
}

// TestLargeD exercises d > 16, where S needs the extra CIPH(R xor [j]^16)
// blocks (b > 12), and d > 32 (two extra blocks).
func TestLargeD(t *testing.T) {
	key := testKey(32)
	r := rng(16)
	for _, tc := range []struct{ radix, n int }{
		{10, 58},    // v = 29 -> 97 bits -> b = 13 -> d = 20
		{10, 60},    // b = 13
		{2, 200},    // v = 100 -> b = 13 -> d = 20
		{65536, 14}, // v = 7 -> b = 14 -> d = 20
		{65536, 30}, // v = 15 -> b = 30 -> d = 36: three S blocks
		{36, 200},
		{10, 1000},
	} {
		c := mustNew(t, key, mustRadix(t, tc.radix))
		checkAgainstRef(t, c, key, r.numerals(tc.n, tc.radix), r.bytes(11))
	}
}

// TestTweakBounds is part of T5: empty, maximum, and maximum+1 tweaks,
// including lengths around the 16-byte block boundaries of Q.
func TestTweakBounds(t *testing.T) {
	key := testKey(16)
	r := rng(99)
	x := r.numerals(12, 10)
	for _, maxT := range []int{0, 1, 15, 16, 17, 31, 32, 33, 255, 256} {
		c := mustNew(t, key, mustRadix(t, 10), ff1.WithMaxTweakLength(maxT))
		if c.MaxTweakLength() != maxT {
			t.Fatalf("MaxTweakLength() = %d, want %d", c.MaxTweakLength(), maxT)
		}
		checkAgainstRef(t, c, key, x, nil)
		checkAgainstRef(t, c, key, x, []byte{})
		checkAgainstRef(t, c, key, x, r.bytes(maxT))
		if _, err := c.EncryptNumerals(x, r.bytes(maxT+1)); !errors.Is(err, ff1.ErrTweakTooLong) {
			t.Errorf("maxT %d: EncryptNumerals(tweak %d) error = %v, want ErrTweakTooLong", maxT, maxT+1, err)
		}
		if _, err := c.DecryptNumerals(x, r.bytes(maxT+1)); !errors.Is(err, ff1.ErrTweakTooLong) {
			t.Errorf("maxT %d: DecryptNumerals(tweak %d) error = %v, want ErrTweakTooLong", maxT, maxT+1, err)
		}
		dc := mustNew(t, key, ff1.Digits, ff1.WithMaxTweakLength(maxT))
		if _, err := dc.Encrypt("0123456789", r.bytes(maxT+1)); !errors.Is(err, ff1.ErrTweakTooLong) {
			t.Errorf("maxT %d: Encrypt(tweak %d) error = %v, want ErrTweakTooLong", maxT, maxT+1, err)
		}
	}

	// Every tweak length 0..100 (so every padding length) with the default
	// limit, and a tweak much longer than any block-sized buffer.
	c := mustNew(t, key, mustRadix(t, 36))
	if c.MaxTweakLength() < 1<<31-1 {
		t.Errorf("default MaxTweakLength() = %d", c.MaxTweakLength())
	}
	for tl := 0; tl <= 100; tl++ {
		checkAgainstRef(t, c, key, r.numerals(1+tl%40+4, 36), r.bytes(tl))
	}
	checkAgainstRef(t, c, key, r.numerals(19, 36), r.bytes(64<<10+13))
}

// TestExtremeInputs is part of T5: all-zero and all-(radix-1) inputs.
func TestExtremeInputs(t *testing.T) {
	for _, radix := range []int{2, 10, 36, 256, 65536} {
		key := testKey(32)
		c := mustNew(t, key, mustRadix(t, radix))
		for _, n := range []int{c.MinLength(), c.MinLength() + 1, 40} {
			zeros := make([]uint16, n)
			maxes := make([]uint16, n)
			for i := range maxes {
				maxes[i] = uint16(radix - 1)
			}
			for _, x := range [][]uint16{zeros, maxes} {
				checkAgainstRef(t, c, key, x, nil)
				checkAgainstRef(t, c, key, x, []byte("tweak"))
				// Decrypting the extreme values (as ciphertexts) must work too.
				if _, err := c.DecryptNumerals(x, nil); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	// And through the string API.
	c := mustNew(t, testKey(16), ff1.Digits)
	for _, pt := range []string{"000000", "999999", strings.Repeat("0", 100), strings.Repeat("9", 101)} {
		ct, err := c.Encrypt(pt, nil)
		if err != nil || len(ct) != len(pt) {
			t.Fatalf("Encrypt(%q) = %q, %v", pt, ct, err)
		}
		if back, err := c.Decrypt(ct, nil); err != nil || back != pt {
			t.Fatalf("Decrypt(Encrypt(%q)) = %q, %v", pt, back, err)
		}
	}
}

// TestLengthOptions covers custom length limits: exactly min/max accepted,
// one beyond rejected with ErrInvalidLength.
func TestLengthOptions(t *testing.T) {
	key := testKey(16)
	c := mustNew(t, key, ff1.Digits, ff1.WithMinLength(8), ff1.WithMaxLength(12))
	if c.MinLength() != 8 || c.MaxLength() != 12 {
		t.Fatalf("limits = %d..%d, want 8..12", c.MinLength(), c.MaxLength())
	}
	for n := 5; n <= 14; n++ {
		_, err := c.Encrypt(strings.Repeat("7", n), nil)
		_, errN := c.EncryptNumerals(make([]uint16, n), nil)
		switch {
		case n < 6:
			if !errors.Is(err, ff1.ErrDomainTooSmall) || !errors.Is(errN, ff1.ErrDomainTooSmall) {
				t.Errorf("n=%d: errors %v / %v, want ErrDomainTooSmall", n, err, errN)
			}
		case n < 8 || n > 12:
			if !errors.Is(err, ff1.ErrInvalidLength) || !errors.Is(errN, ff1.ErrInvalidLength) {
				t.Errorf("n=%d: errors %v / %v, want ErrInvalidLength", n, err, errN)
			}
		default:
			if err != nil || errN != nil {
				t.Errorf("n=%d: errors %v / %v, want nil", n, err, errN)
			}
		}
	}
	// minlen == maxlen is allowed.
	fixed := mustNew(t, key, ff1.Digits, ff1.WithMinLength(16), ff1.WithMaxLength(16))
	if _, err := fixed.Encrypt("4111111111111111", nil); err != nil {
		t.Error(err)
	}
	// The default maximum is the specification's 2^32-1 (clamped to int).
	if d := mustNew(t, key, ff1.Digits); d.MaxLength() < 1<<31-1 {
		t.Errorf("default MaxLength() = %d", d.MaxLength())
	}
}

// TestRadix65536Boundaries covers the edges of the largest radix: digits on
// either side of the int16 sign bit and the maximum digit, the shortest
// lengths, and the length where S grows from one block to two.
func TestRadix65536Boundaries(t *testing.T) {
	key := testKey(16)
	c := mustNew(t, key, mustRadix(t, 65536))
	for _, x := range [][]uint16{
		{32767, 32768},
		{65535, 32767, 32768},
		{65535, 65535},
		{0, 65535},
		{32768, 32767, 65535, 0},
	} {
		checkAgainstRef(t, c, key, x, nil)
		checkAgainstRef(t, c, key, x, []byte{0x80})
	}
	// n = 2 and n = 3 (u = 1 in both; v = 1 and 2).
	r := rng(65536)
	for range 8 {
		checkAgainstRef(t, c, key, r.numerals(2, 65536), r.bytes(8))
		checkAgainstRef(t, c, key, r.numerals(3, 65536), r.bytes(8))
	}
	// n = 12: b = 12, d = 16 (S is R alone); n = 13: b = 14, d = 20 (S needs
	// CIPH(R xor [1]^16)). See TestByteLengthsRadix65536.
	for _, n := range []int{12, 13} {
		for range 4 {
			checkAgainstRef(t, c, key, r.numerals(n, 65536), r.bytes(r.intn(20)))
		}
	}

	// Digit validity next to the radix, for radixes around 2^15 and 2^16.
	for _, tc := range []struct {
		radix     int
		ok, notOK uint16
	}{
		{32767, 32766, 32767},
		{32768, 32767, 32768},
		{32769, 32768, 32769},
		{65535, 65534, 65535},
	} {
		rc := mustNew(t, key, mustRadix(t, tc.radix))
		good := []uint16{tc.ok, 0, tc.ok}
		checkAgainstRef(t, rc, key, good, nil)
		if _, err := rc.EncryptNumerals([]uint16{tc.notOK, 0, 0}, nil); !errors.Is(err, ff1.ErrInvalidNumeral) {
			t.Errorf("radix %d: EncryptNumerals(%d) error = %v, want ErrInvalidNumeral", tc.radix, tc.notOK, err)
		}
		if _, err := rc.DecryptNumerals([]uint16{0, 0, tc.notOK}, nil); !errors.Is(err, ff1.ErrInvalidNumeral) {
			t.Errorf("radix %d: DecryptNumerals(%d) error = %v, want ErrInvalidNumeral", tc.radix, tc.notOK, err)
		}
	}
}
