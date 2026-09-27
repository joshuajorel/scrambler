package ff1_test

import (
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/joshuajorel/scrambler/ff1"
)

// TestKeyLengths is part of T6: only 16, 24, and 32-byte keys are accepted.
func TestKeyLengths(t *testing.T) {
	for n := 0; n <= 65; n++ {
		_, err := ff1.New(make([]byte, n), ff1.Digits)
		switch n {
		case 16, 24, 32:
			if err != nil {
				t.Errorf("New(%d-byte key): %v", n, err)
			}
		default:
			if !errors.Is(err, ff1.ErrInvalidKeyLength) {
				t.Errorf("New(%d-byte key) error = %v, want ErrInvalidKeyLength", n, err)
			}
		}
	}
	if _, err := ff1.New(nil, ff1.Digits); !errors.Is(err, ff1.ErrInvalidKeyLength) {
		t.Errorf("New(nil key) error = %v, want ErrInvalidKeyLength", err)
	}
}

// TestInvalidSymbols is part of T6: characters outside the alphabet,
// invalid UTF-8, and out-of-range numerals are rejected.
func TestInvalidSymbols(t *testing.T) {
	key := testKey(16)
	digits := mustNew(t, key, ff1.Digits)
	for _, s := range []string{
		"12345a7890",         // letter
		"１２３４５６７",            // full-width digits (multi-byte, not in alphabet)
		"123456789\xff",      // invalid UTF-8
		"\xc0\x80" + "12345", // overlong encoding
		"12345 67890",        // space
		"1234567 ",           // NBSP
		"123456�",            // U+FFFD literal
		"123456\x00",         // NUL
	} {
		if _, err := digits.Encrypt(s, nil); !errors.Is(err, ff1.ErrInvalidSymbol) {
			t.Errorf("Encrypt(%q) error = %v, want ErrInvalidSymbol", s, err)
		}
		if _, err := digits.Decrypt(s, nil); !errors.Is(err, ff1.ErrInvalidSymbol) {
			t.Errorf("Decrypt(%q) error = %v, want ErrInvalidSymbol", s, err)
		}
	}

	// A rune alphabet counts runes, so a multi-byte symbol is one symbol.
	greek := mustNew(t, key, mustAlphabet(t, "αβγδεζηθικ"))
	if _, err := greek.Encrypt("αβγδεζ", nil); err != nil {
		t.Errorf("Encrypt(6 Greek letters): %v", err)
	}
	if _, err := greek.Encrypt("αβγδεa", nil); !errors.Is(err, ff1.ErrInvalidSymbol) {
		t.Errorf("Encrypt with a Latin letter error = %v, want ErrInvalidSymbol", err)
	}
	// Truncated UTF-8 of an otherwise valid symbol.
	if _, err := greek.Encrypt("αβγδεζ"[:11], nil); !errors.Is(err, ff1.ErrInvalidSymbol) {
		t.Errorf("Encrypt(truncated UTF-8) error = %v, want ErrInvalidSymbol", err)
	}

	// A byte alphabet treats input as raw bytes.
	ba, err := ff1.NewByteAlphabet([]byte{0x00, 0xff, 0x80, 'a', 'b', 'c', 'd', 'e', 'f', 'g'})
	if err != nil {
		t.Fatal(err)
	}
	bc := mustNew(t, key, ba)
	if _, err := bc.Encrypt("\x00\xff\x80abc", nil); err != nil {
		t.Errorf("byte alphabet Encrypt: %v", err)
	}
	if _, err := bc.Encrypt("\x00\xff\x80abz", nil); !errors.Is(err, ff1.ErrInvalidSymbol) {
		t.Errorf("byte alphabet Encrypt(z) error = %v, want ErrInvalidSymbol", err)
	}

	// Numerals must be < radix.
	nc := mustNew(t, key, mustRadix(t, 10))
	for _, x := range [][]uint16{{1, 2, 3, 4, 5, 10}, {10, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, math.MaxUint16}} {
		if _, err := nc.EncryptNumerals(x, nil); !errors.Is(err, ff1.ErrInvalidNumeral) {
			t.Errorf("EncryptNumerals(%v) error = %v, want ErrInvalidNumeral", x, err)
		}
		if _, err := nc.DecryptNumerals(x, nil); !errors.Is(err, ff1.ErrInvalidNumeral) {
			t.Errorf("DecryptNumerals(%v) error = %v, want ErrInvalidNumeral", x, err)
		}
	}
	// Every numeral is valid for radix 65536.
	full := mustNew(t, key, mustRadix(t, 65536))
	if _, err := full.EncryptNumerals([]uint16{math.MaxUint16, math.MaxUint16}, nil); err != nil {
		t.Errorf("radix 65536 EncryptNumerals(max): %v", err)
	}
}

// TestDomainTooSmall is part of T6.
func TestDomainTooSmall(t *testing.T) {
	key := testKey(16)
	c := mustNew(t, key, ff1.Digits)
	for _, s := range []string{"", "1", "12", "12345"} {
		if _, err := c.Encrypt(s, nil); !errors.Is(err, ff1.ErrDomainTooSmall) {
			t.Errorf("Encrypt(%q) error = %v, want ErrDomainTooSmall", s, err)
		}
		if _, err := c.Decrypt(s, nil); !errors.Is(err, ff1.ErrDomainTooSmall) {
			t.Errorf("Decrypt(%q) error = %v, want ErrDomainTooSmall", s, err)
		}
	}
	for _, opt := range []ff1.Option{ff1.WithMinLength(5), ff1.WithMaxLength(5), ff1.WithMinLength(2)} {
		if _, err := ff1.New(key, ff1.Digits, opt); !errors.Is(err, ff1.ErrDomainTooSmall) {
			t.Errorf("New with a sub-10^6 length limit: error = %v, want ErrDomainTooSmall", err)
		}
	}
}

// TestMaxLength is part of T6: n > maxlen is rejected.
func TestMaxLength(t *testing.T) {
	key := testKey(16)
	c := mustNew(t, key, ff1.Digits, ff1.WithMaxLength(19))
	if _, err := c.Encrypt(strings.Repeat("5", 19), nil); err != nil {
		t.Errorf("Encrypt(19 digits): %v", err)
	}
	if _, err := c.Encrypt(strings.Repeat("5", 20), nil); !errors.Is(err, ff1.ErrInvalidLength) {
		t.Errorf("Encrypt(20 digits) error = %v, want ErrInvalidLength", err)
	}
	if _, err := c.DecryptNumerals(make([]uint16, 20), nil); !errors.Is(err, ff1.ErrInvalidLength) {
		t.Errorf("DecryptNumerals(20) error = %v, want ErrInvalidLength", err)
	}
}

func TestInvalidOptions(t *testing.T) {
	key := testKey(16)
	cases := map[string][]ff1.Option{
		"min<2":      {ff1.WithMinLength(1)},
		"min<0":      {ff1.WithMinLength(-5)},
		"max<2":      {ff1.WithMaxLength(1)},
		"maxTweak<0": {ff1.WithMaxTweakLength(-1)},
		"min>max":    {ff1.WithMinLength(10), ff1.WithMaxLength(9)},
	}
	if strconv.IntSize == 64 {
		// FF1 encodes n and t in 4 bytes, so both must be < 2^32. (A
		// variable shift keeps this compiling where int is 32 bits.)
		shift := 32
		tooBig := int(uint64(1) << shift)
		cases["min>=2^32"] = []ff1.Option{ff1.WithMinLength(tooBig)}
		cases["max>=2^32"] = []ff1.Option{ff1.WithMaxLength(tooBig)}
		cases["maxTweak>=2^32"] = []ff1.Option{ff1.WithMaxTweakLength(tooBig)}
		c := mustNew(t, key, ff1.Digits, ff1.WithMaxLength(tooBig-1), ff1.WithMaxTweakLength(tooBig-1))
		if c.MaxLength() != tooBig-1 || c.MaxTweakLength() != tooBig-1 {
			t.Errorf("limits %d/%d, want 2^32-1", c.MaxLength(), c.MaxTweakLength())
		}
	}
	for name, opts := range cases {
		if _, err := ff1.New(key, ff1.Digits, opts...); !errors.Is(err, ff1.ErrInvalidOption) {
			t.Errorf("%s: error = %v, want ErrInvalidOption", name, err)
		}
	}
	// nil options are ignored.
	if _, err := ff1.New(key, ff1.Digits, nil, ff1.WithMaxLength(100), nil); err != nil {
		t.Errorf("New with nil options: %v", err)
	}
	// The last option of a kind wins.
	c := mustNew(t, key, ff1.Digits, ff1.WithMaxLength(50), ff1.WithMaxLength(60))
	if c.MaxLength() != 60 {
		t.Errorf("MaxLength() = %d, want 60", c.MaxLength())
	}
}

func TestInvalidAlphabets(t *testing.T) {
	for name, s := range map[string]string{
		"duplicate":        "0123456789012",
		"duplicate-rune":   "αβγα",
		"invalid-utf8":     "01\xff23",
		"surrogate-in-str": "01\xed\xa0\x80", // UTF-8 encoded surrogate: invalid UTF-8
		"replacement":      "01�",
	} {
		if _, err := ff1.NewAlphabet(s); !errors.Is(err, ff1.ErrInvalidAlphabet) {
			t.Errorf("NewAlphabet(%s) error = %v, want ErrInvalidAlphabet", name, err)
		}
	}
	for name, rs := range map[string][]rune{
		"surrogate":   {'0', '1', 0xD800},
		"negative":    {'0', '1', -1},
		"too-large":   {'0', '1', 0x110000},
		"replacement": {'0', '1', 0xFFFD},
		"duplicate":   {'a', 'b', 'a'},
	} {
		if _, err := ff1.NewRuneAlphabet(rs); !errors.Is(err, ff1.ErrInvalidAlphabet) {
			t.Errorf("NewRuneAlphabet(%s) error = %v, want ErrInvalidAlphabet", name, err)
		}
	}
	if _, err := ff1.NewByteAlphabet([]byte("abca")); !errors.Is(err, ff1.ErrInvalidAlphabet) {
		t.Errorf("NewByteAlphabet(duplicate) error = %v, want ErrInvalidAlphabet", err)
	}
	// The zero Alphabet is rejected by New.
	if _, err := ff1.New(testKey(16), ff1.Alphabet{}); !errors.Is(err, ff1.ErrInvalidRadix) {
		t.Errorf("New(zero Alphabet) error = %v, want ErrInvalidRadix", err)
	}
}

func TestRadixOnlyHasNoSymbols(t *testing.T) {
	c := mustNew(t, testKey(16), mustRadix(t, 10))
	if _, err := c.Encrypt("0123456789", nil); !errors.Is(err, ff1.ErrNoSymbols) {
		t.Errorf("Encrypt error = %v, want ErrNoSymbols", err)
	}
	if _, err := c.Decrypt("0123456789", nil); !errors.Is(err, ff1.ErrNoSymbols) {
		t.Errorf("Decrypt error = %v, want ErrNoSymbols", err)
	}
}

// TestZeroCipher checks that a zero or nil Cipher returns errors instead of
// panicking.
func TestZeroCipher(t *testing.T) {
	for name, c := range map[string]*ff1.Cipher{"zero": new(ff1.Cipher), "nil": nil} {
		if _, err := c.Encrypt("0123456789", nil); !errors.Is(err, ff1.ErrUninitialized) {
			t.Errorf("%s: Encrypt error = %v", name, err)
		}
		if _, err := c.Decrypt("0123456789", nil); !errors.Is(err, ff1.ErrUninitialized) {
			t.Errorf("%s: Decrypt error = %v", name, err)
		}
		if _, err := c.EncryptNumerals(make([]uint16, 10), nil); !errors.Is(err, ff1.ErrUninitialized) {
			t.Errorf("%s: EncryptNumerals error = %v", name, err)
		}
		if _, err := c.DecryptNumerals(make([]uint16, 10), nil); !errors.Is(err, ff1.ErrUninitialized) {
			t.Errorf("%s: DecryptNumerals error = %v", name, err)
		}
		if c.Radix() != 0 || c.MinLength() != 0 || c.MaxLength() != 0 || c.MaxTweakLength() != 0 || c.Alphabet().Radix() != 0 {
			t.Errorf("%s: accessors return non-zero values", name)
		}
	}
}

// TestErrorsDoNotLeak checks that error messages never contain key,
// tweak, plaintext, or ciphertext material, and that every error wraps
// exactly one sentinel.
func TestErrorsDoNotLeak(t *testing.T) {
	key := mustHex(t, "0f1e2d3c4b5a69788796a5b4c3d2e1f0")
	secret := "8765432109876543x"
	tweak := []byte("TWEAK-SECRET-VALUE")
	c := mustNew(t, key, ff1.Digits, ff1.WithMaxTweakLength(4))
	var errs []error
	_, err := c.Encrypt(secret, nil)
	errs = append(errs, err)
	_, err = c.Encrypt(secret[:16], tweak)
	errs = append(errs, err)
	_, err = c.Decrypt("12345", tweak[:2])
	errs = append(errs, err)
	_, err = ff1.New(key[:15], ff1.Digits)
	errs = append(errs, err)
	for _, err := range errs {
		if err == nil {
			t.Fatal("expected an error")
		}
		msg := err.Error()
		for _, leak := range []string{secret[:10], "TWEAK", "12345", hex.EncodeToString(key[:4]), string(key[:4])} {
			if strings.Contains(msg, leak) {
				t.Errorf("error %q leaks %q", msg, leak)
			}
		}
		if n := sentinelCount(err); n != 1 {
			t.Errorf("error %q wraps %d sentinels, want 1", msg, n)
		}
	}
}
