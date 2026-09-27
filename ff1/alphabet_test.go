package ff1_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/joshuajorel/scrambler/ff1"
)

func TestPredefinedAlphabets(t *testing.T) {
	for _, tc := range []struct {
		name  string
		a     ff1.Alphabet
		want  string
		radix int
	}{
		{"Digits", ff1.Digits, "0123456789", 10},
		{"HexLower", ff1.HexLower, "0123456789abcdef", 16},
		{"HexUpper", ff1.HexUpper, "0123456789ABCDEF", 16},
		{"LowerAlphanumeric", ff1.LowerAlphanumeric, "0123456789abcdefghijklmnopqrstuvwxyz", 36},
		{"UpperAlphanumeric", ff1.UpperAlphanumeric, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", 36},
		{"Alphanumeric", ff1.Alphanumeric, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 62},
	} {
		if tc.a.String() != tc.want || tc.a.Radix() != tc.radix {
			t.Errorf("%s = %q (radix %d), want %q (radix %d)", tc.name, tc.a.String(), tc.a.Radix(), tc.want, tc.radix)
		}
	}
	// Alphanumeric extends LowerAlphanumeric, like math/big's digit order.
	if !strings.HasPrefix(ff1.Alphanumeric.String(), ff1.LowerAlphanumeric.String()) {
		t.Error("Alphanumeric does not start with LowerAlphanumeric")
	}
}

// TestRuneAlphabetRadix checks that the radix of a Unicode alphabet is its
// rune count, not its byte length, and that lengths are counted in runes.
func TestRuneAlphabetRadix(t *testing.T) {
	s := "日本語のテキスト😀🎉ÄÖÜ" // 3-byte, 4-byte, and 2-byte runes
	a := mustAlphabet(t, s)
	if want := utf8.RuneCountInString(s); a.Radix() != want || want == len(s) {
		t.Fatalf("Radix() = %d, want %d (byte length %d)", a.Radix(), want, len(s))
	}
	if a.String() != s {
		t.Fatalf("String() = %q", a.String())
	}
	rs, err := ff1.NewRuneAlphabet([]rune(s))
	if err != nil || rs.String() != s || rs.Radix() != a.Radix() {
		t.Fatalf("NewRuneAlphabet = %q, %v", rs.String(), err)
	}

	key := testKey(16)
	c := mustNew(t, key, a)
	// radix 15: 15^5 = 759375 < 10^6 <= 15^6, so minlen is 6 runes (>= 6 bytes).
	if c.MinLength() != 6 {
		t.Fatalf("MinLength() = %d, want 6", c.MinLength())
	}
	pt := "😀日😀本🎉Ü"
	ct, err := c.Encrypt(pt, []byte("t"))
	if err != nil {
		t.Fatal(err)
	}
	if utf8.RuneCountInString(ct) != utf8.RuneCountInString(pt) {
		t.Fatalf("Encrypt(%q) = %q changes the rune count", pt, ct)
	}
	for _, r := range ct {
		if !strings.ContainsRune(s, r) {
			t.Fatalf("ciphertext %q contains %q, not in the alphabet", ct, r)
		}
	}
	if back, err := c.Decrypt(ct, []byte("t")); err != nil || back != pt {
		t.Fatalf("Decrypt = %q, %v; want %q", back, err, pt)
	}
	// Agrees with the numeral API under the same symbol order.
	nc := mustNew(t, key, mustRadix(t, a.Radix()))
	y, err := nc.EncryptNumerals(toNumerals(t, s, pt), []byte("t"))
	if err != nil || encodeWith(s, y) != ct {
		t.Fatalf("numeral API gives %q, string API %q", encodeWith(s, y), ct)
	}
}

// TestByteAlphabet checks that a byte alphabet treats strings as raw bytes,
// including bytes that are not valid UTF-8 on their own.
func TestByteAlphabet(t *testing.T) {
	syms := make([]byte, 256)
	for i := range syms {
		syms[i] = byte(i)
	}
	a, err := ff1.NewByteAlphabet(syms)
	if err != nil {
		t.Fatal(err)
	}
	if a.Radix() != 256 || a.String() != string(syms) {
		t.Fatalf("radix %d", a.Radix())
	}
	key := testKey(24)
	c := mustNew(t, key, a)
	pt := "\xff\x00\x80\xc3\x28binary"
	ct, err := c.Encrypt(pt, nil)
	if err != nil || len(ct) != len(pt) {
		t.Fatalf("Encrypt = %q, %v", ct, err)
	}
	if back, err := c.Decrypt(ct, nil); err != nil || back != pt {
		t.Fatalf("Decrypt = %q, %v; want %q", back, err, pt)
	}
	// Same result as the numeral API with numeral = byte value.
	x := make([]uint16, len(pt))
	for i := range len(pt) {
		x[i] = uint16(pt[i])
	}
	y, err := mustNew(t, key, mustRadix(t, 256)).EncryptNumerals(x, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range y {
		if byte(y[i]) != ct[i] {
			t.Fatalf("byte %d: numeral API %d, string API %d", i, y[i], ct[i])
		}
	}

	// A rune alphabet over the same 256 code points is different: symbols
	// 0x80-0xFF are two-byte runes there.
	ra, err := ff1.NewRuneAlphabet([]rune(string(syms[:128])))
	if err != nil || ra.Radix() != 128 {
		t.Fatalf("NewRuneAlphabet(ASCII) = %d, %v", ra.Radix(), err)
	}
}

func TestZeroAlphabet(t *testing.T) {
	var a ff1.Alphabet
	if a.Radix() != 0 || a.String() != "" {
		t.Errorf("zero Alphabet: radix %d, %q", a.Radix(), a.String())
	}
	ro := mustRadix(t, 1000)
	if ro.Radix() != 1000 || ro.String() != "" {
		t.Errorf("RadixOnly(1000): radix %d, %q", ro.Radix(), ro.String())
	}
	c := mustNew(t, testKey(16), ff1.Digits)
	if c.Alphabet().String() != ff1.Digits.String() || c.Alphabet() != ff1.Digits {
		t.Error("Cipher.Alphabet() does not return the construction alphabet")
	}
}
