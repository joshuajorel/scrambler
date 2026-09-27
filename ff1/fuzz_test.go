package ff1_test

import (
	"errors"
	"slices"
	"testing"
	"unicode/utf8"

	"github.com/joshuajorel/scrambler/ff1"
)

// fuzzKey turns arbitrary bytes into a 16, 24, or 32-byte AES key.
func fuzzKey(b []byte) []byte {
	n := 16
	switch {
	case len(b) >= 32:
		n = 32
	case len(b) >= 24:
		n = 24
	}
	k := make([]byte, n)
	copy(k, b)
	return k
}

// fuzzNumerals reads big-endian 16-bit values from data, reduced mod radix.
func fuzzNumerals(data []byte, radix int) []uint16 {
	x := make([]uint16, len(data)/2)
	for i := range x {
		x[i] = uint16((int(data[2*i])<<8 | int(data[2*i+1])) % radix)
	}
	return x
}

func encodeNumerals(x []uint16) []byte {
	b := make([]byte, 0, 2*len(x))
	for _, v := range x {
		b = append(b, byte(v>>8), byte(v))
	}
	return b
}

// FuzzRoundTrip is T3: for any key, radix, input, and tweak, decryption
// inverts encryption, the length is preserved, every output numeral is less
// than the radix, and (for small inputs) the result matches the reference
// implementation. Seeded with the NIST samples.
func FuzzRoundTrip(f *testing.F) {
	for _, s := range nistSamples {
		key, _ := hexDecode(s.key)
		tweak, _ := hexDecode(s.tweak)
		alpha := s.alphabet.String()
		var x []uint16
		for _, r := range s.pt {
			x = append(x, uint16(indexRune(alpha, r)))
		}
		f.Add(key, uint32(s.alphabet.Radix()-2), encodeNumerals(x), tweak)
	}
	f.Add(make([]byte, 16), uint32(65536-2), []byte{0, 0, 0, 1}, make([]byte, 8)) // radix 65536 regression
	f.Add(make([]byte, 32), uint32(0), make([]byte, 2*464), []byte{})             // radix 2, v = 232

	f.Fuzz(func(t *testing.T, keyBytes []byte, radixSeed uint32, data, tweak []byte) {
		key := fuzzKey(keyBytes)
		radix := int(radixSeed%(ff1.MaxRadix-1)) + ff1.MinRadix
		x := fuzzNumerals(data, radix)
		c, err := ff1.New(key, mustRadix(t, radix))
		if err != nil {
			t.Fatal(err)
		}
		ct, err := c.EncryptNumerals(x, tweak)
		if len(x) < c.MinLength() {
			if !errors.Is(err, ff1.ErrDomainTooSmall) {
				t.Fatalf("n=%d < minlen %d: error = %v, want ErrDomainTooSmall", len(x), c.MinLength(), err)
			}
			return
		}
		if err != nil {
			t.Fatalf("EncryptNumerals(radix %d, n %d): %v", radix, len(x), err)
		}
		if len(ct) != len(x) {
			t.Fatalf("length %d -> %d", len(x), len(ct))
		}
		for i, v := range ct {
			if int(v) >= radix {
				t.Fatalf("ct[%d] = %d >= radix %d", i, v, radix)
			}
		}
		pt, err := c.DecryptNumerals(ct, tweak)
		if err != nil || !slices.Equal(pt, x) {
			t.Fatalf("DecryptNumerals(EncryptNumerals(x)) = %v, %v; want %v", pt, err, x)
		}
		if len(x) <= 64 && len(tweak) <= 64 {
			if want := refCrypt(key, radix, tweak, x, true); !slices.Equal(ct, want) {
				t.Fatalf("radix %d n %d: EncryptNumerals = %v, reference %v", radix, len(x), ct, want)
			}
		}
	})
}

// FuzzNoPanic is T4: arbitrary keys, alphabets, inputs, tweaks, and options
// never make the package panic; every failure is an error wrapping exactly
// one sentinel, and every success round-trips.
func FuzzNoPanic(f *testing.F) {
	f.Add([]byte("0123456789abcdef"), "0123456789", "4111111111111111", []byte("tw"), 0, 0, -1, uint8(0))
	f.Add([]byte{}, "", "", []byte(nil), 1, 1, 1, uint8(1))
	f.Add(make([]byte, 24), "日本語のテキスト😀🎉", "日本語のテキスト", []byte{0xff}, 0, 40, 3, uint8(2))
	f.Add(make([]byte, 32), "ab", "\xff\xfe\xfd", []byte("x"), 2, 1, 0, uint8(3))
	f.Add(make([]byte, 16), "0123456789", "12345", []byte{}, 5, 5, 0, uint8(4))
	f.Add(make([]byte, 16), "\x00\x01\x02\x03", "\x00\x01\x02\x03\x00\x01\x02\x03\x00\x01", []byte{}, 0, 0, 0, uint8(5))

	f.Fuzz(func(t *testing.T, key []byte, alphabet, input string, tweak []byte, minLen, maxLen, maxTweak int, mode uint8) {
		var a ff1.Alphabet
		var err error
		switch mode % 4 {
		case 0:
			a, err = ff1.NewAlphabet(alphabet)
		case 1:
			a, err = ff1.NewRuneAlphabet([]rune(alphabet))
		case 2:
			a, err = ff1.NewByteAlphabet([]byte(alphabet))
		case 3:
			a, err = ff1.RadixOnly(len(alphabet) + minLen)
		}
		checkErr(t, err)
		_ = a.Radix()
		_ = a.String()

		var opts []ff1.Option
		if mode&4 != 0 {
			opts = append(opts, ff1.WithMinLength(minLen))
		}
		if mode&8 != 0 {
			opts = append(opts, ff1.WithMaxLength(maxLen))
		}
		if mode&16 != 0 {
			opts = append(opts, ff1.WithMaxTweakLength(maxTweak))
		}
		if mode&32 != 0 {
			opts = append(opts, nil)
		}
		c, err := ff1.New(key, a, opts...)
		checkErr(t, err)
		if err != nil {
			// A failed New must still leave a usable (erroring) nil *Cipher.
			if _, err := c.Encrypt(input, tweak); !errors.Is(err, ff1.ErrUninitialized) {
				t.Fatalf("nil Cipher Encrypt error = %v", err)
			}
			return
		}
		_, _, _, _ = c.Radix(), c.MinLength(), c.MaxLength(), c.MaxTweakLength()

		// String API.
		// Byte alphabets count bytes; rune alphabets count runes.
		count := utf8.RuneCountInString
		if mode%4 == 2 {
			count = func(s string) int { return len(s) }
		}
		ct, err := c.Encrypt(input, tweak)
		checkErr(t, err)
		if err == nil {
			if n, m := count(input), count(ct); n != m {
				t.Fatalf("Encrypt changed the length: %d -> %d", n, m)
			}
			pt, err := c.Decrypt(ct, tweak)
			if err != nil || pt != input {
				t.Fatalf("Decrypt(Encrypt(%q)) = %q, %v", input, pt, err)
			}
		}
		_, err = c.Decrypt(input, tweak)
		checkErr(t, err)

		// Numeral API over the raw input bytes, with and without reduction.
		raw := make([]uint16, len(input))
		for i := range len(input) {
			raw[i] = uint16(input[i]) * 257
		}
		for _, x := range [][]uint16{raw, fuzzNumerals([]byte(input), max(c.Radix(), 1))} {
			y, err := c.EncryptNumerals(x, tweak)
			checkErr(t, err)
			if err == nil {
				back, err := c.DecryptNumerals(y, tweak)
				if err != nil || !slices.Equal(back, x) {
					t.Fatalf("DecryptNumerals(EncryptNumerals(x)) = %v, %v; want %v", back, err, x)
				}
			}
			_, err = c.DecryptNumerals(x, tweak)
			checkErr(t, err)
		}
	})
}

// checkErr fails unless err is nil or wraps exactly one exported sentinel.
func checkErr(t *testing.T, err error) {
	t.Helper()
	if err != nil && sentinelCount(err) != 1 {
		t.Fatalf("error %q wraps %d sentinels, want 1", err, sentinelCount(err))
	}
}

func hexDecode(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	for i := range b {
		hi, lo := unhex(s[2*i]), unhex(s[2*i+1])
		if hi < 0 || lo < 0 {
			return nil, errors.New("bad hex")
		}
		b[i] = byte(hi<<4 | lo)
	}
	return b, nil
}

func unhex(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c-'a') + 10
	case 'A' <= c && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func indexRune(s string, r rune) int {
	return slices.Index([]rune(s), r)
}
