package ff1_test

import (
	"slices"
	"testing"

	"github.com/joshuajorel/scrambler/ff1"
)

// NIST FF1 sample keys (CSRC "FF1samples.pdf", Cryptographic Standards and
// Guidelines, Examples with Intermediate Values).
const (
	nistK128 = "2B7E151628AED2A6ABF7158809CF4F3C"
	nistK192 = nistK128 + "EF4359D8D580AA4F"
	nistK256 = nistK192 + "7F036D6F04FC6A94"

	nistT10 = "39383736353433323130"
	nistT11 = "3737373770717273373737"
)

// nistSamples are the nine NIST FF1 samples.
var nistSamples = []struct {
	name     string
	key      string
	tweak    string
	alphabet ff1.Alphabet
	pt, ct   string
}{
	{"Sample1/AES128/radix10", nistK128, "", ff1.Digits, "0123456789", "2433477484"},
	{"Sample2/AES128/radix10", nistK128, nistT10, ff1.Digits, "0123456789", "6124200773"},
	{"Sample3/AES128/radix36", nistK128, nistT11, ff1.LowerAlphanumeric, "0123456789abcdefghi", "a9tv40mll9kdu509eum"},
	{"Sample4/AES192/radix10", nistK192, "", ff1.Digits, "0123456789", "2830668132"},
	{"Sample5/AES192/radix10", nistK192, nistT10, ff1.Digits, "0123456789", "2496655549"},
	{"Sample6/AES192/radix36", nistK192, nistT11, ff1.LowerAlphanumeric, "0123456789abcdefghi", "xbj3kv35jrawxv32ysr"},
	{"Sample7/AES256/radix10", nistK256, "", ff1.Digits, "0123456789", "6657667009"},
	{"Sample8/AES256/radix10", nistK256, nistT10, ff1.Digits, "0123456789", "1001623463"},
	{"Sample9/AES256/radix36", nistK256, nistT11, ff1.LowerAlphanumeric, "0123456789abcdefghi", "xs8a0azh2avyalyzuwd"},
}

// TestNISTSamples is T1: all nine NIST samples, in both directions, through
// both the string API and the numeral API.
func TestNISTSamples(t *testing.T) {
	for _, s := range nistSamples {
		t.Run(s.name, func(t *testing.T) {
			key, tweak := mustHex(t, s.key), mustHex(t, s.tweak)
			c := mustNew(t, key, s.alphabet)

			ct, err := c.Encrypt(s.pt, tweak)
			if err != nil || ct != s.ct {
				t.Errorf("Encrypt(%q) = %q, %v; want %q", s.pt, ct, err, s.ct)
			}
			pt, err := c.Decrypt(s.ct, tweak)
			if err != nil || pt != s.pt {
				t.Errorf("Decrypt(%q) = %q, %v; want %q", s.ct, pt, err, s.pt)
			}

			alpha := s.alphabet.String()
			ptN, ctN := toNumerals(t, alpha, s.pt), toNumerals(t, alpha, s.ct)
			nc := mustNew(t, key, mustRadix(t, s.alphabet.Radix()))
			gotN, err := nc.EncryptNumerals(ptN, tweak)
			if err != nil || !slices.Equal(gotN, ctN) {
				t.Errorf("EncryptNumerals = %v, %v; want %v", gotN, err, ctN)
			}
			gotN, err = nc.DecryptNumerals(ctN, tweak)
			if err != nil || !slices.Equal(gotN, ptN) {
				t.Errorf("DecryptNumerals = %v, %v; want %v", gotN, err, ptN)
			}
		})
	}
}

// TestNISTSamplesNilTweak checks that a nil tweak and an empty tweak are
// the same tweak (the empty-tweak samples).
func TestNISTSamplesNilTweak(t *testing.T) {
	for _, s := range nistSamples {
		if s.tweak != "" {
			continue
		}
		c := mustNew(t, mustHex(t, s.key), s.alphabet)
		for _, tw := range [][]byte{nil, {}} {
			if ct, err := c.Encrypt(s.pt, tw); err != nil || ct != s.ct {
				t.Errorf("%s: Encrypt with tweak %#v = %q, %v; want %q", s.name, tw, ct, err, s.ct)
			}
		}
	}
}

// TestRadix65536Regression pins radix 65536, where [radix]^3 in P must be
// 01 00 00. Bouncy Castle's SP80038G.calculateP_FF1 hardcodes P[3] = 0 and so
// encodes it as 00 00 00 (reported on bcprov-jdk18on 1.83; reproduced on 1.86
// by tools/differential), which yields [6653 42184] for this input. The
// correct answer, which the Rust fpe crate agrees with, is [18476 48157].
func TestRadix65536Regression(t *testing.T) {
	key := make([]byte, 16)
	tweak := make([]byte, 8)
	pt := []uint16{0, 1}
	want := []uint16{18476, 48157}

	c := mustNew(t, key, mustRadix(t, 65536))
	ct, err := c.EncryptNumerals(pt, tweak)
	if err != nil || !slices.Equal(ct, want) {
		t.Fatalf("EncryptNumerals = %v, %v; want %v", ct, err, want)
	}
	if got, err := c.DecryptNumerals(want, tweak); err != nil || !slices.Equal(got, pt) {
		t.Fatalf("DecryptNumerals = %v, %v; want %v", got, err, pt)
	}
	if got := refCrypt(key, 65536, tweak, pt, true); !slices.Equal(got, want) {
		t.Fatalf("reference = %v, want %v", got, want)
	}
	// Reproduce the mis-encoding to confirm it explains Bouncy Castle's output.
	if got := refCryptP(key, 65536, tweak, pt, true, []byte{0, 0, 0}); !slices.Equal(got, []uint16{6653, 42184}) {
		t.Fatalf("reference with P[3..5] = 00 00 00 gives %v, want [6653 42184]", got)
	}
}
