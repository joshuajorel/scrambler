package ff1_test

import (
	"slices"
	"testing"

	"github.com/joshuajorel/scrambler/ff1"
)

// Golden outputs for fixed inputs over every built-in alphabet, a Unicode
// alphabet, and radix-65536 numerals.
//
// CHANGING ANY OF THESE OUTPUTS IS A BREAKING CHANGE. Deployments that use
// FF1 for deterministic masking (for example of join keys shared across
// databases; see the README) depend on the same input always producing the
// same output across library versions. A symbol-order change in a built-in
// alphabet, a different encoding of P or Q, or any other behavioural drift
// shows up here first. TestGoldenOutputs also checks every value against the
// reference implementation, so these are FF1 outputs, not merely this
// package's current ones.
const (
	goldenKey128 = "000102030405060708090a0b0c0d0e0f"
	goldenKey256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	goldenTweak  = "golden-v1"
)

// goldenStrings are the string-API golden cases; a zero Alphabet stands for
// goldenUnicode.
var goldenStrings = []struct {
	name     string
	alphabet ff1.Alphabet
	key      string
	pt, ct   string
}{
	{"Digits/AES-128", ff1.Digits, goldenKey128, "4111111111111111", "5162169348723101"},
	{"Digits/AES-256", ff1.Digits, goldenKey256, "4111111111111111", "8065321097951437"},
	{"Digits/min-length/AES-128", ff1.Digits, goldenKey128, "000000", "004977"},
	{"Digits/min-length/AES-256", ff1.Digits, goldenKey256, "000000", "889041"},
	{"HexLower/AES-128", ff1.HexLower, goldenKey128, "0123456789abcdef", "25ca5f56451723fa"},
	{"HexLower/AES-256", ff1.HexLower, goldenKey256, "0123456789abcdef", "75a9bd319bdf206e"},
	{"HexUpper/AES-128", ff1.HexUpper, goldenKey128, "DEADBEEF00", "D3D0FB0E6E"},
	{"HexUpper/AES-256", ff1.HexUpper, goldenKey256, "DEADBEEF00", "4712607F02"},
	{"LowerAlphanumeric/AES-128", ff1.LowerAlphanumeric, goldenKey128, "user1234", "0cgnx5ej"},
	{"LowerAlphanumeric/AES-256", ff1.LowerAlphanumeric, goldenKey256, "user1234", "uh74wqlw"},
	{"UpperAlphanumeric/AES-128", ff1.UpperAlphanumeric, goldenKey128, "AB12CD34", "L5AVMVRJ"},
	{"UpperAlphanumeric/AES-256", ff1.UpperAlphanumeric, goldenKey256, "AB12CD34", "BY1K8VRT"},
	{"Alphanumeric/AES-128", ff1.Alphanumeric, goldenKey128, "Hello2World", "cqNCcePCjZB"},
	{"Alphanumeric/AES-256", ff1.Alphanumeric, goldenKey256, "Hello2World", "3kp633hlrHG"},
	{"Unicode/AES-128", ff1.Alphabet{}, goldenKey128, "καλημερα", "κυμωιζρχ"},
}

// goldenUnicode is the alphabet of the Unicode golden case.
const goldenUnicode = "αβγδεζηθικλμνξοπρστυφχψω"

// goldenNumerals are the numeral-API golden cases.
var goldenNumerals = []struct {
	name   string
	radix  int
	key    string
	pt, ct []uint16
}{
	{"Radix65536/AES-128", 65536, goldenKey128, []uint16{0, 1, 65535, 32768}, []uint16{64366, 64569, 14543, 5141}},
}

// TestGoldenOutputs checks the golden cases in both directions.
func TestGoldenOutputs(t *testing.T) {
	tweak := []byte(goldenTweak)
	for _, g := range goldenStrings {
		t.Run(g.name, func(t *testing.T) {
			alphabet := g.alphabet
			if alphabet.Radix() == 0 {
				alphabet = mustAlphabet(t, goldenUnicode)
			}
			key := mustHex(t, g.key)
			c := mustNew(t, key, alphabet)
			if ct, err := c.Encrypt(g.pt, tweak); err != nil || ct != g.ct {
				t.Errorf("Encrypt(%q) = %q, %v; golden value %q", g.pt, ct, err, g.ct)
			}
			if pt, err := c.Decrypt(g.ct, tweak); err != nil || pt != g.pt {
				t.Errorf("Decrypt(%q) = %q, %v; want %q", g.ct, pt, err, g.pt)
			}
			alpha := alphabet.String()
			ref := refCrypt(key, alphabet.Radix(), tweak, toNumerals(t, alpha, g.pt), true)
			if got := encodeWith(alpha, ref); got != g.ct {
				t.Errorf("reference gives %q for the golden value %q", got, g.ct)
			}
		})
	}
	for _, g := range goldenNumerals {
		t.Run(g.name, func(t *testing.T) {
			key := mustHex(t, g.key)
			c := mustNew(t, key, mustRadix(t, g.radix))
			if ct, err := c.EncryptNumerals(g.pt, tweak); err != nil || !slices.Equal(ct, g.ct) {
				t.Errorf("EncryptNumerals(%v) = %v, %v; golden value %v", g.pt, ct, err, g.ct)
			}
			if pt, err := c.DecryptNumerals(g.ct, tweak); err != nil || !slices.Equal(pt, g.pt) {
				t.Errorf("DecryptNumerals(%v) = %v, %v; want %v", g.ct, pt, err, g.pt)
			}
			if ref := refCrypt(key, g.radix, tweak, g.pt, true); !slices.Equal(ref, g.ct) {
				t.Errorf("reference gives %v for the golden value %v", ref, g.ct)
			}
		})
	}
}
