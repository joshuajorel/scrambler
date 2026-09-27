package ff1_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/joshuajorel/scrambler/ff1"
)

// Wycheproof AES-FF1 vectors (testdata/wycheproof, see its README.md).

type wycheproofFile struct {
	Algorithm     string `json:"algorithm"`
	Schema        string `json:"schema"`
	NumberOfTests int    `json:"numberOfTests"`
	TestGroups    []struct {
		Type     string `json:"type"`
		KeySize  int    `json:"keySize"`
		MsgSize  int    `json:"msgSize"`
		Radix    int    `json:"radix"`
		Alphabet string `json:"alphabet"` // FpeStrTest only
		Tests    []struct {
			TcID    int             `json:"tcId"`
			Comment string          `json:"comment"`
			Flags   []string        `json:"flags"`
			Key     string          `json:"key"`
			Tweak   string          `json:"tweak"`
			Msg     json.RawMessage `json:"msg"` // string or list of digits
			CT      json.RawMessage `json:"ct"`
			Result  string          `json:"result"`
		} `json:"tests"`
	} `json:"testGroups"`
}

// wycheproofTally counts how each case was resolved.
type wycheproofTally struct {
	total int
	// valid: encryption and decryption matched.
	valid int
	// validDomainRejected: valid under the 2016 rule (radix^n >= 100) but
	// radix^n < 10^6, so rejected with ErrDomainTooSmall by design.
	validDomainRejected int
	// invalid cases, by the error that rejected them.
	invalidKey  int // ErrInvalidKeyLength
	invalidSize int // ErrDomainTooSmall
	// invalidInput: out-of-range digits or characters, rejected with
	// ErrInvalidNumeral or ErrInvalidSymbol.
	invalidInput int
	// invalidUnrepresentable: a digit outside 0..65535 cannot be put in the
	// []uint16 the numeral API takes, so it is rejected at the type boundary.
	invalidUnrepresentable int
}

// wycheproofCounts are the exact expected per-file results.
var wycheproofCounts = map[string]wycheproofTally{
	"aes_ff1_base10":     {total: 3845, valid: 3300, validDomainRejected: 12, invalidKey: 5, invalidSize: 6, invalidInput: 522},
	"aes_ff1_base16":     {total: 3872, valid: 3348, validDomainRejected: 9, invalidKey: 5, invalidSize: 6, invalidInput: 504},
	"aes_ff1_base26":     {total: 3076, valid: 2642, validDomainRejected: 9, invalidKey: 5, invalidSize: 6, invalidInput: 414},
	"aes_ff1_base32":     {total: 2868, valid: 2455, validDomainRejected: 6, invalidKey: 5, invalidSize: 6, invalidInput: 396},
	"aes_ff1_base36":     {total: 2854, valid: 2459, validDomainRejected: 6, invalidKey: 5, invalidSize: 6, invalidInput: 378},
	"aes_ff1_base45":     {total: 2421, valid: 2044, validDomainRejected: 6, invalidKey: 5, invalidSize: 6, invalidInput: 360},
	"aes_ff1_base62":     {total: 2474, valid: 2133, validDomainRejected: 6, invalidKey: 5, invalidSize: 6, invalidInput: 324},
	"aes_ff1_base64":     {total: 2417, valid: 2076, validDomainRejected: 6, invalidKey: 5, invalidSize: 6, invalidInput: 324},
	"aes_ff1_base85":     {total: 1852, valid: 1547, validDomainRejected: 6, invalidKey: 5, invalidSize: 6, invalidInput: 288},
	"aes_ff1_radix10":    {total: 3845, valid: 3300, validDomainRejected: 12, invalidKey: 5, invalidSize: 6, invalidInput: 261, invalidUnrepresentable: 261},
	"aes_ff1_radix16":    {total: 3872, valid: 3348, validDomainRejected: 9, invalidKey: 5, invalidSize: 6, invalidInput: 252, invalidUnrepresentable: 252},
	"aes_ff1_radix26":    {total: 3076, valid: 2642, validDomainRejected: 9, invalidKey: 5, invalidSize: 6, invalidInput: 207, invalidUnrepresentable: 207},
	"aes_ff1_radix32":    {total: 2868, valid: 2455, validDomainRejected: 6, invalidKey: 5, invalidSize: 6, invalidInput: 198, invalidUnrepresentable: 198},
	"aes_ff1_radix36":    {total: 2854, valid: 2459, validDomainRejected: 6, invalidKey: 5, invalidSize: 6, invalidInput: 189, invalidUnrepresentable: 189},
	"aes_ff1_radix45":    {total: 2421, valid: 2044, validDomainRejected: 6, invalidKey: 5, invalidSize: 6, invalidInput: 180, invalidUnrepresentable: 180},
	"aes_ff1_radix62":    {total: 2474, valid: 2133, validDomainRejected: 6, invalidKey: 5, invalidSize: 6, invalidInput: 162, invalidUnrepresentable: 162},
	"aes_ff1_radix64":    {total: 2417, valid: 2076, validDomainRejected: 6, invalidKey: 5, invalidSize: 6, invalidInput: 162, invalidUnrepresentable: 162},
	"aes_ff1_radix85":    {total: 1852, valid: 1547, validDomainRejected: 6, invalidKey: 5, invalidSize: 6, invalidInput: 144, invalidUnrepresentable: 144},
	"aes_ff1_radix255":   {total: 1853, valid: 1587, validDomainRejected: 3, invalidKey: 5, invalidSize: 6, invalidInput: 126, invalidUnrepresentable: 126},
	"aes_ff1_radix256":   {total: 2021, valid: 1755, validDomainRejected: 3, invalidKey: 5, invalidSize: 6, invalidInput: 126, invalidUnrepresentable: 126},
	"aes_ff1_radix65535": {total: 965, valid: 834, invalidKey: 5, invalidSize: 6, invalidInput: 60, invalidUnrepresentable: 60},
	"aes_ff1_radix65536": {total: 1049, valid: 918, invalidKey: 5, invalidSize: 6, invalidUnrepresentable: 120},
}

// wycheproofText is a message in either schema: symbols for FpeStrTest,
// digits for FpeListTest. unrepresentable is set when a digit does not fit
// in a uint16.
type wycheproofText struct {
	str             string
	digits          []uint16
	unrepresentable bool
	n               int
}

func parseWycheproofText(t *testing.T, raw json.RawMessage, list bool) wycheproofText {
	t.Helper()
	if !list {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatalf("bad string message: %v", err)
		}
		return wycheproofText{str: s, n: len([]rune(s))}
	}
	var wide []int64
	if err := json.Unmarshal(raw, &wide); err != nil {
		t.Fatalf("bad digit list: %v", err)
	}
	out := wycheproofText{n: len(wide)}
	for _, d := range wide {
		if d < 0 || d > 0xFFFF {
			out.unrepresentable = true
			return out
		}
		out.digits = append(out.digits, uint16(d))
	}
	return out
}

// crypt runs the cipher over m in the given direction, recovering any panic
// as a test failure so the offending case is named.
func wycheproofCrypt(t *testing.T, c *ff1.Cipher, m wycheproofText, tweak []byte, list, encrypt bool) (out wycheproofText, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()
	if list {
		f := c.DecryptNumerals
		if encrypt {
			f = c.EncryptNumerals
		}
		d, err := f(m.digits, tweak)
		return wycheproofText{digits: d, n: len(d)}, err
	}
	f := c.Decrypt
	if encrypt {
		f = c.Encrypt
	}
	s, err := f(m.str, tweak)
	return wycheproofText{str: s, n: len([]rune(s))}, err
}

func (m wycheproofText) equal(o wycheproofText) bool {
	return m.str == o.str && slices.Equal(m.digits, o.digits) && m.unrepresentable == o.unrepresentable
}

func TestWycheproof(t *testing.T) {
	files, err := filepath.Glob("testdata/wycheproof/aes_ff1_*_test.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(wycheproofCounts) {
		t.Fatalf("found %d Wycheproof files, want %d", len(files), len(wycheproofCounts))
	}
	var grand wycheproofTally
	for _, path := range files {
		name := strings.TrimSuffix(filepath.Base(path), "_test.json")
		t.Run(name, func(t *testing.T) {
			var f wycheproofFile
			loadJSON(t, path, &f)
			if f.Algorithm != "AES-FF1" {
				t.Fatalf("algorithm %q", f.Algorithm)
			}
			list := f.Schema == "fpe_list_test_schema.json"
			if !list && f.Schema != "fpe_str_test_schema.json" {
				t.Fatalf("unknown schema %q", f.Schema)
			}
			var got wycheproofTally
			for _, g := range f.TestGroups {
				var alpha ff1.Alphabet
				if list {
					alpha = mustRadix(t, g.Radix)
				} else {
					alpha = mustAlphabet(t, g.Alphabet)
				}
				if alpha.Radix() != g.Radix {
					t.Fatalf("alphabet radix %d, group radix %d", alpha.Radix(), g.Radix)
				}
				for _, tc := range g.Tests {
					got.total++
					t.Run(fmt.Sprintf("tc%d", tc.TcID), func(t *testing.T) {
						runWycheproofCase(t, &got, alpha, list, tc.Key, tc.Tweak, tc.Msg, tc.CT, tc.Result, tc.Flags)
					})
				}
			}
			if got.total != f.NumberOfTests {
				t.Errorf("ran %d cases, file declares %d", got.total, f.NumberOfTests)
			}
			if want := wycheproofCounts[name]; got != want {
				t.Errorf("tally = %+v\n want   %+v", got, want)
			}
			t.Logf("%s: %d cases: %d valid matched, %d valid rejected by the 10^6 rule, %d invalid rejected "+
				"(%d key size, %d message size, %d bad digit/symbol, %d digit outside uint16)",
				name, got.total, got.valid, got.validDomainRejected,
				got.invalidKey+got.invalidSize+got.invalidInput+got.invalidUnrepresentable,
				got.invalidKey, got.invalidSize, got.invalidInput, got.invalidUnrepresentable)
			grand.total += got.total
			grand.valid += got.valid
			grand.validDomainRejected += got.validDomainRejected
			grand.invalidKey += got.invalidKey
			grand.invalidSize += got.invalidSize
			grand.invalidInput += got.invalidInput
			grand.invalidUnrepresentable += got.invalidUnrepresentable
		})
	}
	t.Logf("all files: %+v", grand)
}

func runWycheproofCase(t *testing.T, tally *wycheproofTally, alpha ff1.Alphabet, list bool,
	keyHex, tweakHex string, rawMsg, rawCT json.RawMessage, result string, flags []string) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	tweak, err := hex.DecodeString(tweakHex)
	if err != nil {
		t.Fatal(err)
	}
	msg := parseWycheproofText(t, rawMsg, list)
	ct := parseWycheproofText(t, rawCT, list)

	c, err := ff1.New(key, alpha)
	if err != nil {
		if result != "invalid" || !errors.Is(err, ff1.ErrInvalidKeyLength) || !slices.Contains(flags, "InvalidKeySize") {
			t.Fatalf("New: %v (result %s, flags %v)", err, result, flags)
		}
		tally.invalidKey++
		return
	}

	switch result {
	case "valid":
		if !domainOK(alpha.Radix(), msg.n) {
			// Legal under the 2016 rule (radix^n >= 100) only.
			if !slices.Equal(flags, []string{"SmallMessageSize"}) {
				t.Fatalf("valid case below 10^6 with flags %v", flags)
			}
			if _, err := wycheproofCrypt(t, c, msg, tweak, list, true); !errors.Is(err, ff1.ErrDomainTooSmall) {
				t.Errorf("encrypt error = %v, want ErrDomainTooSmall", err)
			}
			if _, err := wycheproofCrypt(t, c, ct, tweak, list, false); !errors.Is(err, ff1.ErrDomainTooSmall) {
				t.Errorf("decrypt error = %v, want ErrDomainTooSmall", err)
			}
			tally.validDomainRejected++
			return
		}
		if msg.unrepresentable || ct.unrepresentable {
			t.Fatal("valid case with a digit outside uint16")
		}
		gotCT, err := wycheproofCrypt(t, c, msg, tweak, list, true)
		if err != nil || !gotCT.equal(ct) {
			t.Errorf("encrypt = %+v, %v; want %+v", gotCT, err, ct)
		}
		gotPT, err := wycheproofCrypt(t, c, ct, tweak, list, false)
		if err != nil || !gotPT.equal(msg) {
			t.Errorf("decrypt = %+v, %v; want %+v", gotPT, err, msg)
		}
		if !t.Failed() {
			tally.valid++
		}

	case "invalid":
		if len(flags) != 1 {
			t.Fatalf("flags %v", flags)
		}
		// Decrypting the listed ciphertext must not panic and must not
		// produce the invalid plaintext.
		if !ct.unrepresentable {
			if pt, err := wycheproofCrypt(t, c, ct, tweak, list, false); err == nil && pt.equal(msg) {
				t.Errorf("decrypt(ct) returned the invalid plaintext")
			}
		}
		switch flags[0] {
		case "InvalidMessageSize":
			if _, err := wycheproofCrypt(t, c, msg, tweak, list, true); !errors.Is(err, ff1.ErrDomainTooSmall) {
				t.Errorf("encrypt error = %v, want ErrDomainTooSmall", err)
			}
			tally.invalidSize++
		case "InvalidPlaintext":
			if msg.unrepresentable {
				tally.invalidUnrepresentable++
				return
			}
			want := ff1.ErrInvalidSymbol
			if list {
				want = ff1.ErrInvalidNumeral
			}
			if _, err := wycheproofCrypt(t, c, msg, tweak, list, true); !errors.Is(err, want) {
				t.Errorf("encrypt error = %v, want %v", err, want)
			}
			tally.invalidInput++
		default:
			t.Fatalf("unexpected invalid flag %q", flags[0])
		}

	default:
		t.Fatalf("unknown result %q", result)
	}
}

// wycheproofSHA256 reads testdata/wycheproof/SHA256SUMS.
func wycheproofSHA256(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile("testdata/wycheproof/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	sums := map[string]string{}
	for line := range strings.Lines(string(data)) {
		sum, name, ok := strings.Cut(strings.TrimSpace(line), "  ")
		if !ok {
			t.Fatalf("bad SHA256SUMS line %q", line)
		}
		sums[name] = sum
	}
	return sums
}

// TestWycheproofSanity pins the radix-65536 case quoted in the review
// (tcId 7) independently of the file runner.
func TestWycheproofSanity(t *testing.T) {
	c := mustNew(t, mustHex(t, "ad65778960d778c614e2673dee073acb"), mustRadix(t, 65536))
	tweak := mustHex(t, "4505f45a8fa30b90")
	ct, err := c.EncryptNumerals([]uint16{35521, 37776}, tweak)
	if err != nil || !slices.Equal(ct, []uint16{24655, 32503}) {
		t.Fatalf("EncryptNumerals = %v, %v; want [24655 32503]", ct, err)
	}
	if pt, err := c.DecryptNumerals(ct, tweak); err != nil || !slices.Equal(pt, []uint16{35521, 37776}) {
		t.Fatalf("DecryptNumerals = %v, %v", pt, err)
	}
}
