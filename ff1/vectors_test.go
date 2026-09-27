package ff1_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/joshuajorel/scrambler/ff1"
)

// ---------------------------------------------------------------------------
// T1b: vectors extracted from other libraries' test suites.

type thirdPartyFile struct {
	Sources []struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		Commit  string `json:"commit"`
		SHA256  string `json:"sha256"`
		License string `json:"license"`
	} `json:"sources"`
	Vectors []thirdPartyVector `json:"vectors"`
}

type thirdPartyVector struct {
	Name       string `json:"name"`
	Provenance struct {
		SourceURL string `json:"source_url"`
		Commit    string `json:"commit"`
		Locator   string `json:"locator"`
		License   string `json:"license"`
	} `json:"provenance"`
	Key      string   `json:"key"`
	Radix    int      `json:"radix"`
	Tweak    string   `json:"tweak"`
	PT       []uint16 `json:"pt"`
	CT       []uint16 `json:"ct"`
	Alphabet string   `json:"alphabet"`
	PTStr    string   `json:"pt_str"`
	CTStr    string   `json:"ct_str"`
	Expect   string   `json:"expect"`
	Error    string   `json:"error"`
	Note     string   `json:"note"`
}

var sentinelByName = map[string]error{
	"ErrDomainTooSmall": ff1.ErrDomainTooSmall,
	"ErrInvalidNumeral": ff1.ErrInvalidNumeral,
}

var hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

func TestThirdPartyVectors(t *testing.T) {
	var f thirdPartyFile
	loadJSON(t, "testdata/thirdparty_vectors.json", &f)

	const wantVectors = 69
	if len(f.Vectors) != wantVectors {
		t.Fatalf("got %d vectors, want %d (regenerate with tools/extract_vectors/extract.py)", len(f.Vectors), wantVectors)
	}
	if len(f.Sources) != 4 {
		t.Fatalf("got %d sources, want 4", len(f.Sources))
	}
	for _, s := range f.Sources {
		if !hex40.MatchString(s.Commit) || len(s.SHA256) != 64 || s.License == "" || !strings.Contains(s.URL, s.Commit) {
			t.Errorf("source %s: incomplete provenance %+v", s.Name, s)
		}
	}

	counts := map[string]int{}
	for _, v := range f.Vectors {
		counts[v.Expect+v.Error]++
		// Vector names contain "/", which t.Run would treat as nesting.
		t.Run(strings.ReplaceAll(v.Name, "/", ":"), func(t *testing.T) {
			p := v.Provenance
			if !strings.HasPrefix(p.SourceURL, "https://github.com/") || !hex40.MatchString(p.Commit) ||
				!strings.Contains(p.SourceURL, p.Commit) || p.Locator == "" || p.License == "" {
				t.Fatalf("incomplete provenance: %+v", p)
			}
			runThirdPartyVector(t, v)
		})
	}
	// 60 known answers, 3 round-trip-only inputs, and 6 rejections: 4 for
	// the 10^6 domain rule and 2 for out-of-radix numerals.
	want := map[string]int{"match": 60, "roundtrip": 3, "errorErrDomainTooSmall": 4, "errorErrInvalidNumeral": 2}
	if !maps.Equal(counts, want) {
		t.Errorf("expect counts = %v, want %v", counts, want)
	}
}

func runThirdPartyVector(t *testing.T, v thirdPartyVector) {
	key, tweak := mustHex(t, v.Key), mustHex(t, v.Tweak)

	// Numeral API, over a symbol-less alphabet of the vector's radix.
	nc := mustNew(t, key, mustRadix(t, v.Radix))
	// String API, when the source gave an alphabet.
	var sc *ff1.Cipher
	if v.Alphabet != "" {
		a := mustAlphabet(t, v.Alphabet)
		if a.Radix() != v.Radix {
			t.Fatalf("alphabet radix %d, vector radix %d", a.Radix(), v.Radix)
		}
		sc = mustNew(t, key, a)
	}

	switch v.Expect {
	case "match":
		if !domainOK(v.Radix, len(v.PT)) {
			t.Fatalf("known-answer vector violates the domain rule")
		}
		if got, err := nc.EncryptNumerals(v.PT, tweak); err != nil || !slices.Equal(got, v.CT) {
			t.Errorf("EncryptNumerals = %v, %v; want %v", got, err, v.CT)
		}
		if got, err := nc.DecryptNumerals(v.CT, tweak); err != nil || !slices.Equal(got, v.PT) {
			t.Errorf("DecryptNumerals = %v, %v; want %v", got, err, v.PT)
		}
		if sc != nil && v.PTStr != "" {
			if got, err := sc.Encrypt(v.PTStr, tweak); err != nil || got != v.CTStr {
				t.Errorf("Encrypt(%q) = %q, %v; want %q", v.PTStr, got, err, v.CTStr)
			}
			if got, err := sc.Decrypt(v.CTStr, tweak); err != nil || got != v.PTStr {
				t.Errorf("Decrypt(%q) = %q, %v; want %q", v.CTStr, got, err, v.PTStr)
			}
		}

	case "roundtrip":
		ct, err := nc.EncryptNumerals(v.PT, tweak)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := nc.DecryptNumerals(ct, tweak); err != nil || !slices.Equal(got, v.PT) {
			t.Errorf("DecryptNumerals(EncryptNumerals(pt)) = %v, %v; want %v", got, err, v.PT)
		}
		if sc != nil && v.PTStr != "" {
			sct, err := sc.Encrypt(v.PTStr, tweak)
			if err != nil {
				t.Fatal(err)
			}
			if want := v.Alphabet; sct != encodeWith(want, ct) {
				t.Errorf("string and numeral APIs disagree: %q vs %v", sct, ct)
			}
			if got, err := sc.Decrypt(sct, tweak); err != nil || got != v.PTStr {
				t.Errorf("Decrypt(Encrypt(%q)) = %q, %v", v.PTStr, got, err)
			}
		}

	case "error":
		want, ok := sentinelByName[v.Error]
		if !ok {
			t.Fatalf("unknown error %q", v.Error)
		}
		if want == ff1.ErrDomainTooSmall && domainOK(v.Radix, len(v.PT)) {
			t.Fatalf("vector satisfies the domain rule but is marked %s", v.Error)
		}
		if _, err := nc.EncryptNumerals(v.PT, tweak); !errors.Is(err, want) {
			t.Errorf("EncryptNumerals error = %v, want %v", err, want)
		}
		if _, err := nc.DecryptNumerals(v.PT, tweak); !errors.Is(err, want) {
			t.Errorf("DecryptNumerals error = %v, want %v", err, want)
		}
		if want == ff1.ErrDomainTooSmall {
			if sc != nil && v.PTStr != "" {
				if _, err := sc.Encrypt(v.PTStr, tweak); !errors.Is(err, want) {
					t.Errorf("Encrypt(%q) error = %v, want %v", v.PTStr, err, want)
				}
			}
			// Configuring a cipher for this length is rejected up front too.
			if len(v.PT) >= 2 {
				if _, err := ff1.New(key, mustRadix(t, v.Radix), ff1.WithMinLength(len(v.PT))); !errors.Is(err, want) {
					t.Errorf("New(WithMinLength(%d)) error = %v, want %v", len(v.PT), err, want)
				}
			}
		}

	default:
		t.Fatalf("unknown expect %q", v.Expect)
	}
}

// ---------------------------------------------------------------------------
// T2: NIST ACVP vectors.

type acvpFile struct {
	Algorithm  string `json:"algorithm"`
	Revision   string `json:"revision"`
	TestGroups []struct {
		TgID      int    `json:"tgId"`
		TestType  string `json:"testType"`
		Direction string `json:"direction"`
		KeyLen    int    `json:"keyLen"`
		Alphabet  string `json:"alphabet"`
		Radix     int    `json:"radix"`
		Tests     []struct {
			TcID     int    `json:"tcId"`
			Key      string `json:"key"`
			Tweak    string `json:"tweak"`
			TweakLen int    `json:"tweakLen"`
			PT       string `json:"pt"`
			CT       string `json:"ct"`
		} `json:"tests"`
	} `json:"testGroups"`
}

const acvpPath = "testdata/acvp/internalProjection.json"

// acvpSHA256 is the SHA-256 of the unmodified upstream file; see
// testdata/acvp/README.md.
const acvpSHA256 = "63cd6642095fbb1ce7af3fa53d7d720d725a58fe331d35ced1540b5e433668ee"

func TestACVP(t *testing.T) {
	var f acvpFile
	loadJSON(t, acvpPath, &f)
	if f.Algorithm != "ACVP-AES-FF1" || f.Revision != "1.0" {
		t.Fatalf("unexpected vector set %s %s", f.Algorithm, f.Revision)
	}

	cases := 0
	for _, g := range f.TestGroups {
		t.Run(fmt.Sprintf("tg%d", g.TgID), func(t *testing.T) {
			if g.TestType != "AFT" {
				t.Fatalf("unsupported test type %q", g.TestType)
			}
			alpha := mustAlphabet(t, g.Alphabet)
			if alpha.Radix() != g.Radix {
				t.Fatalf("alphabet %q has radix %d, group says %d", g.Alphabet, alpha.Radix(), g.Radix)
			}
			for _, tc := range g.Tests {
				cases++
				t.Run(fmt.Sprintf("tc%d", tc.TcID), func(t *testing.T) {
					key, tweak := mustHex(t, tc.Key), mustHex(t, tc.Tweak)
					if len(key)*8 != g.KeyLen || len(tweak)*8 != tc.TweakLen {
						t.Fatalf("key/tweak lengths %d/%d bits, want %d/%d", len(key)*8, len(tweak)*8, g.KeyLen, tc.TweakLen)
					}
					c := mustNew(t, key, alpha)
					switch g.Direction {
					case "encrypt":
						if got, err := c.Encrypt(tc.PT, tweak); err != nil || got != tc.CT {
							t.Errorf("Encrypt = %q, %v; want %q", got, err, tc.CT)
						}
					case "decrypt":
						if got, err := c.Decrypt(tc.CT, tweak); err != nil || got != tc.PT {
							t.Errorf("Decrypt = %q, %v; want %q", got, err, tc.PT)
						}
					default:
						t.Fatalf("unknown direction %q", g.Direction)
					}
					// The projection carries both texts, so check the inverse too.
					if g.Direction == "encrypt" {
						if got, err := c.Decrypt(tc.CT, tweak); err != nil || got != tc.PT {
							t.Errorf("inverse Decrypt = %q, %v; want %q", got, err, tc.PT)
						}
					} else if got, err := c.Encrypt(tc.PT, tweak); err != nil || got != tc.CT {
						t.Errorf("inverse Encrypt = %q, %v; want %q", got, err, tc.CT)
					}
				})
			}
		})
	}
	if len(f.TestGroups) != 30 || cases != 750 {
		t.Errorf("ran %d groups / %d cases, want 30 / 750", len(f.TestGroups), cases)
	}
}

// TestTestdataIntegrity pins the vendored NIST and Wycheproof files to their
// upstream hashes, so the committed vectors cannot drift from the published
// ones.
func TestTestdataIntegrity(t *testing.T) {
	want := map[string]string{acvpPath: acvpSHA256}
	for name, sum := range wycheproofSHA256(t) {
		want["testdata/wycheproof/"+name] = sum
	}
	vendored, err := filepath.Glob("testdata/wycheproof/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(vendored) != len(want)-1 {
		t.Errorf("testdata/wycheproof has %d JSON files, SHA256SUMS lists %d", len(vendored), len(want)-1)
	}
	for path, sum := range want {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Error(err)
			continue
		}
		if got := sha256.Sum256(data); hex.EncodeToString(got[:]) != sum {
			t.Errorf("%s: sha256 %x, want %s", path, got, sum)
		}
	}
}
