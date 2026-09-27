package ff1_test

import (
	"errors"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/joshuajorel/scrambler/ff1"
)

// T1b: vectors extracted from other libraries' test suites by
// tools/extract_vectors/extract.py.

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

// thirdPartyVectors and thirdPartyExpect are the expected size and mix of
// testdata/thirdparty_vectors.json: 60 known answers, 3 round-trip-only
// inputs, and 6 rejections (4 for the 10^6 domain rule, 2 for out-of-radix
// numerals). README.md quotes them; see TestREADMECounts.
const thirdPartyVectors = 69

var thirdPartyExpect = map[string]int{"match": 60, "roundtrip": 3, "errorErrDomainTooSmall": 4, "errorErrInvalidNumeral": 2}

var sentinelByName = map[string]error{
	"ErrDomainTooSmall": ff1.ErrDomainTooSmall,
	"ErrInvalidNumeral": ff1.ErrInvalidNumeral,
}

var hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

func TestThirdPartyVectors(t *testing.T) {
	var f thirdPartyFile
	loadJSON(t, "testdata/thirdparty_vectors.json", &f)

	if len(f.Vectors) != thirdPartyVectors {
		t.Fatalf("got %d vectors, want %d (regenerate with tools/extract_vectors/extract.py)", len(f.Vectors), thirdPartyVectors)
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
	if !maps.Equal(counts, thirdPartyExpect) {
		t.Errorf("expect counts = %v, want %v", counts, thirdPartyExpect)
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
