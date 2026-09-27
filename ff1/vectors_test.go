package ff1_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// T2: NIST ACVP vectors, and the integrity of all vendored vector files.

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

// acvpGroups and acvpCases are the size of the NIST vector set.
const acvpGroups, acvpCases = 30, 750

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
		cases += len(g.Tests)
		t.Run(fmt.Sprintf("tg%d", g.TgID), func(t *testing.T) {
			if g.TestType != "AFT" {
				t.Fatalf("unsupported test type %q", g.TestType)
			}
			alpha := mustAlphabet(t, g.Alphabet)
			if alpha.Radix() != g.Radix {
				t.Fatalf("alphabet %q has radix %d, group says %d", g.Alphabet, alpha.Radix(), g.Radix)
			}
			for _, tc := range g.Tests {
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
	if len(f.TestGroups) != acvpGroups || cases != acvpCases {
		t.Errorf("vector file has %d groups / %d cases, want %d / %d", len(f.TestGroups), cases, acvpGroups, acvpCases)
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
