package ff1_test

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// T8: differential vectors computed by other FF1 implementations; see
// tools/differential/README.md.

// differentialFile is the format tools/differential/generate.sh writes.
type differentialFile struct {
	Generator      string            `json:"generator"`
	Library        string            `json:"library"`
	LibraryVersion string            `json:"library_version"`
	Seed           string            `json:"seed"`
	Pinned         map[string]string `json:"pinned"`
	MaxRadix       int               `json:"max_radix"` // set when the generator stops below 65536
	// Radix65536Excluded records why a generator leaves out radix 65536,
	// with the wrong answer the library gives there.
	Radix65536Excluded *struct {
		Reason string   `json:"reason"`
		Key    string   `json:"key"`
		Tweak  string   `json:"tweak"`
		PT     []uint16 `json:"pt"`
		BadCT  []uint16 `json:"bouncycastle_ct"`
	} `json:"radix65536_excluded"`
	Vectors []struct {
		ID    int      `json:"id"`
		Key   string   `json:"key"`
		Radix int      `json:"radix"`
		Tweak string   `json:"tweak"`
		PT    []uint16 `json:"pt"`
		CT    []uint16 `json:"ct"`
	} `json:"vectors"`
}

// differentialOracles lists the expected generator outputs and the radixes
// each must cover. The Rust fpe crate is the primary oracle and the only one
// used at radix 65536: Bouncy Castle mis-encodes radix 65536 in P, so its
// file stops at 65535.
var differentialOracles = map[string]struct {
	vectors  int
	radixes  []int
	maxRadix int
}{
	"fpe-rs":       {vectors: 846, radixes: []int{2, 3, 10, 256, 257, 1000, 32768, 65535, 65536}, maxRadix: 65536},
	"bouncycastle": {vectors: 634, radixes: []int{2, 3, 10, 256, 257, 1000, 32768, 65535}, maxRadix: 65535},
}

func TestDifferential(t *testing.T) {
	files, err := filepath.Glob("testdata/differential_*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(differentialOracles) {
		t.Fatalf("found %d testdata/differential_*.json files, want %d; run tools/differential/generate.sh", len(files), len(differentialOracles))
	}
	for _, path := range files {
		t.Run(strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "differential_"), ".json"), func(t *testing.T) {
			var f differentialFile
			loadJSON(t, path, &f)
			if f.Generator == "" || f.Library == "" || f.LibraryVersion == "" || f.Seed == "" || len(f.Pinned) == 0 {
				t.Fatalf("%s: missing generator provenance", path)
			}
			if len(f.Vectors) == 0 {
				t.Fatalf("%s: no vectors", path)
			}
			radixes := map[int]bool{}
			for _, v := range f.Vectors {
				radixes[v.Radix] = true
				t.Run(fmt.Sprintf("%d_radix%d_n%d", v.ID, v.Radix, len(v.PT)), func(t *testing.T) {
					if !domainOK(v.Radix, len(v.PT)) {
						t.Fatalf("vector violates the domain rule")
					}
					key, tweak := mustHex(t, v.Key), mustHex(t, v.Tweak)
					c := mustNew(t, key, mustRadix(t, v.Radix))
					if got, err := c.EncryptNumerals(v.PT, tweak); err != nil || !slices.Equal(got, v.CT) {
						t.Errorf("EncryptNumerals = %v, %v; want %v", got, err, v.CT)
					}
					if got, err := c.DecryptNumerals(v.CT, tweak); err != nil || !slices.Equal(got, v.PT) {
						t.Errorf("DecryptNumerals = %v, %v; want %v", got, err, v.PT)
					}
				})
			}
			name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "differential_"), ".json")
			want, ok := differentialOracles[name]
			if !ok {
				t.Fatalf("unexpected oracle %q", name)
			}
			if len(f.Vectors) != want.vectors {
				t.Errorf("%d vectors, want %d", len(f.Vectors), want.vectors)
			}
			for _, r := range want.radixes {
				if !radixes[r] {
					t.Errorf("no radix-%d vectors", r)
				}
			}
			for r := range radixes {
				if r > want.maxRadix {
					t.Errorf("radix-%d vector from an oracle trusted only up to radix %d", r, want.maxRadix)
				}
			}
			if want.maxRadix < 65536 {
				// The generator must say why it stops short, and its recorded
				// radix-65536 output must indeed be wrong.
				ex := f.Radix65536Excluded
				if f.MaxRadix != want.maxRadix || ex == nil || ex.Reason == "" {
					t.Fatalf("missing radix-65536 exclusion record")
				}
				c := mustNew(t, mustHex(t, ex.Key), mustRadix(t, 65536))
				ours, err := c.EncryptNumerals(ex.PT, mustHex(t, ex.Tweak))
				if err != nil || slices.Equal(ours, ex.BadCT) {
					t.Errorf("recorded radix-65536 output %v unexpectedly agrees with ours (%v, %v)", ex.BadCT, ours, err)
				}
				if !slices.Equal(ex.BadCT, []uint16{6653, 42184}) || !slices.Equal(ours, []uint16{18476, 48157}) {
					t.Errorf("radix-65536 evidence changed: theirs %v, ours %v", ex.BadCT, ours)
				}
			}
		})
	}
}
