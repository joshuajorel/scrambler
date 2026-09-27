package ff1_test

import (
	"runtime"
	"sync"
	"testing"

	"github.com/joshuajorel/scrambler/ff1"
)

// TestFullPermutationRadix10Len6 is T7: FF1 over radix 10, n = 6 (the
// smallest permitted domain, exactly 10^6 values) is a bijection, and
// decryption inverts it, for every input.
func TestFullPermutationRadix10Len6(t *testing.T) {
	const n, size = 6, 1_000_000
	key := mustHex(t, nistK128)
	tweak := []byte("full-permutation")
	c := mustNew(t, key, mustRadix(t, 10))

	perm := make([]int32, size)
	workers := runtime.GOMAXPROCS(0)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			x := make([]uint16, n)
			for v := w; v < size; v += workers {
				for i, rest := n-1, v; i >= 0; i, rest = i-1, rest/10 {
					x[i] = uint16(rest % 10)
				}
				ct, err := c.EncryptNumerals(x, tweak)
				if err != nil {
					t.Errorf("EncryptNumerals(%06d): %v", v, err)
					return
				}
				y := 0
				for _, d := range ct {
					y = y*10 + int(d)
				}
				perm[v] = int32(y)
				pt, err := c.DecryptNumerals(ct, tweak)
				if err != nil {
					t.Errorf("DecryptNumerals(%06d): %v", y, err)
					return
				}
				for i := range pt {
					if pt[i] != x[i] {
						t.Errorf("Decrypt(Encrypt(%06d)) = %v", v, pt)
						return
					}
				}
			}
		})
	}
	wg.Wait()
	if t.Failed() {
		return
	}

	seen := make([]bool, size)
	fixed := 0
	for v, y := range perm {
		if y < 0 || y >= size {
			t.Fatalf("Encrypt(%06d) = %d out of range", v, y)
		}
		if seen[y] {
			t.Fatalf("Encrypt is not injective: %06d collides", y)
		}
		seen[y] = true
		if int(y) == v {
			fixed++
		}
	}
	// A random permutation of 10^6 points has about one fixed point; many
	// would indicate a broken round function.
	if fixed > 20 {
		t.Errorf("%d fixed points", fixed)
	}
	t.Logf("bijective over all %d inputs; %d fixed points", size, fixed)

	// Spot-check that the string API agrees with the numeral API.
	s := mustNew(t, key, ff1.Digits)
	for _, v := range []int{0, 1, 123456, 999999} {
		pt := []byte("000000")
		for i, rest := n-1, v; i >= 0; i, rest = i-1, rest/10 {
			pt[i] = byte('0' + rest%10)
		}
		ct, err := s.Encrypt(string(pt), tweak)
		if err != nil {
			t.Fatal(err)
		}
		y := 0
		for _, ch := range ct {
			y = y*10 + int(ch-'0')
		}
		if int32(y) != perm[v] {
			t.Errorf("string API: Encrypt(%s) = %s, numeral API %06d", pt, ct, perm[v])
		}
	}
}
