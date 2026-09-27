package ff1

import (
	"math/big"
	"slices"
	"testing"
)

func pow(radix, e int) *big.Int {
	return new(big.Int).Exp(big.NewInt(int64(radix)), big.NewInt(int64(e)), nil)
}

// bytesNeeded is an independent definition of b: the smallest b with
// 256^b > radix^v - 1.
func bytesNeeded(radix, v int) int {
	limit := new(big.Int).Sub(pow(radix, v), big.NewInt(1))
	b := 0
	for p := big.NewInt(1); p.Cmp(limit) <= 0; p.Lsh(p, 8) {
		b++
	}
	return b
}

func bOnly(radixV *big.Int) int {
	b, _ := byteLengths(radixV)
	return b
}

func TestByteLengthsKnown(t *testing.T) {
	for _, tc := range []struct{ radix, v, want int }{
		{2, 232, 29},  // 232 bits exactly: floating-point log2 is prone to 233 -> 30
		{2, 231, 29},  // 231 bits
		{2, 233, 30},  // 233 bits
		{2, 8, 1},     // 255
		{2, 9, 2},     // 511
		{256, 29, 29}, // Bouncy Castle testFF1Rounding (n = 57, v = 29)
		{256, 1, 1},   // 255
		{10, 3, 2},    // 999 -> 10 bits
		{10, 5, 3},    // NIST samples 1-2, 4-5, 7-8 (v = 5): 99999 -> 17 bits
		{36, 10, 7},   // NIST radix-36 samples (v = 10): 36^10-1 -> 52 bits
		{65536, 1, 2}, // 0xFFFF
		{65536, 2, 4}, // 2^32 - 1
		{65536, 16, 32},
		{16, 58, 29}, // 232 bits again, via radix 16
		{1024, 2, 3}, // Bouncy Castle testFF1w (v = 2): 2^20 - 1
	} {
		if got := bOnly(pow(tc.radix, tc.v)); got != tc.want {
			t.Errorf("b(radix %d, v %d) = %d, want %d", tc.radix, tc.v, got, tc.want)
		}
	}
}

// TestByteLengthsExhaustive compares b from byteLengths with the independent definition
// for every radix power of two (where rounding errors bite) and a spread of
// other radixes, over a wide range of v.
func TestByteLengthsExhaustive(t *testing.T) {
	radixes := []int{3, 5, 6, 7, 9, 10, 11, 26, 36, 62, 64, 94, 95, 100, 255, 257, 1000, 4095, 4097, 65535}
	for k := 1; k <= 16; k++ {
		radixes = append(radixes, 1<<k)
	}
	for _, r := range radixes {
		for v := 1; v <= 600; v++ {
			if got, want := bOnly(pow(r, v)), bytesNeeded(r, v); got != want {
				t.Fatalf("b(radix %d, v %d) = %d, want %d", r, v, got, want)
			}
		}
	}
}

func TestDomainMinLength(t *testing.T) {
	for _, tc := range []struct{ radix, want int }{
		{2, 20}, {3, 13}, {4, 10}, {8, 7}, {9, 7}, {10, 6}, {16, 5}, {26, 5}, {31, 5}, {32, 4},
		{36, 4}, {62, 4}, {64, 4}, {99, 4}, {100, 3}, {101, 3}, {256, 3}, {999, 3},
		{1000, 2}, {1024, 2}, {65535, 2}, {65536, 2},
	} {
		if got := domainMinLength(uint64(tc.radix)); got != tc.want {
			t.Errorf("domainMinLength(%d) = %d, want %d", tc.radix, got, tc.want)
		}
	}
	// Cross-check the defining property for every radix.
	million := big.NewInt(MinDomainSize)
	for r := MinRadix; r <= MaxRadix; r++ {
		n := domainMinLength(uint64(r))
		if pow(r, n).Cmp(million) < 0 || (n > 2 && pow(r, n-1).Cmp(million) >= 0) {
			t.Fatalf("domainMinLength(%d) = %d is not minimal", r, n)
		}
	}
}

func TestChunkSize(t *testing.T) {
	maxU64 := new(big.Int).SetUint64(^uint64(0))
	for _, r := range []int{2, 3, 10, 16, 36, 255, 256, 257, 1000, 65535, 65536} {
		k, p := chunkSize(uint64(r))
		if pow(r, k).Cmp(new(big.Int).SetUint64(p)) != 0 {
			t.Errorf("chunkSize(%d): %d != %d^%d", r, p, r, k)
		}
		if pow(r, k+1).Cmp(maxU64) <= 0 {
			t.Errorf("chunkSize(%d) = %d is not maximal", r, k)
		}
	}
}

// TestNumStr checks the chunked NUM/STR conversions against their
// definitions, including zero-padding and all-max values.
func TestNumStr(t *testing.T) {
	seed := uint64(1)
	next := func() uint64 {
		seed ^= seed << 13
		seed ^= seed >> 7
		seed ^= seed << 17
		return seed
	}
	for _, r := range []int{2, 3, 10, 36, 256, 1000, 65535, 65536} {
		a, err := RadixOnly(r)
		if err != nil {
			t.Fatal(err)
		}
		c, err := New(make([]byte, 16), a)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range []int{1, 2, 3, 19, 20, 21, 63, 64, 65, 200} {
			for trial := range 20 {
				x := make([]uint16, m)
				for i := range x {
					switch trial {
					case 0: // all zero
					case 1:
						x[i] = uint16(r - 1)
					default:
						x[i] = uint16(next() % uint64(r))
					}
				}
				want := new(big.Int)
				for _, d := range x {
					want.Mul(want, big.NewInt(int64(r)))
					want.Add(want, big.NewInt(int64(d)))
				}
				got := c.num(x)
				if got.Cmp(want) != 0 {
					t.Fatalf("radix %d: num(%v) = %v, want %v", r, x, got, want)
				}
				back := make([]uint16, m)
				c.str(got, back)
				if !slices.Equal(back, x) {
					t.Fatalf("radix %d: str(num(%v)) = %v", r, x, back)
				}
			}
		}
	}
}

func TestBuildP(t *testing.T) {
	for _, tc := range []struct {
		radix   uint64
		u, n, t int
		want    [16]byte
	}{
		// NIST sample 1 (radix 10, n = 10, empty tweak), as printed in
		// FF1samples.pdf.
		{10, 5, 10, 0, [16]byte{1, 2, 1, 0, 0, 10, 10, 5, 0, 0, 0, 10, 0, 0, 0, 0}},
		// NIST sample 3 (radix 36, n = 19, 11-byte tweak).
		{36, 9, 19, 11, [16]byte{1, 2, 1, 0, 0, 36, 10, 9, 0, 0, 0, 19, 0, 0, 0, 11}},
		// radix 65536 is [radix]^3 = 01 00 00. Truncating the radix to 16
		// bits (or hardcoding P[3] = 0, as Bouncy Castle does) gives 00 00 00.
		{65536, 1, 2, 8, [16]byte{1, 2, 1, 1, 0, 0, 10, 1, 0, 0, 0, 2, 0, 0, 0, 8}},
		{65535, 1, 3, 0, [16]byte{1, 2, 1, 0, 0xff, 0xff, 10, 1, 0, 0, 0, 3, 0, 0, 0, 0}},
		{32768, 2, 4, 0, [16]byte{1, 2, 1, 0, 0x80, 0, 10, 2, 0, 0, 0, 4, 0, 0, 0, 0}},
		{256, 1, 3, 0, [16]byte{1, 2, 1, 0, 1, 0, 10, 1, 0, 0, 0, 3, 0, 0, 0, 0}},
		{2, 10, 20, 0, [16]byte{1, 2, 1, 0, 0, 2, 10, 10, 0, 0, 0, 20, 0, 0, 0, 0}},
		// [u mod 256]^1, and multi-byte n and t.
		{10, 300, 601, 0x01020304, [16]byte{1, 2, 1, 0, 0, 10, 10, 44, 0, 0, 2, 0x59, 1, 2, 3, 4}},
		{10, 256, 512, 256, [16]byte{1, 2, 1, 0, 0, 10, 10, 0, 0, 0, 2, 0, 0, 0, 1, 0}},
		{10, 1<<30 - 1, 1<<31 - 1, 1<<31 - 1, [16]byte{1, 2, 1, 0, 0, 10, 10, 0xff, 0x7f, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff}},
	} {
		if got := buildP(tc.radix, tc.u, tc.n, tc.t); got != tc.want {
			t.Errorf("buildP(%d, %d, %d, %d) = % x, want % x", tc.radix, tc.u, tc.n, tc.t, got, tc.want)
		}
	}
}

// TestRadixWidth checks that radix 65536 survives construction: it is held
// in a type wider than uint16, reported unchanged, and encoded in P.
func TestRadixWidth(t *testing.T) {
	a, err := RadixOnly(MaxRadix)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(make([]byte, 16), a)
	if err != nil {
		t.Fatal(err)
	}
	// This does not compile if the radix field is narrowed below uint64.
	wide := func(v uint64) uint64 { return v }(c.radix)
	if wide != 1<<16 || c.Radix() != 1<<16 || a.Radix() != 1<<16 || c.bigRadix.Int64() != 1<<16 {
		t.Fatalf("radix = %d / %d / %d / %v, want 65536", c.radix, c.Radix(), a.Radix(), c.bigRadix)
	}
	if p := buildP(c.radix, 1, 2, 0); p[3] != 1 || p[4] != 0 || p[5] != 0 {
		t.Fatalf("P[3..5] = % x, want 01 00 00", p[3:6])
	}
}

// TestByteLengthsRadix65536 covers b and d at radix 65536, including the
// step from one S block (n = 12: b = 12, d = 16) to two (n = 13: b = 14,
// d = 20).
func TestByteLengthsRadix65536(t *testing.T) {
	for _, tc := range []struct{ n, b, d, blocks int }{
		{2, 2, 8, 1},
		{3, 4, 8, 1},
		{4, 4, 8, 1},
		{12, 12, 16, 1},
		{13, 14, 20, 2},
		{14, 14, 20, 2},
		{24, 24, 28, 2},
		{25, 26, 32, 2},
		{27, 28, 32, 2},
		{29, 30, 36, 3},
	} {
		v := tc.n - tc.n/2
		b, d := byteLengths(pow(MaxRadix, v))
		if b != tc.b || d != tc.d || (d+15)/16 != tc.blocks {
			t.Errorf("radix 65536, n %d: b = %d, d = %d (%d blocks); want %d, %d (%d)", tc.n, b, d, (d+15)/16, tc.b, tc.d, tc.blocks)
		}
	}
}
