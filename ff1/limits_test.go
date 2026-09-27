package ff1

import (
	"errors"
	"math"
	"strconv"
	"testing"
)

// These tests exercise the length arithmetic at the largest accepted inputs
// and tweaks without allocating them: checkParams and layoutFor take
// lengths, not data. They run for 32- and 64-bit ints on 64-bit hosts, and
// natively with 32-bit ints under GOARCH=386 in CI.

func TestLengthLimits(t *testing.T) {
	for _, tc := range []struct {
		intBits      int
		maxLen, maxT int64
	}{
		{64, 1<<32 - 1, 1<<32 - 1}, // the specification's limits bind
		{32, 1<<27 - 1, 1<<30 - 1},
	} {
		n, tw := lengthLimits(tc.intBits)
		if n != tc.maxLen || tw != tc.maxT {
			t.Errorf("lengthLimits(%d) = %d, %d; want %d, %d", tc.intBits, n, tw, tc.maxLen, tc.maxT)
		}
	}
	n, tw := lengthLimits(strconv.IntSize)
	if int64(maxLenLimit) != n || int64(maxTweakLenLimit) != tw {
		t.Errorf("platform limits %d, %d; want %d, %d", maxLenLimit, maxTweakLenLimit, n, tw)
	}
	t.Logf("int is %d bits: inputs up to %d numerals, tweaks up to %d bytes", strconv.IntSize, maxLenLimit, maxTweakLenLimit)
}

// TestLayoutWithinLimits checks that at the largest n and t a platform
// accepts, every value layoutFor computes, and every intermediate sum it
// forms, is at most that platform's maxInt, and that the layout is well
// formed.
func TestLayoutWithinLimits(t *testing.T) {
	for _, intBits := range []int{32, 64} {
		if intBits > strconv.IntSize {
			continue // a 32-bit int cannot even hold the 64-bit limits
		}
		maxInt := int64(math.MaxInt64 >> (64 - intBits))
		maxN, maxT := lengthLimits(intBits)
		for _, n := range []int64{2, 3, 4, maxN - 1, maxN} {
			v := n - n/2
			// radix 2^16 maximizes BITLEN(radix^v - 1) = 16v for a given v.
			for _, bits := range []int64{1, 16 * v} {
				for _, tw := range []int64{0, 1, 13, 14, 15, 16, 17, maxT - 17, maxT - 1, maxT} {
					checkLayout(t, intBits, maxInt, n, tw, bits)
				}
			}
		}
	}
}

func checkLayout(t *testing.T, intBits int, maxInt, n, tw, bits int64) {
	t.Helper()
	l := layoutFor(int(tw), int(bits))
	b, pad, prefix, tail := int64(l.b), int64(l.pad), int64(l.prefix), int64(l.tail)
	for name, v := range map[string]int64{
		"bits+7": bits + 7, "d+15": int64(l.d) + 15, "t+b+1": tw + b + 1,
		"t+pad": tw + pad, "tail": tail, "sLen": int64(l.sLen),
	} {
		if v > maxInt {
			t.Fatalf("int%d, n=%d, t=%d, bits=%d: %s = %d exceeds %d", intBits, n, tw, bits, name, v, maxInt)
		}
	}
	qLen := tw + pad + 1 + b
	switch {
	case b != (bits+7)/8 || int64(l.d) != 4*((b+3)/4)+4:
		t.Fatalf("t=%d bits=%d: b=%d d=%d", tw, bits, l.b, l.d)
	case pad < 0 || pad > 15 || qLen%16 != 0:
		t.Fatalf("t=%d b=%d: pad=%d leaves len(Q)=%d", tw, b, pad, qLen)
	case prefix < 0 || prefix%16 != 0 || prefix > tw+pad || tw+pad-prefix >= 16:
		t.Fatalf("t=%d pad=%d: prefix=%d", tw, pad, prefix)
	case prefix+tail != qLen || tail%16 != 0 || tail < 1+b:
		t.Fatalf("t=%d: prefix=%d tail=%d, len(Q)=%d", tw, prefix, tail, qLen)
	case int64(l.sLen) < int64(l.d) || l.sLen%16 != 0 || int64(l.sLen) >= int64(l.d)+16:
		t.Fatalf("d=%d: sLen=%d", l.d, l.sLen)
	}
}

// TestLayoutSmall cross-checks layoutFor against its definition for every
// small tweak length and b.
func TestLayoutSmall(t *testing.T) {
	for tw := int64(0); tw <= 80; tw++ {
		for bits := int64(1); bits <= 300; bits++ {
			checkLayout(t, 64, math.MaxInt64, 0, tw, bits)
		}
	}
}

// TestCheckParamsAtLimits validates lengths at and beyond the platform
// limits through the same check every call makes before crypt, including
// the 32-bit case that used to overflow: radix 65536, n = 2, and the largest
// accepted tweak.
func TestCheckParamsAtLimits(t *testing.T) {
	a, err := RadixOnly(MaxRadix)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(make([]byte, 16), a)
	if err != nil {
		t.Fatal(err)
	}
	if c.maxLen != maxLenLimit || c.maxTweakLen != maxTweakLenLimit {
		t.Fatalf("defaults %d, %d; want the platform limits %d, %d", c.maxLen, c.maxTweakLen, maxLenLimit, maxTweakLenLimit)
	}
	for _, tc := range []struct {
		n, tw int
		want  error
	}{
		{2, maxTweakLenLimit, nil},
		{2, maxTweakLenLimit - 1, nil},
		{2, maxTweakLenLimit + 1, ErrTweakTooLong},
		{maxLenLimit, 0, nil},
		{maxLenLimit, maxTweakLenLimit, nil},
		{maxLenLimit + 1, 0, ErrInvalidLength},
		{1, 0, ErrDomainTooSmall},
	} {
		if err := c.checkParams(tc.n, tc.tw); !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
			t.Errorf("checkParams(%d, %d) = %v, want %v", tc.n, tc.tw, err, tc.want)
		}
	}

	// The layout for the largest accepted tweak with n = 2 at radix 65536:
	// b = 2, pad = 14, and the prefix covers T and the pad's first bytes.
	l := layoutFor(maxTweakLenLimit, bitLen(pow(MaxRadix, 1)))
	if l.b != 2 || l.pad != 14 || l.prefix < maxTweakLenLimit-15 || l.prefix > maxTweakLenLimit+l.pad || l.tail != 16 {
		t.Fatalf("layout at t = %d: %+v", maxTweakLenLimit, l)
	}

	// Options beyond the platform limits are rejected up front.
	for _, opt := range []Option{
		WithMaxTweakLength(maxTweakLenLimit + 1),
		WithMaxLength(maxLenLimit + 1),
		WithMinLength(maxLenLimit + 1),
	} {
		if _, err := New(make([]byte, 16), a, opt); !errors.Is(err, ErrInvalidOption) {
			t.Errorf("option beyond the platform limit: error %v, want ErrInvalidOption", err)
		}
	}
	if strconv.IntSize == 32 {
		// The value from the review: 2^31-1 used to be the 32-bit default.
		if _, err := New(make([]byte, 16), a, WithMaxTweakLength(math.MaxInt32)); !errors.Is(err, ErrInvalidOption) {
			t.Errorf("WithMaxTweakLength(2^31-1) on 32-bit: error %v, want ErrInvalidOption", err)
		}
	}
}
