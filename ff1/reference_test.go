package ff1_test

import (
	"crypto/aes"
	"math/big"
	"slices"
	"testing"
)

// refCrypt is a literal, deliberately unoptimized transcription of
// FF1.Encrypt and FF1.Decrypt from SP 800-38G Rev. 1 (Algorithms 1-6). It
// shares no code with the package: it rebuilds P || Q and runs the whole PRF
// every round, converts with NUM/STR every round, encodes [x]^s by repeated
// division, and finds b as the smallest byte count with 256^b > radix^v - 1
// rather than via BITLEN. It is used to cross-check the optimized
// implementation on inputs no published vector covers.
func refCrypt(key []byte, radix int, tweak []byte, x []uint16, encrypt bool) []uint16 {
	return refCryptP(key, radix, tweak, x, encrypt, refBytes(big.NewInt(int64(radix)), 3))
}

// refCryptP is refCrypt with the [radix]^3 field of P supplied by the caller,
// so that tests can reproduce implementations that encode it incorrectly.
func refCryptP(key []byte, radix int, tweak []byte, x []uint16, encrypt bool, radix3 []byte) []uint16 {
	ciph, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	n, t := len(x), len(tweak)
	bigRadix := big.NewInt(int64(radix))

	// 1. u = floor(n/2); v = n - u.
	u := n / 2
	v := n - u
	// 2. A = X[1..u]; B = X[u+1..n].
	A := slices.Clone(x[:u])
	B := slices.Clone(x[u:])

	// 3. b: the number of bytes needed to hold radix^v - 1.
	limit := new(big.Int).Exp(bigRadix, big.NewInt(int64(v)), nil)
	limit.Sub(limit, big.NewInt(1))
	b := 0
	for pow := big.NewInt(1); pow.Cmp(limit) <= 0; pow.Lsh(pow, 8) {
		b++
	}
	// 4. d = 4*ceil(b/4) + 4.
	d := 4*((b+3)/4) + 4

	// 5. P.
	P := []byte{1, 2, 1}
	P = append(P, radix3...)
	P = append(P, 10, byte(u%256))
	P = append(P, refBytes(big.NewInt(int64(n)), 4)...)
	P = append(P, refBytes(big.NewInt(int64(t)), 4)...)

	// (-t-b-1) mod 16 via Euclidean modulus.
	pad := int(new(big.Int).Mod(big.NewInt(int64(-t-b-1)), big.NewInt(16)).Int64())

	for step := range 10 {
		i := step
		if !encrypt {
			i = 9 - step
		}
		// 6.i Q = T || [0]^pad || [i]^1 || [NUM_radix(B or A)]^b.
		src := B
		if !encrypt {
			src = A
		}
		Q := slices.Clone(tweak)
		Q = append(Q, make([]byte, pad)...)
		Q = append(Q, byte(i))
		Q = append(Q, refBytes(refNum(src, radix), b)...)

		// 6.ii R = PRF(P || Q).
		R := refPRF(ciph, append(slices.Clone(P), Q...))

		// 6.iii S = first d bytes of R || CIPH(R xor [1]^16) || ...
		S := slices.Clone(R)
		for j := 1; j < (d+15)/16; j++ {
			jb := refBytes(big.NewInt(int64(j)), 16)
			blk := make([]byte, 16)
			for k := range blk {
				blk[k] = R[k] ^ jb[k]
			}
			out := make([]byte, 16)
			ciph.Encrypt(out, blk)
			S = append(S, out...)
		}
		S = S[:d]

		// 6.iv y = NUM(S).
		y := new(big.Int).SetBytes(S)
		// 6.v m.
		m := u
		if i%2 == 1 {
			m = v
		}
		mod := new(big.Int).Exp(bigRadix, big.NewInt(int64(m)), nil)
		c := new(big.Int)
		if encrypt {
			// 6.vi c = (NUM_radix(A) + y) mod radix^m.
			c.Add(refNum(A, radix), y)
			c.Mod(c, mod)
			// 6.vii-ix.
			C := refStr(c, radix, m)
			A, B = B, C
		} else {
			c.Sub(refNum(B, radix), y)
			c.Mod(c, mod)
			C := refStr(c, radix, m)
			B, A = A, C
		}
	}
	return append(A, B...)
}

// refNum is Algorithm 1, NUM_radix(X).
func refNum(X []uint16, radix int) *big.Int {
	x := new(big.Int)
	r := big.NewInt(int64(radix))
	for _, d := range X {
		x.Mul(x, r)
		x.Add(x, big.NewInt(int64(d)))
	}
	return x
}

// refStr is Algorithm 3, STR^m_radix(x).
func refStr(x *big.Int, radix, m int) []uint16 {
	x = new(big.Int).Set(x)
	r := big.NewInt(int64(radix))
	X := make([]uint16, m)
	rem := new(big.Int)
	for i := 1; i <= m; i++ {
		x.DivMod(x, r, rem)
		X[m-i] = uint16(rem.Int64())
	}
	if x.Sign() != 0 {
		panic("refStr: x >= radix^m")
	}
	return X
}

// refBytes is [x]^s: x as s big-endian bytes.
func refBytes(x *big.Int, s int) []byte {
	x = new(big.Int).Set(x)
	out := make([]byte, s)
	b256 := big.NewInt(256)
	rem := new(big.Int)
	for i := s - 1; i >= 0; i-- {
		x.DivMod(x, b256, rem)
		out[i] = byte(rem.Int64())
	}
	if x.Sign() != 0 {
		panic("refBytes: x >= 256^s")
	}
	return out
}

// refPRF is Algorithm 4: CBC-MAC with a zero IV over a block string.
func refPRF(ciph interface{ Encrypt(dst, src []byte) }, X []byte) []byte {
	if len(X)%16 != 0 {
		panic("refPRF: not a block string")
	}
	Y := make([]byte, 16)
	for j := 0; j < len(X); j += 16 {
		for k := range 16 {
			Y[k] ^= X[j+k]
		}
		ciph.Encrypt(Y, Y)
	}
	return Y
}

// TestReferenceAgainstNIST checks the reference implementation itself
// against the NIST samples, so that agreement with it is meaningful.
func TestReferenceAgainstNIST(t *testing.T) {
	for _, s := range nistSamples {
		t.Run(s.name, func(t *testing.T) {
			key, tweak := mustHex(t, s.key), mustHex(t, s.tweak)
			alpha := s.alphabet.String()
			pt, ct := toNumerals(t, alpha, s.pt), toNumerals(t, alpha, s.ct)
			if got := refCrypt(key, s.alphabet.Radix(), tweak, pt, true); !slices.Equal(got, ct) {
				t.Errorf("ref encrypt = %v, want %v", got, ct)
			}
			if got := refCrypt(key, s.alphabet.Radix(), tweak, ct, false); !slices.Equal(got, pt) {
				t.Errorf("ref decrypt = %v, want %v", got, pt)
			}
		})
	}
}
