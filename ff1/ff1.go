package ff1

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
)

// MinDomainSize is the minimum domain size radix^minlen required by
// SP 800-38G Rev. 1. It is always enforced; there is no way to relax it.
const MinDomainSize = 1_000_000

// rounds is the number of Feistel rounds in FF1.
const rounds = 10

// Cipher is an FF1 cipher bound to an AES key, an alphabet, and length and
// tweak limits. It holds no mutable state (the tweak is supplied on every
// call), so a Cipher is safe for concurrent use by multiple goroutines.
//
// The zero value is not usable: its methods return [ErrUninitialized].
// Create a Cipher with [New].
type Cipher struct {
	block cipher.Block
	alpha *alphabet
	radix uint64

	bigRadix    *big.Int
	chunkDigits int      // largest k with radix^k <= 2^64-1
	chunkPow    *big.Int // radix^chunkDigits

	domainMinLen int // smallest n with radix^n >= MinDomainSize
	minLen       int
	maxLen       int
	maxTweakLen  int
}

// New returns an FF1 cipher that uses AES with the given key (16, 24, or 32
// bytes for AES-128, AES-192, or AES-256) over the given alphabet. The key
// is expanded immediately; New does not retain the key slice.
//
// The minimum input length defaults to the smallest n with
// radix^n >= 1,000,000 (for example 6 for radix 10, 20 for radix 2, and 2
// for radix 65536). See [WithMinLength], [WithMaxLength], and
// [WithMaxTweakLength] for the other limits.
func New(key []byte, alphabet Alphabet, opts ...Option) (*Cipher, error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("%w: %d bytes, want 16, 24, or 32", ErrInvalidKeyLength, len(key))
	}
	a := alphabet.a
	if a == nil || a.radix < MinRadix || a.radix > MaxRadix {
		return nil, fmt.Errorf("%w: zero-value or invalid Alphabet", ErrInvalidRadix)
	}

	cfg := config{maxLen: maxLenLimit, maxTweakLen: maxTweakLenLimit}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}

	radix := uint64(a.radix)
	domainMin := domainMinLength(radix)
	if cfg.minLen == 0 {
		cfg.minLen = domainMin
	}
	if cfg.minLen < domainMin {
		return nil, fmt.Errorf("%w: min length %d with radix %d, need at least %d", ErrDomainTooSmall, cfg.minLen, radix, domainMin)
	}
	if cfg.maxLen < domainMin {
		return nil, fmt.Errorf("%w: max length %d with radix %d, need at least %d", ErrDomainTooSmall, cfg.maxLen, radix, domainMin)
	}
	if cfg.maxLen < cfg.minLen {
		return nil, fmt.Errorf("%w: max length %d < min length %d", ErrInvalidOption, cfg.maxLen, cfg.minLen)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyLength, err)
	}

	k, pow := chunkSize(radix)
	return &Cipher{
		block:        block,
		alpha:        a,
		radix:        radix,
		bigRadix:     new(big.Int).SetUint64(radix),
		chunkDigits:  k,
		chunkPow:     new(big.Int).SetUint64(pow),
		domainMinLen: domainMin,
		minLen:       cfg.minLen,
		maxLen:       cfg.maxLen,
		maxTweakLen:  cfg.maxTweakLen,
	}, nil
}

// domainMinLength returns the smallest n >= 2 with radix^n >= MinDomainSize,
// computed with exact integer arithmetic.
func domainMinLength(radix uint64) int {
	n := 0
	for d := uint64(1); d < MinDomainSize; d *= radix {
		n++
	}
	return max(n, 2)
}

// chunkSize returns the largest k with radix^k <= 2^64-1, and radix^k.
func chunkSize(radix uint64) (int, uint64) {
	k, p := 0, uint64(1)
	for p <= math.MaxUint64/radix {
		p *= radix
		k++
	}
	return k, p
}

// bitLen returns BITLEN(radix^v - 1) given radixV = radix^v.
// BITLEN(radix^v - 1) = ceil(v * log2(radix)), computed without floating
// point.
func bitLen(radixV *big.Int) int {
	var m big.Int
	m.Sub(radixV, big.NewInt(1))
	return m.BitLen()
}

// layout holds the byte lengths FF1 derives from the tweak length t and
// BITLEN(radix^v - 1).
type layout struct {
	b      int // step 3: b = ceil(BITLEN(radix^v - 1) / 8), the length of [NUM_radix(B)]^b
	d      int // step 4: d = 4*ceil(b/4) + 4, the length of S
	pad    int // (-t-b-1) mod 16, the zero padding in Q
	prefix int // whole blocks of T || [0]^pad, MACed once per call
	tail   int // len(Q) - prefix: rest of T || [0]^pad, [i]^1, [NUM_radix(B)]^b
	sLen   int // ceil(d/16) whole blocks holding S
}

// layoutFor computes the layout for a t-byte tweak and
// bits = BITLEN(radix^v - 1). Callers must have checked t and n against
// maxTweakLenLimit and maxLenLimit (checkParams does), which bounds
// bits <= 16v and keeps every value here, including t+b+1 and len(Q), within
// an int on every platform; see lengthLimits.
func layoutFor(t, bits int) layout {
	b := (bits + 7) / 8
	d := 4*((b+3)/4) + 4
	pad := (16 - (t+b+1)%16) % 16 // t+b+1 >= 0, so this is (-t-b-1) mod 16
	prefix := (t + pad) / 16 * 16
	return layout{
		b:      b,
		d:      d,
		pad:    pad,
		prefix: prefix,
		tail:   t + pad - prefix + 1 + b,
		sLen:   (d + 15) / 16 * 16,
	}
}

// buildP returns the block P of step 5 of the FF1 algorithms:
//
//	P = [1]^1 || [2]^1 || [1]^1 || [radix]^3 || [10]^1 || [u mod 256]^1 || [n]^4 || [t]^4
//
// radix is at most 2^16, so [radix]^3 is 01 00 00 for radix 65536; it must
// not be truncated to 16 bits. n and t are less than 2^32.
func buildP(radix uint64, u, n, t int) [aes.BlockSize]byte {
	var p [aes.BlockSize]byte
	p[0], p[1], p[2] = 1, 2, 1
	p[3], p[4], p[5] = byte(radix>>16), byte(radix>>8), byte(radix)
	p[6] = rounds
	p[7] = byte(u % 256)
	binary.BigEndian.PutUint32(p[8:12], uint32(n))
	binary.BigEndian.PutUint32(p[12:16], uint32(t))
	return p
}

// Radix returns the cipher's radix (the alphabet size), or 0 for a zero or
// nil Cipher.
func (c *Cipher) Radix() int {
	if c == nil {
		return 0
	}
	return int(c.radix)
}

// Alphabet returns the cipher's alphabet.
func (c *Cipher) Alphabet() Alphabet {
	if c == nil {
		return Alphabet{}
	}
	return Alphabet{c.alpha}
}

// MinLength returns the minimum accepted input length in symbols (numerals).
func (c *Cipher) MinLength() int {
	if c == nil {
		return 0
	}
	return c.minLen
}

// MaxLength returns the maximum accepted input length in symbols (numerals).
func (c *Cipher) MaxLength() int {
	if c == nil {
		return 0
	}
	return c.maxLen
}

// MaxTweakLength returns the maximum accepted tweak length in bytes.
func (c *Cipher) MaxTweakLength() int {
	if c == nil {
		return 0
	}
	return c.maxTweakLen
}

// Encrypt encrypts plaintext, a string of symbols from the cipher's
// alphabet, under the given tweak (which may be nil or empty). The
// ciphertext is a string over the same alphabet with the same number of
// symbols.
func (c *Cipher) Encrypt(plaintext string, tweak []byte) (string, error) {
	return c.cryptString(plaintext, tweak, true)
}

// Decrypt decrypts ciphertext, a string of symbols from the cipher's
// alphabet, under the tweak that was used to encrypt it.
func (c *Cipher) Decrypt(ciphertext string, tweak []byte) (string, error) {
	return c.cryptString(ciphertext, tweak, false)
}

// EncryptNumerals encrypts a numeral string (each element less than the
// radix) under the given tweak and returns the ciphertext numerals in a new
// slice. x is not modified. It works for every alphabet kind, including
// [RadixOnly].
func (c *Cipher) EncryptNumerals(x []uint16, tweak []byte) ([]uint16, error) {
	if err := c.checkNumerals(x, tweak); err != nil {
		return nil, err
	}
	return c.crypt(x, tweak, true), nil
}

// DecryptNumerals decrypts a numeral string (each element less than the
// radix) under the given tweak and returns the plaintext numerals in a new
// slice. x is not modified.
func (c *Cipher) DecryptNumerals(x []uint16, tweak []byte) ([]uint16, error) {
	if err := c.checkNumerals(x, tweak); err != nil {
		return nil, err
	}
	return c.crypt(x, tweak, false), nil
}

func (c *Cipher) cryptString(s string, tweak []byte, encrypt bool) (string, error) {
	if c == nil || c.block == nil {
		return "", ErrUninitialized
	}
	if c.alpha.kind == kindRadixOnly {
		return "", ErrNoSymbols
	}
	// Check the length (counted without allocating) and the tweak before
	// decode allocates n numerals.
	n := c.alpha.symbolCount(s)
	if err := c.checkParams(n, len(tweak)); err != nil {
		return "", err
	}
	x, err := c.alpha.decode(s, n)
	if err != nil {
		return "", err
	}
	return c.alpha.encode(c.crypt(x, tweak, encrypt)), nil
}

// checkParams validates an input of n symbols and a t-byte tweak against
// the cipher's limits. Every length crypt handles passes through here, and
// the limits never exceed maxLenLimit and maxTweakLenLimit.
func (c *Cipher) checkParams(n, t int) error {
	if n < c.domainMinLen {
		return fmt.Errorf("%w: length %d with radix %d, need at least %d", ErrDomainTooSmall, n, c.radix, c.domainMinLen)
	}
	if n < c.minLen || n > c.maxLen {
		return fmt.Errorf("%w: length %d not in %d..%d", ErrInvalidLength, n, c.minLen, c.maxLen)
	}
	if t > c.maxTweakLen {
		return fmt.Errorf("%w: %d bytes, max %d", ErrTweakTooLong, t, c.maxTweakLen)
	}
	return nil
}

func (c *Cipher) checkNumerals(x []uint16, tweak []byte) error {
	if c == nil || c.block == nil {
		return ErrUninitialized
	}
	if err := c.checkParams(len(x), len(tweak)); err != nil {
		return err
	}
	for i, v := range x {
		if uint64(v) >= c.radix {
			return fmt.Errorf("%w: at position %d (radix %d)", ErrInvalidNumeral, i, c.radix)
		}
	}
	return nil
}

// crypt runs FF1.Encrypt or FF1.Decrypt (SP 800-38G Rev. 1 Algorithms 5
// and 6) on validated input. The halves A and B are carried as integers
// between rounds and converted with STR only at the end, which is
// equivalent to the specification because every intermediate value is
// reduced mod radix^m and STR^m is a bijection on [0, radix^m).
func (c *Cipher) crypt(x []uint16, tweak []byte, encrypt bool) []uint16 {
	n, t := len(x), len(tweak)
	// 1. u = floor(n/2); v = n - u.
	u := n / 2
	v := n - u

	// radix^u and radix^v, the moduli for even and odd rounds.
	modV := new(big.Int).Exp(c.bigRadix, big.NewInt(int64(v)), nil)
	modU := modV
	if u != v {
		modU = new(big.Int).Exp(c.bigRadix, big.NewInt(int64(u)), nil)
	}

	// 3. b; 4. d; and the layout of Q = T || [0]^pad || [i]^1 || [NUM]^b.
	l := layoutFor(t, bitLen(modV))
	d := l.d

	// 5. P.
	p := buildP(c.radix, u, n, t)

	// PRF(P || Q) is CBC-MAC with a zero IV (Algorithm 4). The part of Q
	// before [i]^1, T || [0]^pad, is the same in every round, so its whole
	// blocks (after P) are MACed once.
	var state [aes.BlockSize]byte
	c.block.Encrypt(state[:], p[:])
	var blk [aes.BlockSize]byte
	for off := 0; off < l.prefix; off += aes.BlockSize {
		blk = [aes.BlockSize]byte{}
		if off < t {
			copy(blk[:], tweak[off:min(off+aes.BlockSize, t)])
		}
		subtle.XORBytes(state[:], state[:], blk[:])
		c.block.Encrypt(state[:], state[:])
	}

	// tail = rest of T || [0]^pad, then [i]^1 || [NUM_radix(B)]^b. Its length
	// is a multiple of 16 because len(Q) = t + pad + 1 + b is.
	tail := make([]byte, l.tail)
	if l.prefix < t {
		copy(tail, tweak[l.prefix:])
	}
	iPos := l.tail - 1 - l.b
	qNum := tail[iPos+1:] // the [NUM_radix(.)]^b field of Q: exactly b bytes

	s := make([]byte, l.sLen)

	// 2. A = X[1..u]; B = X[u+1..n].
	numA := c.num(x[:u])
	numB := c.num(x[u:])
	y := new(big.Int)

	for round := range rounds {
		// Encryption runs i = 0..9 with Q built from B; decryption runs
		// i = 9..0 with Q built from A.
		i := round
		half := numB
		if !encrypt {
			i = rounds - 1 - round
			half = numA
		}

		// 6.i  Q = T || [0]^pad || [i]^1 || [NUM_radix(.)]^b. FillBytes
		//      left-pads to exactly b bytes; the value is < radix^v <= 256^b.
		tail[iPos] = byte(i)
		half.FillBytes(qNum)

		// 6.ii R = PRF(P || Q).
		r := state
		for off := 0; off < len(tail); off += aes.BlockSize {
			subtle.XORBytes(r[:], r[:], tail[off:off+aes.BlockSize])
			c.block.Encrypt(r[:], r[:])
		}

		// 6.iii S = first d bytes of R || CIPH(R xor [1]^16) || ... ||
		//       CIPH(R xor [ceil(d/16)-1]^16). [j]^16 is j as 16 big-endian
		//       bytes; j < 2^64, so only the low 8 bytes of R change.
		copy(s, r[:])
		for j := 1; j*aes.BlockSize < d; j++ {
			blk = r
			binary.BigEndian.PutUint64(blk[8:], binary.BigEndian.Uint64(r[8:])^uint64(j))
			c.block.Encrypt(s[j*aes.BlockSize:], blk[:])
		}

		// 6.iv y = NUM(S).
		y.SetBytes(s[:d])

		// 6.v m = u for even i, v for odd i.
		mod := modU
		if i%2 == 1 {
			mod = modV
		}

		// 6.vi-ix. big.Int.Mod is Euclidean, so the result is in [0, radix^m)
		// even when NUM(B) - y is negative.
		if encrypt {
			// c = (NUM(A) + y) mod radix^m; A = B; B = C.
			numA.Add(numA, y)
			numA.Mod(numA, mod)
			numA, numB = numB, numA
		} else {
			// c = (NUM(B) - y) mod radix^m; B = A; A = C.
			numB.Sub(numB, y)
			numB.Mod(numB, mod)
			numA, numB = numB, numA
		}
	}

	// 7. Y = A || B, with STR^u and STR^v left-padding to exactly u and v
	// numerals.
	out := make([]uint16, n)
	c.str(numA, out[:u])
	c.str(numB, out[u:])
	return out
}

// num returns NUM_radix(x) (Algorithm 1), folding chunkDigits numerals into
// each big.Int step.
func (c *Cipher) num(x []uint16) *big.Int {
	z := new(big.Int)
	var tmp big.Int
	first := len(x) % c.chunkDigits
	if first == 0 && len(x) > 0 {
		first = c.chunkDigits
	}
	acc := uint64(0)
	for _, d := range x[:first] {
		acc = acc*c.radix + uint64(d)
	}
	z.SetUint64(acc)
	for i := first; i < len(x); i += c.chunkDigits {
		acc = 0
		for _, d := range x[i : i+c.chunkDigits] {
			acc = acc*c.radix + uint64(d)
		}
		z.Mul(z, c.chunkPow)
		z.Add(z, tmp.SetUint64(acc))
	}
	return z
}

// str writes STR^m_radix(z) (Algorithm 3) into out, where m = len(out) and
// 0 <= z < radix^m, left-padding with zero numerals. z is not modified.
func (c *Cipher) str(z *big.Int, out []uint16) {
	q := new(big.Int).Set(z)
	var r big.Int
	for pos := len(out); pos > 0; {
		q.QuoRem(q, c.chunkPow, &r)
		acc := r.Uint64()
		for j := 0; j < c.chunkDigits && pos > 0; j++ {
			pos--
			out[pos] = uint16(acc % c.radix)
			acc /= c.radix
		}
	}
}
