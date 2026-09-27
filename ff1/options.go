package ff1

import (
	"fmt"
	"math"
	"strconv"
)

// maxSpecLen is the largest input or tweak length FF1 can encode: P holds
// n and t as 4-byte big-endian integers, so both must be < 2^32.
const maxSpecLen = 1<<32 - 1

// maxLenLimit and maxTweakLenLimit are the largest input length (in
// numerals) and tweak length (in bytes) this package accepts on the running
// platform, and the defaults for [WithMaxLength] and [WithMaxTweakLength].
var maxLenLimit, maxTweakLenLimit = platformLimits()

func platformLimits() (int, int) {
	n, t := lengthLimits(strconv.IntSize)
	return int(n), int(t)
}

// lengthLimits returns the input and tweak length limits for a platform
// whose int has intBits bits: the specification's 2^32-1, lowered where an
// int could not hold every size FF1 derives from n and t. For radix at most
// 2^16:
//
//   - BITLEN(radix^v - 1) <= 16v <= 8(n+1), b <= 2v <= n+1, and
//     d <= b+7, so n <= maxInt/16 keeps all of them far below maxInt;
//   - len(Q) = t + pad + 1 + b <= t + n + 17, so t <= maxInt/2 keeps it,
//     t+b+1 in the pad computation, and the block loop bounds in range.
//
// The 64-bit limits are therefore 2^32-1 for both, and the 32-bit limits
// are 2^27-1 numerals and 2^30-1 tweak bytes. layoutFor relies on these
// bounds; TestLayoutWithinLimits checks them for both word sizes.
func lengthLimits(intBits int) (maxLen, maxTweakLen int64) {
	maxInt := int64(math.MaxInt64 >> (64 - intBits))
	return min(maxSpecLen, maxInt/16), min(maxSpecLen, maxInt/2)
}

type config struct {
	minLen      int // 0 means "use the domain minimum"
	maxLen      int
	maxTweakLen int
}

// Option configures a [Cipher] in [New].
type Option func(*config) error

// WithMinLength sets the minimum accepted input length (in numerals or
// symbols). It must be >= 2 and must itself satisfy radix^n >= 1,000,000;
// otherwise [New] fails with [ErrDomainTooSmall]. The default is the
// smallest length satisfying the domain rule for the alphabet's radix.
func WithMinLength(n int) Option {
	return func(c *config) error {
		if n < 2 || n > maxLenLimit {
			return fmt.Errorf("%w: min length %d not in 2..%d", ErrInvalidOption, n, maxLenLimit)
		}
		c.minLen = n
		return nil
	}
}

// WithMaxLength sets the maximum accepted input length (in numerals or
// symbols). It must be at least 2 and not less than the minimum length, and
// a maximum below the domain minimum makes [New] fail with
// [ErrDomainTooSmall]. The default, and the largest value accepted, is
// 2^32-1 on 64-bit platforms and 2^27-1 on 32-bit ones. Inputs from
// untrusted sources should get a much smaller limit (see the README).
func WithMaxLength(n int) Option {
	return func(c *config) error {
		if n < 2 || n > maxLenLimit {
			return fmt.Errorf("%w: max length %d not in 2..%d", ErrInvalidOption, n, maxLenLimit)
		}
		c.maxLen = n
		return nil
	}
}

// WithMaxTweakLength sets the maximum accepted tweak length in bytes. The
// default, and the largest value accepted, is 2^32-1 on 64-bit platforms
// and 2^30-1 on 32-bit ones; tweaks from untrusted sources should get a much
// smaller limit.
func WithMaxTweakLength(n int) Option {
	return func(c *config) error {
		if n < 0 || n > maxTweakLenLimit {
			return fmt.Errorf("%w: max tweak length %d not in 0..%d", ErrInvalidOption, n, maxTweakLenLimit)
		}
		c.maxTweakLen = n
		return nil
	}
}
