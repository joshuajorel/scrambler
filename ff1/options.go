package ff1

import (
	"fmt"
	"math"
)

// maxSpecLen is the largest input or tweak length FF1 can encode: P holds
// n and t as 4-byte big-endian integers, so both must be < 2^32.
const maxSpecLen = 1<<32 - 1

// defaultMaxLen is maxSpecLen clamped to the platform's int.
var defaultMaxLen = int(min(int64(math.MaxInt), maxSpecLen))

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
		if n < 2 || int64(n) > maxSpecLen {
			return fmt.Errorf("%w: min length %d not in 2..%d", ErrInvalidOption, n, int64(maxSpecLen))
		}
		c.minLen = n
		return nil
	}
}

// WithMaxLength sets the maximum accepted input length (in numerals or
// symbols). It must be in 2..2^32-1 and not less than the minimum length,
// and a maximum below the domain minimum makes [New] fail with
// [ErrDomainTooSmall]. The default is 2^32-1 (clamped to the platform's
// int).
func WithMaxLength(n int) Option {
	return func(c *config) error {
		if n < 2 || int64(n) > maxSpecLen {
			return fmt.Errorf("%w: max length %d not in 2..%d", ErrInvalidOption, n, int64(maxSpecLen))
		}
		c.maxLen = n
		return nil
	}
}

// WithMaxTweakLength sets the maximum accepted tweak length in bytes. It
// must be in 0..2^32-1. The default is 2^32-1 (clamped to the platform's
// int).
func WithMaxTweakLength(n int) Option {
	return func(c *config) error {
		if n < 0 || int64(n) > maxSpecLen {
			return fmt.Errorf("%w: max tweak length %d not in 0..%d", ErrInvalidOption, n, int64(maxSpecLen))
		}
		c.maxTweakLen = n
		return nil
	}
}
