package mask

import (
	"fmt"
	"math/big"
	"unicode/utf8"

	"github.com/joshuajorel/scrambler/ff1"
)

// PartKind selects one explicit layout operation. A LuhnDigit must be the
// final part and checks all preceding ASCII digits, including retained ones.
type PartKind uint8

const (
	LiteralPart PartKind = iota + 1
	EncryptedPart
	RetainedPart
	LuhnDigit
)

// Part describes one fixed-width piece of a structured value. LiteralPart
// copies Literal exactly. EncryptedPart and RetainedPart require Width and an
// ordered Alphabet; retained characters are validated and copied. LuhnDigit
// consumes one digit and is recomputed after masking.
type Part struct {
	Kind     PartKind
	Literal  string
	Alphabet string
	Width    int
}

type compiledPart struct {
	kind    PartKind
	literal []rune
	symbols []rune
	lookup  map[rune]int
	width   int
}

type compiledLayout struct {
	parts  []compiledPart
	width  int
	domain *big.Int
	bits   int
}

var million = big.NewInt(1_000_000)

func compileLayout(parts []Part, key []byte, maxTweak int) (*compiledLayout, *ff1.Cipher, error) {
	if len(parts) > maxWidth {
		return nil, nil, fmt.Errorf("%w: too many layout parts", ErrInvalidSpec)
	}
	l := &compiledLayout{domain: big.NewInt(1), parts: make([]compiledPart, 0, len(parts))}
	check := false
	for i, part := range parts {
		cp := compiledPart{kind: part.Kind}
		switch part.Kind {
		case LiteralPart:
			if part.Literal == "" || !utf8.ValidString(part.Literal) || part.Width != 0 || part.Alphabet != "" {
				return nil, nil, fmt.Errorf("%w: invalid literal part %d", ErrInvalidSpec, i)
			}
			cp.literal = []rune(part.Literal)
			cp.width = len(cp.literal)
		case EncryptedPart, RetainedPart:
			if part.Literal != "" || part.Width < 1 || part.Width > maxWidth {
				return nil, nil, fmt.Errorf("%w: invalid segment part %d", ErrInvalidSpec, i)
			}
			alpha, err := ff1.NewAlphabet(part.Alphabet)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: part %d: %w", ErrInvalidSpec, i, err)
			}
			cp.symbols = []rune(alpha.String())
			cp.lookup = make(map[rune]int, len(cp.symbols))
			for n, r := range cp.symbols {
				cp.lookup[r] = n
			}
			cp.width = part.Width
			if part.Kind == EncryptedPart {
				radix := big.NewInt(int64(len(cp.symbols)))
				for j := 0; j < part.Width; j++ {
					l.domain.Mul(l.domain, radix)
				}
			}
		case LuhnDigit:
			if check || i != len(parts)-1 || part.Literal != "" || part.Alphabet != "" || part.Width != 0 {
				return nil, nil, fmt.Errorf("%w: invalid Luhn part %d", ErrInvalidSpec, i)
			}
			check = true
			cp.width = 1
		default:
			return nil, nil, fmt.Errorf("%w: unknown layout part %d", ErrInvalidSpec, i)
		}
		l.width += cp.width
		if l.width > maxWidth {
			return nil, nil, fmt.Errorf("%w: layout exceeds %d symbols", ErrInvalidSpec, maxWidth)
		}
		l.parts = append(l.parts, cp)
	}
	if l.domain.Cmp(million) < 0 {
		return nil, nil, fmt.Errorf("%w: combined encrypted domain below one million", ff1.ErrDomainTooSmall)
	}
	if check {
		for _, part := range l.parts[:len(l.parts)-1] {
			if part.kind == LiteralPart {
				for _, r := range part.literal {
					if r < '0' || r > '9' {
						return nil, nil, fmt.Errorf("%w: Luhn payload must contain only ASCII digits", ErrInvalidSpec)
					}
				}
			} else {
				for _, r := range part.symbols {
					if r < '0' || r > '9' {
						return nil, nil, fmt.Errorf("%w: Luhn payload alphabets must contain only ASCII digits", ErrInvalidSpec)
					}
				}
			}
		}
	}
	l.bits = l.domain.BitLen()
	// A power-of-two domain needs exactly log2(domain) digits.
	if new(big.Int).And(l.domain, new(big.Int).Sub(l.domain, big.NewInt(1))).Sign() == 0 {
		l.bits--
	}
	alpha, _ := ff1.RadixOnly(2)
	c, err := ff1.New(key, alpha, ff1.WithMinLength(l.bits), ff1.WithMaxLength(l.bits), ff1.WithMaxTweakLength(maxTweak))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidSpec, err)
	}
	return l, c, nil
}

func (p *Policy) maskLayout(raw string, tweak []byte) (string, error) {
	l := p.layout
	runes := []rune(raw)
	position := 0
	rank := new(big.Int)
	var precheck []rune
	for _, part := range l.parts {
		piece := runes[position : position+part.width]
		position += part.width
		switch part.kind {
		case LiteralPart:
			for i, r := range part.literal {
				if piece[i] != r {
					return "", ErrInvalidInput
				}
			}
		case EncryptedPart, RetainedPart:
			for _, r := range piece {
				digit, ok := part.lookup[r]
				if !ok {
					return "", ErrInvalidInput
				}
				if part.kind == EncryptedPart {
					rank.Mul(rank, big.NewInt(int64(len(part.symbols))))
					rank.Add(rank, big.NewInt(int64(digit)))
				}
			}
		case LuhnDigit:
			if piece[0] != luhnCheck(precheck) {
				return "", ErrInvalidInput
			}
		}
		if part.kind != LuhnDigit {
			precheck = append(precheck, piece...)
		}
	}
	permuted, err := l.permute(rank, p.cipher, tweak, false)
	if err != nil {
		return "", err
	}
	// Decode the mixed-radix integer from right to left.
	output := make([][]rune, len(l.parts))
	for i := len(l.parts) - 1; i >= 0; i-- {
		part := l.parts[i]
		if part.kind != EncryptedPart {
			continue
		}
		output[i] = make([]rune, part.width)
		radix := big.NewInt(int64(len(part.symbols)))
		for j := part.width - 1; j >= 0; j-- {
			q, rem := new(big.Int).QuoRem(permuted, radix, new(big.Int))
			output[i][j] = part.symbols[int(rem.Int64())]
			permuted = q
		}
	}
	result := make([]rune, 0, l.width)
	position = 0
	for i, part := range l.parts {
		piece := runes[position : position+part.width]
		position += part.width
		switch part.kind {
		case LiteralPart, RetainedPart:
			result = append(result, piece...)
		case EncryptedPart:
			result = append(result, output[i]...)
		case LuhnDigit:
			result = append(result, luhnCheck(result))
		}
	}
	return string(result), nil
}

func (l *compiledLayout) permute(rank *big.Int, c *ff1.Cipher, tweak []byte, inverse bool) (*big.Int, error) {
	x := new(big.Int).Set(rank)
	for {
		numerals := make([]uint16, l.bits)
		for i := 0; i < l.bits; i++ {
			numerals[l.bits-1-i] = uint16(x.Bit(i))
		}
		var err error
		if inverse {
			numerals, err = c.DecryptNumerals(numerals, tweak)
		} else {
			numerals, err = c.EncryptNumerals(numerals, tweak)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidInput, err)
		}
		x.SetInt64(0)
		for _, digit := range numerals {
			x.Lsh(x, 1)
			x.SetBit(x, 0, uint(digit))
		}
		if x.Cmp(l.domain) < 0 {
			return x, nil
		}
	}
}

func luhnCheck(payload []rune) rune {
	sum := 0
	double := true
	for i := len(payload) - 1; i >= 0; i-- {
		digit := int(payload[i] - '0')
		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		double = !double
	}
	return rune('0' + (10-sum%10)%10)
}
