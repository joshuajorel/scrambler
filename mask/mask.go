// Package mask provides deterministic, fixed-width FF1 masking by logical
// domain. Equal canonical inputs under one policy and tweak context
// intentionally mask alike. Masking is pseudonymization, not anonymization.
package mask

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/joshuajorel/scrambler/ff1"
)

const (
	maxWidth    = 256
	maxDomainID = 64
	maxVersion  = 32
	maxContext  = 64
)

var (
	ErrInvalidSpec        = errors.New("mask: invalid policy specification")
	ErrInvalidInput       = errors.New("mask: invalid input")
	ErrEmptyInput         = errors.New("mask: empty input")
	ErrCanonicalization   = errors.New("mask: canonicalization failed")
	ErrCanonicalCollision = errors.New("mask: canonicalization alias forbidden")
	ErrInvalidScope       = errors.New("mask: invalid tweak scope context")
	ErrDivergentPolicy    = errors.New("mask: divergent policy binding")
)

// Scope controls which logical context enters the tweak. JoinDomain uses
// only domain ID and policy version; it never uses a table, column, or row.
type Scope uint8

const (
	JoinDomain Scope = iota
	TenantDomain
	Record
)

// EmptyRule makes handling of absent values explicit. PreserveEmpty returns
// an empty string without invoking FF1; it is only for a known missing-value
// sentinel, never for a short but present value.
type EmptyRule uint8

const (
	RejectEmpty EmptyRule = iota
	PreserveEmpty
)

// AliasRule controls whether normalization may merge distinct raw inputs.
// RejectAliases, the default, requires the raw input to already be in
// canonical form; this is the stateless way to rule out collisions across
// independent processes. AllowAliases is an explicit opt-in to intentional
// aliasing: a field owner chooses it when a canonicalizer deliberately
// normalizes different representations of the same logical value (for
// example zero padding), and those representations then mask alike.
type AliasRule uint8

const (
	RejectAliases AliasRule = iota
	AllowAliases
)

// Canonicalizer must be deterministic and safe for concurrent use. ID must
// change whenever the implementation or its rules change; it is included in
// the policy fingerprint. A zero Canonicalizer is the identity function.
type Canonicalizer struct {
	ID    string
	Apply func(string) (string, error)
}

// Spec is a fixed-width policy. Plain policies use Alphabet and Width;
// structured policies use Layout. Alphabet rune order defines numeral order.
// No key material is stored in a Spec.
type Spec struct {
	DomainID      string
	Version       string
	Alphabet      string
	Width         int // Unicode symbols, not bytes
	Canonicalizer Canonicalizer
	Empty         EmptyRule
	Aliases       AliasRule
	Scope         Scope
	Layout        []Part // Optional structured layout; Alphabet and Width must be unset.
}

// KeyRef names a caller-managed key and its version. Rotate a key by making
// a new policy version and key reference; never put key bytes in Spec.
type KeyRef struct {
	ID      string
	Version string
}

// Context contains logical tweak context. JoinDomain requires the zero
// Context. TenantDomain requires TenantID and no RecordID. Record requires
// RecordID and may additionally use TenantID.
type Context struct {
	TenantID string
	RecordID string
}

// Policy is immutable after Compile and safe to share across goroutines.
type Policy struct {
	domainID, version string
	scope             Scope
	empty             EmptyRule
	aliases           AliasRule
	width             int
	canonicalize      func(string) (string, error)
	cipher            *ff1.Cipher
	fingerprint       string
	layout            *compiledLayout
	inputWidth        int
}

// Compile validates a policy and expands a caller-supplied AES key once.
// The caller owns key retrieval; FF1 does not retain the supplied key slice.
func Compile(spec Spec, ref KeyRef, key []byte) (*Policy, error) {
	if !validLabel(spec.DomainID, maxDomainID) || !validLabel(spec.Version, maxVersion) ||
		!validLabel(ref.ID, maxDomainID) || !validLabel(ref.Version, maxVersion) {
		return nil, fmt.Errorf("%w: domain, policy version, and key reference need bounded nonempty UTF-8 labels", ErrInvalidSpec)
	}
	if spec.Scope > Record || spec.Empty > PreserveEmpty || spec.Aliases > AllowAliases {
		return nil, fmt.Errorf("%w: unsupported width or rule", ErrInvalidSpec)
	}
	if spec.Layout != nil && len(spec.Layout) == 0 {
		return nil, fmt.Errorf("%w: empty structured layout", ErrInvalidSpec)
	}
	if spec.Layout == nil && (spec.Width < 2 || spec.Width > maxWidth) {
		return nil, fmt.Errorf("%w: unsupported width", ErrInvalidSpec)
	}
	canon := spec.Canonicalizer.Apply
	canonID := spec.Canonicalizer.ID
	if canon == nil && canonID == "" {
		canonID = "identity/v1"
		canon = func(s string) (string, error) { return s, nil }
	} else if canon == nil || !validLabel(canonID, maxDomainID) || canonID == "identity/v1" {
		return nil, fmt.Errorf("%w: custom canonicalizer requires a distinct stable ID and function", ErrInvalidSpec)
	}
	// The scope's maximum encoded size is an FF1 bound, including field
	// lengths and the format marker. Actual context labels are checked below.
	maxTweak := len(tweakMarker) + 1 + 4 + maxDomainID + 4 + maxVersion
	if spec.Scope >= TenantDomain {
		maxTweak += 4 + maxContext
	}
	if spec.Scope == Record {
		maxTweak += 4 + maxContext
	}
	var c *ff1.Cipher
	var layout *compiledLayout
	var err error
	inputWidth := spec.Width
	if spec.Layout != nil {
		if spec.Width != 0 || spec.Alphabet != "" {
			return nil, fmt.Errorf("%w: structured policies must leave Width and Alphabet unset", ErrInvalidSpec)
		}
		layout, c, err = compileLayout(spec.Layout, key, maxTweak)
		if err != nil {
			return nil, err
		}
		inputWidth = layout.width
	} else {
		alpha, alphaErr := ff1.NewAlphabet(spec.Alphabet)
		if alphaErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidSpec, alphaErr)
		}
		c, err = ff1.New(key, alpha, ff1.WithMinLength(spec.Width),
			ff1.WithMaxLength(spec.Width), ff1.WithMaxTweakLength(maxTweak))
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidSpec, err)
		}
	}
	p := &Policy{domainID: spec.DomainID, version: spec.Version, scope: spec.Scope,
		empty: spec.Empty, aliases: spec.Aliases, width: spec.Width,
		canonicalize: canon, cipher: c, layout: layout, inputWidth: inputWidth}
	p.fingerprint = policyFingerprint(spec, ref, canonID)
	return p, nil
}

// Fingerprint is a stable SHA-256 digest of policy metadata and key reference,
// not key bytes. It changes when any declared policy rule changes.
func (p *Policy) Fingerprint() string {
	if p == nil {
		return ""
	}
	return p.fingerprint
}

// Mask canonicalizes, validates, and encrypts one fixed-width string.
func (p *Policy) Mask(raw string, ctx Context) (string, error) {
	if p == nil || p.cipher == nil {
		return "", ErrInvalidSpec
	}
	tweak, err := p.tweak(ctx)
	if err != nil {
		return "", err
	}
	if raw == "" {
		if p.empty == PreserveEmpty {
			return "", nil
		}
		return "", ErrEmptyInput
	}
	if len(raw) > p.inputWidth*utf8.UTFMax || !utf8.ValidString(raw) {
		return "", ErrInvalidInput
	}
	canonical, err := p.canonicalize(raw)
	if err != nil {
		return "", ErrCanonicalization
	}
	if p.aliases == RejectAliases && canonical != raw {
		return "", ErrCanonicalCollision
	}
	if len(canonical) > p.inputWidth*utf8.UTFMax || !utf8.ValidString(canonical) ||
		utf8.RuneCountInString(canonical) != p.inputWidth {
		return "", ErrInvalidInput
	}
	if p.layout != nil {
		return p.maskLayout(canonical, tweak)
	}
	masked, err := p.cipher.Encrypt(canonical, tweak)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	return masked, nil
}

const tweakMarker = "scrambler.mask.tweak.v1\x00"

func (p *Policy) tweak(ctx Context) ([]byte, error) {
	if ctx.TenantID != "" && !validLabel(ctx.TenantID, maxContext) ||
		ctx.RecordID != "" && !validLabel(ctx.RecordID, maxContext) {
		return nil, ErrInvalidScope
	}
	switch p.scope {
	case JoinDomain:
		if ctx.TenantID != "" || ctx.RecordID != "" {
			return nil, ErrInvalidScope
		}
	case TenantDomain:
		if ctx.TenantID == "" || ctx.RecordID != "" {
			return nil, ErrInvalidScope
		}
	case Record:
		if ctx.RecordID == "" {
			return nil, ErrInvalidScope
		}
	}
	b := make([]byte, 0, p.cipher.MaxTweakLength())
	b = append(b, tweakMarker...)
	b = append(b, byte(p.scope))
	b = appendField(b, p.domainID)
	b = appendField(b, p.version)
	if p.scope >= TenantDomain {
		b = appendField(b, ctx.TenantID)
	}
	if p.scope == Record {
		b = appendField(b, ctx.RecordID)
	}
	return b, nil
}

func validLabel(s string, maxBytes int) bool {
	return s != "" && len(s) <= maxBytes && utf8.ValidString(s)
}

func appendField(dst []byte, s string) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	dst = append(dst, n[:]...)
	return append(dst, s...)
}

func policyFingerprint(spec Spec, ref KeyRef, canonID string) string {
	b := []byte("scrambler.mask.policy.v1\x00")
	for _, s := range []string{spec.DomainID, spec.Version, ref.ID, ref.Version,
		spec.Alphabet, canonID} {
		b = appendField(b, s)
	}
	b = append(b, byte(spec.Scope), byte(spec.Empty), byte(spec.Aliases))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(spec.Width))
	b = append(b, n[:]...)
	if len(spec.Layout) != 0 {
		b = append(b, []byte("layout/v1\x00")...)
		binary.BigEndian.PutUint32(n[:], uint32(len(spec.Layout)))
		b = append(b, n[:]...)
		for _, part := range spec.Layout {
			b = append(b, byte(part.Kind))
			b = appendField(b, part.Literal)
			b = appendField(b, part.Alphabet)
			binary.BigEndian.PutUint32(n[:], uint32(part.Width))
			b = append(b, n[:]...)
		}
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
