// Package manifest loads versioned, non-secret masking manifests. It has no
// database or key-management dependency: callers supply key bytes and row data.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/joshuajorel/scrambler/mask"
)

var ErrInvalidManifest = errors.New("manifest: invalid manifest")
var ErrInvalidRow = errors.New("manifest: invalid row")
var ErrDuplicateOutput = errors.New("manifest: duplicate output in unique binding")

// Document is the v1 JSON format. Keys and secret material are never serialized.
type Document struct {
	Version  int      `json:"version"`
	Policies []Policy `json:"policies"`
	Bindings []Field  `json:"bindings"`
	Edges    []Edge   `json:"edges"`
	Goldens  []Golden `json:"goldens"`
}

type Policy struct {
	Domain   string       `json:"domain"`
	Version  string       `json:"version"`
	Key      KeyReference `json:"key"`
	Scope    string       `json:"scope"`
	Alphabet string       `json:"alphabet,omitempty"`
	Width    int          `json:"width,omitempty"`
	Layout   []Part       `json:"layout,omitempty"`
}

// KeyReference names caller-managed key bytes without embedding them.
type KeyReference struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

func (k KeyReference) maskRef() mask.KeyRef { return mask.KeyRef{ID: k.ID, Version: k.Version} }

type Part struct {
	Kind     string `json:"kind"`
	Literal  string `json:"literal,omitempty"`
	Alphabet string `json:"alphabet,omitempty"`
	Width    int    `json:"width,omitempty"`
}

// Field identifies one physical column. Mode is "mask" or "clear". Clear
// declarations document intentionally unmasked columns and require a reason.
type Field struct {
	Database string `json:"database"`
	Schema   string `json:"schema"`
	Table    string `json:"table"`
	Column   string `json:"column"`
	Mode     string `json:"mode"`
	Policy   string `json:"policy,omitempty"`
	Codec    Codec  `json:"codec,omitempty"`
	Unique   bool   `json:"unique,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// Width is the physical column capacity in bytes for text/blank_padded_text,
// or decimal digits for zero_padded_numeric.
type Codec struct {
	Kind  string `json:"kind"`
	Width int    `json:"width"`
}

// Edge declares a foreign-key or cross-database equality relationship.
// Endpoints are database.schema.table.column binding IDs.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Golden pins output for one synthetic canonical input and its tweak context.
type Golden struct {
	Binding     string         `json:"binding"`
	Input       string         `json:"input"`
	Output      string         `json:"output"`
	Fingerprint string         `json:"fingerprint"`
	Context     *GoldenContext `json:"context,omitempty"`
}

type GoldenContext struct {
	TenantID string `json:"tenant_id,omitempty"`
	RecordID string `json:"record_id,omitempty"`
}

func (f Field) ID() string { return f.Database + "." + f.Schema + "." + f.Table + "." + f.Column }

type bound struct {
	field  Field
	policy *mask.Binding
	width  int
}

// Set is immutable after Load and safe for concurrent masking. A Detector is
// separate mutable state and must be shared by all rows of a stream.
type Set struct {
	bindings map[string]bound
	tables   map[string][]string
}

// Load parses exactly one JSON object, rejects unknown fields, validates the
// graph and codecs, compiles policies, and checks all golden fixtures before
// any row can be masked. Keys are indexed by their versioned reference.
func Load(r io.Reader, keys map[mask.KeyRef][]byte) (*Set, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var d Document
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("%w: JSON: %w", ErrInvalidManifest, err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing JSON", ErrInvalidManifest)
	}
	return Compile(d, keys)
}

// Compile validates an already decoded document. It does not retain key slices.
func Compile(d Document, keys map[mask.KeyRef][]byte) (*Set, error) {
	if d.Version != 1 {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrInvalidManifest, d.Version)
	}
	if len(d.Policies) == 0 || len(d.Bindings) == 0 {
		return nil, fmt.Errorf("%w: policies and bindings required", ErrInvalidManifest)
	}
	policies := make(map[string]*mask.Policy)
	shapes := make(map[string]Policy)
	for _, p := range d.Policies {
		if p.Domain == "" {
			return nil, fmt.Errorf("%w: empty policy domain", ErrInvalidManifest)
		}
		if _, ok := policies[p.Domain]; ok {
			return nil, fmt.Errorf("%w: divergent or duplicate policy for domain %q", ErrInvalidManifest, p.Domain)
		}
		key, ok := keys[p.Key.maskRef()]
		if !ok {
			return nil, fmt.Errorf("%w: policy %q: missing key %q version %q", ErrInvalidManifest, p.Domain, p.Key.ID, p.Key.Version)
		}
		spec := mask.Spec{DomainID: p.Domain, Version: p.Version, Alphabet: p.Alphabet, Width: p.Width}
		switch p.Scope {
		case "join_domain":
			spec.Scope = mask.JoinDomain
		case "tenant_domain":
			spec.Scope = mask.TenantDomain
		case "record":
			spec.Scope = mask.Record
		default:
			return nil, fmt.Errorf("%w: policy %q: unknown tweak scope %q", ErrInvalidManifest, p.Domain, p.Scope)
		}
		if len(p.Layout) > 0 {
			spec.Layout = make([]mask.Part, len(p.Layout))
			for i, part := range p.Layout {
				kind := map[string]mask.PartKind{"literal": mask.LiteralPart, "encrypted": mask.EncryptedPart, "retained": mask.RetainedPart, "luhn": mask.LuhnDigit}[part.Kind]
				if kind == 0 {
					return nil, fmt.Errorf("%w: policy %q: layout part %d: unknown kind %q", ErrInvalidManifest, p.Domain, i, part.Kind)
				}
				spec.Layout[i] = mask.Part{Kind: kind, Literal: part.Literal, Alphabet: part.Alphabet, Width: part.Width}
			}
		}
		compiled, err := mask.Compile(spec, p.Key.maskRef(), key)
		if err != nil {
			return nil, fmt.Errorf("%w: policy %q: %w", ErrInvalidManifest, p.Domain, err)
		}
		policies[p.Domain], shapes[p.Domain] = compiled, p
	}
	s := &Set{bindings: make(map[string]bound), tables: make(map[string][]string)}
	var registry mask.Registry
	for _, f := range d.Bindings {
		id := f.ID()
		if !validLocation(f) {
			return nil, fmt.Errorf("%w: binding %q: invalid location", ErrInvalidManifest, id)
		}
		if _, ok := s.bindings[id]; ok {
			return nil, fmt.Errorf("%w: binding %q: duplicate", ErrInvalidManifest, id)
		}
		b := bound{field: f}
		switch f.Mode {
		case "clear":
			if f.Policy != "" || f.Codec != (Codec{}) || f.Unique || strings.TrimSpace(f.Reason) == "" {
				return nil, fmt.Errorf("%w: binding %q: clear mode needs a reason and no masking settings", ErrInvalidManifest, id)
			}
		case "mask":
			p, ok := policies[f.Policy]
			if !ok {
				return nil, fmt.Errorf("%w: binding %q: undefined policy %q", ErrInvalidManifest, id, f.Policy)
			}
			var err error
			b.width, err = checkCodec(f.Codec, shapes[f.Policy])
			if err != nil {
				return nil, fmt.Errorf("%w: binding %q: %w", ErrInvalidManifest, id, err)
			}
			b.policy, err = registry.Bind(id, p)
			if err != nil {
				return nil, fmt.Errorf("%w: binding %q: %w", ErrInvalidManifest, id, err)
			}
		default:
			return nil, fmt.Errorf("%w: binding %q: unknown mode %q", ErrInvalidManifest, id, f.Mode)
		}
		s.bindings[id] = b
		table := f.Database + "." + f.Schema + "." + f.Table
		s.tables[table] = append(s.tables[table], id)
	}
	for _, e := range d.Edges {
		a, aok := s.bindings[e.From]
		b, bok := s.bindings[e.To]
		if !aok || !bok || e.From == e.To || a.policy == nil || b.policy == nil || a.field.Policy != b.field.Policy {
			return nil, fmt.Errorf("%w: edge %q -> %q: endpoints must be distinct masked bindings of one domain policy and version", ErrInvalidManifest, e.From, e.To)
		}
		if shapes[a.field.Policy].Scope != "join_domain" {
			return nil, fmt.Errorf("%w: edge %q -> %q: join requires join_domain tweak scope", ErrInvalidManifest, e.From, e.To)
		}
	}
	seenGolden := make(map[string]bool)
	for _, g := range d.Goldens {
		b, ok := s.bindings[g.Binding]
		if !ok || b.policy == nil {
			return nil, fmt.Errorf("%w: golden binding %q: undefined or clear", ErrInvalidManifest, g.Binding)
		}
		if seenGolden[g.Binding] {
			return nil, fmt.Errorf("%w: golden binding %q: duplicate", ErrInvalidManifest, g.Binding)
		}
		seenGolden[g.Binding] = true
		ctx := mask.Context{}
		if g.Context != nil {
			ctx = mask.Context{TenantID: g.Context.TenantID, RecordID: g.Context.RecordID}
		}
		out, err := b.policy.Mask(g.Input, ctx)
		if err != nil || out != g.Output || policies[b.field.Policy].Fingerprint() != g.Fingerprint {
			return nil, fmt.Errorf("%w: golden binding %q: output or fingerprint mismatch: %v", ErrInvalidManifest, g.Binding, err)
		}
	}
	if len(d.Goldens) == 0 {
		return nil, fmt.Errorf("%w: at least one golden fixture required", ErrInvalidManifest)
	}
	for domain := range policies {
		covered := false
		for id := range seenGolden {
			if s.bindings[id].field.Policy == domain {
				covered = true
				break
			}
		}
		if !covered {
			return nil, fmt.Errorf("%w: policy %q: golden fixture required", ErrInvalidManifest, domain)
		}
	}
	return s, nil
}

func validLocation(f Field) bool {
	if f.Database != "oracle" && f.Database != "sqlserver" && f.Database != "postgresql" {
		return false
	}
	for _, s := range []string{f.Schema, f.Table, f.Column} {
		if s == "" || len(s) > 128 || !utf8.ValidString(s) || strings.ContainsAny(s, ".\x00") {
			return false
		}
	}
	return true
}

func checkCodec(c Codec, p Policy) (int, error) {
	if c.Width <= 0 {
		return 0, fmt.Errorf("codec %q: positive width required", c.Kind)
	}
	maxBytes, runes, numeric := outputShape(p)
	switch c.Kind {
	case "text", "blank_padded_text":
		if c.Width < maxBytes {
			return 0, fmt.Errorf("codec %q width %d cannot hold every output (%d bytes)", c.Kind, c.Width, maxBytes)
		}
		if c.Kind == "blank_padded_text" && trailingSpacePossible(p) {
			return 0, fmt.Errorf("codec %q: output may end in a space", c.Kind)
		}
	case "zero_padded_numeric":
		if !numeric || c.Width < runes || runes > 18 {
			return 0, fmt.Errorf("codec %q cannot represent every output as int64 with %d digits", c.Kind, runes)
		}
	default:
		return 0, fmt.Errorf("unknown codec %q", c.Kind)
	}
	return runes, nil
}

func outputShape(p Policy) (maxBytes, runes int, numeric bool) {
	numeric = true
	if len(p.Layout) == 0 {
		runes = p.Width
		for _, r := range p.Alphabet {
			if n := utf8.RuneLen(r); n > maxBytes {
				maxBytes = n
			}
			if r < '0' || r > '9' {
				numeric = false
			}
		}
		return maxBytes * runes, runes, numeric
	}
	for _, part := range p.Layout {
		switch part.Kind {
		case "literal":
			maxBytes += len(part.Literal)
			runes += utf8.RuneCountInString(part.Literal)
			for _, r := range part.Literal {
				if r < '0' || r > '9' {
					numeric = false
				}
			}
		case "luhn":
			maxBytes++
			runes++
		default:
			maxRune := 0
			for _, r := range part.Alphabet {
				if n := utf8.RuneLen(r); n > maxRune {
					maxRune = n
				}
				if r < '0' || r > '9' {
					numeric = false
				}
			}
			maxBytes += part.Width * maxRune
			runes += part.Width
		}
	}
	return
}

func trailingSpacePossible(p Policy) bool {
	if len(p.Layout) == 0 {
		return strings.ContainsRune(p.Alphabet, ' ')
	}
	last := p.Layout[len(p.Layout)-1]
	if last.Kind == "literal" {
		return strings.HasSuffix(last.Literal, " ")
	}
	return strings.ContainsRune(last.Alphabet, ' ')
}

// NullReport names a NULL that passed through without invoking a mask policy.
type NullReport struct{ Binding string }

// MaskRow accepts a complete row keyed by full binding ID. All bindings must
// belong to one table and every declared column of that table must be present.
// Values are strings for text codecs, int64 for numeric, or nil for SQL NULL.
func (s *Set) MaskRow(row map[string]any, ctx mask.Context, detector *Detector) (map[string]any, []NullReport, error) {
	if s == nil || len(row) == 0 {
		return nil, nil, fmt.Errorf("%w: empty row", ErrInvalidRow)
	}
	var table string
	for id := range row {
		b, ok := s.bindings[id]
		if !ok {
			return nil, nil, fmt.Errorf("%w: unknown binding %q", ErrInvalidRow, id)
		}
		t := b.field.Database + "." + b.field.Schema + "." + b.field.Table
		if table != "" && table != t {
			return nil, nil, fmt.Errorf("%w: binding %q belongs to another table", ErrInvalidRow, id)
		}
		table = t
	}
	for _, id := range s.tables[table] {
		if _, ok := row[id]; !ok {
			return nil, nil, fmt.Errorf("%w: missing binding %q", ErrInvalidRow, id)
		}
	}
	out := make(map[string]any, len(row))
	var nulls []NullReport
	for _, id := range s.tables[table] {
		v := row[id]
		b := s.bindings[id]
		if v == nil {
			out[id] = nil
			nulls = append(nulls, NullReport{Binding: id})
			continue
		}
		if b.policy == nil {
			out[id] = v
			continue
		}
		canonical, err := decode(b, v)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: binding %q: %w", ErrInvalidRow, id, err)
		}
		masked, err := b.policy.Mask(canonical, ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: binding %q: %w", ErrInvalidRow, id, err)
		}
		stored, err := encode(b, masked)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: binding %q: %w", ErrInvalidRow, id, err)
		}
		out[id] = stored
	}
	if detector != nil {
		if err := detector.check(s, out); err != nil {
			return nil, nil, err
		}
	}
	return out, nulls, nil
}

func decode(b bound, v any) (string, error) {
	c := b.field.Codec
	if c.Kind == "zero_padded_numeric" {
		n, ok := v.(int64)
		if !ok || n < 0 {
			return "", fmt.Errorf("codec %q expects nonnegative int64", c.Kind)
		}
		s := strconv.FormatInt(n, 10)
		if len(s) > c.Width || len(s) > b.width {
			return "", fmt.Errorf("codec %q value exceeds width", c.Kind)
		}
		return strings.Repeat("0", b.width-len(s)) + s, nil
	}
	s, ok := v.(string)
	if !ok || !utf8.ValidString(s) {
		return "", fmt.Errorf("codec %q expects UTF-8 string", c.Kind)
	}
	if len(s) > c.Width {
		return "", fmt.Errorf("codec %q value exceeds width", c.Kind)
	}
	if c.Kind == "blank_padded_text" {
		if len(s) != c.Width {
			return "", fmt.Errorf("codec %q expects exactly %d bytes", c.Kind, c.Width)
		}
		s = strings.TrimRight(s, " ")
	}
	return s, nil
}

func encode(b bound, s string) (any, error) {
	c := b.field.Codec
	if c.Kind == "zero_padded_numeric" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("codec %q output not representable as int64", c.Kind)
		}
		return n, nil
	}
	if len(s) > c.Width {
		return nil, fmt.Errorf("codec %q output exceeds width", c.Kind)
	}
	if c.Kind == "blank_padded_text" {
		s += strings.Repeat(" ", c.Width-len(s))
	}
	return s, nil
}

// Detector rejects repeated masked values in bindings declared unique.
// Create one per target dataset. It is safe for concurrent streams.
type Detector struct {
	mu   sync.Mutex
	seen map[string]map[string]struct{}
}

func (d *Detector) check(s *Set, row map[string]any) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen == nil {
		d.seen = make(map[string]map[string]struct{})
	}
	ids := make([]string, 0, len(row))
	for id := range row {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		v := row[id]
		if !s.bindings[id].field.Unique || v == nil {
			continue
		}
		key := fmt.Sprint(v)
		if _, ok := d.seen[id][key]; ok {
			return fmt.Errorf("%w: binding %q", ErrDuplicateOutput, id)
		}
	}
	for _, id := range ids {
		v := row[id]
		if !s.bindings[id].field.Unique || v == nil {
			continue
		}
		if d.seen[id] == nil {
			d.seen[id] = make(map[string]struct{})
		}
		d.seen[id][fmt.Sprint(v)] = struct{}{}
	}
	return nil
}

// LoadBytes is a convenience for embedded manifests.
func LoadBytes(data []byte, keys map[mask.KeyRef][]byte) (*Set, error) {
	return Load(bytes.NewReader(data), keys)
}
