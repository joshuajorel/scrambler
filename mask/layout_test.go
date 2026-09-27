package mask

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/joshuajorel/scrambler/ff1"
)

const digits = "0123456789"
const lower = "abcdefghijklmnopqrstuvwxyz"

func structuredSpecs() map[string]struct {
	spec  Spec
	input string
} {
	return map[string]struct {
		spec  Spec
		input string
	}{
		"customer": {Spec{DomainID: "customer-number", Version: "v1", Layout: []Part{
			{Kind: LiteralPart, Literal: "C"},
			{Kind: EncryptedPart, Width: 6, Alphabet: digits},
		}}, "C000123"},
		"card": {Spec{DomainID: "card-number", Version: "v1", Layout: []Part{
			{Kind: RetainedPart, Width: 6, Alphabet: digits},
			{Kind: EncryptedPart, Width: 9, Alphabet: digits},
			{Kind: LuhnDigit},
		}}, "4111111111111111"},
		"phone": {Spec{DomainID: "us-phone", Version: "v1", Layout: []Part{
			{Kind: LiteralPart, Literal: "+1-"},
			{Kind: EncryptedPart, Width: 3, Alphabet: digits},
			{Kind: LiteralPart, Literal: "-"},
			{Kind: EncryptedPart, Width: 3, Alphabet: digits},
			{Kind: LiteralPart, Literal: "-"},
			{Kind: EncryptedPart, Width: 4, Alphabet: digits},
		}}, "+1-202-555-0001"},
		"email": {Spec{DomainID: "email-local-len-15", Version: "v1", Layout: []Part{
			{Kind: EncryptedPart, Width: 3, Alphabet: lower},
			{Kind: LiteralPart, Literal: "."},
			{Kind: EncryptedPart, Width: 6, Alphabet: lower},
			{Kind: LiteralPart, Literal: "."},
			{Kind: EncryptedPart, Width: 6, Alphabet: digits},
			{Kind: LiteralPart, Literal: "@example.test"},
		}}, "ava.nguyen.000001@example.test"},
	}
}

func TestStructuredFormatsAndRoundTrips(t *testing.T) {
	for name, tc := range structuredSpecs() {
		t.Run(name, func(t *testing.T) {
			p, err := Compile(tc.spec, testRef, testKey)
			if err != nil {
				t.Fatal(err)
			}
			out, err := p.Mask(tc.input, Context{})
			if err != nil {
				t.Fatal(err)
			}
			if len([]rune(out)) != len([]rune(tc.input)) {
				t.Fatalf("width changed: %q", out)
			}
			before, after := []rune(tc.input), []rune(out)
			at := 0
			for _, part := range p.layout.parts {
				if part.kind == LiteralPart || part.kind == RetainedPart {
					if string(before[at:at+part.width]) != string(after[at:at+part.width]) {
						t.Fatalf("clear piece changed: %q -> %q", tc.input, out)
					}
				}
				at += part.width
			}
			if name == "card" && after[15] != luhnCheck(after[:15]) {
				t.Fatalf("masked card has invalid Luhn digit: %q", out)
			}
			base, _ := p.tweak(Context{})
			originalRank, tweak, err := p.layout.parse([]rune(tc.input), base)
			if err != nil {
				t.Fatal(err)
			}
			base, _ = p.tweak(Context{})
			maskedRank, maskedTweak, err := p.layout.parse([]rune(out), base)
			if err != nil || string(maskedTweak) != string(tweak) {
				t.Fatalf("masked value changed clear tweak context: %v", err)
			}
			recovered, err := p.layout.permute(maskedRank, p.cipher, tweak, true)
			if err != nil || recovered.Cmp(originalRank) != 0 {
				t.Fatalf("internal permutation round trip: %v", err)
			}
		})
	}
}

func TestStructuredClearTextBindsTweak(t *testing.T) {
	card, err := Compile(structuredSpecs()["card"].spec, testRef, testKey)
	if err != nil {
		t.Fatal(err)
	}
	var middles []string
	for _, bin := range []string{"411111", "550000"} {
		payload := []rune(bin + "123456789")
		input := string(append(payload, luhnCheck(payload)))
		out, err := card.Mask(input, Context{})
		if err != nil {
			t.Fatal(err)
		}
		if out[:6] != bin {
			t.Fatalf("retained prefix changed: %q -> %q", input, out)
		}
		middles = append(middles, out[6:15])
	}
	if middles[0] == middles[1] {
		t.Fatalf("different retained prefixes share masked middle digits %q", middles[0])
	}

	var letters []string
	for _, shape := range []struct {
		first, second int
		input         string
	}{
		{3, 6, "ava.nguyen.000001@example.test"},
		{4, 5, "avan.guyen.000001@example.test"},
	} {
		p, err := Compile(Spec{DomainID: "email-local-len-15", Version: "v1", Layout: []Part{
			{Kind: EncryptedPart, Width: shape.first, Alphabet: lower},
			{Kind: LiteralPart, Literal: "."},
			{Kind: EncryptedPart, Width: shape.second, Alphabet: lower},
			{Kind: LiteralPart, Literal: "."},
			{Kind: EncryptedPart, Width: 6, Alphabet: digits},
			{Kind: LiteralPart, Literal: "@example.test"},
		}}, testRef, testKey)
		if err != nil {
			t.Fatal(err)
		}
		out, err := p.Mask(shape.input, Context{})
		if err != nil {
			t.Fatal(err)
		}
		letters = append(letters, strings.ReplaceAll(out[:17], ".", ""))
	}
	if letters[0] == letters[1] {
		t.Fatalf("different separator positions share masked local part %q", letters[0])
	}
}

func TestStructuredBindingsAndNoCollisions(t *testing.T) {
	tc := structuredSpecs()["customer"]
	p, err := Compile(tc.spec, testRef, testKey)
	if err != nil {
		t.Fatal(err)
	}
	q, err := Compile(tc.spec, testRef, testKey)
	if err != nil {
		t.Fatal(err)
	}
	var registry Registry
	a, _ := registry.Bind("customers.number", p)
	b, _ := registry.Bind("orders.customer_number", q)
	seen := make(map[string]string)
	for i := 0; i < 1000; i++ {
		input := fmt.Sprintf("C%06d", i)
		first, err := a.Mask(input, Context{})
		if err != nil {
			t.Fatal(err)
		}
		second, err := b.Mask(input, Context{})
		if err != nil || first != second {
			t.Fatalf("binding mismatch: %q %q %v", first, second, err)
		}
		if prior, exists := seen[first]; exists {
			t.Fatalf("collision: %q and %q", prior, input)
		}
		seen[first] = input
	}
}

func TestStructuredPowerOfTwoDomain(t *testing.T) {
	s := Spec{DomainID: "binary-id", Version: "v1", Layout: []Part{
		{Kind: LiteralPart, Literal: "B"},
		{Kind: EncryptedPart, Width: 20, Alphabet: "01"},
	}}
	p, err := Compile(s, testRef, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if p.layout.bits != 20 {
		t.Fatalf("power-of-two domain uses %d bits", p.layout.bits)
	}
	input := "B" + strings.Repeat("0", 20)
	output, err := p.Mask(input, Context{})
	if err != nil || len(output) != len(input) || output[0] != 'B' {
		t.Fatalf("binary layout: %q %v", output, err)
	}
	base, _ := p.tweak(Context{})
	rank, tweak, err := p.layout.parse([]rune(output), base)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := p.layout.permute(rank, p.cipher, tweak, true)
	if err != nil || recovered.Sign() != 0 {
		t.Fatalf("binary round trip: %v", err)
	}
}

func TestStructuredRejections(t *testing.T) {
	if _, err := Compile(Spec{DomainID: "empty-layout", Version: "v1", Layout: []Part{}}, testRef, testKey); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("empty layout accepted: %v", err)
	}
	for _, tc := range []struct {
		name  string
		parts []Part
		want  error
	}{
		{"small combined domain", []Part{{Kind: EncryptedPart, Width: 2, Alphabet: digits}, {Kind: LiteralPart, Literal: "-"}, {Kind: EncryptedPart, Width: 3, Alphabet: digits}}, ff1.ErrDomainTooSmall},
		{"check digit excluded", []Part{{Kind: EncryptedPart, Width: 5, Alphabet: digits}, {Kind: LuhnDigit}}, ff1.ErrDomainTooSmall},
		{"no encrypted part", []Part{{Kind: LiteralPart, Literal: "123456"}}, ff1.ErrDomainTooSmall},
		{"empty literal", []Part{{Kind: LiteralPart}, {Kind: EncryptedPart, Width: 6, Alphabet: digits}}, ErrInvalidSpec},
		{"bad alphabet", []Part{{Kind: EncryptedPart, Width: 6, Alphabet: "0000000000"}}, ErrInvalidSpec},
		{"zero segment width", []Part{{Kind: EncryptedPart, Alphabet: digits}}, ErrInvalidSpec},
		{"literal with width", []Part{{Kind: LiteralPart, Literal: "C", Width: 1}, {Kind: EncryptedPart, Width: 6, Alphabet: digits}}, ErrInvalidSpec},
		{"check not last", []Part{{Kind: EncryptedPart, Width: 6, Alphabet: digits}, {Kind: LuhnDigit}, {Kind: LiteralPart, Literal: "X"}}, ErrInvalidSpec},
		{"Luhn non-digits", []Part{{Kind: LiteralPart, Literal: "C"}, {Kind: EncryptedPart, Width: 6, Alphabet: digits}, {Kind: LuhnDigit}}, ErrInvalidSpec},
		{"unknown kind", []Part{{Kind: PartKind(99)}, {Kind: EncryptedPart, Width: 6, Alphabet: digits}}, ErrInvalidSpec},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile(Spec{DomainID: "invalid", Version: "v1", Layout: tc.parts}, testRef, testKey)
			if !errors.Is(err, ErrInvalidSpec) || !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	cases := structuredSpecs()
	for _, tc := range []struct{ name, input string }{
		{"customer", "D000123"},
		{"customer", "C00012"},
		{"customer", "C00012x"},
		{"card", "4111111111111112"},
		{"card", "41111X1111111111"},
		{"phone", "+1-202-555/0001"},
		{"email", "ava_nguyen.000001@example.test"},
		{"email", "ava.nguyen.000001@example.com"},
		{"email", "ava.nguyen.000001@example.testX"},
		{"customer", "C00012\xff"},
	} {
		t.Run(tc.name+"/"+tc.input, func(t *testing.T) {
			p, err := Compile(cases[tc.name].spec, testRef, testKey)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := p.Mask(tc.input, Context{}); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("got %v", err)
			}
		})
	}
	base := cases["customer"].spec
	base.Width = 6
	if _, err := Compile(base, testRef, testKey); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("layout plus plain width accepted: %v", err)
	}
	shortEmail := Spec{DomainID: "email-local-len-1", Version: "v1", Layout: []Part{
		{Kind: EncryptedPart, Width: 1, Alphabet: lower}, {Kind: LiteralPart, Literal: "@example.test"},
	}}
	if _, err := Compile(shortEmail, testRef, testKey); !errors.Is(err, ErrInvalidSpec) || !errors.Is(err, ff1.ErrDomainTooSmall) {
		t.Fatalf("short email domain accepted: %v", err)
	}
}

func TestLayoutFingerprintAndRegistry(t *testing.T) {
	tc := structuredSpecs()["customer"]
	p, _ := Compile(tc.spec, testRef, testKey)
	var registry Registry
	if _, err := registry.Bind("customers.number", p); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Spec){
		func(s *Spec) { s.Layout[0].Literal = "D" },
		func(s *Spec) { s.Layout[1].Width = 7 },
		func(s *Spec) { s.Layout[1].Alphabet = "9876543210" },
		func(s *Spec) { s.Layout = append(s.Layout, Part{Kind: LiteralPart, Literal: "!"}) },
	} {
		s := tc.spec
		s.Layout = append([]Part(nil), s.Layout...)
		change(&s)
		q, err := Compile(s, testRef, testKey)
		if err != nil {
			t.Fatal(err)
		}
		if q.Fingerprint() == p.Fingerprint() {
			t.Fatal("changed layout kept fingerprint")
		}
		if _, err := registry.Bind("other.location", q); !errors.Is(err, ErrDivergentPolicy) {
			t.Fatalf("divergent layout bound: %v", err)
		}
	}
}

func TestStructuredGoldenAcrossProcesses(t *testing.T) {
	data, err := os.ReadFile("testdata/structured_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string]goldenFixture
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	for name, tc := range structuredSpecs() {
		g := golden[name]
		if g.Input != tc.input {
			t.Fatalf("%s fixture input changed", name)
		}
		p, err := Compile(tc.spec, testRef, testKey)
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.Mask(g.Input, Context{})
		if err != nil || got != g.Output || p.Fingerprint() != g.Fingerprint {
			t.Fatalf("%s golden mismatch: output %q (%v), fingerprint %q", name, got, err, p.Fingerprint())
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStructuredGoldenChild$")
	cmd.Env = append(os.Environ(), "SCRAMBLER_STRUCTURED_GOLDEN_CHILD=1")
	child, err := cmd.Output()
	if err != nil {
		t.Fatalf("independent process: %v", err)
	}
	var outputs map[string]string
	if err := json.Unmarshal(child, &outputs); err != nil {
		t.Fatal(err)
	}
	for name, g := range golden {
		if outputs[name] != g.Output {
			t.Fatalf("%s independent process mismatch", name)
		}
	}
}

func TestStructuredGoldenChild(t *testing.T) {
	if os.Getenv("SCRAMBLER_STRUCTURED_GOLDEN_CHILD") != "1" {
		return
	}
	outputs := make(map[string]string)
	for name, tc := range structuredSpecs() {
		p, err := Compile(tc.spec, testRef, testKey)
		if err != nil {
			t.Fatal(err)
		}
		outputs[name], err = p.Mask(tc.input, Context{})
		if err != nil {
			t.Fatal(err)
		}
	}
	b, _ := json.Marshal(outputs)
	fmt.Println(string(b))
	os.Exit(0)
}

func TestStructuredCanonicalizationAndEmpty(t *testing.T) {
	tc := structuredSpecs()["customer"]
	s := tc.spec
	s.Canonicalizer = Canonicalizer{ID: "customer-uppercase/v1", Apply: func(raw string) (string, error) {
		return strings.ToUpper(raw), nil
	}}
	p, err := Compile(s, testRef, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Mask("c000123", Context{}); !errors.Is(err, ErrCanonicalCollision) {
		t.Fatalf("canonical alias accepted: %v", err)
	}
	s.Empty = PreserveEmpty
	q, err := Compile(s, testRef, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := q.Mask("", Context{}); got != "" || err != nil {
		t.Fatalf("empty rule: %q %v", got, err)
	}
}
