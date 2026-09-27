package mask

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/joshuajorel/scrambler/ff1"
)

var testKey = []byte("0123456789abcdef")
var testRef = KeyRef{ID: "local-test-key", Version: "1"}

func accountSpec() Spec {
	return Spec{DomainID: "account-number", Version: "v1", Alphabet: "0123456789", Width: 12, Scope: JoinDomain}
}

func compileAccount(t *testing.T) *Policy {
	t.Helper()
	p, err := Compile(accountSpec(), testRef, testKey)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestJoinBindingsAndIndependentCompilation(t *testing.T) {
	p := compileAccount(t)
	other := compileAccount(t)
	if p.Fingerprint() != other.Fingerprint() {
		t.Fatal("independent compiles have different fingerprints")
	}
	var registry Registry
	var output string
	for _, location := range []string{"accounts.id", "orders.account_id", "payments.account_id"} {
		b, err := registry.Bind(location, p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := b.Mask("000123456789", Context{})
		if err != nil {
			t.Fatal(err)
		}
		if output != "" && got != output {
			t.Fatalf("join broken at %s: %s != %s", location, got, output)
		}
		output = got
	}
	got, err := other.Mask("000123456789", Context{})
	if err != nil || got != output {
		t.Fatalf("independent compile: %q, %v; want %q", got, err, output)
	}
	if _, err := registry.Bind("accounts.id", other); err != nil {
		t.Fatalf("equivalent rebind: %v", err)
	}
}

type goldenFixture struct {
	Input       string `json:"input"`
	Output      string `json:"output"`
	Fingerprint string `json:"fingerprint"`
}

func loadGolden(t *testing.T) goldenFixture {
	t.Helper()
	b, err := os.ReadFile("testdata/account_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var g goldenFixture
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGoldenAcrossProcesses(t *testing.T) {
	g := loadGolden(t)
	p := compileAccount(t)
	got, err := p.Mask(g.Input, Context{})
	if err != nil || got != g.Output || p.Fingerprint() != g.Fingerprint {
		t.Fatalf("golden mismatch: output %q (%v), fingerprint %q", got, err, p.Fingerprint())
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestGoldenChild$")
	cmd.Env = append(os.Environ(), "SCRAMBLER_MASK_GOLDEN_CHILD=1")
	child, err := cmd.Output()
	if err != nil {
		t.Fatalf("independent process: %v", err)
	}
	if string(child) != g.Output+"\n" {
		t.Fatalf("independent process output %q, want %q", child, g.Output)
	}
}

func TestGoldenChild(t *testing.T) {
	if os.Getenv("SCRAMBLER_MASK_GOLDEN_CHILD") != "1" {
		return
	}
	g := loadGolden(t)
	p := compileAccount(t)
	got, err := p.Mask(g.Input, Context{})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(got)
	os.Exit(0)
}

func TestSameLengthValuesDoNotCollide(t *testing.T) {
	p := compileAccount(t)
	seen := make(map[string]string)
	for i := 0; i < 1000; i++ {
		input := fmt.Sprintf("%012d", i)
		output, err := p.Mask(input, Context{})
		if err != nil {
			t.Fatal(err)
		}
		if first, ok := seen[output]; ok {
			t.Fatalf("%s and %s collided as %s", first, input, output)
		}
		seen[output] = input
	}
}

func TestRejections(t *testing.T) {
	t.Run("small domain", func(t *testing.T) {
		s := accountSpec()
		s.Width = 5
		_, err := Compile(s, testRef, testKey)
		if !errors.Is(err, ff1.ErrDomainTooSmall) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("invalid and overlong", func(t *testing.T) {
		p := compileAccount(t)
		for _, tc := range []struct {
			input string
			want  error
		}{
			{"", ErrEmptyInput},
			{"00012345678X", ff1.ErrInvalidSymbol},
			{"00012345678", ErrInvalidInput},
			{strings.Repeat("1", 49), ErrInvalidInput},
			{"00012345678\xff", ErrInvalidInput},
		} {
			if _, err := p.Mask(tc.input, Context{}); !errors.Is(err, tc.want) {
				t.Errorf("input length %d: got %v, want %v", len(tc.input), err, tc.want)
			}
		}
	})
	t.Run("divergent configuration", func(t *testing.T) {
		p := compileAccount(t)
		var registry Registry
		if _, err := registry.Bind("accounts.id", p); err != nil {
			t.Fatal(err)
		}
		variants := []struct {
			spec Spec
			ref  KeyRef
		}{
			{func() Spec { s := accountSpec(); s.Alphabet = "9876543210"; return s }(), testRef},
			{func() Spec { s := accountSpec(); s.Scope = TenantDomain; return s }(), testRef},
			{accountSpec(), KeyRef{ID: "other-key", Version: "1"}},
		}
		for i, variant := range variants {
			q, err := Compile(variant.spec, variant.ref, testKey)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := registry.Bind(fmt.Sprintf("foreign-key-%d", i), q); !errors.Is(err, ErrDivergentPolicy) {
				t.Errorf("variant %d: got %v", i, err)
			}
		}
	})
}

func TestCanonicalizationCollisionRule(t *testing.T) {
	s := accountSpec()
	s.Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	s.Canonicalizer = Canonicalizer{ID: "ascii-uppercase/v1", Apply: func(raw string) (string, error) {
		return strings.ToUpper(raw), nil
	}}
	s.Aliases = RejectAliases
	p, err := Compile(s, testRef, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Mask("abc123456789", Context{}); !errors.Is(err, ErrCanonicalCollision) {
		t.Fatalf("alias accepted: %v", err)
	}
	if _, err := p.Mask("ABC123456789", Context{}); err != nil {
		t.Fatalf("canonical input rejected: %v", err)
	}
	s.Aliases = AllowAliases
	allow, err := Compile(s, testRef, testKey)
	if err != nil {
		t.Fatal(err)
	}
	a, err := allow.Mask("abc123456789", Context{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := allow.Mask("ABC123456789", Context{})
	if err != nil || a != b {
		t.Fatalf("allowed aliases should agree: %q, %q, %v", a, b, err)
	}
}

func TestTweakScopes(t *testing.T) {
	s := accountSpec()
	join, _ := Compile(s, testRef, testKey)
	if _, err := join.Mask("000123456789", Context{TenantID: "tenant-a"}); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("join accepted context: %v", err)
	}
	s.Scope = TenantDomain
	tenant, err := Compile(s, testRef, testKey)
	if err != nil {
		t.Fatal(err)
	}
	a, err := tenant.Mask("000123456789", Context{TenantID: "tenant-a"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := tenant.Mask("000123456789", Context{TenantID: "tenant-b"})
	if err != nil || a == b {
		t.Fatalf("tenant separation: %q, %q, %v", a, b, err)
	}
	s.Scope = Record
	record, err := Compile(s, testRef, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record.Mask("000123456789", Context{}); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("record without ID accepted: %v", err)
	}
	t1, _ := record.tweak(Context{TenantID: "a", RecordID: "bc"})
	t2, _ := record.tweak(Context{TenantID: "ab", RecordID: "c"})
	if string(t1) == string(t2) {
		t.Fatal("length-prefixed context collided")
	}
}

func TestUnicodeFixedWidthAndExplicitEmpty(t *testing.T) {
	s := Spec{
		DomainID: "greek-id", Version: "v1", Alphabet: "αβγδεζηθικ",
		Width: 8, Scope: JoinDomain, Empty: PreserveEmpty,
	}
	p, err := Compile(s, testRef, testKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Mask("αβγδεζηθ", Context{})
	if err != nil || utf8.RuneCountInString(got) != 8 {
		t.Fatalf("Unicode width: %q, %v", got, err)
	}
	if got, err := p.Mask("", Context{}); err != nil || got != "" {
		t.Fatalf("explicit missing value: %q, %v", got, err)
	}
	s.Invalid = 1
	if _, err := Compile(s, testRef, testKey); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("unsupported invalid-input handling: %v", err)
	}
}
