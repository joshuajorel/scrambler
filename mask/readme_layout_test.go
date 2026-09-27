// This function mirrors the corresponding compilable README snippet.
package mask_test

import (
	"testing"

	"github.com/joshuajorel/scrambler/mask"
)

func maskCustomerNumber(key []byte, raw string) (string, error) {
	policy, err := mask.Compile(mask.Spec{
		DomainID: "customer-number", Version: "v1", Scope: mask.JoinDomain,
		Layout: []mask.Part{
			{Kind: mask.LiteralPart, Literal: "C"},
			{Kind: mask.EncryptedPart, Width: 6, Alphabet: "0123456789"},
		},
	}, mask.KeyRef{ID: "customer-key", Version: "2026-09"}, key)
	if err != nil {
		return "", err
	}
	return policy.Mask(raw, mask.Context{}) // e.g. raw == "C000123"
}

func TestREADMELayout(t *testing.T) {
	got, err := maskCustomerNumber([]byte("0123456789abcdef"), "C000123")
	if err != nil || len(got) != 7 || got[0] != 'C' {
		t.Fatalf("masked customer number: %q, %v", got, err)
	}
}
