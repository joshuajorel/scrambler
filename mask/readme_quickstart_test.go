// This function mirrors the corresponding compilable README snippet.
package mask_test

import (
	"testing"

	"github.com/joshuajorel/scrambler/mask"
)

func maskAccountIDs(key []byte) (string, string, error) {
	policy, err := mask.Compile(mask.Spec{
		DomainID: "account-number", Version: "v1",
		Alphabet: "0123456789", Width: 12, Scope: mask.JoinDomain,
	}, mask.KeyRef{ID: "accounts-key", Version: "2026-09"}, key)
	if err != nil {
		return "", "", err
	}

	var registry mask.Registry
	parent, err := registry.Bind("accounts.id", policy)
	if err != nil {
		return "", "", err
	}
	foreignKey, err := registry.Bind("orders.account_id", policy)
	if err != nil {
		return "", "", err
	}

	a, err := parent.Mask("000123456789", mask.Context{})
	if err != nil {
		return "", "", err
	}
	b, err := foreignKey.Mask("000123456789", mask.Context{})
	return a, b, err // a == b when err is nil
}

func TestREADMEQuickStart(t *testing.T) {
	a, b, err := maskAccountIDs([]byte("0123456789abcdef"))
	if err != nil || a != b || len(a) != 12 {
		t.Fatalf("masked account IDs: %q, %q, %v", a, b, err)
	}
}
