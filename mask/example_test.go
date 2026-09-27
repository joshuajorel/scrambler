package mask_test

import (
	"fmt"

	"github.com/joshuajorel/scrambler/mask"
)

func Example() {
	// Supply the key from your key manager. This fixed key is for the example.
	key := []byte("0123456789abcdef")
	policy, err := mask.Compile(mask.Spec{
		DomainID: "account-number", Version: "v1",
		Alphabet: "0123456789", Width: 12, Scope: mask.JoinDomain,
	}, mask.KeyRef{ID: "local-test-key", Version: "1"}, key)
	if err != nil {
		panic(err)
	}
	var bindings mask.Registry
	parent, err := bindings.Bind("accounts.id", policy)
	if err != nil {
		panic(err)
	}
	foreignKey, err := bindings.Bind("orders.account_id", policy)
	if err != nil {
		panic(err)
	}
	a, err := parent.Mask("000123456789", mask.Context{})
	if err != nil {
		panic(err)
	}
	b, err := foreignKey.Mask("000123456789", mask.Context{})
	if err != nil {
		panic(err)
	}
	fmt.Println(a == b)
	// Output: true
}
