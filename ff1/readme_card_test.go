// This function mirrors the corresponding compilable README snippet.
package ff1_test

import (
	"encoding/hex"
	"testing"

	"github.com/joshuajorel/scrambler/ff1"
)

func maskCardMiddle(key []byte) (string, error) {
	c, err := ff1.New(key, ff1.Digits)
	if err != nil {
		return "", err
	}
	card := "4111119876541111"
	// Encrypt the middle six digits; retain the first six and last four.
	tweak := []byte("card-middle-v1|" + card[:6] + "|" + card[12:])
	middle, err := c.Encrypt(card[6:12], tweak)
	if err != nil {
		return "", err
	}
	return card[:6] + middle + card[12:], nil
}

func TestREADMECardMiddle(t *testing.T) {
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	if err != nil {
		t.Fatal(err)
	}
	got, err := maskCardMiddle(key)
	if err != nil || got != "4111111204311111" {
		t.Fatalf("masked card: %q, %v", got, err)
	}
}
