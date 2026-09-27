package ff1_test

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"github.com/joshuajorel/scrambler/ff1"
)

// The key would come from a key management system; this is NIST's sample
// AES-128 key.
var exampleKey, _ = hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")

// Encrypt the middle six digits of a card number, using the digits that
// stay in the clear (plus a purpose label) as the tweak, as in
// SP 800-38G Rev. 1 Appendix C.
func Example() {
	c, err := ff1.New(exampleKey, ff1.Digits)
	if err != nil {
		log.Fatal(err)
	}
	card := "4111119876541111"
	head, middle, tail := card[:6], card[6:12], card[12:]
	tweak := []byte("card-middle-v1|" + head + "|" + tail)

	enc, err := c.Encrypt(middle, tweak)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(head + enc + tail)

	dec, err := c.Decrypt(enc, tweak)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(head + dec + tail)
	// Output:
	// 4111111204311111
	// 4111119876541111
}

func ExampleNew() {
	c, err := ff1.New(exampleKey, ff1.Digits)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(c.Radix(), c.MinLength())

	// Inputs shorter than the 10^6 domain minimum cannot be configured...
	_, err = ff1.New(exampleKey, ff1.Digits, ff1.WithMinLength(5))
	fmt.Println(errors.Is(err, ff1.ErrDomainTooSmall))
	// ...or encrypted.
	_, err = c.Encrypt("12345", nil)
	fmt.Println(errors.Is(err, ff1.ErrDomainTooSmall))
	// Output:
	// 10 6
	// true
	// true
}

// The first NIST FF1 sample.
func ExampleCipher_Encrypt() {
	c, err := ff1.New(exampleKey, ff1.Digits)
	if err != nil {
		log.Fatal(err)
	}
	ct, err := c.Encrypt("0123456789", nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ct)
	// Output: 2433477484
}

func ExampleCipher_EncryptNumerals() {
	// A radix-65536 cipher: each numeral is a 16-bit value.
	alpha, err := ff1.RadixOnly(65536)
	if err != nil {
		log.Fatal(err)
	}
	c, err := ff1.New(make([]byte, 16), alpha)
	if err != nil {
		log.Fatal(err)
	}
	ct, err := c.EncryptNumerals([]uint16{0, 1}, make([]byte, 8))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ct)
	// Output: [18476 48157]
}

// A Unicode alphabet: the radix is the number of runes, and lengths are
// counted in runes.
func ExampleNewAlphabet() {
	greek, err := ff1.NewAlphabet("αβγδεζηθικλμνξοπρστυφχψω")
	if err != nil {
		log.Fatal(err)
	}
	c, err := ff1.New(exampleKey, greek, ff1.WithMaxTweakLength(16))
	if err != nil {
		log.Fatal(err)
	}
	ct, err := c.Encrypt("καλησπερα", []byte("greeting"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(greek.Radix(), c.MinLength(), ct)
	pt, _ := c.Decrypt(ct, []byte("greeting"))
	fmt.Println(pt)
	// Output:
	// 24 5 ερλβσκωοη
	// καλησπερα
}
