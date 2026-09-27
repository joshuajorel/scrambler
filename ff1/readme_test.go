package ff1_test

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestREADMECounts keeps every count the documentation quotes equal to the
// value the corresponding test asserts, so the docs cannot drift from the
// suites: the numbers below all come from the tests' own tables.
func TestREADMECounts(t *testing.T) {
	var w wycheproofTally
	for _, c := range wycheproofCounts {
		w.total += c.total
		w.valid += c.valid
		w.validDomainRejected += c.validDomainRejected
		w.invalidKey += c.invalidKey
		w.invalidSize += c.invalidSize
		w.invalidInput += c.invalidInput
		w.invalidUnrepresentable += c.invalidUnrepresentable
	}
	invalid := w.invalidKey + w.invalidSize + w.invalidInput + w.invalidUnrepresentable
	if invalid+w.valid+w.validDomainRejected != w.total {
		t.Fatalf("Wycheproof tally does not add up: %+v", w)
	}
	r65535, r65536 := wycheproofCounts["aes_ff1_radix65535"], wycheproofCounts["aes_ff1_radix65536"]
	rust, bc := differentialOracles["fpe-rs"], differentialOracles["bouncycastle"]
	rejections := thirdPartyExpect["errorErrDomainTooSmall"] + thirdPartyExpect["errorErrInvalidNumeral"]

	checkQuotes(t, "../README.md", []string{
		fmt.Sprintf("| %d, both directions", len(nistSamples)),
		fmt.Sprintf("| %s (%d groups × %d)", commas(acvpCases), acvpGroups, acvpCases/acvpGroups),
		fmt.Sprintf("| %s in %d files, incl. radix 65535 (%s) and 65536 (%s)",
			commas(w.total), len(wycheproofCounts), commas(r65535.total), commas(r65536.total)),
		fmt.Sprintf("| %d: %d known answers, %d round-trip, %d rejections",
			thirdPartyVectors, thirdPartyExpect["match"], thirdPartyExpect["roundtrip"], rejections),
		fmt.Sprintf("| %d from the Rust `fpe` crate 0.6.1 (radix 2..65536), %d from Bouncy Castle 1.86 (radix ≤ 65535)",
			rust.vectors, bc.vectors),
		fmt.Sprintf("| %d fixed inputs", len(goldenStrings)+len(goldenNumerals)),
		fmt.Sprintf("%s valid cases match; %d cases that are valid under the 2016 rule",
			commas(w.valid), w.validDomainRejected),
		fmt.Sprintf("all %s invalid cases are rejected (%d bad key sizes, %d short messages, %s out-of-range digits or symbols, and %s digits",
			commas(invalid), w.invalidKey, w.invalidSize, commas(w.invalidInput), commas(w.invalidUnrepresentable)),
		fmt.Sprintf("also passes all %d valid Wycheproof radix-65536 cases", r65536.valid),
	})
	checkQuotes(t, "../tools/differential/README.md", []string{
		fmt.Sprintf("| 2..65536 | %d |", rust.vectors),
		fmt.Sprintf("| 2..65535 | %d |", bc.vectors),
	})
	checkQuotes(t, "testdata/wycheproof/README.md", []string{
		fmt.Sprintf("%s cases in total", commas(w.total)),
		fmt.Sprintf("(%d cases)", w.validDomainRejected),
		fmt.Sprintf("(%s cases)", commas(w.invalidUnrepresentable)),
		fmt.Sprintf("(%d files)", len(wycheproofCounts)),
	})

	// The per-file case counts in the Wycheproof README's table.
	data, err := os.ReadFile("testdata/wycheproof/README.md")
	if err != nil {
		t.Fatal(err)
	}
	rows := regexp.MustCompile(`(?m)^\| (aes_ff1_\w+)_test\.json \| [0-9a-f]{40} \| (\d+) \|\r?$`).FindAllStringSubmatch(string(data), -1)
	if len(rows) != len(wycheproofCounts) {
		t.Errorf("Wycheproof README lists %d files, want %d", len(rows), len(wycheproofCounts))
	}
	for _, r := range rows {
		if n, _ := strconv.Atoi(r[2]); n != wycheproofCounts[r[1]].total {
			t.Errorf("Wycheproof README: %s has %d cases, the test asserts %d", r[1], n, wycheproofCounts[r[1]].total)
		}
	}
}

// checkQuotes fails for each phrase that does not appear in the file, with
// runs of whitespace (including line breaks) treated as single spaces.
func checkQuotes(t *testing.T, path string, phrases []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(string(data)), " ")
	for _, p := range phrases {
		if !strings.Contains(text, strings.Join(strings.Fields(p), " ")) {
			t.Errorf("%s does not contain %q", path, p)
		}
	}
}

// commas formats n with thousands separators, as the docs do.
func commas(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
