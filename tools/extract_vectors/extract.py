#!/usr/bin/env python3
"""Extract FF1 test vectors from other FPE libraries' test suites.

Downloads each source file at a pinned commit, parses the FF1 vectors out of
it, and writes ff1/testdata/thirdparty_vectors.json. Nothing is typed in by
hand: every key/tweak/plaintext/ciphertext comes from the fetched source, and
the SHA-256 of each fetched file is recorded next to its URL.

Sources (FF3/FF3-1 vectors in the same files are deliberately skipped):
  - Bouncy Castle SP80038GTest.java: ff1Samples, testFF1, testFF1w (radix
    1024), testFF1Rounding (radix 256, n = 57), testFF1Bounds, testUtility.
  - str4d/fpe (Rust) src/ff1/test_vectors.rs: all 15 entries.
  - capitalone/fpe ff1/ff1_test.go: testVectors, TestLong, TestIssue14, the
    two Example functions, and the BenchmarkEncryptLong input.
  - ubiq-fpe-go ff1_test.go: all TestFF1* functions and the six
    BenchmarkFF1{Encrypt,Decrypt}* known answers.

Each vector has expect = "match" (encrypt(pt) = ct and decrypt(ct) = pt),
"roundtrip" (the source only checks decrypt(encrypt(pt)) = pt), or "error"
(the input must be rejected with the named sentinel). Vectors that violate
radix^n >= 1,000,000 are reclassified as errors with ErrDomainTooSmall.

Usage (from the repository root):
    python3 tools/extract_vectors/extract.py

Stdlib only. Re-running with the same pinned commits reproduces the file
byte-for-byte.
"""

import hashlib
import json
import os
import re
import sys
import urllib.request

BC = {
    "repo": "bcgit/bc-java",
    "commit": "6d7d611b9dcb20c59b2172975ba2a863f17705dc",
    "path": "core/src/test/java/org/bouncycastle/crypto/test/SP80038GTest.java",
    "license": "MIT (Bouncy Castle licence); test data used for interoperability testing",
}
FPE_RS = {
    "repo": "str4d/fpe",
    "commit": "913e533c9345d5c8e11aac42318fc5743d6f58e9",
    "path": "src/ff1/test_vectors.rs",
    "license": "MIT OR Apache-2.0 (fpe crate 0.6.1)",
}
CAPITALONE = {
    "repo": "capitalone/fpe",
    "commit": "b7dcc90b924e240eac5af5ff2d4d913fbf9985f0",
    "path": "ff1/ff1_test.go",
    "license": "Apache-2.0",
}
UBIQ = {
    "repo": "ubiqsecurity/ubiq-fpe-go",
    "commit": "f0d5bc065c59a766b5e7f69e6eecd895d2112659",
    "path": "ff1_test.go",
    "license": "MIT",
}

OUT = os.path.join(os.path.dirname(__file__), "..", "..", "ff1", "testdata", "thirdparty_vectors.json")

B36 = "0123456789abcdefghijklmnopqrstuvwxyz"
UBIQ_DEFAULT = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def raw_url(src):
    return f"https://raw.githubusercontent.com/{src['repo']}/{src['commit']}/{src['path']}"


def fetch(src):
    with urllib.request.urlopen(raw_url(src)) as r:
        data = r.read()
    src["sha256"] = hashlib.sha256(data).hexdigest()
    return data.decode("utf-8")


def provenance(src, locator):
    return {
        "source_url": f"https://github.com/{src['repo']}/blob/{src['commit']}/{src['path']}",
        "commit": src["commit"],
        "locator": locator,
        "license": src["license"],
    }


def vec(name, src, locator, key, radix, tweak, pt, ct=None, *, alphabet=None,
        pt_str=None, ct_str=None, expect="match", error=None, note=None):
    v = {
        "name": name,
        "provenance": provenance(src, locator),
        "key": key.upper(),
        "radix": radix,
        "tweak": tweak.upper(),
        "pt": pt,
    }
    if ct is not None:
        v["ct"] = ct
    if alphabet is not None:
        v["alphabet"] = alphabet
    if pt_str is not None:
        v["pt_str"] = pt_str
    if ct_str is not None:
        v["ct_str"] = ct_str
    v["expect"] = expect
    if error:
        v["error"] = error
    if note:
        v["note"] = note
    return v


def domain_ok(radix, n):
    return radix ** n >= 1_000_000


def classify(v):
    """Vectors violating radix^n >= 10^6 must be rejected with ErrDomainTooSmall."""
    if v["expect"] != "error" and not domain_ok(v["radix"], len(v["pt"])):
        v["expect"] = "error"
        v["error"] = "ErrDomainTooSmall"
        v.pop("ct", None)
        v.pop("ct_str", None)
        v["note"] = (v.get("note", "") + " " if v.get("note") else "") + \
            "violates radix^n >= 1000000; must be rejected"
    return v


def str_to_numerals(s, alphabet):
    return [alphabet.index(ch) for ch in s]


def hexstr_bytes(h):
    return list(bytes.fromhex(h))


# --- Bouncy Castle -----------------------------------------------------------

def method_body(src, name):
    m = re.search(r"void\s+" + name + r"\s*\(\)[^{]*\{", src)
    if not m:
        sys.exit(f"BC: method {name} not found")
    i, depth = m.end(), 1
    while depth:
        depth += {"{": 1, "}": -1}.get(src[i], 0)
        i += 1
    return src[m.end():i - 1]


def hex_var(body, var):
    m = re.search(r"\b" + var + r"\s*=\s*Hex\.decode(?:Strict)?\(\"([0-9A-Fa-f]*)\"\)", body)
    if not m:
        sys.exit(f"BC: hex var {var} not found")
    return m.group(1)


def be16(h):
    b = bytes.fromhex(h)
    return [(b[i] << 8) | b[i + 1] for i in range(0, len(b), 2)]


def extract_bc():
    src = fetch(BC)
    out = []
    samples = re.findall(
        r'FFSample\.from\((\d+),\s*"([0-9A-F]+)",\s*"([0-9a-z]+)",\s*"([0-9a-z]+)",\s*"([0-9A-F]*)"\)', src)
    ff1_block = src[src.index("ff1Samples = new FFSample[]"):src.index("ff3_1Samples")]
    ff1_samples = [s for s in samples if s[1] in ff1_block and f'"{s[3]}"' in ff1_block]
    if len(ff1_samples) != 9:
        sys.exit(f"BC: expected 9 FF1 samples, got {len(ff1_samples)}")
    for i, (radix, key, pt, ct, tweak) in enumerate(ff1_samples, 1):
        radix = int(radix)
        out.append(vec(f"bc/ff1Samples[{i-1}]", BC, "ff1Samples", key, radix, tweak,
                       str_to_numerals(pt, B36), str_to_numerals(ct, B36),
                       alphabet=B36[:radix], pt_str=pt, ct_str=ct))

    # testFF1w: radix 1024, AES-192, numerals as 16-bit big-endian values.
    body = method_body(src, "testFF1w")
    key, pt, ct, tweak = (hex_var(body, v) for v in ("key", "plainText", "cipherText", "tweak"))
    radix = int(re.search(r"new KeyParameter\(key\),\s*(\d+),", body).group(1))
    out.append(vec("bc/testFF1w", BC, "testFF1w", key, radix, tweak, be16(pt), be16(ct),
                   note="numerals encoded as 16-bit big-endian in the BC test"))
    out_pt = hex_var(body, "outPt")
    out.append(vec("bc/testFF1w/out-of-radix", BC, "testFF1w (outPt)", key, radix, tweak, be16(out_pt),
                   expect="error", error="ErrInvalidNumeral"))

    # testFF1Rounding: radix 256, n = 57.
    body = method_body(src, "testFF1Rounding")
    radix = int(re.search(r"int\s+radix\s*=\s*(\d+);", body).group(1))
    key, tweak, pt, ct = (hex_var(body, v) for v in ("key", "tweak", "asciiPT", "asciiCT"))
    out.append(vec("bc/testFF1Rounding", BC, "testFF1Rounding", key, radix, tweak,
                   hexstr_bytes(pt), hexstr_bytes(ct)))

    # testFF1: radix 24 with numerals >= 24, and a 1-numeral input.
    body = method_body(src, "testFF1")
    key, pt, tweak = (hex_var(body, v) for v in ("key", "plainText", "tweak"))
    radix = int(re.search(r"new KeyParameter\(key\),\s*(\d+),", body).group(1))
    out.append(vec("bc/testFF1/outside-radix", BC, "testFF1 (input data outside of radix)", key, radix, tweak,
                   hexstr_bytes(pt), expect="error", error="ErrInvalidNumeral"))
    short = [int(x) for x in re.search(r"processBlock\(new byte\[\] \{ ([\d, ]+) \}", body).group(1).split(",")]
    out.append(classify(vec("bc/testFF1/too-short", BC, "testFF1 (input too short)", key, radix, tweak, short)))

    # testFF1Bounds: radix 9 and radix 4 with a 3-numeral input.
    body = method_body(src, "testFF1Bounds")
    key, tweak = hex_var(body, "key"), hex_var(body, "tweak")
    alphas = re.findall(r'new BasicAlphabetMapper\("([^"]+)"\)', body)
    inputs = re.findall(r"process\(fpeEngine, new byte\[\] \{ ([\d, ]+) \}\)", body)
    for alpha, inp in zip(alphas, inputs):
        pt = [int(x) for x in inp.split(",")]
        out.append(classify(vec(f"bc/testFF1Bounds/{alpha}", BC, "testFF1Bounds", key, len(alpha), tweak, pt,
                                alphabet=alpha)))

    # testUtility: round-trip only (no expected ciphertext in the source).
    body = method_body(src, "testUtility")
    key = re.search(r'Hex\.decode\("([0-9A-F]+)"\)', body).group(1)
    alpha = re.search(r'"(\d+)"\.toCharArray\(\)', body).group(1)
    inp = re.search(r'char\[\] input = "(\d+)"', body).group(1)
    out.append(vec("bc/testUtility", BC, "testUtility", key, len(alpha), "", str_to_numerals(inp, alpha),
                   alphabet=alpha, pt_str=inp, expect="roundtrip",
                   note="BC asserts only decrypt(encrypt(x)) == x"))
    return out


# --- Rust fpe crate ----------------------------------------------------------

def rust_vec(expr):
    expr = expr.strip()
    m = re.fullmatch(r"vec!\[\s*(\d+)\s*;\s*(\d+)\s*\]", expr)
    if m:
        return [int(m.group(1))] * int(m.group(2))
    m = re.fullmatch(r"vec!\[(.*)\]", expr, re.S)
    if not m:
        sys.exit(f"fpe: cannot parse {expr[:40]}")
    return [int(x, 0) for x in re.split(r"[,\s]+", m.group(1)) if x]


def extract_fpe():
    src = fetch(FPE_RS)
    out = []
    origin = None
    pos = 0
    field = lambda name, body: re.search(name + r":\s*(vec!\[[^\]]*\])", body).group(1)
    for m in re.finditer(r"(?m)((?:^[ \t]*//[^\n]*\n)*)^[ \t]*TestVector \{", src):
        comments = re.findall(r"//\s*([^\n]*)", m.group(0))
        for c in comments:
            if c.startswith("From ") or "test vectors" in c.lower() or "test cases" in c.lower():
                origin = c
        # body up to the matching close brace
        i, depth = m.end(), 1
        while depth:
            depth += {"{": 1, "}": -1}.get(src[i], 0)
            i += 1
        body = src[m.end():i - 1]
        body = re.sub(r"binary:.*", "", body, flags=re.S)
        pos += 1
        key = bytes(rust_vec(field("key", body))).hex()
        radix = int(re.search(r"radix:\s*(\d+)", body).group(1))
        tweak = bytes(rust_vec(field("tweak", body))).hex()
        pt = rust_vec(field("pt", body))
        ct = rust_vec(field("ct", body))
        label = next((c for c in comments if c.startswith("Sample")), None)
        name = f"fpe-rs/{pos:02d}" + (f" ({label})" if label else "")
        out.append(classify(vec(name, FPE_RS, f"get() entry #{pos}", key, radix, tweak, pt, ct,
                                note=f"fpe crate comment: {origin}" if origin else None)))
    if len(out) != 15:
        sys.exit(f"fpe: expected 15 vectors, got {len(out)}")
    return out


# --- capitalone/fpe ----------------------------------------------------------

def extract_capitalone():
    src = fetch(CAPITALONE)
    out = []
    block = src[src.index("var testVectors = []testVector{"):]
    block = block[:block.index("\n}\n")]
    entries = re.findall(r'\{\s*(\d+),\s*"([0-9A-F]*)",\s*"([0-9A-F]*)",\s*"([0-9a-z]*)",\s*"([0-9a-z]*)",?\s*\}', block)
    if len(entries) != 9:
        sys.exit(f"capitalone: expected 9 vectors, got {len(entries)}")
    for i, (radix, key, tweak, pt, ct) in enumerate(entries, 1):
        radix = int(radix)
        out.append(vec(f"capitalone/testVectors[{i-1}]", CAPITALONE, "testVectors", key, radix, tweak,
                       str_to_numerals(pt, B36), str_to_numerals(ct, B36),
                       alphabet=B36[:radix], pt_str=pt, ct_str=ct))

    def test_fn(name):
        m = re.search(r"func " + name + r"\(t \*testing\.T\) \{(.*?)\n\}", src, re.S)
        body = m.group(1)
        key = re.search(r'key, err := hex\.DecodeString\("([0-9A-F]*)"\)', body).group(1)
        tweak = re.search(r'tweak, err := hex\.DecodeString\("([0-9A-F]*)"\)', body).group(1)
        radix = int(re.search(r"NewCipher\((\d+),", body).group(1))
        pt = re.search(r'plaintext := "([0-9a-z]+)"', body).group(1)
        return key, tweak, radix, pt

    key, tweak, radix, pt = test_fn("TestLong")
    out.append(vec("capitalone/TestLong", CAPITALONE, "TestLong", key, radix, tweak,
                   str_to_numerals(pt, B36), alphabet=B36[:radix], pt_str=pt, expect="roundtrip",
                   note="capitalone asserts only decrypt(encrypt(x)) == x"))
    key, tweak, radix, pt = test_fn("TestIssue14")
    out.append(classify(vec("capitalone/TestIssue14", CAPITALONE, "TestIssue14", key, radix, tweak,
                            str_to_numerals(pt, B36), alphabet=B36[:radix], pt_str=pt, expect="roundtrip")))

    # Examples: verified against their "// Output:" comments by go test.
    for name, var in (("ExampleCipher_Encrypt", "original"), ("ExampleCipher_Decrypt", "ciphertext")):
        m = re.search(r"func " + name + r"\(\) \{(.*?)\n\}", src, re.S)
        body = m.group(1)
        key = re.search(r'key, err := hex\.DecodeString\("([0-9A-F]*)"\)', body).group(1)
        tweak = re.search(r'tweak, err := hex\.DecodeString\("([0-9A-F]*)"\)', body).group(1)
        radix = int(re.search(r"NewCipher\((\d+),", body).group(1))
        inp = re.search(var + r' := "([0-9a-z]+)"', body).group(1)
        outp = re.search(r"// Output: ([0-9a-z]+)", body).group(1)
        pt, ct = (inp, outp) if name.endswith("Encrypt") else (outp, inp)
        out.append(vec(f"capitalone/{name}", CAPITALONE, name, key, radix, tweak,
                       str_to_numerals(pt, B36[:radix]), str_to_numerals(ct, B36[:radix]),
                       alphabet=B36[:radix], pt_str=pt, ct_str=ct))

    # BenchmarkEncryptLong: input only, no expected output in the source.
    m = re.search(r"func BenchmarkEncryptLong\(b \*testing\.B\) \{(.*?)\n\}", src, re.S)
    body = m.group(1)
    key = re.search(r'key, err := hex\.DecodeString\("([0-9A-F]*)"\)', body).group(1)
    tweak = re.search(r'tweak, err := hex\.DecodeString\("([0-9A-F]*)"\)', body).group(1)
    radix = int(re.search(r"NewCipher\((\d+),", body).group(1))
    pt = re.search(r'ff1\.Encrypt\("([0-9a-z]+)"\)', body).group(1)
    out.append(vec("capitalone/BenchmarkEncryptLong", CAPITALONE, "BenchmarkEncryptLong", key, radix, tweak,
                   str_to_numerals(pt, B36), alphabet=B36[:radix], pt_str=pt, expect="roundtrip",
                   note="benchmark input; the source has no expected ciphertext"))
    return out


# --- ubiq-fpe-go -------------------------------------------------------------

def go_bytes(expr):
    return bytes(int(x, 0) for x in re.findall(r"0x[0-9a-fA-F]+|\d+", expr)).hex()


def extract_ubiq():
    src = fetch(UBIQ)
    out = []
    for m in re.finditer(r"func (TestFF1\w+)\(t \*testing\.T\) \{(.*?)\n\}", src, re.S):
        name, body = m.group(1), m.group(2)
        alpha = UBIQ_DEFAULT
        am = re.search(r'var alphabet string = "([^"]+)"', body)
        if am:
            alpha = am.group(1)
        call = re.search(r"testFF1\(t,\s*\[\]byte\{([^}]*)\},\s*\[\]byte\{([^}]*)\},\s*\"([^\"]*)\",\s*\"([^\"]*)\",\s*([^\n]+)\)",
                         body, re.S)
        key, tweak, pt, ct = go_bytes(call.group(1)), go_bytes(call.group(2)), call.group(3), call.group(4)
        radix_expr = call.group(5).split(",")[0].strip()
        radix = len(alpha) if "len(" in radix_expr else int(radix_expr)
        a = alpha[:radix]
        out.append(classify(vec(f"ubiq/{name}", UBIQ, name, key, radix, tweak,
                                str_to_numerals(pt, a), str_to_numerals(ct, a),
                                alphabet=a, pt_str=pt, ct_str=ct)))
    if len(out) != 17:
        sys.exit(f"ubiq: expected 17 vectors, got {len(out)}")

    # Benchmarks panic unless f(INP) == OUT, so they assert known answers too.
    benches = re.findall(r"func (BenchmarkFF1(Encrypt|Decrypt)\d+)\(b \*testing\.B\) \{\s*benchmarkFF1\(b, \(\*FF1\)\.\w+,"
                         r"\s*\[\]byte\{([^}]*)\},\s*\[\]byte\{([^}]*)\},\s*\"([^\"]*)\",\s*\"([^\"]*)\",\s*(\d+)\)", src)
    if len(benches) != 6:
        sys.exit(f"ubiq: expected 6 benchmark vectors, got {len(benches)}")
    for name, direction, k, tw, inp, outp, radix in benches:
        radix = int(radix)
        a = UBIQ_DEFAULT[:radix]
        pt, ct = (inp, outp) if direction == "Encrypt" else (outp, inp)
        out.append(classify(vec(f"ubiq/{name}", UBIQ, name, go_bytes(k), radix, go_bytes(tw),
                                str_to_numerals(pt, a), str_to_numerals(ct, a),
                                alphabet=a, pt_str=pt, ct_str=ct)))
    return out


def cross_reference(vectors):
    """Note roundtrip-only vectors whose (key, radix, tweak, pt) another source pins to a ciphertext."""
    answers = {}
    for v in vectors:
        if v["expect"] == "match":
            answers.setdefault((v["key"], v["radix"], v["tweak"], tuple(v["pt"])), v["name"])
    for v in vectors:
        other = answers.get((v["key"], v["radix"], v["tweak"], tuple(v["pt"])))
        if v["expect"] == "roundtrip" and other:
            v["note"] = (v["note"] + "; " if v.get("note") else "") + \
                f"the same key/tweak/input is a known-answer vector in {other}"
    return vectors


def main():
    vectors = cross_reference(extract_bc() + extract_fpe() + extract_capitalone() + extract_ubiq())
    doc = {
        "description": "FF1 test vectors extracted verbatim from other FPE libraries' test suites by "
                       "tools/extract_vectors/extract.py. expect=match: encrypt(pt)=ct and decrypt(ct)=pt; "
                       "expect=roundtrip: the source only checks decrypt(encrypt(pt))=pt; expect=error: "
                       "the vector must be rejected with the named sentinel error (vectors that violate "
                       "radix^n >= 1000000 are reclassified as ErrDomainTooSmall).",
        "sources": [
            {"name": s["repo"], "url": raw_url(s), "commit": s["commit"], "sha256": s["sha256"],
             "license": s["license"]}
            for s in (BC, FPE_RS, CAPITALONE, UBIQ)
        ],
        "vectors": vectors,
    }
    text = json.dumps(doc, indent=1, ensure_ascii=False)
    # Keep numeral arrays on one line so the file stays reviewable.
    text = re.sub(r"\[\s*(\d+(?:,\s*\d+)*)\s*\]",
                  lambda m: "[" + ", ".join(re.split(r",\s*", m.group(1))) + "]", text)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    counts = {}
    for v in vectors:
        k = (v["name"].split("/")[0], v["expect"])
        counts[k] = counts.get(k, 0) + 1
    for k in sorted(counts):
        print(k, counts[k])
    print("total", len(vectors))


if __name__ == "__main__":
    main()
