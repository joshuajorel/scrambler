# scrambler

Format-preserving encryption (FPE) for Go, implementing **FF1** as specified in
NIST SP 800-38G, and following the stricter requirements of the SP 800-38G
Rev. 1 second public draft (Feb 2025):

- FF1 only (FF3 / FF3-1 are intentionally not provided).
- Domain size must satisfy `radix^minlen >= 1,000,000`.
- Exact integer arithmetic only — no floating point.
- Forward AES (AES-128/192/256) via Go's `crypto/aes`.
- Radix 2 through 65,536, with rune, byte, and raw-numeral alphabets.

> Status: under active development. Not yet ready for production use.

## License

Apache-2.0 — see [LICENSE](LICENSE).
