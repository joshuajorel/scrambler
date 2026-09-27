# NIST ACVP FF1 vectors

`internalProjection.json` is an unmodified copy of the ACVP-AES-FF1-1.0
sample vector set published by NIST in the ACVP-Server repository:

| | |
|---|---|
| Source | <https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ACVP-AES-FF1-1.0/internalProjection.json> |
| Repository | `usnistgov/ACVP-Server` |
| Commit | `975de31eb83d87039ec88934fdc47d8c312b892d` (master, 2026-08-12; the file itself was last changed in `b97fa5aeb6b5fce8540021b16bdaa32937089aab`, RELEASE/v1.1.0.29) |
| Git blob SHA-1 | `39faea241274305417050ac2b75f599d89ff1334` |
| SHA-256 | `63cd6642095fbb1ce7af3fa53d7d720d725a58fe331d35ced1540b5e433668ee` |
| Contents | 30 test groups × 25 test cases = 750 cases (AES-128/192/256, radix 2, 4, 16, 32, 64; encrypt and decrypt; tweaks of 0–128 bits) |

`tools/acvp/fetch.sh` re-downloads the file and checks both hashes, and
`TestTestdataIntegrity` in `ff1/vectors_test.go` fails if the committed copy
ever changes. Every case satisfies radix^n ≥ 1,000,000, so all 750 are
expected to pass (none are rejected by the domain-size rule).

## License / notice

This data was developed by NIST. The ACVP-Server repository carries the
following notice, reproduced in full as it requires:

> NIST-developed software is provided by NIST as a public service. You may
> use, copy, and distribute copies of the software in any medium, provided
> that you keep intact this entire notice. You may improve, modify, and
> create derivative works of the software or any portion of the software,
> and you may copy and distribute such modifications or works. Modified works
> should carry a notice stating that you changed the software and should
> note the date and nature of any such change. Please explicitly acknowledge
> the National Institute of Standards and Technology as the source of the
> software.
>
> NIST-developed software is expressly provided "AS IS." NIST MAKES NO
> WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF
> LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF
> MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND
> DATA ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF
> THE SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL
> BE CORRECTED. NIST DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING
> THE USE OF THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO
> THE CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
>
> You are solely responsible for determining the appropriateness of using and
> distributing the software and you assume all risks associated with its use,
> including but not limited to the risks and costs of program errors,
> compliance with applicable laws, damage to or loss of data, programs or
> equipment, and the unavailability or interruption of operation. This
> software is not intended to be used in any situation where a failure could
> cause risk of injury or damage to property. The software developed by NIST
> employees is not subject to copyright protection within the United States.

Source: National Institute of Standards and Technology (NIST), Cryptographic
Algorithm Validation Program. The file has not been modified.
