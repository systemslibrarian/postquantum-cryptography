# Version reconciliation — 1.0.0-rc.1

This file records the assigned package version for `PostQuantum.Cryptography`
in the suite-wide reconciliation and confirms the maturity invariant.

## Target version

`PostQuantum.Cryptography` = **1.0.0-rc.1** (up from `0.2.0-preview.1`).

Version-only bump; no crypto logic or public-API changes in this commit.
General availability as `1.0.0` is gated on a pending independent
third-party audit — until that lands and is addressed, the package will
ship only under the `-rc.N` suffix.

## Suite anchor — maturity invariant

`PostQuantum.Cryptography` is the **anchor** of the `PostQuantum.*` suite:
the foundation library every other package depends on. It depends on
**nothing** in the suite. Therefore it cannot, by construction, violate
the maturity invariant ("no package advertises more maturity than
anything it depends on") — there is no upstream sibling whose tier this
package could outrun.

Conversely, every downstream sibling is now bounded above by `1.0.0-rc.1`:

| Downstream package              | Target version       | Tier vs anchor   |
| ------------------------------- | -------------------- | ---------------- |
| `PostQuantum.FileEncryption`    | `1.0.0-rc.1`         | same tier        |
| `PostQuantum.Jwt`               | `1.0.0-preview.1`    | strictly lower   |
| `PostQuantum.SecureChannel`     | `0.3.0-preview.1`    | strictly lower   |

All satisfied.

## Inter-package dependency constraints changed in this repo

**None.** No `<PackageReference>` to any other `PostQuantum.*` package
exists in this repository. Cross-project wiring inside the repo is done
via `<ProjectReference>` (tests / benchmarks / fuzz / tools → the
library), which carries no version. The only `<PackageReference>` to
`PostQuantum.Cryptography` itself is the self-referential one in
`tests/PostQuantum.Cryptography.SmokeTest`, whose default
`SmokeTestPackageVersion` was updated to `1.0.0-rc.1` to stay in sync
with what this repo ships.

## What did not change

- README "release candidate / not independently audited" assurance
  language is now visible at HEAD; the X-Wing IETF-draft-tracking
  caveat in the README is unchanged and remains prominent. The version
  moved; the honesty about audit status and draft tracking did not.
- `KNOWN-GAPS.md` is unchanged in scope; the only new entries are the
  audit-remediation honesty bullets (JIT constant-time not validated;
  raw X25519 accepts non-canonical u and does not reject low-order
  points), which strengthen — not weaken — the existing caveats.
- Public API surface is unchanged; `Microsoft.CodeAnalysis.PublicApiAnalyzers`
  remains wired. The companion `PublicAPI.Unshipped.txt` → `Shipped.txt`
  promotion that accompanies this rc is pure text-file bookkeeping —
  no symbol additions, removals, or signature changes.

---

*To God be the glory.* — 1 Corinthians 10:31
