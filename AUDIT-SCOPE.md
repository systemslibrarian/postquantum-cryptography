# Audit scope — PostQuantum.Cryptography

A concise brief for an external reviewer commissioned to audit the
**original** cryptographic code in this library before `1.0.0` GA. The
intent is to keep the scope narrow and load-bearing: most of the library
is a thin wrapper over .NET 10 BCL primitives and is **out of scope**;
the audit should concentrate on the small set of files that contain
original code or that bridge between the BCL and the IETF X-Wing draft.

This document complements — it does **not** replace — [`SECURITY.md`](SECURITY.md)
and [`KNOWN-GAPS.md`](KNOWN-GAPS.md). The honest caveats there are
authoritative; this file is just a routing aid for an auditor.

## In scope

### 1. X-Wing combiner, key expansion, and encoding vs `draft-connolly-cfrg-xwing-kem`

**Files:** `src/PostQuantum.Cryptography/XWing.cs` (entire file).

- `XWing.Combiner(ssM, ssX, ctX, pkX[, destination])` — `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)`. Confirm the buffer layout, the 6-byte label bytes (`0x5c 0x2e 0x2f 0x2f 0x5e 0x5c`), and the SHA3-256 instantiation against the draft.
- `XWingPrivateKey.FromSeed` — the `expandDecapsulationKey` operation: `SHAKE256(seed, 96)` split as `(d ‖ z ‖ skX)` where the first 64 bytes are the ML-KEM `(d, z)` private seed and the last 32 bytes are the X25519 scalar. Confirm split boundaries and the §5.5.1 caching of the expanded form.
- Encapsulation key encoding (`pk = pkM ‖ pkX`, sizes 1184 + 32 = 1216).
- Ciphertext encoding (`ct = ctM ‖ ctX`, sizes 1088 + 32 = 1120).
- Exception-safety of `FromSeed` (the freshly-imported `MLKem` handle and the X25519 scalar must be zeroed/disposed if construction throws partway — see the `success` flag path).
- Secret hygiene on encap/decap: `ssM`, `ssX`, `ekX` cleared in `finally`; `ctX` deliberately **not** cleared because it is the transmitted ephemeral public value.

### 2. Bundled X25519 vs RFC 7748

**File:** `src/PostQuantum.Cryptography/Internal/X25519.cs` (entire file).

- A faithful port of TweetNaCl's `crypto_scalarmult` (public domain). Signed `long` limbs that go negative through `Sub` / `Sel25519` / `Car25519` / `Pack25519` / `Mul` / `Inv25519`. **This has been read line-by-line and confirmed bounds-safe; the recommendation is to verify against an independent reference rather than re-audit the carry chain in isolation.**
- Scalar clamping per RFC 7748 §5 (`z[0] &= 248; z[31] &= 127; z[31] |= 64`).
- `Unpack25519` high-bit mask of `u` (`o[15] &= 0x7fff`) — the bare primitive accepts non-canonical u.
- The Montgomery ladder and `Sel25519` are designed branch-free w.r.t. secret data (bitmask selection, no scalar-dependent control flow); auditor should treat the "constant-time" claim as **by-construction, not by-measurement** (see §3).
- Stack-allocation discipline: all working arrays are `stackalloc`'d and `.Clear()`'d in `finally`; the scalar `z` is `ZeroMemory`'d.

### 3. Constant-time review under the .NET JIT / tiered compilation

This is the first-order audit item that cannot be settled by source reading.

- Confirm or refute that tiered compilation, code-gen optimizations, and speculative execution **do not** introduce scalar-dependent branches or scalar-dependent memory access patterns in the produced machine code (R2R, tier-0, tier-1) for `X25519.ScalarMult`, `X25519.Sel25519`, and the inner field ops.
- Recommended tooling: `ctgrind`-style Valgrind taint analysis on a native AOT build of the library; `dudect` measurement of `ScalarMult` over equal-class inputs; manual review of the JIT'd assembly for `Sel25519`.
- Cache, branch-predictor, port-contention, and prefetch side channels are explicitly **in scope** for the auditor — they are listed as known gaps in `KNOWN-GAPS.md` and have not been measured.

### 4. Wrapper-boundary fail-closed behavior

**Files:** `src/PostQuantum.Cryptography/MLKem768.cs`, `MLDsa87.cs`, `XWing.cs`, and the matching key types (`*PrivateKey`, `*PublicKey`).

- Up-front length validation (`ArgumentException`) on every import/decap/sign path.
- PEM label validation (`PRIVATE KEY` vs `PUBLIC KEY`).
- FIPS 204 §5.2 context-length validation (≤ 255 bytes).
- `ObjectDisposedException` on use-after-dispose, idempotent disposal.
- `KemEncapsulation.ToString()` does not leak bytes.

These are not original cryptography but they are the surface that protects
callers from misuse — they should be exercised by the auditor with adversarial
inputs.

## Out of scope

- **ML-KEM (FIPS 203)** and **ML-DSA (FIPS 204)** implementations themselves — these are the native `System.Security.Cryptography.MLKem` and `MLDsa` types from .NET 10. Their correctness, FIPS validation status, and side-channel posture are inherited from the platform and are out of scope for this audit.
- **SHA-3 / SHAKE-256** primitives used by the X-Wing combiner and key expansion — these come from `System.Security.Cryptography.SHA3_256` / `Shake256` (.NET 10).
- **Build, packaging, supply-chain.** Deterministic builds, SourceLink, SBOM, NuGet signing are documented in `KNOWN-GAPS.md`; a supply-chain audit is a separate engagement.

## Existing KAT coverage matrix

| Component                                       | Vectors                                                                                          | Test class                                | CI default? |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------ | ----------------------------------------- | ----------- |
| X25519 `ScalarMult` / `ScalarMultBase`          | RFC 7748 §5.2 vectors 1 & 2, §6.1 DH agreement                                                   | `X25519Tests`                             | yes         |
| X25519 §5.2 iterated chain                      | 1 iteration, 1,000 iterations                                                                    | `X25519PropertyTests`                     | yes         |
| X25519 §5.2 iterated chain                      | 1,000,000 iterations                                                                             | `X25519AdversarialKatTests`               | gated `[Trait("Category","LongRunning")]` |
| X25519 non-canonical u                          | High bit set; `u ≥ 2²⁵⁵−19`                                                                      | `X25519AdversarialKatTests`               | yes         |
| X25519 low-order points                         | The 7 curve-side small-subgroup u-coordinates from libsodium's `has_small_order` blacklist (u ∈ {0, 1, the two order-8 points, p−1, p, p+1}); clamped scalarmult yields all-zero | `X25519AdversarialKatTests`               | yes         |
| X25519 differential                             | RFC 7748 vectors + randomized inputs cross-checked vs `Org.BouncyCastle.Math.EC.Rfc7748.X25519`  | `X25519DifferentialTests`                 | yes         |
| X25519 DH commutativity property                | 64 random keys                                                                                   | `X25519PropertyTests`                     | yes         |
| X-Wing combiner                                 | Fixed 134-byte input → exact SHA3-256(32) output                                                  | `XWingCombinerKatTests`                   | yes         |
| X-Wing `expandDecapsulationKey`                 | SHAKE256(seed, 96) split (d ‖ z ‖ skX) standalone                                                | `XWingCombinerKatTests`                   | yes         |
| X-Wing end-to-end key generation                | `draft-connolly-cfrg-xwing-kem` Appendix C: seed → encapsulation key                              | `XWingTests.Kat_KeyGeneration_*`          | yes         |
| X-Wing end-to-end decapsulation                 | Appendix C: seed + ciphertext → shared secret                                                    | `XWingTests.Kat_Decapsulation_*`          | yes         |
| ML-KEM / ML-DSA across all parameter sets       | Round-trip, size, determinism (seed → public-key fingerprint), tamper, span overloads, disposal  | `MLKem*Tests`, `MLDsa*Tests`, `RobustnessTests`, `DeterminismKatTests`, `SpanOverloadTests`, `DisposalAndCrossAlgorithmTests` | yes         |
| Smoke fuzzer (in-process)                       | 5,000 pseudo-random inputs per target every CI build                                              | `SmokeFuzzTests`                          | yes         |
| Coverage-guided AFL fuzzer                      | Long-running, run out-of-band                                                                    | `fuzz/PostQuantum.Cryptography.Fuzz`      | no (out-of-band) |

## Paths NOT covered by automated tests

These are deliberately uncovered and are the auditor's responsibility:

- **Microarchitectural side-channel measurement** of the bundled X25519 under the .NET JIT (cache, branch-predictor, port-contention, prefetch, speculative execution). The CI suite proves *functional* constant-time-by-construction; it cannot prove *physical* constant-time.
- **Derandomized X-Wing encapsulation.** `EncapsulateDerand` is a testing aid in the draft and is intentionally not part of the public API; consequently the bundled KATs cover key generation and decapsulation but not derandomized encap. An auditor with access to the draft's full vector set can cross-check by adapting our internal `Encapsulate` against the derandomized path.
- **Cross-implementation X-Wing interop** beyond the IETF draft Appendix C vectors. The draft is not yet an RFC; if another implementation diverges on encoding, our package will rev its major version (per the wire-format policy in `README.md`).
- **Long-running differential** of X25519 against multiple independent references (`libsodium`, `monocypher`, `BoringSSL`). The default suite cross-checks BouncyCastle only.
- **Twist-side low-order points.** The all-zero clamped-scalarmult property does not hold on the twist; testing those requires a separate "invalid curve" framing and is out of scope for the per-push KAT suite. Auditor may exercise the twist-side cases if invalid-curve attacks against X-Wing's `pk_X` are within the engagement.

## Reporting

If the audit produces findings, please follow the private-disclosure path
in [`SECURITY.md`](SECURITY.md). The maintainer welcomes coordination on
remediation scope before findings are made public.

---

*To God be the glory.* — 1 Corinthians 10:31
