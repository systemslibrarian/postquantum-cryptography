# Security Policy

## Status and assurance level

`PostQuantum.Cryptography` is **release-candidate software** (`1.0.x` line, currently at `1.0.0-rc.1`). It is built to a high standard and tested, but it has **not** undergone an independent third-party security audit. Treat it accordingly: it is suitable for evaluation, prototyping, and helping the .NET ecosystem move toward post-quantum cryptography — not yet as the sole protection for high-value production secrets without your own review. **General availability as `1.0.0` is gated on the pending external audit.** The leading `1.0` reflects API stability; the `-rc.N` suffix carries the assurance caveat, and the [`AUDIT-SCOPE.md`](AUDIT-SCOPE.md) brief enumerates exactly what an external reviewer should focus on.

## What this library trusts

The cryptographic strength of this library rests on two foundations:

1. **The .NET 10 BCL.** All three ML-KEM parameter sets (FIPS 203: 512/768/1024), all three ML-DSA parameter sets (FIPS 204: 44/65/87), and the SHA-3 / SHAKE primitives, are provided by `System.Security.Cryptography` in the .NET 10 runtime. We do not reimplement them. Their correctness and side-channel posture are the platform's responsibility.

2. **A bundled X25519 implementation.** The BCL does not expose X25519, which X-Wing requires. We include a small, constant-time implementation ported faithfully from the public-domain TweetNaCl `crypto_scalarmult`, verified against the RFC 7748 known-answer tests. This is the only original cryptographic primitive in the library and the most important code to review.

## Design choices that reduce risk

- **No insecure options.** A single strong parameter set is exposed per primitive. There are no weak modes to select by accident.
- **CSPRNG-only key generation.** Keys are always generated from `RandomNumberGenerator`.
- **Secret hygiene.** Private-key types implement `IDisposable` and zero key material and intermediate shared secrets on disposal.
- **Spec-faithful X-Wing.** The combiner, key expansion, and encoding follow `draft-connolly-cfrg-xwing-kem` exactly, including the `XWingLabel` and concatenation order.

## Thread-safety

These types **are not thread-safe**: do not invoke instance methods on the same key object from multiple threads concurrently. This matches the contract of the underlying `System.Security.Cryptography.MLKem` / `MLDsa` BCL types, which we deliberately don't paper over with internal locks (that would slow the common single-threaded case and would mask incorrect concurrency in caller code).

Safe usage patterns:

- **Per-thread keys**: each thread owns its own `MLKemPrivateKey` / `MLDsaPrivateKey` / `XWingPrivateKey` (cheap to import from the same seed if needed).
- **Per-request keys**: in a request-scoped DI container, instantiate one key per request and dispose it at the end of the request.
- **Pool of keys**: keep a small pool of reusable instances and check one out per call.

Unsafe (will give corrupted output, surface BCL exceptions, or in the worst case crash the native handle):

- Sharing one `MLDsaPrivateKey` across two threads that both call `SignData` simultaneously.
- Sharing one `XWingPrivateKey` across two threads that both call `Decapsulate` simultaneously.

Static facades (`MLKem768.GenerateKeyPair()`, `MLDsa87.ImportPrivateSeed(...)`, etc.) are safe to call from any thread; each call returns a fresh instance.

## Known limitations

See [`KNOWN-GAPS.md`](KNOWN-GAPS.md) for the authoritative, up-to-date list. Highlights:

- The bundled X25519 is **designed branch-free** in its core ladder and conditional swap with respect to secret data, but that guarantee is **source-level only** — it has **not** been validated under the .NET JIT, tiered compilation, or speculative execution, and has **not** been independently audited for microarchitectural side channels (cache, branch-predictor, port-contention, prefetch). Listed as a first-order item in [`AUDIT-SCOPE.md`](AUDIT-SCOPE.md).
- No FIPS 140-3 validation is claimed for this wrapper. The underlying BCL primitives' validation status is the platform's matter.
- The API surface is intentionally small. Encrypted PKCS#8 (password-protected private keys) is not yet wrapped, and X-Wing keys are exchanged as their raw fixed-size byte strings only.

## Reporting a vulnerability

If you believe you have found a security issue, please report it **privately**. Two channels are available; either is fine:

1. **GitHub Security Advisories (preferred).** Open a private advisory at
   <https://github.com/systemslibrarian/postquantum-cryptography/security/advisories/new>.
   This keeps the report invisible to the public and lets us collaborate on the fix
   in a private fork.
2. **Email.** Send to **systemslibrarian@gmail.com** with the subject line
   `PostQuantum.Cryptography security` and as much detail / reproduction as you can.

### Response targets

These are targets, not contractual SLAs — but we take them seriously:

| Phase                    | Target time                |
| ------------------------ | -------------------------- |
| Acknowledgement          | within 3 business days     |
| Initial triage + severity | within 7 business days    |
| Fix landed or mitigation | within 30 days for High/Critical, 90 days for Medium/Low |
| Coordinated disclosure   | by mutual agreement, default 90 days from triage          |

If you don't hear back within the acknowledgement window, please follow up — email
filters are imperfect.

### What we ask of reporters

- Don't exploit the issue beyond what's needed to demonstrate it.
- Don't share it publicly until we've agreed on a coordinated disclosure date.
- Give us a reasonable window to fix before publishing details.

We're happy to credit you in the advisory and release notes — let us know how you'd like to be named.

## Supported versions

| Version line                    | Status     | Receives security fixes?                                |
| ------------------------------- | ---------- | ------------------------------------------------------- |
| `1.0.x-rc.N` (release candidate, current) | Active     | Latest rc only                                |
| `0.2.x` (preview, earlier)      | Superseded | No — upgrade to `1.0.0-rc.N`                            |
| `0.1.x` (preview, earlier)      | Superseded | No — upgrade to `1.0.0-rc.N`                            |
| `1.0.x` GA and later (post-audit) | _t.b.d._ | The two most recent minor releases of the current major |

While we are in `1.0.x-rc` only the latest rc receives backported fixes.
When `1.0.0` GA ships (after the pending external audit), this table will
be updated with the concrete post-GA policy.

---

*To God be the glory.* — 1 Corinthians 10:31
