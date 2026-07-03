# Security Policy

## Status and assurance level

`PostQuantum.Cryptography` is **generally available** (`1.0.x` line). It is built to a high standard and heavily tested, but it has **not** undergone an independent third-party security audit. The `1.0` communicates **API stability** — the public surface is locked and semantic versioning applies — not external assurance.

**Why no audit yet, and the plan.** A professional cryptographic audit is a significant expense that this project cannot fund right now. The audit has not been dropped: [`AUDIT-SCOPE.md`](AUDIT-SCOPE.md) is a ready-to-hand reviewer brief kept current for exactly that engagement, and commissioning it is the project's first priority if funding comes through — sponsorship, a grant, or a commercial consumer underwriting it. Audit findings will be fixed and shipped as `1.0.x` patches, or as a new major version if anything structural surfaces. If your organization depends on this library and can help fund or coordinate an audit, please reach out via the contact channels below.

Until then, treat the library accordingly: suitable for evaluation, prototyping, and helping the .NET ecosystem move toward post-quantum cryptography — not as the sole protection for high-value production secrets without your own review.

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

- The bundled X25519 is **designed branch-free** in its core ladder and conditional swap with respect to secret data. First-party measured evidence exists (a dudect-style statistical timing test and a JIT disassembly capture, both produced by the `constant-time.yml` workflow — see [`KNOWN-GAPS.md`](KNOWN-GAPS.md)), but the implementation has **not** been independently audited for microarchitectural side channels (cache, branch-predictor, port-contention, prefetch, speculative execution). Listed as a first-order item in [`AUDIT-SCOPE.md`](AUDIT-SCOPE.md).
- No FIPS 140-3 validation is claimed for this wrapper. The underlying BCL primitives' validation status is the platform's matter.
- The API surface is intentionally small. Encrypted PKCS#8 (password-protected private keys) is supported for ML-KEM and ML-DSA with a fixed strong PBE policy (PBKDF2-HMAC-SHA256 · 600,000 iterations · AES-256-CBC; empty passwords refused). X-Wing keys are exchanged as their raw fixed-size byte strings only.

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
| `1.0.x` (GA, current)           | Active     | Latest patch of the line                                |
| `1.0.0-rc.1`                    | Superseded | No — upgrade to the latest `1.0.x`                      |
| `0.2.x` / `0.1.x` (previews)    | Superseded | No — upgrade to the latest `1.0.x`                      |

Security fixes land on the newest release of the current major line. When a
second minor line exists (`1.1.x`), the two most recent minor releases of the
current major will receive fixes.

---

*To God be the glory.* — 1 Corinthians 10:31
