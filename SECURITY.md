# Security Policy

## Status and assurance level

`PostQuantum.Cryptography` is **preview software** (`0.1.x`). It is built to a high standard and tested, but it has **not** undergone an independent third-party security audit. Treat it accordingly: it is suitable for evaluation, prototyping, and helping the .NET ecosystem move toward post-quantum cryptography — not yet as the sole protection for high-value production secrets without your own review.

## What this library trusts

The cryptographic strength of this library rests on two foundations:

1. **The .NET 10 BCL.** ML-KEM-768 (FIPS 203) and ML-DSA-87 (FIPS 204), and the SHA-3 / SHAKE primitives, are provided by `System.Security.Cryptography` in the .NET 10 runtime. We do not reimplement them. Their correctness and side-channel posture are the platform's responsibility.

2. **A bundled X25519 implementation.** The BCL does not expose X25519, which X-Wing requires. We include a small, constant-time implementation ported faithfully from the public-domain TweetNaCl `crypto_scalarmult`, verified against the RFC 7748 known-answer tests. This is the only original cryptographic primitive in the library and the most important code to review.

## Design choices that reduce risk

- **No insecure options.** A single strong parameter set is exposed per primitive. There are no weak modes to select by accident.
- **CSPRNG-only key generation.** Keys are always generated from `RandomNumberGenerator`.
- **Secret hygiene.** Private-key types implement `IDisposable` and zero key material and intermediate shared secrets on disposal.
- **Spec-faithful X-Wing.** The combiner, key expansion, and encoding follow `draft-connolly-cfrg-xwing-kem` exactly, including the `XWingLabel` and concatenation order.

## Known limitations

See [`KNOWN-GAPS.md`](KNOWN-GAPS.md) for the authoritative, up-to-date list. Highlights:

- The bundled X25519 is constant-time in its core ladder but has **not** been independently audited for microarchitectural side channels.
- No FIPS 140-3 validation is claimed for this wrapper. The underlying BCL primitives' validation status is the platform's matter.
- The API surface is intentionally small. Encrypted PKCS#8 (password-protected private keys) is not yet wrapped, and X-Wing keys are exchanged as their raw fixed-size byte strings only.

## Reporting a vulnerability

If you believe you have found a security issue:

- **Do not** open a public GitHub issue.
- Email the maintainer at **systemslibrarian@gmail.com** with details and, if possible, a reproduction.
- You will receive an acknowledgement, and we will work with you on a coordinated disclosure timeline.

Please include "PostQuantum.Cryptography security" in the subject line.

## Supported versions

While in `0.x` preview, only the latest released version receives security fixes.

---

*To God be the glory.* — 1 Corinthians 10:31
