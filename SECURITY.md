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

| Version line     | Status   | Receives security fixes? |
| ---------------- | -------- | ------------------------ |
| `0.x` (preview)  | Active   | Latest release only      |
| `1.x` and later  | _t.b.d._ | The two most recent minor releases of the current major |

When `1.0` ships, this table will be updated with a concrete policy. While we are
in `0.x` preview, only the most recent release receives backported fixes.

---

*To God be the glory.* — 1 Corinthians 10:31
