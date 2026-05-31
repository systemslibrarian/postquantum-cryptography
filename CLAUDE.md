# CLAUDE.md — Project conventions for PostQuantum.Cryptography

This file orients any contributor (human or AI) to how this repository is built and the standards it holds itself to. Read it before making changes.

## What this project is

A clean, high-level, secure-by-default post-quantum cryptography **primitives** library for **.NET 10**. It is the foundation of the `PostQuantum.*` ecosystem. It wraps the native .NET 10 BCL PQC implementations (ML-KEM-768, ML-DSA-87) and adds a spec-compliant X-Wing hybrid KEM. It is **not** a reimplementation of lattice cryptography.

## Non-negotiable principles

1. **Secure by default.** No insecure modes, no weak parameters, no "raw" escape hatches. One strong option per primitive.
2. **Delegate to the platform.** Use the BCL primitives. The only original cryptographic code is the bundled X25519 (RFC 7748), required because the BCL does not expose it. Do not add hand-rolled crypto without an exceptionally strong reason and KATs.
3. **Honesty over polish.** If something is incomplete, unaudited, or uncertain, say so — in `KNOWN-GAPS.md`, `SECURITY.md`, and XML docs. Never overstate assurance.
4. **Small, hard-to-misuse APIs.** Prefer fixed-size byte strings matching the standards, disposable key types, and clear names over flexibility that invites mistakes.

## Target framework

- `net10.0` only. The library depends on `System.Security.Cryptography` APIs new in .NET 10 (`MLKem`, `MLDsa`, `SHA3_256`, `Shake256`).

## Repository layout

```
src/PostQuantum.Cryptography/        the library
  MLKem768.cs                        ML-KEM-768 facade + key types
  MLDsa87.cs                         ML-DSA-87 facade + key types
  XWing.cs                           X-Wing hybrid KEM
  KemEncapsulation.cs                shared (ciphertext, secret) result type
  Internal/X25519.cs                 bundled constant-time X25519
tests/PostQuantum.Cryptography.Tests/  xUnit tests (round-trip + KAT)
docs/                                additional docs
Directory.Build.props                shared build settings + SourceLink
```

## Build conventions

- Nullable reference types **enabled**; warnings are **errors** (`TreatWarningsAsErrors`).
- Deterministic builds; SourceLink to GitHub; symbol packages (`snupkg`).
- Full NuGet packaging metadata lives in the library `.csproj`; shared metadata in `Directory.Build.props`.
- Public members carry XML doc comments. `GenerateDocumentationFile` is on.

## API conventions

- Each primitive has a **static facade** (`MLKem768`, `MLDsa87`, `XWing`) for generation/import, and **disposable key types** (`*PrivateKey`, `*PublicKey`).
- Private-key types implement `IDisposable`, dispose the underlying native handle, and `CryptographicOperations.ZeroMemory` their secrets.
- Size constants are public `const int … SizeInBytes` and are asserted against the BCL algorithm metadata in tests.
- Import methods validate input lengths and throw `ArgumentException` on mismatch.
- Operations on a disposed key throw `ObjectDisposedException`.

## Testing conventions

- xUnit. Every primitive has: round-trip, size assertions, determinism (seed → keys), tamper/negative cases, and known-answer tests where authoritative vectors exist.
- X25519 is validated against RFC 7748 KATs. X-Wing is validated against `draft-connolly-cfrg-xwing-kem` key-generation and decapsulation vectors.
- `dotnet test -c Release` must be green before any release.

## Documentation conventions

- `README.md`: overview, usage, security posture.
- `SECURITY.md`: assurance level, what is trusted, reporting.
- `KNOWN-GAPS.md`: the honest inventory of what's missing — keep it current with every change in scope.
- Every primary doc ends with the footer: *To God be the glory.* — 1 Corinthians 10:31

## When adding a feature

1. Confirm it cannot be done by delegating to the BCL before writing any crypto.
2. Add KATs from an authoritative source.
3. Update `KNOWN-GAPS.md` (remove the gap or add the new caveat).
4. Keep the API minimal and secure-by-default.

---

*To God be the glory.* — 1 Corinthians 10:31
