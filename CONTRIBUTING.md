# Contributing to PostQuantum.Cryptography

Thank you for your interest in helping make post-quantum cryptography easier to
use safely on .NET. This document describes how the project accepts
contributions and what we ask of every change.

The library's [non-negotiable principles](CLAUDE.md) — secure-by-default,
delegate to the platform, honesty over polish, small hard-to-misuse APIs — are
the lens through which every change is reviewed. Please read them first.

## Ground rules

1. **Open an issue before significant work.** Anything bigger than a typo, a
   doc fix, or an obvious bug should start with a short issue describing the
   change and your motivation, so we can agree on direction before you invest
   time.
2. **No hand-rolled cryptography** unless it cannot be delegated to the BCL,
   and it ships with KATs from an authoritative source. The bundled X25519
   already meets this bar; nothing else does today.
3. **Every public API needs XML documentation** and an entry in
   `PublicAPI.Unshipped.txt`. The `PublicApiAnalyzer` will fail the build if
   you forget.
4. **Tests required.** Every behavior change needs a corresponding test in
   `tests/PostQuantum.Cryptography.Tests/`. Cryptographic primitives also need
   round-trip, determinism, tamper, and (where vectors exist) KAT coverage.
5. **No new dependencies** for the runtime library. Test-only dependencies are
   evaluated case-by-case.

## Local development

```bash
dotnet restore PostQuantum.Cryptography.slnx
dotnet build PostQuantum.Cryptography.slnx -c Release
dotnet test  PostQuantum.Cryptography.slnx -c Release
```

The library targets `net10.0`; you need the .NET 10 SDK (10.0.300 or later).

On platforms where the runtime doesn't expose ML-KEM / ML-DSA (for example, a
Linux build without OpenSSL 3.5+), the PQC tests are skipped automatically.
The pure-managed X25519 tests always run.

## Commit and pull-request hygiene

- Conventional commits welcome but not required. Write clear messages that
  explain the *why*, not just the *what*.
- Keep PRs focused. If you find a tangential cleanup, ship it in its own PR.
- CI must be green before merge: build, tests, deterministic-build check, and
  the SBOM step.

## Security issues

**Do not** open a public GitHub issue for security vulnerabilities. See
[`SECURITY.md`](SECURITY.md) for the private reporting channel.

## Code of conduct

By participating, you agree to abide by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).

---

*To God be the glory.* — 1 Corinthians 10:31
