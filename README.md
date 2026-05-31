# PostQuantum.Cryptography

**Clean, high-level, secure-by-default post-quantum cryptography primitives for .NET 10.**

`PostQuantum.Cryptography` is the foundation library of the `PostQuantum.*` ecosystem. It wraps the native .NET 10 BCL implementations of the NIST-standardized post-quantum algorithms in small, safe, hard-to-misuse APIs, and adds a spec-compliant **X-Wing** hybrid KEM for migrations that want both classical and post-quantum assurance.

It does not reimplement the heavy lattice math: ML-KEM and ML-DSA come straight from the .NET 10 runtime. This library's job is to give you a clean surface, strong defaults, and honest documentation.

> ℹ️ **Status:** `0.1.0-preview.1`. The API may change before `1.0`. See [`KNOWN-GAPS.md`](KNOWN-GAPS.md) for exactly what is and isn't covered yet.

---

## What's included

| Primitive | Standard | Purpose |
| --- | --- | --- |
| **ML-KEM-512 / 768 / 1024** | FIPS 203 (NIST levels 1 / 3 / 5) | Key encapsulation (key exchange) |
| **ML-DSA-44 / 65 / 87** | FIPS 204 (NIST levels 2 / 3 / 5) | Digital signatures |
| **X-Wing** | [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) | Hybrid KEM: ML-KEM-768 **+** X25519 |

**Recommended defaults:** `MLKem768` and `MLDsa87`. The other parameter sets are provided for when a different security/size trade-off is genuinely required — each is a separate, clearly named facade so the default stays the obvious choice.

SLH-DSA (FIPS 205) is intentionally **not** included yet: the .NET 10 BCL type is still marked experimental (`SYSLIB5006`). See [`KNOWN-GAPS.md`](KNOWN-GAPS.md).

## Requirements

- **.NET 10** or later. The post-quantum primitives use the native BCL APIs (`System.Security.Cryptography.MLKem`, `MLDsa`, `SHA3_256`, `Shake256`) introduced in .NET 10.

## Installation

```bash
dotnet add package PostQuantum.Cryptography --prerelease
```

## Usage

### ML-KEM-768 — key encapsulation

```csharp
using PostQuantum.Cryptography;

// Recipient generates a key pair and publishes the encapsulation (public) key.
using MLKem768PrivateKey recipient = MLKem768.GenerateKeyPair();
byte[] publicKeyBytes = recipient.ExportEncapsulationKey();

// Sender encapsulates a fresh shared secret to that public key.
using MLKem768PublicKey publicKey = MLKem768.ImportEncapsulationKey(publicKeyBytes);
KemEncapsulation result = publicKey.Encapsulate();
byte[] ciphertext = result.Ciphertext;       // send to recipient
byte[] senderSecret = result.SharedSecret;    // 32 bytes, keep secret

// Recipient recovers the same shared secret from the ciphertext.
byte[] recipientSecret = recipient.Decapsulate(ciphertext);
// senderSecret == recipientSecret
```

### ML-DSA-87 — digital signatures

```csharp
using PostQuantum.Cryptography;

using MLDsa87PrivateKey signer = MLDsa87.GenerateKeyPair();
using MLDsa87PublicKey verifier = signer.GetPublicKey();

byte[] message = "To God be the glory."u8.ToArray();
byte[] signature = signer.SignData(message);

bool ok = verifier.Verify(message, signature); // true
```

An optional `context` (FIPS 204 §5.2) binds a signature to a usage domain. Both sides must agree on it:

```csharp
byte[] context = "invoice-signing-v1"u8.ToArray();
byte[] signature = signer.SignData(message, context);
bool ok = verifier.Verify(message, signature, context);
```

### X-Wing — hybrid KEM (recommended for migrations)

```csharp
using PostQuantum.Cryptography;

using XWingPrivateKey recipient = XWing.GenerateKeyPair();
byte[] publicKeyBytes = recipient.ExportEncapsulationKey(); // 1216 bytes

XWingPublicKey publicKey = XWing.ImportEncapsulationKey(publicKeyBytes);
KemEncapsulation result = publicKey.Encapsulate();

byte[] recipientSecret = recipient.Decapsulate(result.Ciphertext);
// result.SharedSecret == recipientSecret
```

X-Wing's shared secret stays secure as long as **either** ML-KEM-768 **or** X25519 is unbroken, which makes it a strong default while the world transitions to post-quantum cryptography.

### Other parameter sets

```csharp
using MLKemPrivateKey k512 = MLKem512.GenerateKeyPair();   // NIST level 1
using MLKemPrivateKey k1024 = MLKem1024.GenerateKeyPair(); // NIST level 5
using MLDsaPrivateKey d44 = MLDsa44.GenerateKeyPair();     // NIST level 2
using MLDsaPrivateKey d65 = MLDsa65.GenerateKeyPair();     // NIST level 3
```

All facades return the same algorithm-aware `MLKemPrivateKey` / `MLDsaPrivateKey` types, so the rest of your code stays uniform.

### Key import / export (raw, PKCS#8, PEM)

```csharp
using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();

// PEM (PKCS#8 private key, SubjectPublicKeyInfo public key)
string privatePem = priv.ExportPkcs8PrivateKeyPem();
string publicPem  = priv.GetPublicKey().ExportSubjectPublicKeyInfoPem();

using MLKemPrivateKey loaded = MLKemKey.ImportPrivateKeyFromPem(privatePem);
using MLKemPublicKey  pub    = MLKemKey.ImportPublicKeyFromPem(publicPem);

// Or raw fixed-size byte strings (seed / encapsulation / decapsulation key)
byte[] seed = priv.ExportPrivateSeed();
using MLKemPrivateKey fromSeed = MLKem768.ImportPrivateSeed(seed);
```

ML-DSA exposes the same surface via `MLDsaKey` and the `MLDsaPrivateKey` / `MLDsaPublicKey` types.

## Security posture

- **Secure by default.** Every key is generated with a cryptographically secure RNG. There are no insecure modes, no "raw" backdoors, and no footgun parameters.
- **Standards-based.** ML-KEM-768 and ML-DSA-87 are the FIPS 203 / FIPS 204 implementations shipped in the .NET 10 runtime. X-Wing follows `draft-connolly-cfrg-xwing-kem`.
- **Minimal trusted code.** The only cryptographic code original to this library is a faithful, constant-time port of X25519 (RFC 7748), which the BCL does not provide. It is verified against the RFC 7748 known-answer tests. Everything else delegates to the platform.
- **Sensitive material is cleared.** Private-key objects implement `IDisposable` and zero their secrets (and intermediate shared secrets) on disposal. **Dispose your keys.**
- **Shared secrets are yours to protect.** Use a returned `SharedSecret` to key a symmetric algorithm, then clear it with `CryptographicOperations.ZeroMemory`.
- **Honest about gaps.** This is preview software. Read [`KNOWN-GAPS.md`](KNOWN-GAPS.md) and [`SECURITY.md`](SECURITY.md) before depending on it.

This library has **not** undergone an independent security audit. See [`SECURITY.md`](SECURITY.md) for reporting vulnerabilities.

## Project layout

```
src/    PostQuantum.Cryptography      — the library
tests/  PostQuantum.Cryptography.Tests — round-trip and known-answer tests
docs/   additional documentation
```

## Building and testing

```bash
dotnet build -c Release
dotnet test  -c Release
```

## License

[MIT](LICENSE) © 2026 Paul Clark.

---

*To God be the glory.* — 1 Corinthians 10:31
