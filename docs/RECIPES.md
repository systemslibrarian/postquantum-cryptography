# Recipes

How-tos for common tasks. Each recipe is a self-contained snippet plus a link
to a fully runnable [sample](../samples/) when one exists.

For algorithm picking guidance, see the top-level [README](../README.md). For
what isn't included and why, see [KNOWN-GAPS.md](../KNOWN-GAPS.md).

---

## Table of contents

- [Picking the right primitive](#picking-the-right-primitive)
- [Key encapsulation](#key-encapsulation)
  - [Recipe 1 — Hybrid handshake (X-Wing, recommended)](#recipe-1--hybrid-handshake-x-wing-recommended)
  - [Recipe 2 — Pure-PQ key exchange (ML-KEM-768)](#recipe-2--pure-pq-key-exchange-ml-kem-768)
  - [Recipe 3 — Encrypt a file to a public key](#recipe-3--encrypt-a-file-to-a-public-key)
- [Digital signatures](#digital-signatures)
  - [Recipe 4 — Sign and verify a message](#recipe-4--sign-and-verify-a-message)
  - [Recipe 5 — Domain-bind a signature with a context](#recipe-5--domain-bind-a-signature-with-a-context)
  - [Recipe 6 — Detached file signing](#recipe-6--detached-file-signing)
- [Key handling](#key-handling)
  - [Recipe 7 — Persist a key as PEM and load it back](#recipe-7--persist-a-key-as-pem-and-load-it-back)
  - [Recipe 8 — Derive a key pair deterministically from a seed](#recipe-8--derive-a-key-pair-deterministically-from-a-seed)
- [Performance](#performance)
  - [Recipe 9 — Zero-allocation in a hot loop](#recipe-9--zero-allocation-in-a-hot-loop)
- [Hygiene](#hygiene)
  - [Recipe 10 — Constant-time secret comparison](#recipe-10--constant-time-secret-comparison)
  - [Recipe 11 — Detecting unsupported platforms gracefully](#recipe-11--detecting-unsupported-platforms-gracefully)

---

## Picking the right primitive

| You want to…                                          | Use                                          |
| ----------------------------------------------------- | -------------------------------------------- |
| Agree on a shared key with a peer, PQ-secure today    | [`XWing`](#recipe-1--hybrid-handshake-x-wing-recommended) (hybrid, recommended default) |
| Agree on a shared key, PQ-only (no classical hedge)   | [`MLKem768`](#recipe-2--pure-pq-key-exchange-ml-kem-768) |
| Encrypt a payload to a recipient's public key         | [`XWing` + AES-GCM](#recipe-3--encrypt-a-file-to-a-public-key) |
| Sign a document                                       | [`MLDsa87`](#recipe-4--sign-and-verify-a-message) (FIPS 204 level 5) |
| Sign with usage-domain binding                        | [`MLDsa87` + context](#recipe-5--domain-bind-a-signature-with-a-context) |
| Persist a key                                         | [PKCS#8 PEM](#recipe-7--persist-a-key-as-pem-and-load-it-back) |
| Re-derive the same key from backup material           | [Seeded import](#recipe-8--derive-a-key-pair-deterministically-from-a-seed) |
| Maximum throughput                                    | [Span overloads](#recipe-9--zero-allocation-in-a-hot-loop) |

---

## Key encapsulation

### Recipe 1 — Hybrid handshake (X-Wing, recommended)

**When:** you're agreeing on a key with another party and want the result to
stay secure as long as either ML-KEM-768 or X25519 is unbroken.

```csharp
using PostQuantum.Cryptography;

// Recipient: generate a key pair, publish the public part (1216 bytes).
using XWingPrivateKey recipient = XWing.GenerateKeyPair();
byte[] recipientPub = recipient.ExportEncapsulationKey();

// Sender: import recipient's public key, encapsulate a fresh shared secret.
using XWingPublicKey pub = XWing.ImportEncapsulationKey(recipientPub);
KemEncapsulation kem = pub.Encapsulate();
byte[] sharedSecret = kem.SharedSecret;       // 32 bytes — use as a key
byte[] ciphertext   = kem.Ciphertext;          // 1120 bytes — send to recipient

// Recipient: recover the same shared secret.
byte[] recovered = recipient.Decapsulate(ciphertext);
```

> Runnable end-to-end: [`samples/01-XWingHandshake`](../samples/01-XWingHandshake/).

### Recipe 2 — Pure-PQ key exchange (ML-KEM-768)

**When:** you specifically need only the post-quantum component (e.g. you're
combining ML-KEM with your own classical KEM somewhere else, or you've already
weighed the trade-offs).

```csharp
using PostQuantum.Cryptography;

using MLKemPrivateKey recipient = MLKem768.GenerateKeyPair();
using MLKemPublicKey pub        = recipient.GetPublicKey();

KemEncapsulation enc      = pub.Encapsulate();
byte[] recoveredSecret    = recipient.Decapsulate(enc.Ciphertext);
```

For NIST level 1 use `MLKem512`; for level 5 use `MLKem1024`.

### Recipe 3 — Encrypt a file to a public key

**When:** you want to ship a payload that only the recipient can read.

Compose: `KEM → HKDF-SHA-256 → AES-GCM`. The KEM gives you a per-message
shared secret; HKDF derives an AES key + nonce from it so two messages to the
same recipient don't reuse keys; AES-GCM authenticates the payload.

> Full implementation, including envelope format and associated-data binding:
> [`samples/03-HybridFileEncryption`](../samples/03-HybridFileEncryption/).

---

## Digital signatures

### Recipe 4 — Sign and verify a message

```csharp
using PostQuantum.Cryptography;

using MLDsaPrivateKey signer    = MLDsa87.GenerateKeyPair();
using MLDsaPublicKey  verifier  = signer.GetPublicKey();

byte[] message   = "hello"u8.ToArray();
byte[] signature = signer.SignData(message);
bool ok          = verifier.Verify(message, signature);
```

For NIST level 2 use `MLDsa44`; for level 3 use `MLDsa65`.

### Recipe 5 — Domain-bind a signature with a context

**When:** the same key signs different kinds of things (invoices, tokens, log
entries) and you don't want a signature minted for one purpose to be
replayable as another. FIPS 204 §5.2 defines an up-to-255-byte *context* that
both signer and verifier must supply identically.

```csharp
byte[] context = "invoice-signing/v1"u8.ToArray();

byte[] sig = signer.SignData(message, context);

bool good      = verifier.Verify(message, sig, context);            // true
bool wrongCtx  = verifier.Verify(message, sig, "other-domain"u8);   // false
bool emptyCtx  = verifier.Verify(message, sig);                     // false
```

Contexts longer than 255 bytes are rejected up-front with `ArgumentException`.

### Recipe 6 — Detached file signing

The library doesn't ship a CLI, but building one is a few dozen lines.

> Working `keygen` / `sign` / `verify` CLI with proper exit codes:
> [`samples/05-DetachedSignatureCli`](../samples/05-DetachedSignatureCli/).

---

## Key handling

### Recipe 7 — Persist a key as PEM and load it back

**When:** you need to write a key to disk, a vault, a secret manager, or
exchange it with another tool.

```csharp
using MLKemPrivateKey original = MLKem768.GenerateKeyPair();

string privatePem = original.ExportPkcs8PrivateKeyPem();           // BEGIN PRIVATE KEY
string publicPem  = original.GetPublicKey().ExportSubjectPublicKeyInfoPem(); // BEGIN PUBLIC KEY

// Round-trip. The importer validates the PEM label up front, so passing the
// wrong kind of PEM (e.g., publicPem to the private importer) throws
// ArgumentException immediately instead of a confusing CryptographicException
// later when you try to decapsulate.
using MLKemPrivateKey reimported = MLKemKey.ImportPrivateKeyFromPem(privatePem);
using MLKemPublicKey  pub        = MLKemKey.ImportPublicKeyFromPem(publicPem);
```

Same surface on `MLDsaKey` for ML-DSA. For raw byte-string interchange (smaller
but loses the parameter-set identifier), use `ExportEncapsulationKey()` etc.

> Runnable end-to-end: [`samples/02-SignAndVerifyFiles`](../samples/02-SignAndVerifyFiles/).

### Recipe 8 — Derive a key pair deterministically from a seed

**When:** you back up a small seed and want to be able to rederive the same
key pair (for HD wallet–style key derivation, deterministic test fixtures,
or backup-and-restore flows).

```csharp
// Generate; export the *seed* (64 bytes for ML-KEM, 32 bytes for ML-DSA / X-Wing).
using MLKemPrivateKey original = MLKem768.GenerateKeyPair();
byte[] seed = original.ExportPrivateSeed();   // 64 bytes — store securely

// Rebuild later from the same seed. Both the public AND the expanded
// decapsulation key are byte-identical.
using MLKemPrivateKey restored = MLKem768.ImportPrivateSeed(seed);
```

For X-Wing, the 32-byte decapsulation key *is* the seed — no separate
"private seed" concept: `XWing.ImportDecapsulationKey(seed)`.

---

## Performance

### Recipe 9 — Zero-allocation in a hot loop

**When:** you're driving many handshakes or signatures per second and don't
want GC pressure on every call.

```csharp
using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
using MLKemPublicKey pub   = priv.GetPublicKey();

Span<byte> ciphertext   = stackalloc byte[MLKem768.CiphertextSizeInBytes];
Span<byte> sharedSecret = stackalloc byte[MLKem768.SharedSecretSizeInBytes];

for (int i = 0; i < n; i++)
{
    pub.Encapsulate(ciphertext, sharedSecret);   // 0 heap allocs on this call
    // ... use sharedSecret to drive a symmetric algorithm ...
}
```

The Span overloads exist on `MLKemPublicKey.Encapsulate`,
`MLKemPrivateKey.Decapsulate`, `XWingPublicKey.Encapsulate`,
`XWingPrivateKey.Decapsulate`, and `MLDsaPrivateKey.SignData`.

> Runnable benchmark of allocating vs Span path:
> [`samples/04-ZeroAllocHotLoop`](../samples/04-ZeroAllocHotLoop/). Typical
> result on a developer laptop: **0 bytes/op** Span vs **1224 bytes/op**
> allocating, similar wall-clock time per op.

---

## Hygiene

### Recipe 10 — Constant-time secret comparison

**When:** you need to check that two secrets are byte-equal without leaking
timing information about *which* byte differs.

```csharp
using System.Security.Cryptography;

bool same = CryptographicOperations.FixedTimeEquals(secretA, secretB);
```

**Do not** use `secretA.SequenceEqual(secretB)` or `==` on a
`KemEncapsulation` value for content comparison — those short-circuit on the
first mismatch and leak timing info. The library's `KemEncapsulation.Equals`
deliberately compares the *array references*, not their contents, to make the
unsafe path harder to take by accident.

### Recipe 11 — Detecting unsupported platforms gracefully

**When:** your code might run on a runtime where ML-KEM/ML-DSA aren't
exposed (older Linux without OpenSSL 3.5+, some macOS builds, etc.).

```csharp
if (!MLKem768.IsSupported || !MLDsa87.IsSupported)
{
    // Fall back to classical crypto or surface a clear setup error.
    log.LogWarning("PQC primitives unavailable on this runtime.");
    return UseClassicalFallback();
}
```

`IsSupported` is also available on `XWing` (which additionally requires
`SHA3_256` / `Shake256`).

See the [platform / runtime support matrix](../README.md#platform--runtime-support-matrix)
in the top-level README for which combinations expose which primitives.

---

*To God be the glory.* — 1 Corinthians 10:31
