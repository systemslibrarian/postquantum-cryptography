# Third-Party Notices

`PostQuantum.Cryptography` incorporates the following third-party material.
Each entry is licensed under the terms reproduced below.

## TweetNaCl — X25519 implementation

The constant-time X25519 (Curve25519 Diffie-Hellman, RFC 7748) implementation
in [`src/PostQuantum.Cryptography/Internal/X25519.cs`](src/PostQuantum.Cryptography/Internal/X25519.cs)
is a faithful port of the field arithmetic and Montgomery ladder from
[**TweetNaCl**](https://tweetnacl.cr.yp.to/) (`crypto_scalarmult`), authored by
Daniel J. Bernstein, Bernard van Gastel, Wesley Janssen, Tanja Lange, Peter
Schwabe, and Sjaak Smetsers.

TweetNaCl is **dedicated to the public domain** by its authors. From the
TweetNaCl distribution:

> All TweetNaCl software is in the public domain.

This library reproduces no TweetNaCl source verbatim; the C source was
re-expressed in C# while preserving the algorithmic structure. Errors in
translation are ours.

## .NET runtime and BCL primitives

`MLKem`, `MLDsa`, `SHA3_256`, and `Shake256` are provided by
[.NET 10](https://github.com/dotnet/runtime), © .NET Foundation and contributors,
licensed under the
[MIT License](https://github.com/dotnet/runtime/blob/main/LICENSE.TXT).

## Microsoft.SourceLink.GitHub

Used at build time to embed source-link metadata.
© Microsoft Corporation, licensed under the
[MIT License](https://github.com/dotnet/sourcelink/blob/main/License.txt).

## Microsoft.CodeAnalysis.PublicApiAnalyzers

Used at build time to track the public API surface. © Microsoft Corporation,
licensed under the
[MIT License](https://github.com/dotnet/roslyn-analyzers/blob/main/License.txt).

---

*To God be the glory.* — 1 Corinthians 10:31
