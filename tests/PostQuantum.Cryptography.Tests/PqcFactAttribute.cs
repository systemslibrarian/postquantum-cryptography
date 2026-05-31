using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// A <see cref="FactAttribute"/> that is skipped when the current platform or
/// runtime does not support the native ML-KEM / ML-DSA primitives.
/// </summary>
/// <remarks>
/// .NET 10 surfaces ML-KEM (FIPS 203) and ML-DSA (FIPS 204) through the BCL, but
/// availability depends on the underlying platform crypto provider (on Linux,
/// OpenSSL 3.5+ wired into the runtime). On hosts where the runtime does not
/// expose these algorithms, <see cref="MLKem.IsSupported"/> /
/// <see cref="MLDsa.IsSupported"/> return <see langword="false"/> and the BCL
/// throws <see cref="System.PlatformNotSupportedException"/>. Tests that exercise
/// these primitives are skipped (not failed) in that situation. The pure-managed
/// X25519 known-answer tests are not gated and always run.
/// </remarks>
public sealed class PqcFactAttribute : FactAttribute
{
    public PqcFactAttribute()
    {
        if (!MLKem.IsSupported || !MLDsa.IsSupported)
        {
            Skip = "ML-KEM/ML-DSA are not supported on this platform/runtime (requires .NET 10 with a PQC-capable crypto provider, e.g. OpenSSL 3.5+ on Linux).";
        }
    }
}
