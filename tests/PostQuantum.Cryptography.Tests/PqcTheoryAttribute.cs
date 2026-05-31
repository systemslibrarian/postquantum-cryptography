using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// A <see cref="TheoryAttribute"/> that is skipped when the current platform or
/// runtime does not support the native ML-KEM / ML-DSA primitives. The theory
/// counterpart of <see cref="PqcFactAttribute"/>.
/// </summary>
public sealed class PqcTheoryAttribute : TheoryAttribute
{
    public PqcTheoryAttribute()
    {
        if (!MLKem.IsSupported || !MLDsa.IsSupported)
        {
            Skip = "ML-KEM/ML-DSA are not supported on this platform/runtime (requires .NET 10 with a PQC-capable crypto provider, e.g. OpenSSL 3.5+ on Linux).";
        }
    }
}
