using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// A <see cref="FactAttribute"/> for X-Wing known-answer tests. It is skipped
/// when the platform does not support ML-KEM/ML-DSA, or when the specification
/// KAT vectors are not embedded (<see cref="XWingKnownAnswers.Available"/>).
/// </summary>
public sealed class XWingKatFactAttribute : FactAttribute
{
    public XWingKatFactAttribute()
    {
        if (!MLKem.IsSupported || !MLDsa.IsSupported || !XWingKnownAnswers.Available)
        {
            Skip = "ML-KEM/ML-DSA unsupported on this platform/runtime, or X-Wing KAT vectors not embedded.";
        }
    }
}
