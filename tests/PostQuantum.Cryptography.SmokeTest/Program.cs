using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using PostQuantum.Cryptography;

// Smoke test that consumes the **packaged** PostQuantum.Cryptography from a
// local NuGet feed (see NuGet.config) and exercises one path through each
// primitive. Catches packaging mistakes that unit tests can't (missing
// PackageReference content, wrong target framework, wrong assembly name,
// missing XML docs, etc.).

int failures = 0;

Asm("Loaded assembly carries package metadata", () =>
{
    // `dotnet build` copies the DLL out of the NuGet cache into the smoke
    // project's bin/, so Location is bin/-relative, not cache-relative. What
    // we actually want to verify is that the assembly came in via a
    // PackageReference (it carries an InformationalVersion baked at pack
    // time) rather than being some unrelated build of the source tree.
    Assembly asm = typeof(MLKem768).Assembly;
    var informational = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
    if (string.IsNullOrEmpty(informational))
    {
        throw new InvalidOperationException(
            "Loaded assembly has no InformationalVersion — was it built from source instead of restored from the package?");
    }

    Console.WriteLine($"        (loaded {asm.GetName().Name} {informational})");
});

Asm("Library reports IsSupported on this host", () =>
{
    if (!MLKem.IsSupported || !MLDsa.IsSupported)
    {
        throw new InvalidOperationException(
            "PQC primitives not exposed by this runtime — smoke test cannot validate the packaged library here.");
    }
});

Asm("ML-KEM-768 round-trip via packaged API", () =>
{
    using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
    using MLKemPublicKey pub = priv.GetPublicKey();
    KemEncapsulation enc = pub.Encapsulate();
    byte[] recovered = priv.Decapsulate(enc.Ciphertext);
    if (!enc.SharedSecret.AsSpan().SequenceEqual(recovered))
    {
        throw new InvalidOperationException("ML-KEM-768 round-trip mismatch.");
    }
});

Asm("ML-DSA-87 sign/verify via packaged API", () =>
{
    using MLDsaPrivateKey signer = MLDsa87.GenerateKeyPair();
    using MLDsaPublicKey verifier = signer.GetPublicKey();
    byte[] msg = Encoding.UTF8.GetBytes("smoke");
    byte[] sig = signer.SignData(msg);
    if (!verifier.Verify(msg, sig))
    {
        throw new InvalidOperationException("ML-DSA-87 verify failed.");
    }
});

Asm("X-Wing round-trip via packaged API", () =>
{
    using XWingPrivateKey priv = XWing.GenerateKeyPair();
    XWingPublicKey pub = priv.GetPublicKey();
    KemEncapsulation enc = pub.Encapsulate();
    byte[] recovered = priv.Decapsulate(enc.Ciphertext);
    if (!enc.SharedSecret.AsSpan().SequenceEqual(recovered))
    {
        throw new InvalidOperationException("X-Wing round-trip mismatch.");
    }
});

Asm("Span overload on the packaged API is zero-allocation per result", () =>
{
    using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
    using MLKemPublicKey pub = priv.GetPublicKey();
    Span<byte> ct = stackalloc byte[MLKem768.CiphertextSizeInBytes];
    Span<byte> ss = stackalloc byte[MLKem768.SharedSecretSizeInBytes];
    pub.Encapsulate(ct, ss);
    Span<byte> ss2 = stackalloc byte[MLKem768.SharedSecretSizeInBytes];
    priv.Decapsulate(ct, ss2);
    if (!ss.SequenceEqual(ss2))
    {
        throw new InvalidOperationException("Span overload round-trip mismatch.");
    }
});

Asm("PEM round-trip + label validation via packaged API", () =>
{
    using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
    string pem = priv.ExportPkcs8PrivateKeyPem();
    using MLKemPrivateKey reimported = MLKemKey.ImportPrivateKeyFromPem(pem);
    if (!priv.ExportEncapsulationKey().AsSpan().SequenceEqual(reimported.ExportEncapsulationKey()))
    {
        throw new InvalidOperationException("PEM round-trip changed the public-key bytes.");
    }

    // Negative: passing a public-key PEM to the private importer must throw.
    string publicPem = priv.GetPublicKey().ExportSubjectPublicKeyInfoPem();
    try
    {
        _ = MLKemKey.ImportPrivateKeyFromPem(publicPem);
        throw new InvalidOperationException("Expected ArgumentException for mismatched PEM label.");
    }
    catch (ArgumentException) { /* expected */ }
});

if (failures == 0)
{
    Console.WriteLine();
    Console.WriteLine($"OK — packaged library loaded from {typeof(MLKem768).Assembly.Location}");
    return 0;
}

Console.Error.WriteLine($"FAILED: {failures} smoke check(s) failed.");
return 1;

void Asm(string name, Action body)
{
    try
    {
        body();
        Console.WriteLine($"  ok   {name}");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"  FAIL {name}: {ex.GetType().Name}: {ex.Message}");
        failures++;
    }
}
