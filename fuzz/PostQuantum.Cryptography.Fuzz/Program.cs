using System.Security.Cryptography;
using PostQuantum.Cryptography;
using PostQuantum.Cryptography.Fuzz;
using SharpFuzz;

// Coverage-guided fuzzer entry point. Drives one target per process; the
// target is selected by FUZZ_TARGET env var so a single binary can be invoked
// against several harnesses without recompilation.
//
// Use with afl-fuzz (afl++) via sharpfuzz instrumentation:
//
//   1. Publish & instrument:
//        dotnet publish fuzz/PostQuantum.Cryptography.Fuzz -c Release -o ./fuzz-out
//        sharpfuzz ./fuzz-out/PostQuantum.Cryptography.dll
//
//   2. Run:
//        FUZZ_TARGET=mlkem-decap afl-fuzz -i corpus/mlkem -o findings/mlkem -- ./fuzz-out/PostQuantum.Cryptography.Fuzz
//
// Targets must (by contract):
//   - never throw on arbitrary input (anything below ArgumentException),
//   - never enter infinite loops,
//   - be deterministic for the same input bytes.

string target = Environment.GetEnvironmentVariable("FUZZ_TARGET") ?? TargetIds.MLKemDecap;
Console.Error.WriteLine($"[fuzz] target = {target}");

if (!MLKem.IsSupported || !MLDsa.IsSupported)
{
    Console.Error.WriteLine("[fuzz] PQC primitives unsupported on this host — aborting.");
    return 1;
}

switch (target)
{
    case TargetIds.MLKemDecap:
        {
            using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
            byte[] buffer = new byte[MLKem768.SharedSecretSizeInBytes];
            Fuzzer.Run(stream =>
            {
                byte[] data = ReadAll(stream);
                if (data.Length != MLKem768.CiphertextSizeInBytes) return;
                priv.Decapsulate(data, buffer);
            });
            break;
        }

    case TargetIds.XWingDecap:
        {
            using XWingPrivateKey priv = XWing.GenerateKeyPair();
            byte[] buffer = new byte[XWing.SharedSecretSizeInBytes];
            Fuzzer.Run(stream =>
            {
                byte[] data = ReadAll(stream);
                if (data.Length != XWing.CiphertextSizeInBytes) return;
                priv.Decapsulate(data, buffer);
            });
            break;
        }

    case TargetIds.MLDsaVerify:
        {
            using MLDsaPrivateKey signer = MLDsa87.GenerateKeyPair();
            using MLDsaPublicKey verifier = signer.GetPublicKey();
            byte[] message = "fuzz target message"u8.ToArray();
            Fuzzer.Run(stream =>
            {
                byte[] data = ReadAll(stream);
                if (data.Length != MLDsa87.SignatureSizeInBytes) return;
                verifier.Verify(message, data);
            });
            break;
        }

    case TargetIds.MLKemImportEk:
        {
            // Importer for a public key. Wrong-size or otherwise malformed input
            // must surface as ArgumentException / CryptographicException, not an
            // uncaught exception. Anything below those is a real crash.
            Fuzzer.Run(stream =>
            {
                byte[] data = ReadAll(stream);
                try { _ = MLKem768.ImportEncapsulationKey(data); }
                catch (ArgumentException) { }
                catch (CryptographicException) { }
            });
            break;
        }

    case TargetIds.MLKemImportPem:
        {
            Fuzzer.Run(stream =>
            {
                byte[] data = ReadAll(stream);
                string text;
                try { text = System.Text.Encoding.UTF8.GetString(data); }
                catch (ArgumentException) { return; }

                try { _ = MLKemKey.ImportPrivateKeyFromPem(text); }
                catch (ArgumentException) { }
                catch (CryptographicException) { }
            });
            break;
        }

    default:
        Console.Error.WriteLine($"[fuzz] unknown FUZZ_TARGET '{target}'.");
        return 2;
}

return 0;

static byte[] ReadAll(Stream stream)
{
    using var ms = new MemoryStream();
    stream.CopyTo(ms);
    return ms.ToArray();
}

namespace PostQuantum.Cryptography.Fuzz
{
    internal static class TargetIds
    {
        public const string MLKemDecap = "mlkem-decap";
        public const string XWingDecap = "xwing-decap";
        public const string MLDsaVerify = "mldsa-verify";
        public const string MLKemImportEk = "mlkem-import-ek";
        public const string MLKemImportPem = "mlkem-import-pem";
    }
}
