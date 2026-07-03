// Sample 05 — A small command-line tool that does PQ-secure detached signing.
//
// Commands:
//   pqcsign keygen    --out-priv signer.key.pem --out-pub signer.pub.pem [--password <p>]
//   pqcsign sign      --key signer.key.pem --in document.pdf --out document.pdf.sig [--password <p>]
//   pqcsign verify    --key signer.pub.pem --in document.pdf --sig document.pdf.sig
//
// Demonstrates: building a realistic CLI surface on top of the library —
// parsing args, loading PEM keys, signing files, returning meaningful exit
// codes (0 = ok, 1 = bad signature, 2 = usage / IO error). Production-ready
// CLIs will of course want a proper arg parser; we keep it dependency-free
// here.

using System.Text;
using PostQuantum.Cryptography;

if (!MLDsa87.IsSupported)
{
    Console.Error.WriteLine("ML-DSA-87 is not supported on this runtime.");
    return 2;
}

if (args.Length == 0)
{
    PrintUsage();
    return 2;
}

string command = args[0];
Dictionary<string, string> flags = ParseFlags(args.AsSpan(1));

try
{
    return command switch
    {
        "keygen"  => CmdKeygen(flags),
        "sign"    => CmdSign(flags),
        "verify"  => CmdVerify(flags),
        "--help" or "-h" or "help" => Help(),
        _ => UnknownCommand(command),
    };
}
catch (IOException ex)
{
    // Covers FileNotFoundException, DirectoryNotFoundException, and friends.
    Console.Error.WriteLine($"error: {ex.Message}");
    return 2;
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine($"error: {ex.Message}");
    return 2;
}
catch (System.Security.Cryptography.CryptographicException ex)
{
    // Wrong --password on an encrypted key lands here.
    Console.Error.WriteLine($"error: {ex.Message}");
    return 2;
}

static int CmdKeygen(Dictionary<string, string> flags)
{
    string privPath = Require(flags, "--out-priv");
    string pubPath  = Require(flags, "--out-pub");
    string? password = flags.GetValueOrDefault("--password");

    using MLDsaPrivateKey signer   = MLDsa87.GenerateKeyPair();
    using MLDsaPublicKey  verifier = signer.GetPublicKey();

    // With --password the private key is written as encrypted PKCS#8
    // (PBKDF2-HMAC-SHA256 · 600k iterations · AES-256-CBC — the library's
    // single fixed policy). Without it, plaintext PKCS#8: fine for throwaway
    // keys, wrong for anything long-lived.
    File.WriteAllText(privPath, password is null
        ? signer.ExportPkcs8PrivateKeyPem()
        : signer.ExportEncryptedPkcs8PrivateKeyPem(password));
    File.WriteAllText(pubPath,  verifier.ExportSubjectPublicKeyInfoPem());

    Console.WriteLine($"wrote private key  : {privPath}{(password is null ? " (PLAINTEXT — consider --password)" : " (encrypted)")}");
    Console.WriteLine($"wrote public key   : {pubPath}");
    return 0;
}

static int CmdSign(Dictionary<string, string> flags)
{
    string keyPath = Require(flags, "--key");
    string inPath  = Require(flags, "--in");
    string outPath = Require(flags, "--out");
    string? password = flags.GetValueOrDefault("--password");
    byte[] context = Encoding.UTF8.GetBytes(flags.GetValueOrDefault("--context", "pqcsign/v1"));

    string keyPem = File.ReadAllText(keyPath);
    using MLDsaPrivateKey signer = password is null
        ? MLDsaKey.ImportPrivateKeyFromPem(keyPem)
        : MLDsaKey.ImportEncryptedPrivateKeyFromPem(password, keyPem);
    byte[] data = File.ReadAllBytes(inPath);
    byte[] signature = signer.SignData(data, context);
    File.WriteAllBytes(outPath, signature);

    Console.WriteLine($"signed {inPath} ({data.Length} bytes) → {outPath} ({signature.Length} bytes)");
    return 0;
}

static int CmdVerify(Dictionary<string, string> flags)
{
    string keyPath = Require(flags, "--key");
    string inPath  = Require(flags, "--in");
    string sigPath = Require(flags, "--sig");
    byte[] context = Encoding.UTF8.GetBytes(flags.GetValueOrDefault("--context", "pqcsign/v1"));

    using MLDsaPublicKey verifier = MLDsaKey.ImportPublicKeyFromPem(File.ReadAllText(keyPath));
    byte[] data = File.ReadAllBytes(inPath);
    byte[] signature = File.ReadAllBytes(sigPath);

    bool ok = verifier.Verify(data, signature, context);
    Console.WriteLine(ok ? "VALID" : "INVALID");
    return ok ? 0 : 1;
}

static int Help()
{
    PrintUsage();
    return 0;
}

static int UnknownCommand(string command)
{
    Console.Error.WriteLine($"error: unknown command '{command}'.");
    PrintUsage();
    return 2;
}

static void PrintUsage()
{
    Console.WriteLine("pqcsign — ML-DSA-87 detached signing CLI (sample)");
    Console.WriteLine();
    Console.WriteLine("Commands:");
    Console.WriteLine("  keygen --out-priv <path> --out-pub <path> [--password <p>]");
    Console.WriteLine("  sign   --key <priv-pem> --in <file> --out <sig> [--context <s>] [--password <p>]");
    Console.WriteLine("  verify --key <pub-pem>  --in <file> --sig <sig> [--context <s>]");
    Console.WriteLine();
    Console.WriteLine("With --password the private key is stored as encrypted PKCS#8.");
    Console.WriteLine();
    Console.WriteLine("Exit codes: 0 = ok / valid, 1 = invalid signature, 2 = usage / IO error.");
}

static Dictionary<string, string> ParseFlags(ReadOnlySpan<string> args)
{
    var map = new Dictionary<string, string>(StringComparer.Ordinal);
    for (int i = 0; i < args.Length; i += 2)
    {
        if (i + 1 >= args.Length)
        {
            throw new ArgumentException($"flag {args[i]} is missing a value");
        }

        map[args[i]] = args[i + 1];
    }

    return map;
}

static string Require(Dictionary<string, string> flags, string name)
{
    if (!flags.TryGetValue(name, out string? value) || string.IsNullOrEmpty(value))
    {
        throw new ArgumentException($"missing required flag {name}");
    }

    return value;
}
