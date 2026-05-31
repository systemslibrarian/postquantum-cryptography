// Sample 05 — A small command-line tool that does PQ-secure detached signing.
//
// Commands:
//   pqcsign keygen    --out-priv signer.key.pem --out-pub signer.pub.pem
//   pqcsign sign      --key signer.key.pem --in document.pdf --out document.pdf.sig
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
catch (FileNotFoundException ex)
{
    Console.Error.WriteLine($"error: {ex.Message}");
    return 2;
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine($"error: {ex.Message}");
    return 2;
}

static int CmdKeygen(Dictionary<string, string> flags)
{
    string privPath = Require(flags, "--out-priv");
    string pubPath  = Require(flags, "--out-pub");

    using MLDsaPrivateKey signer   = MLDsa87.GenerateKeyPair();
    using MLDsaPublicKey  verifier = signer.GetPublicKey();

    File.WriteAllText(privPath, signer.ExportPkcs8PrivateKeyPem());
    File.WriteAllText(pubPath,  verifier.ExportSubjectPublicKeyInfoPem());

    Console.WriteLine($"wrote private key  : {privPath}");
    Console.WriteLine($"wrote public key   : {pubPath}");
    return 0;
}

static int CmdSign(Dictionary<string, string> flags)
{
    string keyPath = Require(flags, "--key");
    string inPath  = Require(flags, "--in");
    string outPath = Require(flags, "--out");
    byte[] context = Encoding.UTF8.GetBytes(flags.GetValueOrDefault("--context", "pqcsign/v1"));

    using MLDsaPrivateKey signer = MLDsaKey.ImportPrivateKeyFromPem(File.ReadAllText(keyPath));
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
    Console.WriteLine("  keygen --out-priv <path> --out-pub <path>");
    Console.WriteLine("  sign   --key <priv-pem> --in <file> --out <sig> [--context <s>]");
    Console.WriteLine("  verify --key <pub-pem>  --in <file> --sig <sig> [--context <s>]");
    Console.WriteLine();
    Console.WriteLine("Exit codes: 0 = ok / valid, 1 = invalid signature, 2 = usage / IO error.");
}

static Dictionary<string, string> ParseFlags(ReadOnlySpan<string> args)
{
    var map = new Dictionary<string, string>(StringComparer.Ordinal);
    for (int i = 0; i + 1 < args.Length; i += 2)
    {
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
