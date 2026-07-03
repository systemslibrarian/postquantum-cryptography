// Sample 10 — ASP.NET Core signing service (Recipe 13 made runnable).
//
// Demonstrates: the SAFE key-lifetime pattern for ML-DSA-87 keys in a
// dependency-injection container, exercised under real concurrency and
// self-tested in-process. The app starts Kestrel on a dynamic port, fires
// 48 concurrent POST /sign requests at itself, verifies every signature
// locally against the service's published public key, and exits 0 only if
// all assertions pass.
//
// The rule (SECURITY.md, "Thread-safety"):
//
//   Key INSTANCES are not thread-safe. Static FACADES are.
//
// ---------------------------------------------------------------------------
// THE WRONG PATTERN — do not do this:
//
//     builder.Services.AddSingleton(MLDsa87.GenerateKeyPair());   // BUG!
//
// A singleton MLDsaPrivateKey is shared by every concurrent request. Two
// requests that call SignData(...) on that one instance at the same time
// race inside the underlying System.Security.Cryptography.MLDsa handle:
// you get corrupted signatures that fail verification, surfaced BCL
// CryptographicExceptions, or in the worst case a crashed native handle.
// The failure is load-dependent, so it passes a single-request smoke test
// and detonates in production.
//
// THE SAFE PATTERN (Recipe 13, Pattern A) — used below:
//
//   1. Hold the 32-byte private SEED as the singleton (it is inert data).
//   2. Register MLDsaPrivateKey as SCOPED: each request imports its own
//      instance from the seed via the thread-safe static facade
//      MLDsa87.ImportPrivateSeed(...). Import-from-seed is cheap
//      (docs/PERFORMANCE.md), no instance is ever shared across requests,
//      and the DI container disposes the key at the end of each request.
// ---------------------------------------------------------------------------

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using PostQuantum.Cryptography;

if (!MLDsa87.IsSupported)
{
    Console.Error.WriteLine("ML-DSA-87 is not supported on this runtime.");
    return 1;
}

Console.WriteLine("=== Sample 10: ASP.NET Core signing service (scoped-key pattern) ===\n");

// ---------------------------------------------------------------------------
// 1. Startup: generate the service key once, keep only the 32-byte seed and
//    the public half. In a real deployment the seed comes from a vault or
//    KMS, not from GenerateKeyPair() at boot.
// ---------------------------------------------------------------------------

byte[] seed;
string publicKeyPem;
string keyId;

using (MLDsaPrivateKey bootstrapKey = MLDsa87.GenerateKeyPair())
{
    seed = bootstrapKey.ExportPrivateSeed();                       // 32 bytes
    publicKeyPem = bootstrapKey.ExportSubjectPublicKeyInfoPem();
    // A short stable identifier so clients can tell which key signed what
    // (Recipe 15): first 8 bytes of SHA-256 over the SPKI, hex-encoded.
    keyId = Convert.ToHexStringLower(SHA256.HashData(bootstrapKey.ExportSubjectPublicKeyInfo()))[..16];
}

var builder = WebApplication.CreateBuilder(args);
builder.Logging.SetMinimumLevel(LogLevel.Warning);   // keep the self-test output readable
builder.WebHost.UseUrls("http://127.0.0.1:0");       // dynamic port for the in-process test

// SINGLETON: the seed wrapper — plain bytes, safe to share across threads.
builder.Services.AddSingleton(new SigningKeySeed(seed));
builder.Services.AddSingleton(new ServiceIdentity(publicKeyPem, keyId));

// SCOPED: one MLDsaPrivateKey per request, imported from the shared seed via
// the thread-safe static facade. The container calls Dispose() on it when the
// request scope ends, zeroing the key material (see SECURITY.md).
builder.Services.AddScoped(sp =>
    MLDsa87.ImportPrivateSeed(sp.GetRequiredService<SigningKeySeed>().Value));

var app = builder.Build();

// POST /sign — body: raw bytes to sign; response: { signatureBase64, keyId }.
app.MapPost("/sign", async (HttpContext http, MLDsaPrivateKey signingKey, ServiceIdentity identity) =>
{
    using var buffer = new MemoryStream();
    await http.Request.Body.CopyToAsync(buffer);
    byte[] payload = buffer.ToArray();
    if (payload.Length == 0)
    {
        return Results.Text("Request body must contain the bytes to sign.", statusCode: 400);
    }

    // 'signingKey' is THIS request's private instance — no other request can
    // touch it, so concurrent /sign calls never race (FIPS 204 context binds
    // the signature to this service's domain).
    byte[] signature = signingKey.SignData(payload, Protocol.Context);

    return Results.Json(
        new SignResponse(Convert.ToBase64String(signature), identity.KeyId),
        AppJsonContext.Default.SignResponse);
});

// GET /public-key — response: { publicKeyPem, keyId }.
app.MapGet("/public-key", (ServiceIdentity identity) =>
    Results.Json(
        new PublicKeyResponse(identity.PublicKeyPem, identity.KeyId),
        AppJsonContext.Default.PublicKeyResponse));

// ---------------------------------------------------------------------------
// 2. Self-test: start the server, hammer it with 48 concurrent signing
//    requests, and verify every signature locally like an external client.
// ---------------------------------------------------------------------------

await app.StartAsync();

string baseAddress = app.Services.GetRequiredService<IServer>()
    .Features.Get<IServerAddressesFeature>()!.Addresses.First();
Console.WriteLine($"Service listening on {baseAddress}");

int exitCode = 0;

using (var client = new HttpClient { BaseAddress = new Uri(baseAddress) })
{
    // Fetch the service's public key the way a real client would.
    PublicKeyResponse pk = JsonSerializer.Deserialize(
        await client.GetStringAsync("/public-key"),
        AppJsonContext.Default.PublicKeyResponse)!;
    Console.WriteLine($"Fetched public key (keyId {pk.KeyId})");

    // Fire 48 concurrent signing requests with distinct payloads. On the
    // server this means many overlapping request scopes, each importing and
    // disposing its own key — the pattern under test.
    const int Concurrency = 48;
    byte[][] payloads = Enumerable.Range(0, Concurrency)
        .Select(i => Encoding.UTF8.GetBytes($"invoice #{i:D3} — {Guid.NewGuid():N}"))
        .ToArray();

    Task<SignResponse>[] inFlight = payloads
        .Select(async payload =>
        {
            using var content = new ByteArrayContent(payload);
            using HttpResponseMessage response = await client.PostAsync("/sign", content);
            response.EnsureSuccessStatusCode();
            return JsonSerializer.Deserialize(
                await response.Content.ReadAsStringAsync(),
                AppJsonContext.Default.SignResponse)!;
        })
        .ToArray();

    SignResponse[] responses = await Task.WhenAll(inFlight);
    Console.WriteLine($"Completed {responses.Length} concurrent /sign requests");

    // Verify locally. Note: the verification loop is sequential on purpose —
    // this one MLDsaPublicKey instance has the same "not thread-safe"
    // contract as the private key.
    int verified = 0;
    bool keyIdsConsistent = true;
    using (MLDsaPublicKey verifier = MLDsaKey.ImportPublicKeyFromPem(pk.PublicKeyPem))
    {
        for (int i = 0; i < payloads.Length; i++)
        {
            byte[] signature = Convert.FromBase64String(responses[i].SignatureBase64);
            if (verifier.Verify(payloads[i], signature, Protocol.Context))
            {
                verified++;
            }

            keyIdsConsistent &= responses[i].KeyId == pk.KeyId;
        }

        // Negative case: a tampered payload must not verify.
        byte[] tampered = (byte[])payloads[0].Clone();
        tampered[0] ^= 0xFF;
        bool tamperedAccepted = verifier.Verify(
            tampered, Convert.FromBase64String(responses[0].SignatureBase64), Protocol.Context);

        Console.WriteLine();
        Console.WriteLine($"Signatures verified        : {verified}/{payloads.Length}");
        Console.WriteLine($"Key ids consistent         : {keyIdsConsistent}");
        Console.WriteLine($"Tampered payload rejected  : {!tamperedAccepted}");

        if (verified != payloads.Length || !keyIdsConsistent || tamperedAccepted)
        {
            Console.Error.WriteLine("\nSELF-TEST FAILED.");
            exitCode = 1;
        }
        else
        {
            Console.WriteLine("\nAll assertions passed: 48 concurrent requests, 48 valid signatures,");
            Console.WriteLine("zero shared key instances. That is the whole point of Recipe 13.");
        }
    }
}

await app.StopAsync();
CryptographicOperations.ZeroMemory(seed);
return exitCode;

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// <summary>The FIPS 204 signing context that domain-binds this service's signatures.</summary>
internal static class Protocol
{
    public static readonly byte[] Context = "signing-service/v1"u8.ToArray();
}

/// <summary>Singleton wrapper for the 32-byte ML-DSA-87 private seed. Inert
/// bytes — unlike a key instance, safe to share across concurrent requests.</summary>
internal sealed record SigningKeySeed(byte[] Value);

/// <summary>Singleton, immutable public identity of the service.</summary>
internal sealed record ServiceIdentity(string PublicKeyPem, string KeyId);

internal sealed record SignResponse(string SignatureBase64, string KeyId);

internal sealed record PublicKeyResponse(string PublicKeyPem, string KeyId);

// Source-generated JSON keeps the sample reflection-free (AOT-friendly).
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(SignResponse))]
[JsonSerializable(typeof(PublicKeyResponse))]
internal sealed partial class AppJsonContext : JsonSerializerContext;
