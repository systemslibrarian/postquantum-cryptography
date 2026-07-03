// Sample 09 — Large-file streaming: sign + encrypt files too big for memory.
//
// This library deliberately has no SignData(Stream). The .NET 10 BCL has no
// streaming ML-DSA, and a wrapper that silently buffered an arbitrarily large
// stream into memory would be deceptive (see KNOWN-GAPS.md). The sanctioned
// large-file patterns (docs/RECIPES.md, Recipe 14) are demonstrated here on a
// 32 MB test file with strictly bounded memory — no step ever holds more than
// one 1 MiB chunk (plus an 80 KB hash buffer), regardless of file size.
//
// Part 1 — hash-then-sign:
//   Stream the file through SHA-256 with a small reusable buffer, then sign
//   only the 32-byte digest with ML-DSA-87 (+ a domain-separation context).
//   The collision resistance of SHA-256 binds the signature to the file body
//   — the same construction cosign and TLS use.
//
// Part 2 — chunked authenticated encryption:
//   Encapsulate ONCE to the recipient's X-Wing public key, expand the shared
//   secret through HKDF-SHA-256 into a single AES-256 key, then AES-GCM each
//   1 MiB chunk independently:
//     nonce = 4-byte chunk index in a zeroed 12-byte buffer (safe here ONLY
//             because the key is unique to this one file, so counter nonces
//             can never collide across messages);
//     AD    = chunk index | total chunk count | total plaintext length,
//             which cryptographically pins chunk ORDER and file COMPLETENESS.
//
//   Envelope wire format:
//     [magic "PQ09"(4) | salt(16) | X-Wing ciphertext(1120)
//      | chunkCount(4, LE) | plaintextLength(8, LE)]
//     then per chunk: [tag(16) | ciphertext(<= 1 MiB)]
//
// Self-checked negatives: a tampered chunk, two swapped chunks (order
// violation caught by the AD), and a truncated envelope (missing chunks
// caught by the header count). Each must be REJECTED with a clean exception.

using System.Buffers.Binary;
using System.Security.Cryptography;
using PostQuantum.Cryptography;

if (!XWing.IsSupported || !MLDsa87.IsSupported)
{
    Console.Error.WriteLine("X-Wing and/or ML-DSA-87 are not supported on this runtime.");
    return 1;
}

Console.WriteLine("=== Sample 09: large-file streaming (hash-then-sign + chunked AES-GCM) ===\n");

string workDir = Path.Combine(Path.GetTempPath(), "pqc-sample-09");
Directory.CreateDirectory(workDir);
string bigFilePath   = Path.Combine(workDir, "big.bin");
string envelopePath  = Path.Combine(workDir, "big.bin.pqenv");
string roundTripPath = Path.Combine(workDir, "big.roundtrip.bin");
string truncatedPath = Path.Combine(workDir, "big.bin.pqenv.truncated");
string junkPath      = Path.Combine(workDir, "junk.bin"); // sink for decrypts that must fail

try
{
    // -----------------------------------------------------------------------
    // 0. Synthesize a 32 MB test file — streamed to disk, never held in RAM.
    //    Deterministic pseudo-random blocks: SHA-256 over a running counter,
    //    generated and written one 1 MiB block at a time.
    // -----------------------------------------------------------------------

    SynthesizeTestFile(bigFilePath, Wire.TestFileSizeInBytes);
    Console.WriteLine($"SETUP    : synthesized {bigFilePath}");
    Console.WriteLine($"           {Wire.TestFileSizeInBytes:N0} bytes, streamed in {Wire.TestFileSizeInBytes / Wire.ChunkSize} x 1 MiB blocks\n");

    // -----------------------------------------------------------------------
    // 1. Hash-then-sign: stream -> 32-byte digest -> ML-DSA-87 signature.
    //    The signer never sees more than 80 KB of the file at once.
    // -----------------------------------------------------------------------

    using MLDsaPrivateKey signerKey = MLDsa87.GenerateKeyPair();
    using MLDsaPublicKey verifierKey = signerKey.GetPublicKey();

    (byte[] digest, long hashedBytes) = HashFileSha256(bigFilePath);
    byte[] signature = signerKey.SignData(digest, "large-file-sample/v1"u8);

    Console.WriteLine($"SIGN     : streamed {hashedBytes:N0} bytes through SHA-256 (80 KB buffer)");
    Console.WriteLine($"           signed the 32-byte digest -> {signature.Length}-byte ML-DSA-87 signature");

    // Verify by re-streaming the file and checking the signature over the
    // freshly recomputed digest — never trust a digest you didn't compute.
    (byte[] recomputed, _) = HashFileSha256(bigFilePath);
    Check(verifierKey.Verify(recomputed, signature, "large-file-sample/v1"u8),
        "signature verifies over the re-streamed digest");

    // Flip ONE byte in the middle of the 32 MB file: verification must fail.
    long middle = Wire.TestFileSizeInBytes / 2;
    FlipByteAt(bigFilePath, middle);
    (byte[] tamperedDigest, _) = HashFileSha256(bigFilePath);
    Check(!verifierKey.Verify(tamperedDigest, signature, "large-file-sample/v1"u8),
        $"signature REJECTED after flipping 1 byte at offset {middle:N0}");

    // Restore the byte and confirm we are back to a good file.
    FlipByteAt(bigFilePath, middle);
    (byte[] restoredDigest, _) = HashFileSha256(bigFilePath);
    Check(verifierKey.Verify(restoredDigest, signature, "large-file-sample/v1"u8),
        "signature verifies again after restoring the byte");

    // -----------------------------------------------------------------------
    // 2. Chunked authenticated encryption: encapsulate once, HKDF once,
    //    AES-GCM per 1 MiB chunk. Memory high-water mark: one chunk.
    // -----------------------------------------------------------------------

    using XWingPrivateKey recipientKey = XWing.GenerateKeyPair();
    byte[] recipientPublicKey = recipientKey.ExportEncapsulationKey();

    (long plainBytes, int chunkCount) = EncryptFileChunked(bigFilePath, envelopePath, recipientPublicKey);
    long envelopeBytes = new FileInfo(envelopePath).Length;
    Console.WriteLine($"\nENCRYPT  : {plainBytes:N0} plaintext bytes -> {chunkCount} chunks of <= 1 MiB");
    Console.WriteLine($"           envelope {envelopePath}");
    Console.WriteLine($"           {envelopeBytes:N0} bytes = header({Wire.HeaderLength}) + {chunkCount} x [tag(16) | ciphertext]");

    // -----------------------------------------------------------------------
    // 3. Decrypt-verify, streamed to a new file; round-trip must hash equal.
    // -----------------------------------------------------------------------

    (long decryptedBytes, int decryptedChunks) = DecryptFileChunked(envelopePath, roundTripPath, recipientKey);
    Console.WriteLine($"\nDECRYPT  : {decryptedChunks} chunks -> {decryptedBytes:N0} bytes at {roundTripPath}");

    (byte[] roundTripDigest, _) = HashFileSha256(roundTripPath);
    Check(CryptographicOperations.FixedTimeEquals(restoredDigest, roundTripDigest),
        "SHA-256(round-trip) == SHA-256(original)");

    // -----------------------------------------------------------------------
    // 4. Negatives — every one must be rejected with a clean exception.
    // -----------------------------------------------------------------------

    Console.WriteLine("\nNEGATIVE : tamper / reorder / truncate (each must be rejected):");

    // (a) Flip one byte in the middle of chunk 5's ciphertext -> tag mismatch.
    long chunk5Middle = Wire.HeaderLength + 5L * Wire.RecordSize + Wire.TagSize + Wire.ChunkSize / 2;
    FlipByteAt(envelopePath, chunk5Middle);
    ExpectRejected("1 byte flipped inside chunk 5's ciphertext",
        () => DecryptFileChunked(envelopePath, junkPath, recipientKey));
    FlipByteAt(envelopePath, chunk5Middle); // restore

    // (b) Swap chunks 3 and 7 wholesale (tag + ciphertext). Both records are
    //     individually authentic, but the AD binds each tag to its index, so
    //     decryption of chunk 3 fails the moment order is violated.
    SwapChunkRecords(envelopePath, 3, 7);
    ExpectRejected("chunks 3 and 7 swapped (order bound by associated data)",
        () => DecryptFileChunked(envelopePath, junkPath, recipientKey));
    SwapChunkRecords(envelopePath, 3, 7); // restore

    // (c) Truncate a copy of the envelope after chunk N-2. The header still
    //     promises `chunkCount` chunks, so the reader detects the missing
    //     tail instead of silently returning a shorter file.
    File.Copy(envelopePath, truncatedPath, overwrite: true);
    using (FileStream fs = new(truncatedPath, FileMode.Open, FileAccess.Write))
    {
        fs.SetLength(Wire.HeaderLength + (chunkCount - 2L) * Wire.RecordSize);
    }
    ExpectRejected($"envelope truncated to {chunkCount - 2} of {chunkCount} chunks",
        () => DecryptFileChunked(truncatedPath, junkPath, recipientKey));

    // Prove the restores above left the real envelope intact.
    (long finalBytes, int finalChunks) = DecryptFileChunked(envelopePath, roundTripPath, recipientKey);
    Check(finalBytes == plainBytes && finalChunks == chunkCount,
        "restored envelope still decrypts end-to-end");

    Console.WriteLine("\nAll self-checks passed.");
    return 0;
}
finally
{
    try { Directory.Delete(workDir, recursive: true); }
    catch (IOException) { /* best-effort temp cleanup */ }
    catch (UnauthorizedAccessException) { /* best-effort temp cleanup */ }
}

// ============================ implementation ================================

// Deterministic test data: each 32-byte block is SHA-256 of a little-endian
// counter. Generated into a single reusable 1 MiB buffer and streamed out, so
// the file never exists in memory. (totalBytes must be a multiple of 32.)
static void SynthesizeTestFile(string path, long totalBytes)
{
    byte[] block = new byte[Wire.ChunkSize];
    Span<byte> counterBytes = stackalloc byte[8];
    long counter = 0;
    long written = 0;

    using FileStream fs = new(path, FileMode.Create, FileAccess.Write);
    while (written < totalBytes)
    {
        int blockLen = (int)Math.Min(block.Length, totalBytes - written);
        for (int offset = 0; offset < blockLen; offset += 32)
        {
            BinaryPrimitives.WriteInt64LittleEndian(counterBytes, counter++);
            SHA256.HashData(counterBytes, block.AsSpan(offset, 32));
        }
        fs.Write(block, 0, blockLen);
        written += blockLen;
    }
}

// The bounded-buffer loop IS the teaching point: an 80 KB buffer walks the
// file through IncrementalHash, so memory stays constant however large the
// file gets. (SHA256.HashDataAsync(stream) does the same thing internally.)
static (byte[] Digest, long BytesHashed) HashFileSha256(string path)
{
    using IncrementalHash sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    byte[] buffer = new byte[80 * 1024];
    long total = 0;

    using FileStream fs = File.OpenRead(path);
    int read;
    while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
    {
        sha256.AppendData(buffer.AsSpan(0, read));
        total += read;
    }
    return (sha256.GetHashAndReset(), total);
}

static (long BytesProcessed, int ChunkCount) EncryptFileChunked(
    string inputPath, string envelopePath, byte[] recipientPublicKeyBytes)
{
    using XWingPublicKey recipient = XWing.ImportEncapsulationKey(recipientPublicKeyBytes);
    KemEncapsulation kem = recipient.Encapsulate();   // encapsulate ONCE per file
    byte[] sharedSecret = kem.SharedSecret;
    byte[] kemCiphertext = kem.Ciphertext;

    // Per-file salt so two envelopes to the same recipient derive unrelated
    // AES keys; the info string domain-separates this derivation.
    byte[] salt = RandomNumberGenerator.GetBytes(16);
    byte[] aesKey = new byte[32];

    try
    {
        HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, aesKey, salt, "large-file-sample/aes/v1"u8);

        long plaintextLength = new FileInfo(inputPath).Length;
        int chunkCount = (int)((plaintextLength + Wire.ChunkSize - 1) / Wire.ChunkSize);

        using FileStream input = File.OpenRead(inputPath);
        using FileStream output = new(envelopePath, FileMode.Create, FileAccess.Write);

        output.Write(Wire.Magic);                                 // 4
        output.Write(salt);                                       // 16
        output.Write(kemCiphertext);                              // 1120
        Span<byte> lengths = stackalloc byte[12];
        BinaryPrimitives.WriteInt32LittleEndian(lengths, chunkCount);
        BinaryPrimitives.WriteInt64LittleEndian(lengths[4..], plaintextLength);
        output.Write(lengths);                                    // 4 + 8

        using AesGcm aes = new(aesKey, tagSizeInBytes: Wire.TagSize);
        byte[] plainChunk = new byte[Wire.ChunkSize];   // the ONLY plaintext buffer
        byte[] cipherChunk = new byte[Wire.ChunkSize];  // the ONLY ciphertext buffer
        byte[] tag = new byte[Wire.TagSize];
        Span<byte> nonce = stackalloc byte[12];
        Span<byte> associatedData = stackalloc byte[16];

        long processed = 0;
        for (int index = 0; index < chunkCount; index++)
        {
            int chunkLength = (int)Math.Min(Wire.ChunkSize, plaintextLength - processed);
            input.ReadExactly(plainChunk.AsSpan(0, chunkLength));

            FillNonceAndAssociatedData(index, chunkCount, plaintextLength, nonce, associatedData);
            aes.Encrypt(nonce, plainChunk.AsSpan(0, chunkLength), cipherChunk.AsSpan(0, chunkLength), tag, associatedData);

            output.Write(tag);
            output.Write(cipherChunk.AsSpan(0, chunkLength));
            processed += chunkLength;
        }

        CryptographicOperations.ZeroMemory(plainChunk);
        return (processed, chunkCount);
    }
    finally
    {
        CryptographicOperations.ZeroMemory(sharedSecret);
        CryptographicOperations.ZeroMemory(aesKey);   // the HKDF output
    }
}

static (long BytesProcessed, int ChunkCount) DecryptFileChunked(
    string envelopePath, string outputPath, XWingPrivateKey recipientKey)
{
    using FileStream input = File.OpenRead(envelopePath);

    Span<byte> magic = stackalloc byte[4];
    ReadExactlyOrThrow(input, magic, "magic");
    if (!magic.SequenceEqual(Wire.Magic))
    {
        throw new InvalidDataException("Not a PQ09 streaming envelope (bad magic).");
    }

    byte[] salt = new byte[16];
    ReadExactlyOrThrow(input, salt, "salt");
    byte[] kemCiphertext = new byte[XWing.CiphertextSizeInBytes];
    ReadExactlyOrThrow(input, kemCiphertext, "KEM ciphertext");
    Span<byte> lengths = stackalloc byte[12];
    ReadExactlyOrThrow(input, lengths, "length fields");
    int chunkCount = BinaryPrimitives.ReadInt32LittleEndian(lengths);
    long plaintextLength = BinaryPrimitives.ReadInt64LittleEndian(lengths[4..]);
    if (chunkCount <= 0 || plaintextLength < 0
        || chunkCount != (plaintextLength + Wire.ChunkSize - 1) / Wire.ChunkSize)
    {
        throw new InvalidDataException(
            $"Envelope header is inconsistent: {chunkCount} chunks for {plaintextLength} plaintext bytes.");
    }

    byte[] sharedSecret = recipientKey.Decapsulate(kemCiphertext);
    byte[] aesKey = new byte[32];
    try
    {
        HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, aesKey, salt, "large-file-sample/aes/v1"u8);

        using AesGcm aes = new(aesKey, tagSizeInBytes: Wire.TagSize);
        using FileStream output = new(outputPath, FileMode.Create, FileAccess.Write);
        byte[] cipherChunk = new byte[Wire.ChunkSize];
        byte[] plainChunk = new byte[Wire.ChunkSize];
        byte[] tag = new byte[Wire.TagSize];
        Span<byte> nonce = stackalloc byte[12];
        Span<byte> associatedData = stackalloc byte[16];

        long processed = 0;
        for (int index = 0; index < chunkCount; index++)
        {
            // The header count drives this loop: if the file was truncated,
            // one of these reads comes up short -> InvalidDataException.
            int chunkLength = (int)Math.Min(Wire.ChunkSize, plaintextLength - processed);
            ReadExactlyOrThrow(input, tag, $"chunk {index} tag");
            ReadExactlyOrThrow(input, cipherChunk.AsSpan(0, chunkLength), $"chunk {index} ciphertext");

            // Recomputing the AD from OUR loop index (not anything on the
            // wire) is what catches reordered or replayed chunks: a swapped
            // record carries a tag minted for a different index and fails.
            FillNonceAndAssociatedData(index, chunkCount, plaintextLength, nonce, associatedData);
            aes.Decrypt(nonce, cipherChunk.AsSpan(0, chunkLength), tag, plainChunk.AsSpan(0, chunkLength), associatedData);

            output.Write(plainChunk.AsSpan(0, chunkLength));
            processed += chunkLength;
        }

        CryptographicOperations.ZeroMemory(plainChunk);
        return (processed, chunkCount);
    }
    finally
    {
        CryptographicOperations.ZeroMemory(sharedSecret);
        CryptographicOperations.ZeroMemory(aesKey);   // the HKDF output
    }
}

// nonce = [ chunkIndex (4, LE) | 8 zero bytes ]. A counter nonce is safe here
// only because the AES key is derived fresh for this one file (KEM + salt).
// AD = [ chunkIndex (4) | chunkCount (4) | plaintextLength (8) ], all LE —
// binds each chunk to its position, and the whole file to its exact size.
static void FillNonceAndAssociatedData(
    int chunkIndex, int chunkCount, long plaintextLength, Span<byte> nonce, Span<byte> associatedData)
{
    nonce.Clear();
    BinaryPrimitives.WriteInt32LittleEndian(nonce, chunkIndex);
    BinaryPrimitives.WriteInt32LittleEndian(associatedData, chunkIndex);
    BinaryPrimitives.WriteInt32LittleEndian(associatedData[4..], chunkCount);
    BinaryPrimitives.WriteInt64LittleEndian(associatedData[8..], plaintextLength);
}

static void ReadExactlyOrThrow(Stream stream, Span<byte> destination, string what)
{
    int read = stream.ReadAtLeast(destination, destination.Length, throwOnEndOfStream: false);
    if (read != destination.Length)
    {
        throw new InvalidDataException(
            $"Envelope is truncated: needed {destination.Length} bytes for {what}, got {read}.");
    }
}

static void FlipByteAt(string path, long offset)
{
    using FileStream fs = new(path, FileMode.Open, FileAccess.ReadWrite);
    fs.Position = offset;
    int original = fs.ReadByte();
    fs.Position = offset;
    fs.WriteByte((byte)(original ^ 0xFF));
}

// Swap two full-size [tag | ciphertext] records in place. This negative-test
// helper briefly holds two records; the crypto pipeline itself never exceeds
// one chunk. Only valid for indices below chunkCount - 1 (full chunks).
static void SwapChunkRecords(string path, int indexA, int indexB)
{
    byte[] recordA = new byte[Wire.RecordSize];
    byte[] recordB = new byte[Wire.RecordSize];
    long positionA = Wire.HeaderLength + (long)indexA * Wire.RecordSize;
    long positionB = Wire.HeaderLength + (long)indexB * Wire.RecordSize;

    using FileStream fs = new(path, FileMode.Open, FileAccess.ReadWrite);
    fs.Position = positionA; fs.ReadExactly(recordA);
    fs.Position = positionB; fs.ReadExactly(recordB);
    fs.Position = positionA; fs.Write(recordB);
    fs.Position = positionB; fs.Write(recordA);
}

static void Check(bool condition, string label)
{
    Console.WriteLine($"  {(condition ? "ok  " : "FAIL")} {label}");
    if (!condition)
    {
        throw new InvalidOperationException($"self-check failed: {label}");
    }
}

static void ExpectRejected(string label, Action attempt)
{
    try
    {
        attempt();
    }
    catch (Exception ex) when (ex is CryptographicException or InvalidDataException)
    {
        Console.WriteLine($"  ok   REJECTED [{ex.GetType().Name}] {label}");
        return;
    }
    Console.WriteLine($"  FAIL ACCEPTED {label}");
    throw new InvalidOperationException($"negative case was not rejected: {label}");
}

// ---- Wire constants ----

internal static class Wire
{
    public const int ChunkSize = 1024 * 1024;              // 1 MiB plaintext per chunk
    public const int TagSize = 16;                          // AES-GCM tag
    public const int RecordSize = TagSize + ChunkSize;      // one full on-disk chunk record
    public const long TestFileSizeInBytes = 32L * 1024 * 1024;

    // magic(4) + salt(16) + X-Wing ciphertext(1120) + chunkCount(4) + plaintextLength(8)
    public const int HeaderLength = 4 + 16 + XWing.CiphertextSizeInBytes + 4 + 8;

    public static ReadOnlySpan<byte> Magic => "PQ09"u8;
}
