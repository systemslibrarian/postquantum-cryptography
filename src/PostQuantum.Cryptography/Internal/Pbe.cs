using System.Security.Cryptography;

namespace PostQuantum.Cryptography.Internal;

/// <summary>
/// The single password-based-encryption policy used for every encrypted
/// PKCS#8 export in this library. One strong option, no knobs — per the
/// project's secure-by-default principle, callers choose a password and
/// nothing else.
/// </summary>
internal static class Pbe
{
    /// <summary>
    /// PBES2 with PBKDF2-HMAC-SHA256 at 600,000 iterations (OWASP 2023
    /// guidance for PBKDF2-SHA256) and AES-256-CBC. Decryption reads the
    /// parameters from the PKCS#8 structure itself, so raising this in a
    /// future release does not break existing files.
    /// </summary>
    internal static readonly PbeParameters Parameters =
        new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, iterationCount: 600_000);

    /// <summary>
    /// Rejects an empty password on export. An empty password produces a file
    /// that looks protected but is not — a footgun this library refuses to
    /// hand out. (Imports accept whatever password the file was written with,
    /// including empty ones produced by other tools.)
    /// </summary>
    internal static void RequireNonEmptyPassword(ReadOnlySpan<char> password)
    {
        if (password.IsEmpty)
        {
            throw new ArgumentException(
                "Password must not be empty. An encrypted PKCS#8 export with an empty " +
                "password provides no protection; use the unencrypted ExportPkcs8PrivateKey " +
                "methods if that is genuinely what you want.",
                nameof(password));
        }
    }
}
