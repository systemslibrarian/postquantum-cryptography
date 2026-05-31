namespace PostQuantum.Cryptography;

/// <summary>
/// The result of a KEM (key encapsulation mechanism) encapsulation operation.
/// </summary>
/// <remarks>
/// The <see cref="SharedSecret"/> is sensitive key material. Use it to key a
/// symmetric algorithm and then clear it with
/// <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory(System.Span{byte})"/>
/// when you are finished. The <see cref="Ciphertext"/> is not secret and is
/// transmitted to the holder of the decapsulation (private) key, who recovers
/// the same shared secret.
/// </remarks>
/// <param name="Ciphertext">The encapsulation ciphertext to send to the recipient.</param>
/// <param name="SharedSecret">The 32-byte shared secret derived by both parties.</param>
public readonly record struct KemEncapsulation(byte[] Ciphertext, byte[] SharedSecret);
