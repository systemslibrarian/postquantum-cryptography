using System.Security.Cryptography;

namespace PostQuantum.Cryptography;

/// <summary>
/// The result of a KEM (key encapsulation mechanism) encapsulation operation.
/// </summary>
/// <remarks>
/// <para>
/// The <see cref="SharedSecret"/> is sensitive key material. Use it to key a
/// symmetric algorithm and then clear it with
/// <see cref="CryptographicOperations.ZeroMemory(System.Span{byte})"/> when
/// finished. The <see cref="Ciphertext"/> is not secret and is transmitted to
/// the holder of the decapsulation (private) key, who recovers the same shared
/// secret.
/// </para>
/// <para>
/// <b>Equality semantics.</b> This type is a <see langword="record struct"/>,
/// so two <c>KemEncapsulation</c> values compare equal only when their
/// <i>underlying array references</i> are the same — not when the array
/// contents are byte-identical. This is deliberate: comparing cryptographic
/// material with the default <see cref="object.Equals(object?)"/> would be
/// non–constant-time and leak timing information about secrets. If you need
/// content equality on a shared secret, use
/// <see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>.
/// </para>
/// <para>
/// <b>Default values.</b> Because this is a struct, <see langword="default"/>
/// (<see cref="KemEncapsulation"/>) is a value whose <see cref="Ciphertext"/>
/// and <see cref="SharedSecret"/> are <see langword="null"/>. Only consume
/// <c>KemEncapsulation</c> instances actually returned by an
/// <c>Encapsulate(...)</c> call — never instantiate it via
/// <see langword="default"/> or treat an uninitialized field as a valid result.
/// </para>
/// </remarks>
/// <param name="Ciphertext">The encapsulation ciphertext to send to the recipient.</param>
/// <param name="SharedSecret">The shared secret derived by both parties (32 bytes for every primitive in this library).</param>
public readonly record struct KemEncapsulation(byte[] Ciphertext, byte[] SharedSecret)
{
    /// <summary>
    /// Returns a string representation that intentionally omits the byte
    /// contents — including the bytes (or their length, which can hint at the
    /// primitive in use) in <c>ToString()</c> output makes it trivial to leak
    /// secret material into logs, exception messages, and debugger snapshots.
    /// </summary>
    public override string ToString() => nameof(KemEncapsulation);
}
