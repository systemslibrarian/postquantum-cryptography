using System.Security.Cryptography;

namespace PostQuantum.Cryptography.Internal;

/// <summary>
/// Minimal, constant-time X25519 (Curve25519 Diffie-Hellman) per RFC 7748.
/// </summary>
/// <remarks>
/// .NET 10's BCL ships ML-KEM and ML-DSA natively, but does not expose X25519,
/// which the X-Wing hybrid KEM requires. This implementation is a faithful port
/// of the field arithmetic and Montgomery ladder from TweetNaCl
/// (<c>crypto_scalarmult</c>), which is in the public domain. It is small,
/// widely reviewed, and constant-time with respect to the scalar.
///
/// This is the raw scalar-multiplication function from RFC 7748 (it does not
/// abort on an all-zero / low-order output). That matches the X-Wing
/// specification, whose combiner binds both the ciphertext and the recipient
/// public key, so the bare function is the correct primitive here. Do not reuse
/// this type as a general-purpose Diffie-Hellman without understanding that
/// distinction.
/// </remarks>
internal static class X25519
{
    /// <summary>Size, in bytes, of an X25519 scalar (private key) or u-coordinate (public key).</summary>
    public const int KeySizeInBytes = 32;

    private static readonly long[] _121665 = { 0xDB41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    /// <summary>
    /// Computes the X25519 scalar multiplication of <paramref name="scalar"/> with the
    /// curve base point, yielding a public key.
    /// </summary>
    public static byte[] ScalarMultBase(ReadOnlySpan<byte> scalar)
    {
        Span<byte> basePoint = stackalloc byte[KeySizeInBytes];
        basePoint[0] = 9;
        return ScalarMult(scalar, basePoint);
    }

    /// <summary>
    /// Computes the X25519 scalar multiplication of <paramref name="scalar"/> with the
    /// u-coordinate <paramref name="u"/>.
    /// </summary>
    public static byte[] ScalarMult(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> u)
    {
        if (scalar.Length != KeySizeInBytes)
        {
            throw new ArgumentException($"Scalar must be {KeySizeInBytes} bytes.", nameof(scalar));
        }

        if (u.Length != KeySizeInBytes)
        {
            throw new ArgumentException($"U-coordinate must be {KeySizeInBytes} bytes.", nameof(u));
        }

        Span<byte> z = stackalloc byte[32];
        scalar.CopyTo(z);
        // Clamp the scalar as required by RFC 7748.
        z[0] &= 248;
        z[31] &= 127;
        z[31] |= 64;

        long[] x = new long[80];
        Unpack25519(x, u);

        long[] a = new long[16];
        long[] b = new long[16];
        long[] c = new long[16];
        long[] d = new long[16];
        long[] e = new long[16];
        long[] f = new long[16];

        for (int i = 0; i < 16; i++)
        {
            b[i] = x[i];
        }

        a[0] = 1;
        d[0] = 1;

        for (int i = 254; i >= 0; i--)
        {
            long r = (z[i >> 3] >> (i & 7)) & 1;
            Sel25519(a, b, r);
            Sel25519(c, d, r);
            Add(e, a, c);
            Sub(a, a, c);
            Add(c, b, d);
            Sub(b, b, d);
            Square(d, e);
            Square(f, a);
            Mul(a, c, a);
            Mul(c, b, e);
            Add(e, a, c);
            Sub(a, a, c);
            Square(b, a);
            Sub(c, d, f);
            Mul(a, c, _121665);
            Add(a, a, d);
            Mul(c, c, a);
            Mul(a, d, f);
            Mul(d, b, x);
            Square(b, e);
            Sel25519(a, b, r);
            Sel25519(c, d, r);
        }

        for (int i = 0; i < 16; i++)
        {
            x[i + 16] = a[i];
            x[i + 32] = c[i];
            x[i + 48] = b[i];
            x[i + 64] = d[i];
        }

        long[] x32 = new long[16];
        long[] x16 = new long[16];
        Array.Copy(x, 32, x32, 0, 16);
        Array.Copy(x, 16, x16, 0, 16);
        Inv25519(x32, x32);
        Mul(x16, x16, x32);

        byte[] result = new byte[KeySizeInBytes];
        Pack25519(result, x16);

        CryptographicOperations.ZeroMemory(z);
        Array.Clear(a);
        Array.Clear(b);
        Array.Clear(c);
        Array.Clear(d);
        Array.Clear(e);
        Array.Clear(f);
        Array.Clear(x);
        Array.Clear(x16);
        Array.Clear(x32);

        return result;
    }

    private static void Car25519(long[] o)
    {
        for (int i = 0; i < 16; i++)
        {
            o[i] += 1L << 16;
            long c = o[i] >> 16;
            o[(i + 1) * (i < 15 ? 1 : 0)] += c - 1 + (37 * (c - 1) * (i == 15 ? 1 : 0));
            o[i] -= c << 16;
        }
    }

    private static void Sel25519(long[] p, long[] q, long b)
    {
        long c = ~(b - 1);
        for (int i = 0; i < 16; i++)
        {
            long t = c & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    private static void Pack25519(Span<byte> o, long[] n)
    {
        long[] m = new long[16];
        long[] t = new long[16];
        Array.Copy(n, t, 16);
        Car25519(t);
        Car25519(t);
        Car25519(t);
        for (int j = 0; j < 2; j++)
        {
            m[0] = t[0] - 0xffed;
            for (int i = 1; i < 15; i++)
            {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }

            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            long b = (m[15] >> 16) & 1;
            m[14] &= 0xffff;
            Sel25519(t, m, 1 - b);
        }

        for (int i = 0; i < 16; i++)
        {
            o[2 * i] = (byte)(t[i] & 0xff);
            o[(2 * i) + 1] = (byte)(t[i] >> 8);
        }
    }

    private static void Unpack25519(long[] o, ReadOnlySpan<byte> n)
    {
        for (int i = 0; i < 16; i++)
        {
            o[i] = n[2 * i] + ((long)n[(2 * i) + 1] << 8);
        }

        o[15] &= 0x7fff;
    }

    private static void Add(long[] o, long[] a, long[] b)
    {
        for (int i = 0; i < 16; i++)
        {
            o[i] = a[i] + b[i];
        }
    }

    private static void Sub(long[] o, long[] a, long[] b)
    {
        for (int i = 0; i < 16; i++)
        {
            o[i] = a[i] - b[i];
        }
    }

    private static void Mul(long[] o, long[] a, long[] b)
    {
        long[] t = new long[31];
        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 16; j++)
            {
                t[i + j] += a[i] * b[j];
            }
        }

        for (int i = 0; i < 15; i++)
        {
            t[i] += 38 * t[i + 16];
        }

        for (int i = 0; i < 16; i++)
        {
            o[i] = t[i];
        }

        Car25519(o);
        Car25519(o);
    }

    private static void Square(long[] o, long[] a) => Mul(o, a, a);

    private static void Inv25519(long[] o, long[] i)
    {
        long[] c = new long[16];
        Array.Copy(i, c, 16);
        for (int a = 253; a >= 0; a--)
        {
            Square(c, c);
            if (a != 2 && a != 4)
            {
                Mul(c, c, i);
            }
        }

        Array.Copy(c, o, 16);
    }
}
