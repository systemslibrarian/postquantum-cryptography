using System.Security.Cryptography;

namespace PostQuantum.Cryptography.Internal;

/// <summary>
/// Minimal X25519 (Curve25519 Diffie-Hellman) per RFC 7748, designed to be
/// branch-free with respect to secret data.
/// </summary>
/// <remarks>
/// .NET 10's BCL ships ML-KEM and ML-DSA natively, but does not expose X25519,
/// which the X-Wing hybrid KEM requires. This implementation is a faithful port
/// of the field arithmetic and Montgomery ladder from TweetNaCl
/// (<c>crypto_scalarmult</c>), which is in the public domain. It is small and
/// widely reviewed.
///
/// <b>Constant-time posture.</b> The Montgomery ladder and conditional swap
/// (<c>Sel25519</c>) are <em>designed</em> branch-free with respect to secret
/// data — control flow does not depend on scalar bits, and bitmask-based
/// selection is used in place of conditional moves. This is a source-level
/// guarantee only. It has <b>not</b> been validated under the .NET JIT,
/// tiered compilation, or speculative execution, and it has <b>not</b> been
/// independently audited for microarchitectural side channels (cache,
/// branch-predictor, port-contention, prefetch). Treat it as
/// "constant-time-by-construction, not constant-time-by-measurement", and
/// see <c>AUDIT-SCOPE.md</c>.
///
/// <b>Raw RFC 7748 primitive — safe only inside X-Wing.</b> This is the raw
/// scalar-multiplication function from RFC 7748. It does <em>not</em> abort
/// on an all-zero / low-order output, and it accepts non-canonical
/// u-coordinates (the high bit of <paramref>u</paramref> is masked per the
/// RFC). That is correct for X-Wing, whose combiner cryptographically binds
/// <c>ct_X</c> and <c>pk_X</c> into the derived shared secret, so the bare
/// function is the right primitive here. <b>Do not reuse this type as a
/// general-purpose Diffie-Hellman.</b> Outside of X-Wing those properties
/// would be footguns: an attacker-controlled low-order point would yield a
/// predictable shared secret, and non-canonical encodings would create
/// cross-implementation interop risk. The type is <c>internal</c> for that
/// reason and exposed to the test project only via
/// <c>InternalsVisibleTo</c>.
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

        // TweetNaCl zeroes a/c/d explicitly; this port relies on stackalloc
        // zero-initialization instead (`.locals init`). That assumption is
        // load-bearing: the ladder seeds a[0]=1 / d[0]=1 into otherwise-zero
        // limbs, and Mul accumulates with `+=`. If SkipLocalsInit is ever
        // introduced (attribute or MSBuild property), these clears are what
        // keep the arithmetic correct — do not remove them.
        Span<long> x = stackalloc long[80];
        x.Clear();
        Span<long> a = stackalloc long[16];
        a.Clear();
        Span<long> b = stackalloc long[16];
        Span<long> c = stackalloc long[16];
        c.Clear();
        Span<long> d = stackalloc long[16];
        d.Clear();
        Span<long> e = stackalloc long[16];
        Span<long> f = stackalloc long[16];
        Span<long> x32 = stackalloc long[16];
        Span<long> x16 = stackalloc long[16];
        try
        {
            Unpack25519(x, u);

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

            x.Slice(32, 16).CopyTo(x32);
            x.Slice(16, 16).CopyTo(x16);
            Inv25519(x32, x32);
            Mul(x16, x16, x32);

            byte[] result = new byte[KeySizeInBytes];
            Pack25519(result, x16);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(z);
            a.Clear();
            b.Clear();
            c.Clear();
            d.Clear();
            e.Clear();
            f.Clear();
            x.Clear();
            x16.Clear();
            x32.Clear();
        }
    }

    private static void Car25519(Span<long> o)
    {
        for (int i = 0; i < 16; i++)
        {
            o[i] += 1L << 16;
            long c = o[i] >> 16;
            o[(i + 1) * (i < 15 ? 1 : 0)] += c - 1 + (37 * (c - 1) * (i == 15 ? 1 : 0));
            o[i] -= c << 16;
        }
    }

    private static void Sel25519(Span<long> p, Span<long> q, long b)
    {
        long c = ~(b - 1);
        for (int i = 0; i < 16; i++)
        {
            long t = c & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    private static void Pack25519(Span<byte> o, ReadOnlySpan<long> n)
    {
        Span<long> m = stackalloc long[16];
        Span<long> t = stackalloc long[16];
        try
        {
            n.CopyTo(t);
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
        finally
        {
            m.Clear();
            t.Clear();
        }
    }

    private static void Unpack25519(Span<long> o, ReadOnlySpan<byte> n)
    {
        for (int i = 0; i < 16; i++)
        {
            o[i] = n[2 * i] + ((long)n[(2 * i) + 1] << 8);
        }

        o[15] &= 0x7fff;
    }

    private static void Add(Span<long> o, ReadOnlySpan<long> a, ReadOnlySpan<long> b)
    {
        for (int i = 0; i < 16; i++)
        {
            o[i] = a[i] + b[i];
        }
    }

    private static void Sub(Span<long> o, ReadOnlySpan<long> a, ReadOnlySpan<long> b)
    {
        for (int i = 0; i < 16; i++)
        {
            o[i] = a[i] - b[i];
        }
    }

    private static void Mul(Span<long> o, ReadOnlySpan<long> a, ReadOnlySpan<long> b)
    {
        Span<long> t = stackalloc long[31];
        // The schoolbook accumulation below uses `+=`, so t must start
        // all-zero. Explicit clear so correctness never silently depends on
        // stackalloc zero-initialization (see the note in ScalarMult).
        t.Clear();
        try
        {
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
        finally
        {
            t.Clear();
        }
    }

    private static void Square(Span<long> o, ReadOnlySpan<long> a) => Mul(o, a, a);

    private static void Inv25519(Span<long> o, ReadOnlySpan<long> i)
    {
        Span<long> c = stackalloc long[16];
        try
        {
            i.CopyTo(c);
            for (int a = 253; a >= 0; a--)
            {
                Square(c, c);
                if (a != 2 && a != 4)
                {
                    Mul(c, c, i);
                }
            }

            c.CopyTo(o);
        }
        finally
        {
            c.Clear();
        }
    }
}
