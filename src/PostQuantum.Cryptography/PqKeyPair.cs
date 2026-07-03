using System.Diagnostics;

namespace PostQuantum.Cryptography;

/// <summary>
/// A small value bundle for carrying the public and private halves of a key
/// pair together — for example when a helper method of your own produces both
/// and you want a clearer shape than a tuple. The library's facades return
/// <see cref="MLKemPrivateKey"/> / <see cref="MLDsaPrivateKey"/> /
/// <see cref="XWingPrivateKey"/> directly (get the public half via
/// <c>GetPublicKey()</c>); nothing in this library returns
/// <see cref="PqKeyPair{TPublic, TPrivate}"/> itself.
/// </summary>
/// <typeparam name="TPublic">Public-key type for the algorithm.</typeparam>
/// <typeparam name="TPrivate">Private-key type for the algorithm.</typeparam>
/// <remarks>
/// <para>
/// This type is a thin, allocation-light value bundle — it does <i>not</i>
/// implement <see cref="IDisposable"/> itself, because making a
/// <see langword="struct"/> disposable interacts badly with pass-by-value
/// semantics (every copy would get its own "is it my responsibility to
/// dispose?" question). Instead, dispose <see cref="Public"/> and
/// <see cref="Private"/> explicitly, either directly or by deconstruction.
/// </para>
/// <para>
/// Typical use:
/// <code>
/// var pair = new PqKeyPair&lt;MLKemPublicKey, MLKemPrivateKey&gt;(pub, priv);
/// using (pair.Private)
/// using (pair.Public)
/// {
///     // ... encapsulate / decapsulate ...
/// }
/// </code>
/// or with deconstruction:
/// <code>
/// var (pub, priv) = pair;
/// using (priv) using (pub)
/// {
///     // ...
/// }
/// </code>
/// </para>
/// <para>
/// <b><c>default</c> footgun:</b> like every <see langword="struct"/>, this
/// type has a default instance — and <c>default(PqKeyPair&lt;,&gt;)</c> has
/// <see langword="null"/> <see cref="Public"/> and <see cref="Private"/>
/// despite the non-nullable annotations. Only use instances constructed with
/// both halves.
/// </para>
/// <para>
/// <b>Equality semantics:</b> reference equality on the underlying key
/// objects (the default for a <c>readonly record struct</c> when both fields
/// are reference types). Two pairs are equal only when they wrap the same
/// instances. Do not use <see cref="object.Equals(object?)"/> to test
/// "do these key pairs hold the same cryptographic identity" — export the
/// public-key bytes and compare those with
/// <see cref="System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(System.ReadOnlySpan{byte}, System.ReadOnlySpan{byte})"/>
/// instead.
/// </para>
/// </remarks>
[DebuggerDisplay("PqKeyPair<{typeof(TPublic).Name,nq}, {typeof(TPrivate).Name,nq}>")]
public readonly record struct PqKeyPair<TPublic, TPrivate>(TPublic Public, TPrivate Private)
    where TPublic : class
    where TPrivate : class;
