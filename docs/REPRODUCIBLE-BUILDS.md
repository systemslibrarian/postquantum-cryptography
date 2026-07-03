# Reproducible builds — verifying a published package yourself

You should not have to trust that the DLL on nuget.org was built from the source
in this repository. This document is the recipe for checking it yourself.

## What "deterministic" means here — and what it does not

Every build of this library sets `Deterministic=true`, and CI/release builds add
`ContinuousIntegrationBuild=true` (see `Directory.Build.props` and
`.github/workflows/release.yml`). Together these make the C# compiler produce
**byte-identical IL** from identical inputs: source at the same commit, the same
compiler (which ships with the .NET SDK), and the same build settings. Absolute
paths are normalized (sources map to `/_/…` via SourceLink), and timestamps and
MVIDs are derived from a hash of the inputs rather than the clock. The CI
pipeline includes a `determinism` job that builds twice and fails if the
assembly hashes differ.

What this does **not** guarantee:

- It does not prove the source is *good* — only that the binary matches the
  source. Review the source too.
- It does not make the build reproducible across *different* SDK versions. A
  different compiler produces different (still correct) bytes.
- It does not make the `.nupkg` container itself reproducible (next section).

## Why you can't byte-compare the .nupkg itself

Two reasons:

1. **nuget.org repository-signs every package after upload.** The downloaded
   `.nupkg` contains a `.signature.p7s` entry and a re-written zip envelope
   that a locally packed file will never have.
2. **The package envelope is not fully deterministic even locally** — the
   `.psmdcp` metadata part and zip entry details can differ between packs.

So the comparison target is the **assembly inside the package**:
`lib/net10.0/PostQuantum.Cryptography.dll`. That file is what actually runs in
your process, and it is the deterministic artifact.

## Step-by-step recipe

The example uses `v1.0.0` / package version `1.0.0`; substitute the release you
are verifying.

### 0. Match the SDK the release used

The release workflow (`.github/workflows/release.yml`) runs on
**`windows-latest`** with `actions/setup-dotnet` and `dotnet-version: '10.0.x'`
— a floating patch. The **exact** SDK patch matters, and it is visible in the
release's GitHub Actions run log: open the run for the tag under
<https://github.com/systemslibrarian/postquantum-cryptography/actions>, expand
the "Setup .NET 10" step (and the `dotnet --info` output if present), and note
the resolved SDK version, e.g. `10.0.107`.

Pin it while verifying by dropping a `global.json` next to the cloned repo
root (replace the version with the one from the log):

```json
{
  "sdk": {
    "version": "10.0.107",
    "rollForward": "disable"
  }
}
```

### 1–5. Clone, build, download, extract, compare

**bash:**

```bash
git clone https://github.com/systemslibrarian/postquantum-cryptography.git
cd postquantum-cryptography
git checkout v1.0.0

# Build + pack exactly as the release does (CI flag is NOT on by default locally).
dotnet pack src/PostQuantum.Cryptography/PostQuantum.Cryptography.csproj \
  -c Release -p:ContinuousIntegrationBuild=true -o ./verify/local-pack

# Download the published package from nuget.org's flat container.
curl -sSL -o ./verify/published.nupkg \
  https://api.nuget.org/v3-flatcontainer/postquantum.cryptography/1.0.0/postquantum.cryptography.1.0.0.nupkg

# A .nupkg is a zip. Extract both.
unzip -q ./verify/local-pack/PostQuantum.Cryptography.1.0.0.nupkg -d ./verify/local
unzip -q ./verify/published.nupkg -d ./verify/published

# Compare the assemblies.
sha256sum ./verify/local/lib/net10.0/PostQuantum.Cryptography.dll \
          ./verify/published/lib/net10.0/PostQuantum.Cryptography.dll
```

**PowerShell:**

```powershell
git clone https://github.com/systemslibrarian/postquantum-cryptography.git
Set-Location postquantum-cryptography
git checkout v1.0.0

dotnet pack src/PostQuantum.Cryptography/PostQuantum.Cryptography.csproj -c Release -p:ContinuousIntegrationBuild=true -o ./verify/local-pack

Invoke-WebRequest -Uri "https://api.nuget.org/v3-flatcontainer/postquantum.cryptography/1.0.0/postquantum.cryptography.1.0.0.nupkg" -OutFile ./verify/published.nupkg

# Expand-Archive insists on a .zip extension, so copy first.
Copy-Item ./verify/local-pack/PostQuantum.Cryptography.1.0.0.nupkg ./verify/local.zip
Copy-Item ./verify/published.nupkg ./verify/published.zip
Expand-Archive ./verify/local.zip -DestinationPath ./verify/local
Expand-Archive ./verify/published.zip -DestinationPath ./verify/published

Get-FileHash -Algorithm SHA256 ./verify/local/lib/net10.0/PostQuantum.Cryptography.dll, ./verify/published/lib/net10.0/PostQuantum.Cryptography.dll
```

If the two SHA-256 hashes match, the published assembly is bit-for-bit the one
this source tree produces. Done.

## Caveats — when hashes legitimately differ

- **SDK patch version.** This is by far the most common cause. `10.0.x` floats
  on the runner, so verify against the exact patch from the release run log
  (step 0). A different Roslyn emits different bytes.
- **OS / runner image.** The release built on `windows-latest`. With path
  mapping and `InvariantGlobalization` the build *should* reproduce on
  Linux/macOS too, but that is not something we test; if you get a mismatch on
  another OS, retry on Windows before concluding anything.
- **Forgetting `-p:ContinuousIntegrationBuild=true`.** Locally that property is
  only auto-enabled when `CI=true` is set in the environment, so pass it
  explicitly as shown above.

If hashes still differ, dig before you worry: run
`dotnet tool install -g dotnet-sourcelink` and `sourcelink test <dll>` /
`sourcelink print-urls <dll>` on both assemblies, or open both in an IL/metadata
viewer (ILSpy, JetBrains dotPeek) and compare assembly metadata — MVID, compiler
version in the `#~` metadata, embedded `AssemblyInformationalVersion` — to see
*what* changed rather than just *that* it changed. Compiler-version drift shows
up immediately this way.

A mismatch you cannot explain after matching the SDK is worth reporting —
**privately**, per [`SECURITY.md`](../SECURITY.md), since "the published binary
does not match the source" is exactly the kind of claim that deserves quiet
verification before publicity.

## Complementary check: build-provenance attestations

GitHub build-provenance attestations are being added to the release workflow.
Once a release carries them, you can verify that an artifact was produced by
this repository's workflow — without rebuilding anything — using the GitHub
CLI:

```bash
gh attestation verify <file> --repo systemslibrarian/postquantum-cryptography
```

This is a lower-effort check than a full rebuild: it proves *where* the
artifact came from (this repo, this workflow, this commit), while the recipe
above proves *what* it contains. They complement each other; the strongest
position is both.

---

*To God be the glory.* — 1 Corinthians 10:31
