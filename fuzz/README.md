# Fuzzing

Coverage-guided fuzzing harness for `PostQuantum.Cryptography`, built on
[SharpFuzz](https://github.com/Metalnem/sharpfuzz) and driven by
[afl++](https://github.com/AFLplusplus/AFLplusplus).

## What we fuzz

All targets share the same contract: arbitrary input must surface as a
documented exception (`ArgumentException`, `CryptographicException`) or a
benign return. Any other exception — and especially any crash, hang, or
silent corruption — is a finding.

| `FUZZ_TARGET`         | What it exercises                                                  |
| --------------------- | ------------------------------------------------------------------ |
| `mlkem-decap`         | `MLKemPrivateKey.Decapsulate` with arbitrary 1088-byte ciphertexts |
| `xwing-decap`         | `XWingPrivateKey.Decapsulate` with arbitrary 1120-byte ciphertexts |
| `mldsa-verify`        | `MLDsaPublicKey.Verify` with arbitrary 4627-byte signatures        |
| `mlkem-import-ek`     | `MLKem768.ImportEncapsulationKey` with arbitrary bytes             |
| `mlkem-import-pem`    | `MLKemKey.ImportPrivateKeyFromPem` with arbitrary UTF-8 text       |

## How to run

```bash
# 1. Publish + instrument the harness binary
dotnet publish fuzz/PostQuantum.Cryptography.Fuzz -c Release -o ./fuzz-out

# Install sharpfuzz once:
#   dotnet tool install --global SharpFuzz.CommandLine
sharpfuzz ./fuzz-out/PostQuantum.Cryptography.dll

# 2. Seed a corpus directory and run afl-fuzz
mkdir -p corpus/mlkem-decap
head -c 1088 /dev/urandom > corpus/mlkem-decap/seed1

FUZZ_TARGET=mlkem-decap \
afl-fuzz -i corpus/mlkem-decap -o findings/mlkem-decap \
  -- ./fuzz-out/PostQuantum.Cryptography.Fuzz
```

Repeat for each `FUZZ_TARGET`. Any path under `findings/<target>/crashes/` is a
real bug — file a security report (`SECURITY.md`) before discussing publicly.

## CI

We do not run continuous fuzzing in GitHub Actions today (afl++ doesn't run
unprivileged in standard runners without tuning). The harness is maintained
in-repo so that it can be run on-demand against any commit and so that the
contracts being fuzzed cannot drift away from the production API.
