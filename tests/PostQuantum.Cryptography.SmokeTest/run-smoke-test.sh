#!/usr/bin/env bash
# Bash equivalent of run-smoke-test.ps1 for Linux/macOS CI runners.
set -euo pipefail

VERSION="${1:-0.1.0-preview.2}"
CONFIGURATION="${2:-Release}"

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
REPO_ROOT="$( cd -- "$SCRIPT_DIR/../.." &> /dev/null && pwd )"

cd "$REPO_ROOT"

echo "[1/4] Packing PostQuantum.Cryptography $VERSION..."
rm -rf ./artifacts/packages
dotnet pack src/PostQuantum.Cryptography/PostQuantum.Cryptography.csproj \
    -c "$CONFIGURATION" \
    -p:Version="$VERSION" \
    -o ./artifacts/packages

echo "[2/4] Cleaning smoke test caches..."
rm -rf "$SCRIPT_DIR/bin" "$SCRIPT_DIR/obj"

echo "[3/4] Restoring smoke test against local feed..."
dotnet restore "$SCRIPT_DIR/PostQuantum.Cryptography.SmokeTest.csproj" \
    -p:SmokeTestPackageVersion="$VERSION" \
    --configfile "$SCRIPT_DIR/NuGet.config"

echo "[4/4] Running smoke test..."
dotnet run --project "$SCRIPT_DIR/PostQuantum.Cryptography.SmokeTest.csproj" \
    -c "$CONFIGURATION" \
    --no-restore \
    -p:SmokeTestPackageVersion="$VERSION"

echo ""
echo "Smoke test passed for PostQuantum.Cryptography $VERSION"
