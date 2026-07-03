using PostQuantum.Cryptography.Internal;

// Exercises every bundled-X25519 entry point so the JIT compiles the full
// scalar-multiplication call graph (ladder, Sel25519, field arithmetic).
//
// Run under:
//   DOTNET_TieredCompilation=0  DOTNET_ReadyToRun=0  DOTNET_JitDisasm="*X25519*"
// and the process stdout contains the final-tier native disassembly the JIT
// actually emitted for the constant-time-critical methods — the artifact a
// reviewer inspects for secret-dependent branches or memory access (the loop
// branches on the public 255-iteration counter are expected; anything keyed
// on scalar *bits* is not). See AUDIT-SCOPE.md §3 and the constant-time.yml
// workflow that captures this per SDK servicing update.
//
// The harness is self-checking: it verifies RFC 7748 §5.2 vector 1 and the
// §6.1 base-point result so a captured disassembly always corresponds to a
// functionally correct compilation. Exit code 0 = outputs correct.

byte[] scalar = Convert.FromHexString("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
byte[] u = Convert.FromHexString("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");

string scalarMult = Convert.ToHexString(X25519.ScalarMult(scalar, u)).ToLowerInvariant();
Console.WriteLine($"; ScalarMult      = {scalarMult}");

byte[] alicePriv = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
string scalarMultBase = Convert.ToHexString(X25519.ScalarMultBase(alicePriv)).ToLowerInvariant();
Console.WriteLine($"; ScalarMultBase  = {scalarMultBase}");

bool ok = scalarMult == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
       && scalarMultBase == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

Console.WriteLine(ok ? "; RFC 7748 vectors: OK" : "; RFC 7748 vectors: MISMATCH");
return ok ? 0 : 1;
