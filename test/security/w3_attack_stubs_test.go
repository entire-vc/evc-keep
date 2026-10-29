package security

import "testing"

// Attack stubs for the carrier registry, scanner and rotation packages. One
// test per remaining contract; carrier portions live in w3_carriers_attack_test.go.
// Each is a stub only until its own target package lands (see
// w3Pending). Each comment states the expected refusal and the target package.

// TestW3_A03_SamePrefixValueIsStale - R-CAR-4, threat model 4.1.
// Expected refusal: A carrier holding a value with the same long prefix (v+"x", v cut by one byte, v with trailing space or newline) is stale, not "matched". Comparison is by full HMAC: no prefix compare, no early exit.
// Pending target: scanner; registry portion is independently exercised.
func TestW3_A03_SamePrefixValueIsStale(t *testing.T) { w3Pending(t, "W3-A03", "scanner") }

// TestW3_A04_FingerprintIsKeyedHMACNotSha256 - R-CAR-3, threat model 4.1.
// Expected refusal: The carrier and registry fingerprint is not sha256(value) under any truncation (hex/base32, 4-32 bytes). The same value in two stores gives different fingerprints. Format kfp1.
// Pending target: scanner; registry portion is independently exercised.
func TestW3_A04_FingerprintIsKeyedHMACNotSha256(t *testing.T) { w3Pending(t, "W3-A04", "scanner") }

// TestW3_A05_ScannerStaysInsideList - R-CAR-2.
// Expected refusal: A path outside the scan list (`..`, absolute, glob, `~` expanded into another home) is refused without being read; the response holds no file content.
// Target package: scanner.
func TestW3_A05_ScannerStaysInsideList(t *testing.T) { w3Pending(t, "W3-A05", "scanner") }

// TestW3_A06_ScannerRefusesSymlink - R-CAR-2, threat model I4.
// Expected refusal: A symlink to a file outside the list, a symlink inside a listed directory, a file swapped for a symlink between stat and open (TOCTOU), a hardlink -> refused (O_NOFOLLOW); the target content is never read.
// Target package: scanner.
func TestW3_A06_ScannerRefusesSymlink(t *testing.T) { w3Pending(t, "W3-A06", "scanner") }

// TestW3_A10_ForeignTenantCarriersInvisible - tenant scenarios.
// Expected refusal: Carrier registry, sprawl alerts, rotation and fingerprints of another org -> secret_not_found, indistinguishable from a nonexistent one. org_id comes only from the identity; another store's fp_key is never used.
// Pending target: rotation API; the registry and engine portions are exercised by the _Carriers and _Rotation witnesses.
func TestW3_A10_ForeignTenantCarriersInvisible(t *testing.T) { w3Pending(t, "W3-A10", "rotationapi") }

// TestW3_A11_CarrierGuessOracleBlocked - threat model I4.
// Expected refusal: Registering a guess carrier whose path is writable by the agent uid is refused; N verifies in a row hit a rate limit; the verify response does not tell "someone else's value" from "no file" by its text.
// Pending target: scanner; registry approval is independently exercised.
func TestW3_A11_CarrierGuessOracleBlocked(t *testing.T) { w3Pending(t, "W3-A11", "scanner") }

// TestW3_A13_AgentCannotInjectRotationValue - threat model I5.
// Expected refusal: An agent principal cannot set the value or version of a rotation, nor start an unscheduled one: no endpoint or MCP tool accepts a value from an agent; a rotation is started by actor type.
// Pending target: rotation API; the engine portion is exercised by the _Rotation witness.
func TestW3_A13_AgentCannotInjectRotationValue(t *testing.T) { w3Pending(t, "W3-A13", "rotationapi") }
