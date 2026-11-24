# Independent Security Review Brief (Draft)

**Status: no auditor has been engaged; no independent audit has occurred.** This file is a scope brief for a reviewer who did not implement this software. It is not an audit report or security certification.

## Exact review target

- Published baseline: `vless-rust-v0.3.1`, source commit `139f908ab1536bbf10ca8a10f658133cbfe0049b`.
- Current un-released candidate: `854802705e1be47edb096e5187d81e1d69d766ec` on local branch `security/vision-fragment-eof`. It includes the direct-truncation/fragmented-ServerHello patch `fc534857ed817982aa5b56db5786e40f1f5e2ecf` and follow-up ClientHello filter-budget fix `854802705e1be47edb096e5187d81e1d69d766ec`, based on published main HEAD `b466bf7e51fbf9045826ebbad41972e15bffd14d`.
- The candidate is **not pushed or released**. Rust package version metadata still says 0.3.1, so the candidate must not be mistaken for the released 0.3.1 binary.
- Interoperability reference is pinned Xray-core v26.11.9, source `676eaf66f8f05d4d558ee7a74b4736623d3feeb9`.

The reviewer should obtain the repository at the exact candidate commit and state whether the review covers the full tree or only the delta. For a release decision, review the full tree, including the vendored rustls modifications, and not only the two files in the latest patch.

## Requested scope

1. **Protocol cryptography and authentication**
   - VLESS Encryption key derivation, authentication, record framing/AEAD, nonce/rekey behavior, 0-RTT session expiry/replay handling.
   - REALITY ClientHello authentication, time window, short ID/SNI handling, replay-cache behavior, transcript binding and ServerHello shaping.
   - Optional ML-DSA-65 seed/key lifecycle, proof construction and verification expectations; relationship to Ed25519 TLS CertificateVerify and HMAC authentication.
   - Secret copies, error/log output, configuration serialization and best-effort zeroization assumptions.
2. **Vendored TLS implementation**
   - Review the full patch against upstream rustls 0.23.46, including handshake hooks, transcript handling, certificate resolution, record padding and all modified client/server record paths.
   - Check Ring production paths and AWS-LC paths, feature boundaries, error handling and unsafe-code constraints.
3. **Parsing and resource controls**
   - ClientHello/ServerHello and TLS record parsing, VLESS Addons, Mux/XUDP, padding lengths, truncation behavior and fragmented/coalesced inputs.
   - Allocation and CPU bounds under malformed or deliberately slow client/target traffic.
4. **Vision state and direct forwarding**
   - Addons/Continue/End/Direct state transitions in both directions, random-appearance TLS record-header masking, partial reads/writes, half-close, clean EOF, truncated record/body/header behavior and Mux interactions.
   - The candidate adds truncated direct-record EOF errors, fragmented ClientHello/ServerHello sniffing, and deterministic synthetic bidirectional Direct tests; these changes need independent review as well as retest.
5. **Target and network boundaries**
   - DNS resolution/rebinding assumptions, listener self-target checks, private-destination filtering, custom target CA trust, certificate/SNI validation of the separate metadata probe, fallback relay behavior, timeouts and cache keys/expiry.
   - Confirm that the capture connection and metadata-probe connection cannot be redirected to unsafe or unexpected endpoints.
6. **Deployment and release boundary**
   - `install.sh`, `rust-core/install.sh`, `rust-core/venc`, systemd units/users/permissions, migration/rollback, release workflow and checksum/provenance handling.

## Threat model and exclusions to state in the report

Assume an Internet-reachable service receives malicious unauthenticated and authenticated client input and may be configured with a hostile or misconfigured target. Consider resource exhaustion, parser differentials, replay, target redirection, information disclosure, privilege boundaries and downgrade/interop failures. Do not assume the configured target or its DNS answers are trusted merely because the operator configured a hostname.

The project has **not** established complete TLS fingerprint parity, arbitrary-target compatibility, PSK/resumption or post-handshake REALITY parity, production-grade Vision Direct in both directions with the official client, long-term/mobile/NAT behavior, an extended soak, or an off-host ingress test for v0.3.1. These are known limitations, not audit exclusions to silently omit. The reviewer should list any areas not examined and residual risks explicitly.

## Available maintainer evidence (not independent assurance)

For the v0.3.1 release, `rust-core/VALIDATION.md` records Windows and Debian 13 tests, official Xray-core v26.11.9 interoperability, dependency scans and a systemd smoke. The current candidate has Windows results: 34 Rust tests, strict Clippy, locked release build, 14 core regressions, 16 deployment regressions, 30 REALITY+Vision Xray variants, 30 plain Vision Xray variants, and native/random ML-DSA-65 subsets. Chrome/Firefox/Safari REALITY quick cases passed. New deterministic tests exercise both synthetic Direct directions, fragmented ClientHello/ServerHello boundaries, masked fragmented Direct record headers, clean EOF and truncated headers/bodies.

**The candidate has not been re-run on Debian or systemd**, and GitHub CI has not run for this local branch. No dependency lockfile changed in this candidate. The previous `cargo-audit` v0.23.0 scans of both lockfiles are dependency-advisory scans only; they do not cover project code or protocol design.

## Requested deliverables

- Reviewer identity/qualifications, independence statement, exact commit hash, dates and tools/methodology.
- Findings with severity, affected files/lines, preconditions, impact and minimal reproduction.
- Explicit coverage and exclusions for each scope item above.
- Remediation and independent retest status for every finding before describing the audit as complete.
- A publishable report that contains no server credentials, private keys, client links or access tokens.

Before starting, agree whether the reviewer needs only the source archive or a private review channel. No server access or production credentials should be necessary for this code review. Any live penetration test must be separately authorized and use disposable test nodes and credentials.
