# Independent Security Review Brief (Draft)

**Status: no auditor has been engaged; no independent audit has occurred.** This file is a scope brief for a reviewer who did not implement this software. It is not an audit report or security certification.

## Exact review target

- Published baseline: `vless-rust-v0.3.1`, source commit `139f908ab1536bbf10ca8a10f658133cbfe0049b`.
- Release provenance baseline: `b466bf7e51fbf9045826ebbad41972e15bffd14d`.
- Current unreleased implementation candidate: `87c9381e3409164bb48a0515b78e74694ce896d8` on `security/vision-fragment-eof`, as recorded in [the 2026-11-25 maintainer review](docs/SECURITY_REVIEW_2026-11-25.md). Earlier Vision patches `fc534857ed817982aa5b56db5786e40f1f5e2ecf` and `854802705e1be47edb096e5187d81e1d69d766ec` are included but are not the latest complete candidate. Subsequent documentation commits record its scope; use the frozen implementation commit when reproducing the build.
- The candidate is **not released**. Rust package version metadata still says 0.3.1, so the candidate must not be mistaken for the released 0.3.1 binary.
- Interoperability reference is pinned Xray-core v26.11.9, source `676eaf66f8f05d4d558ee7a74b4736623d3feeb9`.

The reviewer should obtain the repository at the frozen candidate commit and state whether the review covers the full tree or only the delta. For a release decision, review the full tree, including the vendored rustls modifications, configuration replacement, installers, and release workflow. A working-tree description is not a substitute for a reproducible audit snapshot.

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
   - The candidate adds truncated Vision-frame errors and masked random-appearance Direct-record EOF errors, fragmented ClientHello/ServerHello sniffing, timely delivery of short masked Direct records, and deterministic synthetic bidirectional Direct tests; these changes need independent review as well as retest. Native/xorpub Direct passes data through, with TLS integrity checked by the endpoints.
5. **Target and network boundaries**
   - DNS resolution/rebinding assumptions, listener self-target checks, private-destination filtering, custom target CA trust, certificate/SNI validation of the separate metadata probe, fallback relay behavior, timeouts and cache keys/expiry.
   - Confirm that the capture connection and metadata-probe connection cannot be redirected to unsafe or unexpected endpoints.
   - Recheck the default private-target policy for every DNS answer, explicit private-network opt-in, and self-listener protection. An unauthenticated fallback client cannot choose a different configured target; assess the actual configuration/DNS preconditions. Certificate verification on the separate metadata probe does not establish that the capture connection used the same target behavior.
   - Verify custom target CA parsing and native/custom trust-store merging, including empty platform stores, malformed custom certificates and continued chain/SNI validation.
6. **Deployment and release boundary**
   - `install.sh`, `rust-core/install.sh`, `rust-core/venc`, systemd units/users/permissions, migration/rollback, release workflow and checksum/provenance handling.
   - Check bounded file reads, exclusive temporary-file creation, cleanup ownership, atomic replacement and Unix service ownership/group access. Confirm that releases require a matching version tag and do not overwrite an already-published version. Downloaded SHA-256 sidecars are not an independent signature or trust root.

## Threat model and exclusions to state in the report

Assume an Internet-reachable service receives malicious unauthenticated and authenticated client input and may be configured with a hostile or misconfigured target. Consider resource exhaustion, parser differentials, replay, target redirection, information disclosure, privilege boundaries and downgrade/interop failures. Do not assume the configured target or its DNS answers are trusted merely because the operator configured a hostname.

The project has **not** established complete TLS fingerprint parity, arbitrary-target compatibility, PSK/resumption or post-handshake REALITY parity, production-grade Vision Direct in both directions with the official client, long-term/mobile/NAT behavior, an extended soak, or an off-host ingress test for v0.3.1. These are known limitations, not audit exclusions to silently omit. The reviewer should list any areas not examined and residual risks explicitly.

## Available maintainer evidence (not independent assurance)

For the v0.3.1 release, `rust-core/VALIDATION.md` records historical Windows and Debian 13 tests, official Xray-core v26.11.9 interoperability, dependency scans and a systemd smoke. For the 2026-11-25 candidate, use the separate dated section and [maintainer review](docs/SECURITY_REVIEW_2026-11-25.md): they identify the actual tested binary and current results. Do not reuse an earlier debug binary or historical matrix as evidence for this working tree.

**The current candidate has not been re-run on Debian or systemd**, and GitHub CI has not run for this local branch. Ring/std is the executed provider; AWS-LC paths have source review only. Windows skips Unix ownership/permission verification; a dedicated Linux CI regression has been added but is not yet a passing result. No dependency lockfile changed. The 2026-11-25 cargo-audit 0.23.0 scans of both lockfiles report no known advisories with RustSec snapshot `b9b8a3c2cb1f2a3c76ab17a551193568c9f8b7a4`; yanked-crate checks were disabled. These scans do not cover project code, protocol design, or the custom rustls patch.

## Requested deliverables

- Reviewer identity/qualifications, independence statement, exact commit hash, dates and tools/methodology.
- Findings with severity, affected files/lines, preconditions, impact and minimal reproduction.
- Explicit coverage and exclusions for each scope item above.
- Remediation and independent retest status for every finding before describing the audit as complete.
- A publishable report that contains no server credentials, private keys, client links or access tokens.

Before starting, agree whether the reviewer needs only the source archive or a private review channel. No server access or production credentials should be necessary for this code review. Any live penetration test must be separately authorized and use disposable test nodes and credentials.
