# Security

## Current assurance status

As of 2026-11-25, vless-rust has **not received an independent third-party security audit or penetration test**. Passing tests, Clippy, dependency-advisory scans, and maintainer code review are not substitutes. Do not describe the core as independently audited or treat this document as an audit certificate.

The published v0.3.1 functional baseline is source commit `139f908ab1536bbf10ca8a10f658133cbfe0049b`; release provenance is recorded at `b466bf7e51fbf9045826ebbad41972e15bffd14d`. The 2026-11-25 security candidate's implementation and CI fixes are frozen at `87c9381e3409164bb48a0515b78e74694ce896d8` on `security/vision-fragment-eof`; subsequent documentation commits record its scope. These additional fixes have not been released. Package metadata still says 0.3.1, so use the source revision and validation scope to identify a build.

The project implements authentication, key derivation, encrypted records, VLESS parsing, TLS/REALITY handshake shaping, Vision framing, DNS resolution, and network forwarding. The experimental REALITY/Vision paths have a substantially larger review surface than the baseline Encryption path. In particular, target-derived TLS shaping has only been tested against specific local and NVIDIA TLS profiles; it is not full fingerprint parity or an anti-detection guarantee.

## Checks performed

The 2026-11-24 maintainer validation recorded in [rust-core/VALIDATION.md](rust-core/VALIDATION.md) includes:

- Rust unit tests, strict Clippy, release builds, CLI/menu/deployment regressions, and official Xray-core v26.11.9 interoperability on Windows and Debian 13.
- Debian 13/systemd smoke tests for each menu node type, including a real `www.nvidia.com` destination, configuration-preserving core upgrade, and cleanup of the temporary nodes.
- `cargo audit` scans of both the application lockfile and the separately vendored rustls lockfile. The vendored rustls lockfile was updated to patched `rustls-webpki` 0.103.17 and `webpki-roots` 1.0.10 after reviewing advisories RUSTSEC-2026-0382 and RUSTSEC-2026-0381. These scans cover published dependency advisories only; they do not audit project code or cryptographic protocol design.
- Target certificate-chain and SNI verification for the separate REALITY metadata probe, configurable explicit CA certificates for private test targets, bounded TLS record and supported key-share parsing, resolved-address self-target checks, and zeroizing wrappers for stored secret strings/bytes and X25519 static secrets. Zeroization cannot guarantee erasure of every compiler, OS, serialization, or provider copy.

A maintainer-led threat-oriented code review was performed during implementation. It is **not independent** and has not been reviewed or signed off by an external security professional.

The [2026-11-25 maintainer security review](docs/SECURITY_REVIEW_2026-11-25.md) records fixes for REALITY target policy, custom target CA loading when system roots are empty, Vision frame truncation and Direct forwarding, bounded configuration reads, safe configuration replacement, and release asset provenance. It also separates current Windows results from historical Debian/systemd results. The Ring provider was exercised; the alternative AWS-LC paths received source review only. Unix ownership and permission handling is skipped on Windows, with a dedicated Linux CI regression added but not yet executed by GitHub.

On 2026-11-25, official cargo-audit 0.23.0 scanned both lockfiles using RustSec database commit `b9b8a3c2cb1f2a3c76ab17a551193568c9f8b7a4` (1,548 advisories): application 131 packages and vendored rustls 134 packages, with no reported vulnerabilities or warnings. No advisory IDs or platforms were excluded. Yanked-crate checks were disabled. These results do not review application code, protocol design, or the custom vendored TLS changes; see the dated review for tool provenance and exact coverage.

## Operational guidance

- Keep configuration files, Encryption keys, REALITY private keys, and optional ML-DSA seeds private. Share only generated client links and public verification parameters.
- Use a current supported Rust toolchain and keep OS certificate roots and system time updated.
- Do not enable `allow_private_destinations` on an Internet-facing service unless required and understood.
- In the current candidate, this setting also controls REALITY fallback and target-probe connections: private/special-use names and resolved addresses are blocked by default. Private test targets require an explicit opt-in; the self-listener guard remains active. Published v0.3.1 does not include this additional policy check.
- Configure REALITY only with a target you control or are authorized to use. The target is contacted for unauthenticated fallback and authenticated fingerprint capture; optional custom target roots are explicit trust anchors.
- Run experimental nodes on isolated ports and inspect systemd logs. REALITY target compatibility and traffic shape vary by target and can fail closed for authenticated connections.

## Reporting vulnerabilities

Do not post credentials, private configuration, or an unpatched exploitable vulnerability in a public issue. Contact the repository owner through GitHub's private vulnerability reporting feature when available. Include the affected commit/version, Rust toolchain, platform, minimal reproduction, and impact. Do not probe systems you do not own or have explicit permission to test.

## Independent audit needed

An audit has not been arranged or completed. A reviewer-ready scope draft is available in [SECURITY_AUDIT_BRIEF.md](SECURITY_AUDIT_BRIEF.md); it is not a report or certification. A release should not be represented as independently audited until an external auditor, who did not implement this code, has reviewed at least the cryptographic handshake and record layer, ClientHello/TLS parsing and target probing, VLESS/Vision state transitions, DNS/SSRF protections, key lifecycle, and installer/systemd privilege boundaries. Publish the auditor, scope, commit hash, dates, findings, and remediation status with the report; clearly list excluded areas and residual findings.
