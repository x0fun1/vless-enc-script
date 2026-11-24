# Security

## Current assurance status

As of 2026-11-24, vless-rust has **not received an independent third-party security audit or penetration test**. Passing tests, Clippy, dependency-advisory scans, and maintainer code review are not substitutes. Do not describe the core as independently audited or treat this document as an audit certificate.

The project implements authentication, key derivation, encrypted records, VLESS parsing, TLS/REALITY handshake shaping, Vision framing, DNS resolution, and network forwarding. The experimental REALITY/Vision paths have a substantially larger review surface than the baseline Encryption path. In particular, target-derived TLS shaping has only been tested against specific local and NVIDIA TLS profiles; it is not full fingerprint parity or an anti-detection guarantee.

## Checks performed

The 2026-11-24 maintainer validation recorded in [rust-core/VALIDATION.md](rust-core/VALIDATION.md) includes:

- Rust unit tests, strict Clippy, release builds, CLI/menu/deployment regressions, and official Xray-core v26.11.9 interoperability on Windows and Debian 13.
- Debian 13/systemd smoke tests for each menu node type, including a real `www.nvidia.com` destination, configuration-preserving core upgrade, and cleanup of the temporary nodes.
- `cargo audit` scans of both the application lockfile and the separately vendored rustls lockfile. The vendored rustls lockfile was updated to patched `rustls-webpki` 0.103.17 and `webpki-roots` 1.0.10 after reviewing advisories RUSTSEC-2026-0382 and RUSTSEC-2026-0381. These scans cover published dependency advisories only; they do not audit project code or cryptographic protocol design.
- Target certificate-chain and SNI verification for the separate REALITY metadata probe, configurable explicit CA certificates for private test targets, bounded TLS record and supported key-share parsing, resolved-address self-target checks, and zeroizing wrappers for stored secret strings/bytes and X25519 static secrets. Zeroization cannot guarantee erasure of every compiler, OS, serialization, or provider copy.

A maintainer-led threat-oriented code review was performed during implementation. It is **not independent** and has not been reviewed or signed off by an external security professional.

## Operational guidance

- Keep configuration files, Encryption keys, REALITY private keys, and optional ML-DSA seeds private. Share only generated client links and public verification parameters.
- Use a current supported Rust toolchain and keep OS certificate roots and system time updated.
- Do not enable `allow_private_destinations` on an Internet-facing service unless required and understood.
- Configure REALITY only with a target you control or are authorized to use. The target is contacted for unauthenticated fallback and authenticated fingerprint capture; optional custom target roots are explicit trust anchors.
- Run experimental nodes on isolated ports and inspect systemd logs. REALITY target compatibility and traffic shape vary by target and can fail closed for authenticated connections.

## Reporting vulnerabilities

Do not post credentials, private configuration, or an unpatched exploitable vulnerability in a public issue. Contact the repository owner through GitHub's private vulnerability reporting feature when available. Include the affected commit/version, Rust toolchain, platform, minimal reproduction, and impact. Do not probe systems you do not own or have explicit permission to test.

## Independent audit needed

An audit has not been arranged or completed. A reviewer-ready scope draft is available in [SECURITY_AUDIT_BRIEF.md](SECURITY_AUDIT_BRIEF.md); it is not a report or certification. A release should not be represented as independently audited until an external auditor, who did not implement this code, has reviewed at least the cryptographic handshake and record layer, ClientHello/TLS parsing and target probing, VLESS/Vision state transitions, DNS/SSRF protections, key lifecycle, and installer/systemd privilege boundaries. Publish the auditor, scope, commit hash, dates, findings, and remediation status with the report; clearly list excluded areas and residual findings.
