# Source and license notices

The independent protocol implementation uses Xray-core **v26.11.9** as its wire reference. It does not load, embed or launch the Go core. The original repository is GPL-3.0; this Rust package uses GPL-3.0-or-later. Files explicitly marked `SPDX-License-Identifier: MPL-2.0` retain that license for protocol behavior adapted from Xray. The complete MPL text is in `licenses/XRAY-MPL-2.0.txt`.

References:

- `XTLS/Xray-core`, tag `v26.11.9`, release commit `676eaf6`: `proxy/vless/encryption/{server,common,xor}.go`, `transport/internet/reality/reality.go`, `common/mux/frame.go`, and `common/geodata/consts.go`.
- REALITY authentication and certificate proof in `src/reality.rs` are an independent Rust adaptation of the above wire behavior. TLS 1.3 is implemented by rustls; the reference server's live-target handshake camouflage is not implemented. No Go REALITY source is embedded or launched.
- `BLAKE3-team/BLAKE3`, tag `1.8.7`: `reference_impl/reference_impl.rs`, copied to `src/blake3_reference.rs`. This file is distributed under its upstream Apache-2.0 option; see `licenses/BLAKE3-APACHE-2.0.txt`. The `Hasher::new_derive_key` argument accepts raw bytes instead of UTF-8 strings so it matches Xray's binary context. Rustfmt may change formatting.

Cryptographic operations use the exact RustCrypto, ring and rustls dependency versions in `Cargo.toml` and `Cargo.lock`. This new integration has interoperability and regression tests; it has not undergone an independent security audit.
