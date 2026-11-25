# Local changes to rustls 0.23.46

This directory starts from the crates.io source archive for **rustls 0.23.46**.
It is selected by the application's `[patch.crates-io]` entry and contains local
REALITY integration changes; it must not be treated as an unchanged upstream
release. Preserve the upstream license files when upgrading.

To reproduce the comparison, download the official archive at
`https://static.crates.io/crates/rustls/rustls-0.23.46.crate`, unpack it in a
temporary directory, and compare it from the repository root:

```sh
diff -ru --exclude=PATCHES.md /path/to/unpacked/rustls-0.23.46 rust-core/vendor/rustls
```

Compare source contents rather than timestamps. The local `PATCHES.md` is the
additional documentation file; the changes listed below are the expected
differences from the upstream archive.

The 2026-11-25 source comparison against that archive found the following
changed source files:

| Files | Local behavior |
| --- | --- |
| `src/server/server_conn.rs` | Adds optional certificate-resolver hooks for target-derived ServerHello bytes, certificate proof generation after ServerHello serialization, handshake record lengths and SNI acknowledgement. The default hooks keep the upstream behavior. |
| `src/server/tls13.rs` | Calls the hooks, uses the emitted ServerHello bytes in the handshake transcript, and optionally selects the certificate returned after ServerHello. |
| `src/server/hs.rs` | Allows the configured target profile to control the TLS 1.3 SNI acknowledgement. |
| `src/client/tls13.rs` | Records the verified metadata probe's peer SNI acknowledgement. |
| `src/common_state.rs` | Stores target metadata, exposes the peer SNI acknowledgement and shapes encrypted handshake records with zero padding. A four-record target flight may split the server handshake messages before padding. |
| `src/record_layer.rs`, `src/crypto/cipher.rs` | Passes the optional padding length to record encryption; normal record paths pass zero. |
| `src/crypto/ring/tls13.rs`, `src/crypto/aws_lc_rs/tls13.rs` | Encrypts the TLS 1.3 content type plus zero padding and includes the resulting ciphertext length in AEAD associated data. |
| `src/crypto/ring/tls12.rs`, `src/crypto/aws_lc_rs/tls12.rs` | Adapts the encryption interface; ignores the TLS 1.3 padding parameter. |

The independent vendored `Cargo.lock` also updates `rustls-webpki` from
0.103.15 to 0.103.17 and `webpki-roots` from 1.0.9 to 1.0.10. The application
uses `rust-core/Cargo.lock` for its build; scan both lockfiles when checking
dependency advisories.

The application enables `std` and `ring` with rustls default features disabled.
The REALITY path offers TLS 1.3 only and its own server-side hybrid key exchange.
It authenticates the ClientHello before creating the hooked TLS server.
`src/reality.rs` bounds target TLS record sizes before supplying target metadata,
checks target/private-network policy before connecting, and verifies the
separate metadata probe's certificate chain and SNI. The capture and metadata
probe remain distinct connections. These changes do not establish complete
target fingerprint parity.

When updating rustls, compare the full source tree against the new upstream
archive, review these hooks and all changed cipher providers, and run the
application's Rust, malformed-input and official-client interoperability tests.
The 2026-11-25 maintainer review inspected the local Ring and AWS-LC cipher
changes, but execution validation uses the application's Ring build. AWS-LC
was reviewed as source only. This review does not validate every upstream
feature combination and is not an independent security audit. See
[SECURITY.md](../../../SECURITY.md) and
[VALIDATION.md](../../VALIDATION.md) for the scope of recorded validation.
