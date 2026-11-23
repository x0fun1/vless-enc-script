// Experimental REALITY authentication over rustls TLS 1.3.
// SPDX-License-Identifier: MPL-2.0
// Wire reference: Xray-core v26.11.9 transport/internet/reality/reality.go.
// This is NOT the reference server's live-target ServerHello/record camouflage.
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ml_kem::{
    MlKem768,
    kem::{Encapsulate, TryKeyInit},
};
use rand::{RngCore, rngs::OsRng};
use ring::{
    hkdf, hmac,
    signature::{Ed25519KeyPair, KeyPair},
};
use rustls::{
    NamedGroup, ServerConfig,
    crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RealityConfig {
    pub private_key: String,
    pub short_id: String,
    pub server_name: String,
    pub target: String,
    #[serde(default = "default_time_diff")]
    pub max_time_diff_secs: u64,
}
fn default_time_diff() -> u64 {
    300
}

impl RealityConfig {
    pub fn generate(server_name: String, target: String) -> Result<Self> {
        let mut key = Zeroizing::new([0; 32]);
        let mut sid = [0; 8];
        OsRng.fill_bytes(&mut *key);
        OsRng.fill_bytes(&mut sid);
        let config = Self {
            private_key: URL_SAFE_NO_PAD.encode(*key),
            short_id: sid.iter().map(|b| format!("{b:02x}")).collect(),
            server_name,
            target,
            max_time_diff_secs: default_time_diff(),
        };
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        self.secret()?;
        self.sid()?;
        ensure!(
            !self.server_name.is_empty()
                && self.server_name.len() <= 253
                && self
                    .server_name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b)),
            "invalid REALITY server_name"
        );
        let (host, port) = self
            .target
            .rsplit_once(':')
            .context("REALITY target must be HOST:PORT")?;
        ensure!(
            !host.is_empty()
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
                && port.parse::<u16>().is_ok_and(|p| p != 0),
            "invalid REALITY target"
        );
        ensure!(
            (1..=3600).contains(&self.max_time_diff_secs),
            "REALITY max_time_diff_secs must be 1..3600"
        );
        Ok(())
    }
    fn secret(&self) -> Result<StaticSecret> {
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(&self.private_key)
                .context("invalid REALITY private key encoding")?,
        );
        ensure!(bytes.len() == 32, "REALITY private key must be 32 bytes");
        Ok(StaticSecret::from(<[u8; 32]>::try_from(bytes.as_slice())?))
    }
    fn sid(&self) -> Result<[u8; 8]> {
        ensure!(
            !self.short_id.is_empty()
                && self.short_id.len() <= 16
                && self.short_id.len().is_multiple_of(2)
                && self.short_id.bytes().all(|b| b.is_ascii_hexdigit()),
            "REALITY short_id must be 2..16 hex digits with even length"
        );
        let mut sid = [0; 8];
        for (i, pair) in self
            .short_id
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .enumerate()
        {
            sid[i] = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
        }
        Ok(sid)
    }
    pub fn public_key(&self) -> Result<String> {
        Ok(URL_SAFE_NO_PAD.encode(PublicKey::from(&self.secret()?).as_bytes()))
    }
}

// Only used server-side: ML-KEM ciphertext precedes the X25519 public key,
// and the TLS shared secret is ML-KEM secret || X25519 secret.
#[derive(Debug)]
struct HybridGroup;
static HYBRID: HybridGroup = HybridGroup;
impl SupportedKxGroup for HybridGroup {
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
    fn start(&self) -> std::result::Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        Err(rustls::Error::General("server-only hybrid KEM".into()))
    }
    fn start_and_complete(
        &self,
        peer: &[u8],
    ) -> std::result::Result<CompletedKeyExchange, rustls::Error> {
        let result = (|| -> Result<_> {
            ensure!(peer.len() == 1216, "invalid hybrid key share");
            let kem = ml_kem::EncapsulationKey::<MlKem768>::new_from_slice(&peer[..1184])?;
            let (ciphertext, kem_secret) = kem.encapsulate();
            let secret = StaticSecret::random_from_rng(OsRng);
            let shared =
                secret.diffie_hellman(&PublicKey::from(<[u8; 32]>::try_from(&peer[1184..])?));
            ensure!(shared.was_contributory(), "invalid hybrid X25519 key share");
            let mut public = ciphertext.to_vec();
            public.extend_from_slice(PublicKey::from(&secret).as_bytes());
            let mut combined = Zeroizing::new(kem_secret.to_vec());
            combined.extend_from_slice(shared.as_bytes());
            Ok(CompletedKeyExchange {
                group: self.name(),
                pub_key: public,
                secret: SharedSecret::from(combined.as_slice()),
            })
        })();
        result.map_err(|_| rustls::Error::General("invalid REALITY hybrid key exchange".into()))
    }
    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }
}

pub struct Server {
    config: RealityConfig,
    secret: StaticSecret,
    sid: [u8; 8],
    signing_key: Arc<dyn rustls::sign::SigningKey>,
    cert_body: Vec<u8>,
    cert_public: Vec<u8>,
    seen: Mutex<HashMap<[u8; 32], Instant>>,
    max_seen: usize,
}

// Small, fixed Ed25519 X.509 template; the certificate signature is the REALITY
// HMAC-SHA512 proof. CertificateVerify is still a real Ed25519 TLS signature.
fn der(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![tag];
    if bytes.len() < 128 {
        result.push(bytes.len() as u8);
    } else if bytes.len() < 256 {
        result.extend_from_slice(&[0x81, bytes.len() as u8]);
    } else {
        result.extend_from_slice(&[0x82, (bytes.len() >> 8) as u8, bytes.len() as u8]);
    }
    result.extend_from_slice(bytes);
    result
}
fn cert_body(public: &[u8]) -> Vec<u8> {
    let algorithm = der(0x30, &[0x06, 0x03, 0x2b, 0x65, 0x70]);
    let mut key = vec![0];
    key.extend_from_slice(public);
    let mut spki = algorithm.clone();
    spki.extend(der(0x03, &key));
    let mut validity = der(0x17, b"200101000000Z");
    validity.extend(der(0x17, b"491231235959Z"));
    let mut body = vec![0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01];
    body.extend(&algorithm);
    body.extend([0x30, 0x00]);
    body.extend(der(0x30, &validity));
    body.extend([0x30, 0x00]);
    body.extend(der(0x30, &spki));
    let mut result = der(0x30, &body);
    result.extend(algorithm);
    result
}

impl Server {
    pub fn new(config: RealityConfig, max_seen: usize) -> Result<Self> {
        config.validate()?;
        let private = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("generate REALITY certificate key"))?;
        let pair = Ed25519KeyPair::from_pkcs8(private.as_ref())
            .map_err(|_| anyhow::anyhow!("parse certificate key"))?;
        let public = pair.public_key().as_ref().to_vec();
        let signing_key = rustls::crypto::ring::sign::any_supported_type(
            &PrivatePkcs8KeyDer::from(private.as_ref().to_vec()).into(),
        )?;
        Ok(Self {
            secret: config.secret()?,
            sid: config.sid()?,
            config,
            signing_key,
            cert_body: cert_body(&public),
            cert_public: public,
            seen: Mutex::new(HashMap::new()),
            max_seen: max_seen.max(1),
        })
    }
    fn authenticate(&self, hello: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let parsed = Hello::parse(hello)?;
        ensure!(
            parsed.server_name == self.config.server_name.as_bytes(),
            "REALITY SNI mismatch"
        );
        let mut aad = hello.to_vec();
        aad[39..71].fill(0);
        for peer in parsed.peers {
            let shared = self.secret.diffie_hellman(&PublicKey::from(peer));
            if !shared.was_contributory() {
                continue;
            }
            let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &hello[6..26]);
            let prk = salt.extract(shared.as_bytes());
            let info = [b"REALITY".as_slice()];
            let mut auth = Zeroizing::new(vec![0; 32]);
            prk.expand(&info, hkdf::HKDF_SHA256)
                .map_err(|_| anyhow::anyhow!("REALITY HKDF"))?
                .fill(&mut auth)
                .map_err(|_| anyhow::anyhow!("REALITY HKDF"))?;
            let cipher =
                Aes256Gcm::new_from_slice(&auth).map_err(|_| anyhow::anyhow!("REALITY AES key"))?;
            let Ok(plain) = cipher.decrypt(
                Nonce::from_slice(&hello[26..38]),
                Payload {
                    msg: &hello[39..71],
                    aad: &aad,
                },
            ) else {
                continue;
            };
            ensure!(
                plain.len() == 16 && plain[3] == 0 && plain[8..16] == self.sid,
                "REALITY short ID mismatch"
            );
            let timestamp = u32::from_be_bytes(plain[4..8].try_into()?) as u64;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            ensure!(
                now.abs_diff(timestamp) <= self.config.max_time_diff_secs,
                "REALITY timestamp outside allowed window"
            );
            let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
            seen.retain(|_, expires| *expires > Instant::now());
            let digest = ring::digest::digest(&ring::digest::SHA256, hello);
            let id = <[u8; 32]>::try_from(digest.as_ref())?;
            ensure!(
                seen.len() < self.max_seen && !seen.contains_key(&id),
                "REALITY replay or replay cache full"
            );
            seen.insert(
                id,
                Instant::now() + Duration::from_secs(self.config.max_time_diff_secs * 2 + 1),
            );
            return Ok(auth);
        }
        bail!("REALITY authentication failed")
    }
    pub async fn accept(&self, mut socket: TcpStream) -> Result<Option<TlsStream<Replay>>> {
        let (prefix, hello) = read_hello(&mut socket).await?;
        let auth = hello
            .as_deref()
            .and_then(|hello| self.authenticate(hello).ok());
        let Some(auth) = auth else {
            let mut target = TcpStream::connect(&self.config.target)
                .await
                .context("connect REALITY fallback target")?;
            ensure!(
                target.peer_addr()? != socket.local_addr()?,
                "REALITY fallback cannot point to this listener"
            );
            target.write_all(&prefix).await?;
            // Fallback is not a proxy user. The caller keeps it within the bounded
            // handshake timeout/concurrency budget, not an unbounded relay task.
            tokio::io::copy_bidirectional(&mut socket, &mut target).await?;
            return Ok(None);
        };
        let signature = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, &auth), &self.cert_public);
        let mut proof = vec![0];
        proof.extend_from_slice(signature.as_ref());
        let mut body = self.cert_body.clone();
        body.extend(der(0x03, &proof));
        let certified = rustls::sign::CertifiedKey::new(
            vec![CertificateDer::from(der(0x30, &body))],
            Arc::new(RealitySigningKey(self.signing_key.clone())),
        );
        let mut provider = rustls::crypto::ring::default_provider();
        provider.kx_groups = vec![&HYBRID, rustls::crypto::ring::kx_group::X25519];
        let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(FixedCert(Arc::new(certified))));
        config.send_tls13_tickets = 0;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Some(
            TlsAcceptor::from(Arc::new(config))
                .accept(Replay {
                    socket,
                    prefix,
                    offset: 0,
                })
                .await
                .context("REALITY TLS handshake")?,
        ))
    }
}
// REALITY deliberately uses Ed25519 even when a browser fingerprint omits it.
// This resolver is reachable only after authenticating the REALITY ClientHello;
// unauthenticated TLS is relayed untouched to the real target instead.
#[derive(Debug)]
struct RealitySigningKey(Arc<dyn rustls::sign::SigningKey>);
impl rustls::sign::SigningKey for RealitySigningKey {
    fn choose_scheme(
        &self,
        _: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        self.0.choose_scheme(&[rustls::SignatureScheme::ED25519])
    }
    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ED25519
    }
}
#[derive(Debug)]
struct FixedCert(Arc<rustls::sign::CertifiedKey>);
impl rustls::server::ResolvesServerCert for FixedCert {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(self.0.len() >= n, "truncated REALITY ClientHello");
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<usize> {
        Ok(self.take(1)?[0] as usize)
    }
    fn u16(&mut self) -> Result<usize> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into()?) as usize)
    }
    fn vector(&mut self) -> Result<Cursor<'a>> {
        let n = self.u16()?;
        Ok(Cursor(self.take(n)?))
    }
}
struct Hello<'a> {
    server_name: &'a [u8],
    peers: Vec<[u8; 32]>,
}
impl<'a> Hello<'a> {
    fn parse(hello: &'a [u8]) -> Result<Self> {
        ensure!(
            hello.len() >= 71 && hello[0] == 1 && hello[38] == 32,
            "invalid REALITY ClientHello/session ID"
        );
        let mut cursor = Cursor(&hello[71..]);
        cursor.vector()?;
        let n = cursor.u8()?;
        cursor.take(n)?;
        let mut extensions = cursor.vector()?;
        ensure!(cursor.0.is_empty(), "trailing ClientHello bytes");
        let mut server_name = None;
        let mut peers = Vec::new();
        let mut seen = std::collections::HashSet::new();
        while !extensions.0.is_empty() {
            let kind = extensions.u16()?;
            let mut value = extensions.vector()?;
            ensure!(seen.insert(kind), "duplicate ClientHello extension");
            match kind {
                0 => {
                    let mut names = value.vector()?;
                    while !names.0.is_empty() {
                        let kind = names.u8()?;
                        let name = names.vector()?;
                        if kind == 0 {
                            ensure!(server_name.is_none(), "duplicate SNI");
                            server_name = Some(name.0);
                        }
                    }
                }
                51 => {
                    let mut shares = value.vector()?;
                    while !shares.0.is_empty() {
                        let group = shares.u16()?;
                        let key = shares.vector()?;
                        match (group, key.0.len()) {
                            (29, 32) => peers.push(key.0.try_into()?),
                            (4588, 1216) => peers.push(key.0[1184..].try_into()?),
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(Self {
            server_name: server_name.context("missing REALITY SNI")?,
            peers,
        })
    }
}
async fn read_hello(socket: &mut TcpStream) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let mut prefix = Vec::new();
    let mut hello = Vec::new();
    loop {
        let mut header = [0; 5];
        socket.read_exact(&mut header).await?;
        prefix.extend_from_slice(&header);
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        if header[0] != 22
            || header[1] != 3
            || !(1..=16384).contains(&length)
            || prefix.len() + length > 65536
        {
            return Ok((prefix, None));
        }
        let start = prefix.len();
        prefix.resize(start + length, 0);
        socket.read_exact(&mut prefix[start..]).await?;
        hello.extend_from_slice(&prefix[start..]);
        if hello.len() >= 4 {
            let total =
                4 + ((hello[1] as usize) << 16 | (hello[2] as usize) << 8 | hello[3] as usize);
            if total > 65536 || hello[0] != 1 {
                return Ok((prefix, None));
            }
            if hello.len() >= total {
                hello.truncate(total);
                return Ok((prefix, Some(hello)));
            }
        }
    }
}

pub struct Replay {
    socket: TcpStream,
    prefix: Vec<u8>,
    offset: usize,
}
impl AsyncRead for Replay {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let n = buf.remaining().min(self.prefix.len() - self.offset);
            buf.put_slice(&self.prefix[self.offset..self.offset + n]);
            self.offset += n;
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.socket).poll_read(cx, buf)
        }
    }
}
impl AsyncWrite for Replay {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.socket).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn config_roundtrip_and_invalid_fields() {
        let mut c =
            RealityConfig::generate("example.com".into(), "example.com:443".into()).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(c.public_key().unwrap())
                .unwrap()
                .len(),
            32
        );
        assert_eq!(c.short_id.len(), 16);
        c.short_id = "123".into();
        assert!(c.validate().is_err());
        c.short_id = "abcd".into();
        c.max_time_diff_secs = 0;
        assert!(c.validate().is_err());
    }
    fn authenticated_hello(config: &RealityConfig, timestamp: u64, sid: [u8; 8]) -> Vec<u8> {
        fn vector(bytes: &[u8]) -> Vec<u8> {
            let mut output = (bytes.len() as u16).to_be_bytes().to_vec();
            output.extend_from_slice(bytes);
            output
        }
        let peer = StaticSecret::random_from_rng(OsRng);
        let mut random = [0; 32];
        OsRng.fill_bytes(&mut random);
        let mut name = vec![0];
        name.extend(vector(config.server_name.as_bytes()));
        let mut extensions = vec![0, 0];
        extensions.extend(vector(&vector(&name)));
        let mut share = vec![0, 29];
        share.extend(vector(PublicKey::from(&peer).as_bytes()));
        extensions.extend([0, 51]);
        extensions.extend(vector(&vector(&share)));
        let mut body = vec![3, 3];
        body.extend(random);
        body.push(32);
        body.extend([0; 32]);
        body.extend(vector(&[0x13, 0x01]));
        body.extend([1, 0]);
        body.extend(vector(&extensions));
        let length = body.len();
        let mut hello = vec![1, (length >> 16) as u8, (length >> 8) as u8, length as u8];
        hello.extend(body);
        let shared = peer.diffie_hellman(&PublicKey::from(&config.secret().unwrap()));
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &random[..20]);
        let prk = salt.extract(shared.as_bytes());
        let info = [b"REALITY".as_slice()];
        let mut auth = [0; 32];
        prk.expand(&info, hkdf::HKDF_SHA256)
            .unwrap()
            .fill(&mut auth)
            .unwrap();
        let mut plain = vec![26, 11, 9, 0];
        plain.extend((timestamp as u32).to_be_bytes());
        plain.extend(sid);
        let cipher = Aes256Gcm::new_from_slice(&auth).unwrap();
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&random[20..]),
                Payload {
                    msg: &plain,
                    aad: &hello,
                },
            )
            .unwrap();
        hello[39..71].copy_from_slice(&encrypted);
        hello
    }
    #[test]
    fn authentication_enforces_credentials_clock_replay_and_cache_bound() {
        let config =
            RealityConfig::generate("example.com".into(), "example.com:443".into()).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sid = config.sid().unwrap();
        let server = Server::new(config.clone(), 1).unwrap();
        for (timestamp, wrong_sid) in [(now - 301, sid), (now + 301, sid), (now, [0; 8])] {
            assert!(
                server
                    .authenticate(&authenticated_hello(&config, timestamp, wrong_sid))
                    .is_err()
            );
        }
        let mut damaged = authenticated_hello(&config, now, sid);
        damaged[70] ^= 1;
        assert!(server.authenticate(&damaged).is_err());
        let hello = authenticated_hello(&config, now, sid);
        assert!(server.authenticate(&hello).is_ok());
        assert!(server.authenticate(&hello).is_err());
        assert!(
            server
                .authenticate(&authenticated_hello(&config, now, sid))
                .is_err()
        );
        assert_eq!(server.seen.lock().unwrap().len(), 1);
    }
    #[test]
    fn truncated_hello_never_panics() {
        for n in 0..256 {
            assert!(Hello::parse(&vec![0; n]).is_err());
        }
    }
}
