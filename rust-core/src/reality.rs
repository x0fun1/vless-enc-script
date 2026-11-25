// Experimental REALITY authentication over rustls TLS 1.3.
// SPDX-License-Identifier: MPL-2.0
// Wire reference: Xray-core v26.11.9 transport/internet/reality/reality.go.
// Uses live target observations for limited ServerHello and initial record-length shaping;
// this is not full TLS fingerprint replication.
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ml_dsa::{
    KeyExport, Keypair, MlDsa65, Seed as MlDsaSeed, Signer, SigningKey as MlDsaSigningKey,
};
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
    net::{IpAddr, SocketAddr},
    ops::Range,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpStream, lookup_host},
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, server::TlsStream};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RealityConfig {
    pub private_key: Zeroizing<String>,
    pub short_id: String,
    #[serde(default = "default_spider_x")]
    pub spider_x: String,
    pub server_name: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target_ca_certificates: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mldsa65_seed: Option<Zeroizing<String>>,
    #[serde(default = "default_time_diff")]
    pub max_time_diff_secs: u64,
}
fn default_spider_x() -> String {
    "/".to_owned()
}
fn default_time_diff() -> u64 {
    300
}

impl RealityConfig {
    pub fn generate(server_name: String, target: String) -> Result<Self> {
        let mut key = Zeroizing::new([0; 32]);
        let mut sid = [0; 8];
        let mut spider_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut *key);
        OsRng.fill_bytes(&mut sid);
        OsRng.fill_bytes(&mut spider_bytes);
        let config = Self {
            private_key: Zeroizing::new(URL_SAFE_NO_PAD.encode(*key)),
            short_id: sid.iter().map(|b| format!("{b:02x}")).collect(),
            spider_x: format!("/{}", URL_SAFE_NO_PAD.encode(spider_bytes)),
            server_name,
            target,
            target_ca_certificates: Vec::new(),
            mldsa65_seed: None,
            max_time_diff_secs: default_time_diff(),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn generate_with_mldsa65(
        server_name: String,
        target: String,
        enabled: bool,
    ) -> Result<Self> {
        let mut config = Self::generate(server_name, target)?;
        if enabled {
            let mut seed = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(&mut *seed);
            config.mldsa65_seed = Some(Zeroizing::new(URL_SAFE_NO_PAD.encode(*seed)));
        }
        config.validate()?;
        Ok(config)
    }

    pub fn enable_mldsa65(&mut self) -> Result<()> {
        if self.mldsa65_seed.is_none() {
            let mut seed = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(&mut *seed);
            self.mldsa65_seed = Some(Zeroizing::new(URL_SAFE_NO_PAD.encode(*seed)));
        }
        self.validate()
    }

    pub fn disable_mldsa65(&mut self) {
        self.mldsa65_seed = None;
    }

    pub fn mldsa65_public_key(&self) -> Result<Option<Vec<u8>>> {
        let Some(seed) = &self.mldsa65_seed else {
            return Ok(None);
        };
        let seed = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(seed)
                .context("invalid ML-DSA-65 seed encoding")?,
        );
        ensure!(seed.len() == 32, "ML-DSA-65 seed must be 32 bytes");
        let key = MlDsaSigningKey::<MlDsa65>::from_seed(&MlDsaSeed::from(<[u8; 32]>::try_from(
            seed.as_slice(),
        )?));
        Ok(Some(key.verifying_key().to_bytes().to_vec()))
    }

    fn mldsa65_signing_key(&self) -> Result<Option<MlDsaSigningKey<MlDsa65>>> {
        let Some(seed) = &self.mldsa65_seed else {
            return Ok(None);
        };
        let seed = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(seed)
                .context("invalid ML-DSA-65 seed encoding")?,
        );
        ensure!(seed.len() == 32, "ML-DSA-65 seed must be 32 bytes");
        Ok(Some(MlDsaSigningKey::<MlDsa65>::from_seed(
            &MlDsaSeed::from(<[u8; 32]>::try_from(seed.as_slice())?),
        )))
    }

    pub fn validate(&self) -> Result<()> {
        self.secret()?;
        self.sid()?;
        if let Some(seed) = &self.mldsa65_seed {
            ensure!(
                seed != &self.private_key,
                "ML-DSA-65 seed must differ from the REALITY private key"
            );
            let bytes = Zeroizing::new(
                URL_SAFE_NO_PAD
                    .decode(seed)
                    .context("invalid ML-DSA-65 seed encoding")?,
            );
            ensure!(bytes.len() == 32, "ML-DSA-65 seed must be 32 bytes");
        }
        ensure!(
            self.spider_x.len() <= 128
                && self.spider_x.starts_with('/')
                && self.spider_x[1..]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.~".contains(&b)),
            "invalid REALITY spider_x path"
        );
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
            self.target_ca_certificates.len() <= 16,
            "REALITY target_ca_certificates must contain at most 16 DER certificates"
        );
        for encoded in &self.target_ca_certificates {
            let der = URL_SAFE_NO_PAD
                .decode(encoded)
                .context("invalid REALITY target root certificate encoding")?;
            ensure!(
                (64..=16_384).contains(&der.len()),
                "REALITY target root certificate must be 64..16384 DER bytes"
            );
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(CertificateDer::from(der))
                .context("invalid REALITY target root certificate")?;
        }
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

type TargetProfileKey = (SocketAddr, Vec<u8>, Vec<Vec<u8>>);

pub struct Server {
    config: RealityConfig,
    secret: StaticSecret,
    sid: [u8; 8],
    signing_key: Arc<dyn rustls::sign::SigningKey>,
    cert_public: Vec<u8>,
    mldsa_signing_key: Option<MlDsaSigningKey<MlDsa65>>,
    seen: Mutex<HashMap<[u8; 32], Instant>>,
    max_seen: usize,
    target_profile_cache: Mutex<HashMap<TargetProfileKey, TargetTlsProfile>>,
    listen: std::net::SocketAddr,
    allow_private_destinations: bool,
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
fn cert_body(public: &[u8], mldsa_signature: Option<&[u8]>) -> Vec<u8> {
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
    if let Some(signature) = mldsa_signature {
        let mut extension = der(0x06, &[0x00]); // Xray uses the private OID 0.0.
        extension.extend(der(0x04, signature));
        let extensions = der(0x30, &der(0x30, &extension));
        body.extend(der(0xa3, &extensions));
    }
    let mut result = der(0x30, &body);
    result.extend(algorithm);
    result
}

fn certificate(
    cert_body: &[u8],
    auth: &[u8],
    cert_public: &[u8],
    signing_key: &Arc<dyn rustls::sign::SigningKey>,
) -> Arc<rustls::sign::CertifiedKey> {
    let signature = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, auth), cert_public);
    let mut proof = vec![0];
    proof.extend_from_slice(signature.as_ref());
    let mut body = cert_body.to_vec();
    body.extend(der(0x03, &proof));
    Arc::new(rustls::sign::CertifiedKey::new(
        vec![CertificateDer::from(der(0x30, &body))],
        Arc::new(RealitySigningKey(signing_key.clone())),
    ))
}

impl Server {
    pub fn new(
        config: RealityConfig,
        max_seen: usize,
        listen: std::net::SocketAddr,
        allow_private_destinations: bool,
    ) -> Result<Self> {
        config.validate()?;
        let private = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("generate REALITY certificate key"))?;
        let pair = Ed25519KeyPair::from_pkcs8(private.as_ref())
            .map_err(|_| anyhow::anyhow!("parse certificate key"))?;
        let public = pair.public_key().as_ref().to_vec();
        let signing_key = rustls::crypto::ring::sign::any_supported_type(
            &PrivatePkcs8KeyDer::from(private.as_ref().to_vec()).into(),
        )?;
        let mldsa_signing_key = config.mldsa65_signing_key()?;
        Ok(Self {
            secret: config.secret()?,
            sid: config.sid()?,
            config,
            signing_key,
            cert_public: public,
            mldsa_signing_key,
            seen: Mutex::new(HashMap::new()),
            max_seen: max_seen.max(1),
            target_profile_cache: Mutex::new(HashMap::new()),
            listen,
            allow_private_destinations,
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
    fn is_listener_target(&self, target: SocketAddr, accepted_local: SocketAddr) -> bool {
        fn canonical(ip: IpAddr) -> IpAddr {
            match ip {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
                IpAddr::V4(_) => ip,
            }
        }
        fn same_ip(left: IpAddr, right: IpAddr) -> bool {
            canonical(left) == canonical(right)
        }
        fn loopback(ip: IpAddr) -> bool {
            canonical(ip).is_loopback()
        }

        target.port() == self.listen.port()
            && (same_ip(target.ip(), accepted_local.ip())
                || (self.listen.ip().is_unspecified() && loopback(target.ip())))
    }
    async fn connect_target(&self, accepted_local: SocketAddr) -> Result<TcpStream> {
        let (host, _) = self
            .config
            .target
            .rsplit_once(':')
            .context("REALITY target must be HOST:PORT")?;
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        ensure!(
            self.allow_private_destinations
                || host.parse::<IpAddr>().is_ok()
                || !crate::destination::private_domain(host),
            "REALITY target uses a private or special-use domain"
        );
        let mut addresses = timeout(Duration::from_secs(3), lookup_host(&self.config.target))
            .await
            .context("REALITY target DNS lookup timed out")??
            .take(64);
        let mut candidates = Vec::new();
        for address in &mut addresses {
            self.validate_target_address(address, accepted_local)?;
            candidates.push(address);
        }
        ensure!(
            !candidates.is_empty(),
            "REALITY target DNS returned no addresses"
        );

        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        let mut last_error = None;
        for address in candidates {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, TcpStream::connect(address)).await {
                Ok(Ok(socket)) => return Ok(socket),
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => {
                    last_error = Some(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "REALITY target connect budget exhausted",
                    ));
                    break;
                }
            }
        }
        Err(last_error.context("connect REALITY target failed")?.into())
    }

    fn validate_target_address(
        &self,
        target: SocketAddr,
        accepted_local: SocketAddr,
    ) -> Result<()> {
        ensure!(
            !self.is_listener_target(target, accepted_local),
            "REALITY target cannot point to this listener"
        );
        ensure!(
            self.allow_private_destinations || !crate::destination::private_ip(target.ip()),
            "REALITY target resolved to a private or special-use address"
        );
        Ok(())
    }

    pub async fn accept(&self, mut socket: TcpStream) -> Result<Option<TlsStream<Replay>>> {
        let (prefix, hello) = read_hello(&mut socket).await?;
        let auth = hello
            .as_deref()
            .and_then(|hello| self.authenticate(hello).ok());
        let Some(auth) = auth else {
            let mut target = self
                .connect_target(socket.local_addr()?)
                .await
                .context("connect REALITY fallback target")?;
            timeout(Duration::from_secs(10), target.write_all(&prefix))
                .await
                .context("write REALITY fallback ClientHello timed out")??;
            // Fallback is not a proxy user. The caller keeps it within the bounded
            // handshake timeout/concurrency budget, not an unbounded relay task.
            tokio::io::copy_bidirectional(&mut socket, &mut target).await?;
            return Ok(None);
        };
        let client_hello = hello.expect("authenticated REALITY handshake has a parsed ClientHello");
        let parsed_client_hello = Hello::parse(&client_hello)?;
        let cert_body = cert_body(&self.cert_public, None);
        let certified = certificate(&cert_body, &auth, &self.cert_public, &self.signing_key);
        let mut target = self
            .connect_target(socket.local_addr()?)
            .await
            .context("connect REALITY fingerprint target")?;
        timeout(Duration::from_secs(10), target.write_all(&prefix))
            .await
            .context("write REALITY fingerprint ClientHello timed out")??;
        let target_address = target.peer_addr()?;
        let fingerprint = timeout(
            Duration::from_secs(10),
            read_target_fingerprint(&mut target),
        )
        .await
        .context("REALITY fingerprint target handshake timed out")??;
        drop(target);
        let target_profile_key = (
            target_address,
            parsed_client_hello.server_name.to_vec(),
            parsed_client_hello.alpn.clone(),
        );
        let cached_profile = {
            let mut cache = self
                .target_profile_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            cache.retain(|_, profile| profile.observed_at.elapsed() < Duration::from_secs(600));
            cache.get(&target_profile_key).cloned()
        };
        let target_profile = match cached_profile {
            Some(profile) => profile,
            None => {
                let profile = timeout(
                    Duration::from_secs(10),
                    probe_target_alpn(
                        target_address,
                        std::str::from_utf8(parsed_client_hello.server_name)?,
                        &parsed_client_hello.alpn,
                        &self.config.target_ca_certificates,
                    ),
                )
                .await
                .context("REALITY target ALPN probe timed out")??;
                let mut cache = self
                    .target_profile_cache
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if cache.len() < 32 {
                    cache.insert(target_profile_key, profile.clone());
                }
                profile
            }
        };
        let target_alpn = target_profile.alpn.clone();
        let target_server_name_ack = target_profile.server_name_ack;
        let (target_suite, target_group) = server_hello_parameters(&fingerprint.server_hello)?;
        let server_hello_len = fingerprint.server_hello_record_length;
        let target_record_lengths = fingerprint.record_lengths.clone();
        let target_server_hello = fingerprint.server_hello.clone();
        let resolver = Arc::new(RealityCertResolver {
            initial: certified,
            auth,
            client_hello,
            cert_public: self.cert_public.clone(),
            signing_key: self.signing_key.clone(),
            mldsa_signing_key: self.mldsa_signing_key.clone(),
            target_server_hello: fingerprint.server_hello,
            target_record_lengths: fingerprint.record_lengths,
            target_server_name_ack,
        });
        let mut provider = rustls::crypto::ring::default_provider();
        let suite = rustls::CipherSuite::from(target_suite);
        provider
            .cipher_suites
            .retain(|candidate| candidate.suite() == suite);
        ensure!(
            provider.cipher_suites.len() == 1,
            "REALITY target selected an unsupported TLS cipher suite"
        );
        provider.kx_groups = vec![match target_group {
            29 => rustls::crypto::ring::kx_group::X25519,
            4588 => &HYBRID,
            _ => bail!("REALITY target selected an unsupported TLS key exchange group"),
        }];
        let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        config.send_tls13_tickets = 0;
        config.alpn_protocols = target_alpn.clone().into_iter().collect();
        let tls = TlsAcceptor::from(Arc::new(config))
            .accept(Replay::new(
                socket,
                prefix,
                server_hello_len,
                target_record_lengths.clone(),
                target_server_hello.clone(),
                target_server_name_ack,
            ))
            .await
            .context("REALITY TLS handshake")?;
        eprintln!(
            "reality_fingerprint sni_ack={} server_hello={} target_records={:?} server_records={:?} server_hello_match={}",
            tls.get_ref().0.target_server_name_ack,
            tls.get_ref().0.server_hello_len,
            tls.get_ref().0.target_record_lengths,
            tls_record_lengths(&tls.get_ref().0.written),
            server_hello_matches(
                &tls.get_ref().0.target_server_hello,
                tls.get_ref().0.server_hello_len,
                &tls.get_ref().0.written,
            ),
        );
        Ok(Some(tls))
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
struct RealityCertResolver {
    initial: Arc<rustls::sign::CertifiedKey>,
    auth: Zeroizing<Vec<u8>>,
    client_hello: Vec<u8>,
    cert_public: Vec<u8>,
    signing_key: Arc<dyn rustls::sign::SigningKey>,
    mldsa_signing_key: Option<MlDsaSigningKey<MlDsa65>>,
    target_server_hello: Vec<u8>,
    target_record_lengths: Vec<usize>,
    target_server_name_ack: bool,
}

impl rustls::server::ResolvesServerCert for RealityCertResolver {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.initial.clone())
    }

    fn mimic_server_hello(
        &self,
        generated: &[u8],
    ) -> std::result::Result<Option<Vec<u8>>, rustls::Error> {
        patch_server_hello(&self.target_server_hello, generated)
            .map(Some)
            .map_err(|error| rustls::Error::General(format!("REALITY target ServerHello: {error}")))
    }

    fn target_record_lengths(&self) -> Option<Vec<usize>> {
        Some(self.target_record_lengths.clone())
    }

    fn target_server_name_ack(&self) -> Option<bool> {
        Some(self.target_server_name_ack)
    }

    fn resolve_after_server_hello(
        &self,
        server_hello: &[u8],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let key = self.mldsa_signing_key.as_ref()?;
        let mut message = Vec::with_capacity(
            self.cert_public.len() + self.client_hello.len() + server_hello.len(),
        );
        message.extend_from_slice(&self.cert_public);
        message.extend_from_slice(&self.client_hello);
        message.extend_from_slice(server_hello);
        let digest = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA512, &self.auth), &message);
        let signature = key.sign(digest.as_ref()).encode();
        let cert_body = cert_body(&self.cert_public, Some(signature.as_slice()));
        Some(certificate(
            &cert_body,
            &self.auth,
            &self.cert_public,
            &self.signing_key,
        ))
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
    alpn: Vec<Vec<u8>>,
}
impl<'a> Hello<'a> {
    fn parse(hello: &'a [u8]) -> Result<Self> {
        ensure!(
            hello.len() >= 71 && hello[0] == 1 && hello[38] == 32,
            "invalid REALITY ClientHello/session ID"
        );
        let declared =
            4 + ((hello[1] as usize) << 16 | (hello[2] as usize) << 8 | hello[3] as usize);
        ensure!(
            declared == hello.len(),
            "truncated or trailing REALITY ClientHello bytes"
        );
        let mut cursor = Cursor(&hello[71..]);
        cursor.vector()?;
        let n = cursor.u8()?;
        cursor.take(n)?;
        let mut extensions = cursor.vector()?;
        ensure!(cursor.0.is_empty(), "trailing ClientHello bytes");
        let mut server_name = None;
        let mut peers = Vec::new();
        let mut alpn = Vec::new();
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
                    ensure!(
                        value.0.is_empty(),
                        "trailing bytes in server_name extension"
                    );
                }
                16 => {
                    let mut protocols = value.vector()?;
                    while !protocols.0.is_empty() {
                        let length = protocols.u8()?;
                        ensure!(length > 0, "empty ALPN protocol name");
                        alpn.push(protocols.take(length)?.to_vec());
                    }
                    ensure!(value.0.is_empty(), "trailing bytes in ALPN extension");
                }
                51 => {
                    let mut shares = value.vector()?;
                    while !shares.0.is_empty() {
                        let group = shares.u16()?;
                        let key = shares.vector()?;
                        match (group, key.0.len()) {
                            (29, 32) => {
                                ensure!(peers.len() < 8, "too many REALITY X25519 key shares");
                                peers.push(key.0.try_into()?);
                            }
                            (4588, 1216) => {
                                ensure!(peers.len() < 8, "too many REALITY hybrid key shares");
                                peers.push(key.0[1184..].try_into()?);
                            }
                            _ => {}
                        }
                    }
                    ensure!(value.0.is_empty(), "trailing bytes in key_share extension");
                }
                _ => {}
            }
        }
        Ok(Self {
            server_name: server_name.context("missing REALITY SNI")?,
            peers,
            alpn,
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

#[derive(Clone)]
struct TargetTlsProfile {
    alpn: Option<Vec<u8>>,
    server_name_ack: bool,
    observed_at: Instant,
}

fn target_root_store(
    native_certificates: impl IntoIterator<Item = CertificateDer<'static>>,
    custom_roots: &[String],
) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(native_certificates);
    for encoded in custom_roots {
        let der = URL_SAFE_NO_PAD
            .decode(encoded)
            .context("decode configured REALITY target root certificate")?;
        roots
            .add(CertificateDer::from(der))
            .context("add configured REALITY target root certificate")?;
    }
    ensure!(
        !roots.is_empty(),
        "no usable root certificates for REALITY target probe"
    );
    Ok(roots)
}

async fn probe_target_alpn(
    target: SocketAddr,
    server_name: &str,
    protocols: &[Vec<u8>],
    custom_roots: &[String],
) -> Result<TargetTlsProfile> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let native = rustls_native_certs::load_native_certs();
    let roots = target_root_store(native.certs, custom_roots)?;
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = protocols.to_vec();
    config.resumption = rustls::client::Resumption::disabled();
    let name = rustls::pki_types::ServerName::try_from(server_name.to_owned())?;
    let socket = TcpStream::connect(target).await?;
    let tls = TlsConnector::from(Arc::new(config))
        .connect(name, socket)
        .await
        .context("verify REALITY target certificate during ALPN probe")?;
    Ok(TargetTlsProfile {
        alpn: tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec),
        server_name_ack: tls
            .get_ref()
            .1
            .peer_server_name_ack()
            .context("target TLS handshake omitted ServerName acknowledgement state")?,
        observed_at: Instant::now(),
    })
}

struct TargetFingerprint {
    server_hello: Vec<u8>,
    server_hello_record_length: usize,
    record_lengths: Vec<usize>,
}

async fn read_target_record(socket: &mut TcpStream) -> Result<Vec<u8>> {
    let mut record = [0; 5];
    socket.read_exact(&mut record).await?;
    let length = u16::from_be_bytes([record[3], record[4]]) as usize;
    ensure!(
        (1..=16_640).contains(&length),
        "REALITY target sent an invalid TLS record length"
    );
    let mut result = Vec::with_capacity(5 + length);
    result.extend_from_slice(&record);
    result.resize(5 + length, 0);
    socket.read_exact(&mut result[5..]).await?;
    Ok(result)
}

async fn read_target_fingerprint(socket: &mut TcpStream) -> Result<TargetFingerprint> {
    let server_hello_record = read_target_record(socket).await?;
    ensure!(
        server_hello_record.len() >= 9
            && server_hello_record[0] == 22
            && server_hello_record[1..3] == [3, 3]
            && server_hello_record[5] == 2,
        "REALITY target did not send a complete TLS 1.3 ServerHello record header"
    );
    let hello_length = 4
        + ((server_hello_record[6] as usize) << 16)
        + ((server_hello_record[7] as usize) << 8)
        + server_hello_record[8] as usize;
    ensure!(
        (4..=server_hello_record.len() - 5).contains(&hello_length),
        "REALITY target ServerHello is fragmented across TLS records or truncated"
    );
    let server_hello = server_hello_record[5..5 + hello_length].to_vec();
    let ccs = read_target_record(socket).await?;
    ensure!(
        ccs[0] == 20 && ccs[1..3] == [3, 3] && ccs.len() == 6 && ccs[5] == 1,
        "REALITY target omitted or malformed the TLS compatibility CCS"
    );
    let mut record_lengths = Vec::new();
    let first = timeout(Duration::from_secs(5), read_target_record(socket))
        .await
        .context("REALITY target did not send encrypted TLS handshake records")??;
    ensure!(
        first[0] == 23 && first[1..3] == [3, 3],
        "REALITY target sent an unexpected record after compatibility CCS"
    );
    record_lengths.push(first.len());
    for _ in 1..5 {
        let Ok(Ok(record)) = timeout(Duration::from_millis(100), read_target_record(socket)).await
        else {
            break;
        };
        ensure!(
            record[0] == 23 && record[1..3] == [3, 3],
            "REALITY target sent a non-handshake record before its TLS server flight ended"
        );
        record_lengths.push(record.len());
    }
    let (suite, group) = server_hello_parameters(&server_hello)?;
    ensure!(
        matches!(suite, 0x1301..=0x1303),
        "REALITY target selected an unsupported TLS 1.3 cipher suite"
    );
    ensure!(
        matches!(group, 29 | 4588),
        "REALITY target selected an unsupported TLS key exchange group"
    );
    Ok(TargetFingerprint {
        server_hello,
        server_hello_record_length: server_hello_record.len(),
        record_lengths,
    })
}

struct ServerHelloLayout {
    cipher_suite: u16,
    group: u16,
    session_id: Range<usize>,
    key_share: Range<usize>,
    supported_version: u16,
}

fn server_hello_layout(raw: &[u8]) -> Result<ServerHelloLayout> {
    ensure!(
        raw.len() >= 4 && raw[0] == 2,
        "invalid TLS ServerHello handshake message"
    );
    let declared = 4 + ((raw[1] as usize) << 16) + ((raw[2] as usize) << 8) + raw[3] as usize;
    ensure!(
        declared == raw.len(),
        "truncated or trailing TLS ServerHello bytes"
    );
    let mut offset = 4;
    ensure!(raw.len() >= offset + 35, "truncated TLS ServerHello header");
    offset += 2 + 32;
    let session_length = raw[offset] as usize;
    offset += 1;
    let session_id = offset..offset + session_length;
    ensure!(
        raw.len() >= session_id.end + 5,
        "truncated TLS ServerHello session ID"
    );
    offset = session_id.end;
    let cipher_suite = u16::from_be_bytes(raw[offset..offset + 2].try_into()?);
    offset += 2 + 1;
    let extension_length = u16::from_be_bytes(raw[offset..offset + 2].try_into()?) as usize;
    offset += 2;
    ensure!(
        raw.len() == offset + extension_length,
        "invalid TLS ServerHello extensions length"
    );
    let mut key_share = None;
    let mut supported_version = None;
    let mut group = None;
    let mut psk = false;
    while offset < raw.len() {
        ensure!(
            raw.len() >= offset + 4,
            "truncated TLS ServerHello extension"
        );
        let kind = u16::from_be_bytes(raw[offset..offset + 2].try_into()?);
        let length = u16::from_be_bytes(raw[offset + 2..offset + 4].try_into()?) as usize;
        offset += 4;
        let end = offset
            .checked_add(length)
            .context("TLS extension length overflow")?;
        ensure!(
            end <= raw.len(),
            "truncated TLS ServerHello extension value"
        );
        match kind {
            41 => psk = true,
            43 => {
                ensure!(length == 2, "invalid TLS supported_versions extension");
                supported_version = Some(u16::from_be_bytes(raw[offset..end].try_into()?));
            }
            51 => {
                ensure!(length >= 4, "invalid TLS ServerHello key_share extension");
                let selected_group = u16::from_be_bytes(raw[offset..offset + 2].try_into()?);
                let key_length =
                    u16::from_be_bytes(raw[offset + 2..offset + 4].try_into()?) as usize;
                ensure!(
                    key_length + 4 == length,
                    "invalid TLS ServerHello key share length"
                );
                group = Some(selected_group);
                key_share = Some(offset..end);
            }
            _ => {}
        }
        offset = end;
    }
    ensure!(!psk, "REALITY target selected a TLS pre-shared key");
    Ok(ServerHelloLayout {
        cipher_suite,
        group: group.context("missing TLS ServerHello key share")?,
        session_id,
        key_share: key_share.context("missing TLS ServerHello key_share extension")?,
        supported_version: supported_version
            .context("missing TLS ServerHello supported_versions")?,
    })
}

fn server_hello_parameters(raw: &[u8]) -> Result<(u16, u16)> {
    let layout = server_hello_layout(raw)?;
    ensure!(
        layout.supported_version == 0x0304,
        "REALITY target did not negotiate TLS 1.3"
    );
    Ok((layout.cipher_suite, layout.group))
}

fn patch_server_hello(template: &[u8], generated: &[u8]) -> Result<Vec<u8>> {
    let target = server_hello_layout(template)?;
    let ours = server_hello_layout(generated)?;
    ensure!(
        target.cipher_suite == ours.cipher_suite
            && target.group == ours.group
            && target.supported_version == ours.supported_version
            && target.session_id.len() == ours.session_id.len()
            && target.key_share.len() == ours.key_share.len(),
        "target TLS parameters do not match the authenticated client hello"
    );
    let mut result = template.to_vec();
    result[target.session_id.clone()].copy_from_slice(&generated[ours.session_id]);
    result[target.key_share.clone()].copy_from_slice(&generated[ours.key_share]);
    Ok(result)
}

fn server_hello_matches(target: &[u8], target_record_len: usize, written: &[u8]) -> bool {
    if written.len() < 9 {
        return false;
    }
    let server_record_len = 5 + u16::from_be_bytes([written[3], written[4]]) as usize;
    if server_record_len != target_record_len || written.len() < server_record_len {
        return false;
    }
    let server_hello = &written[5..server_record_len];
    patch_server_hello(target, server_hello)
        .is_ok_and(|expected| expected.as_slice() == server_hello)
}

fn tls_record_lengths(data: &[u8]) -> Vec<usize> {
    let mut lengths = Vec::new();
    let mut offset = 0;
    while data.len() >= offset + 5 {
        let length = 5 + u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
        if data.len() < offset + length {
            break;
        }
        lengths.push(length);
        offset += length;
    }
    lengths
}

pub struct Replay {
    socket: TcpStream,
    prefix: Vec<u8>,
    offset: usize,
    server_hello_len: usize,
    target_record_lengths: Vec<usize>,
    target_server_hello: Vec<u8>,
    target_server_name_ack: bool,
    written: Vec<u8>,
}
impl Replay {
    fn new(
        socket: TcpStream,
        prefix: Vec<u8>,
        server_hello_len: usize,
        target_record_lengths: Vec<usize>,
        target_server_hello: Vec<u8>,
        target_server_name_ack: bool,
    ) -> Self {
        Self {
            socket,
            prefix,
            offset: 0,
            server_hello_len,
            target_record_lengths,
            target_server_hello,
            target_server_name_ack,
            written: Vec::new(),
        }
    }
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
        match Pin::new(&mut self.socket).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                if self.written.len() < 64 * 1024 {
                    let take = n.min(64 * 1024 - self.written.len());
                    self.written.extend_from_slice(&buf[..take]);
                }
                Poll::Ready(Ok(n))
            }
            result => result,
        }
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
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    #[test]
    fn target_probe_roots_accept_explicit_trust_without_platform_certificates() {
        // Trust-anchor parsing only needs a structurally valid certificate.
        // Reuse the local DER template with a synthetic public key/signature.
        let mut body = cert_body(&[0x42; 32], None);
        body.extend(der(0x03, &[0; 65]));
        let certificate = CertificateDer::from(der(0x30, &body));
        let encoded = URL_SAFE_NO_PAD.encode(certificate.as_ref());
        assert_eq!(
            target_root_store(Vec::new(), std::slice::from_ref(&encoded))
                .unwrap()
                .len(),
            1
        );
        assert!(target_root_store(Vec::new(), &[]).is_err());
        assert_eq!(
            target_root_store(vec![certificate.clone()], &[])
                .unwrap()
                .len(),
            1
        );
        // Invalid platform entries may be ignored; explicit trust must remain
        // strict even when a valid platform root is already available.
        assert!(
            target_root_store(
                vec![CertificateDer::from(vec![0; 64])],
                std::slice::from_ref(&encoded),
            )
            .is_ok()
        );
        for invalid in ["not-base64url!".to_owned(), URL_SAFE_NO_PAD.encode([0; 64])] {
            assert!(target_root_store(vec![certificate.clone()], &[invalid]).is_err());
        }
    }

    #[test]
    fn mldsa65_seed_derives_a_fixed_size_verification_key_and_signature() {
        use ml_dsa::Verifier;

        let config = RealityConfig::generate_with_mldsa65(
            "example.com".into(),
            "example.com:443".into(),
            true,
        )
        .unwrap();
        let public = config.mldsa65_public_key().unwrap().unwrap();
        assert_eq!(public.len(), 1952);
        let key = config.mldsa65_signing_key().unwrap().unwrap();
        let signature = key.sign(b"REALITY ML-DSA-65 proof test");
        let encoded = signature.encode();
        assert_eq!(encoded.len(), 3309);
        key.verifying_key()
            .verify(b"REALITY ML-DSA-65 proof test", &signature)
            .unwrap();
        let loaded: RealityConfig =
            serde_json::from_slice(&serde_json::to_vec(&config).unwrap()).unwrap();
        assert_eq!(loaded.mldsa65_public_key().unwrap().unwrap(), public);
    }

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
        assert!(c.spider_x.starts_with('/') && c.spider_x.len() > 1);
        let mut legacy = serde_json::to_value(&c).unwrap();
        legacy.as_object_mut().unwrap().remove("spider_x");
        let legacy: RealityConfig = serde_json::from_value(legacy).unwrap();
        assert_eq!(legacy.spider_x, "/");
        c.spider_x = "not-a-path".into();
        assert!(c.validate().is_err());
        c.spider_x = default_spider_x();
        c.short_id = "123".into();
        assert!(c.validate().is_err());
        c.short_id = "abcd".into();
        c.target_ca_certificates = vec!["not-base64url!".into()];
        assert!(c.validate().is_err());
        c.target_ca_certificates.clear();
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
        extensions.extend([0, 16]);
        extensions.extend(vector(&[0, 3, 2, b'h', b'2']));
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
        let server =
            Server::new(config.clone(), 1, "127.0.0.1:443".parse().unwrap(), false).unwrap();
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
        assert_eq!(Hello::parse(&hello).unwrap().alpn, vec![b"h2".to_vec()]);
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
    fn reality_target_loop_guard_detects_wildcard_loopback_and_exact_local_address() {
        let config =
            RealityConfig::generate("example.com".into(), "example.com:443".into()).unwrap();
        let server = Server::new(config, 1, "0.0.0.0:443".parse().unwrap(), true).unwrap();
        let accepted = "192.0.2.10:443".parse().unwrap();
        assert!(server.is_listener_target("127.0.0.1:443".parse().unwrap(), accepted));
        assert!(server.is_listener_target("192.0.2.10:443".parse().unwrap(), accepted));
        assert!(!server.is_listener_target("198.51.100.10:443".parse().unwrap(), accepted));
    }

    #[tokio::test]
    async fn reality_target_loop_is_rejected_before_a_socket_is_opened() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let actual = listener.local_addr().unwrap();
        let config =
            RealityConfig::generate("example.com".into(), format!("127.0.0.1:{}", actual.port()))
                .unwrap();
        let server = Server::new(
            config,
            1,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), actual.port()),
            true,
        )
        .unwrap();
        assert!(
            server
                .connect_target("192.0.2.7:42000".parse().unwrap())
                .await
                .is_err()
        );
        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }

    #[test]
    fn reality_target_policy_checks_every_resolved_address() {
        let config =
            RealityConfig::generate("example.com".into(), "example.com:443".into()).unwrap();
        let listen = "0.0.0.0:443".parse().unwrap();
        let accepted = "192.0.2.7:443".parse().unwrap();
        let restricted = Server::new(config.clone(), 1, listen, false).unwrap();
        let opted_in = Server::new(config, 1, listen, true).unwrap();
        for target in [
            "127.0.0.1:80",
            "10.1.2.3:443",
            "169.254.169.254:80",
            "[::1]:80",
            "[::ffff:192.168.1.1]:80",
            "[fe80::1]:443",
        ] {
            let target = target.parse().unwrap();
            assert!(
                restricted
                    .validate_target_address(target, accepted)
                    .is_err()
            );
            assert!(opted_in.validate_target_address(target, accepted).is_ok());
        }
        assert!(
            restricted
                .validate_target_address("1.1.1.1:443".parse().unwrap(), accepted)
                .is_ok()
        );
        // The explicit private-network opt-in must never bypass the loop guard.
        assert!(
            opted_in
                .validate_target_address("127.0.0.1:443".parse().unwrap(), accepted)
                .is_err()
        );
    }

    #[tokio::test]
    async fn reality_private_target_is_blocked_before_connect_and_allows_explicit_opt_in() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = RealityConfig::generate("example.com".into(), address.to_string()).unwrap();
        let listen = "0.0.0.0:443".parse().unwrap();
        let accepted = "192.0.2.7:443".parse().unwrap();
        let server = Server::new(config.clone(), 1, listen, false).unwrap();
        assert!(server.connect_target(accepted).await.is_err());
        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
        let server = Server::new(config, 1, listen, true).unwrap();
        let socket = server.connect_target(accepted).await.unwrap();
        let (connection, _) = timeout(Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
        drop((socket, connection));
    }

    #[tokio::test]
    async fn reality_private_domain_is_rejected_before_resolution() {
        let config =
            RealityConfig::generate("example.com".into(), "service.localhost:443".into()).unwrap();
        let server = Server::new(config, 1, "0.0.0.0:443".parse().unwrap(), false).unwrap();
        let error = server
            .connect_target("192.0.2.7:443".parse().unwrap())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("special-use domain"));
    }

    #[tokio::test]
    async fn target_fingerprint_rejects_short_server_hello_records_without_panicking() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let sender = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&[22, 3, 3, 0, 3, 2, 0, 0]).await.unwrap();
        });
        let mut socket = TcpStream::connect(address).await.unwrap();
        assert!(read_target_fingerprint(&mut socket).await.is_err());
        sender.await.unwrap();
    }

    #[tokio::test]
    async fn target_tls_record_reader_rejects_oversized_lengths_without_allocating() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let sender = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&[22, 3, 3, 0x41, 1]).await.unwrap();
        });
        let mut socket = TcpStream::connect(address).await.unwrap();
        assert!(read_target_record(&mut socket).await.is_err());
        sender.await.unwrap();
    }

    #[test]
    fn target_server_hello_template_preserves_random_and_extensions() {
        fn hello(random: u8, session: u8, key: u8) -> Vec<u8> {
            let mut extensions = vec![0, 51, 0, 36, 0, 29, 0, 32];
            extensions.extend([key; 32]);
            extensions.extend([0, 43, 0, 2, 3, 4]);
            let mut body = vec![3, 3];
            body.extend([random; 32]);
            body.push(32);
            body.extend([session; 32]);
            body.extend([0x13, 0x01, 0]);
            body.extend((extensions.len() as u16).to_be_bytes());
            body.extend(extensions);
            let mut raw = vec![2];
            raw.extend([
                (body.len() >> 16) as u8,
                (body.len() >> 8) as u8,
                body.len() as u8,
            ]);
            raw.extend(body);
            raw
        }

        let target = hello(0x11, 0x22, 0x33);
        let generated = hello(0x44, 0x55, 0x66);
        let patched = patch_server_hello(&target, &generated).unwrap();
        let patched_layout = server_hello_layout(&patched).unwrap();
        assert_eq!(&patched[6..38], &target[6..38]);
        assert_eq!(
            &patched[patched_layout.session_id],
            &generated[server_hello_layout(&generated).unwrap().session_id]
        );
        assert_eq!(
            &patched[patched_layout.key_share],
            &generated[server_hello_layout(&generated).unwrap().key_share]
        );
        assert_eq!(server_hello_parameters(&patched).unwrap(), (0x1301, 29));
        let mut record = vec![22, 3, 3, (patched.len() >> 8) as u8, patched.len() as u8];
        record.extend_from_slice(&patched);
        assert!(server_hello_matches(&target, record.len(), &record));
        assert_eq!(patch_server_hello(&target, &patched).unwrap(), patched);
    }

    #[test]
    fn target_server_hello_rejects_unmatched_negotiation_parameters() {
        fn hello(group: u16, cipher: u16) -> Vec<u8> {
            let mut extensions = vec![0, 51, 0, 36];
            extensions.extend(group.to_be_bytes());
            extensions.extend([0, 32]);
            extensions.extend([0x33; 32]);
            extensions.extend([0, 43, 0, 2, 3, 4]);
            let mut body = vec![3, 3];
            body.extend([0x11; 32]);
            body.push(32);
            body.extend([0x22; 32]);
            body.extend(cipher.to_be_bytes());
            body.push(0);
            body.extend((extensions.len() as u16).to_be_bytes());
            body.extend(extensions);
            let mut raw = vec![2];
            raw.extend([
                (body.len() >> 16) as u8,
                (body.len() >> 8) as u8,
                body.len() as u8,
            ]);
            raw.extend(body);
            raw
        }

        let target = hello(29, 0x1301);
        assert!(patch_server_hello(&target, &hello(23, 0x1301)).is_err());
        assert!(patch_server_hello(&target, &hello(29, 0x1302)).is_err());
        let mut malformed = target.clone();
        malformed[3] = malformed[3].wrapping_add(1);
        assert!(server_hello_layout(&malformed).is_err());
    }

    #[test]
    fn truncated_hello_never_panics() {
        let config =
            RealityConfig::generate("example.com".into(), "example.com:443".into()).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid = authenticated_hello(&config, now, config.sid().unwrap());
        for end in 0..valid.len() {
            assert!(
                Hello::parse(&valid[..end]).is_err(),
                "accepted truncated hello length {end}"
            );
        }
        for n in 0..256 {
            assert!(Hello::parse(&vec![0; n]).is_err());
        }
    }
}
