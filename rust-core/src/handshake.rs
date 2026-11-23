// Wire behavior follows Xray-core v26.11.9, proxy/vless/encryption/server.go.
// SPDX-License-Identifier: MPL-2.0
use crate::{
    config::{Appearance, EncryptionConfig, Limits},
    crypto::{Aead, Algorithm, HeaderMask, header_mask},
    record::{Reader, Writer},
};
use anyhow::{Context, Result, ensure};
use ctr::cipher::StreamCipher;
use ml_kem::{
    MlKem768,
    kem::{Decapsulate, Encapsulate, KeyExport, KeyInit, TryKeyInit},
};
use rand::{RngCore, rngs::OsRng};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

type KemSecret = ml_kem::DecapsulationKey<MlKem768>;
type KemPublic = ml_kem::EncapsulationKey<MlKem768>;

enum AuthSecret {
    X25519(StaticSecret),
    MlKem(Box<KemSecret>),
}
struct AuthKey {
    secret: AuthSecret,
    public: Vec<u8>,
}

struct Session {
    pfs: Zeroizing<[u8; 64]>,
    expires: Instant,
    seen: HashSet<[u8; 32]>,
}

pub struct Server {
    keys: Vec<AuthKey>,
    relays_length: usize,
    appearance: Appearance,
    lifetime: u16,
    limits: Limits,
    sessions: Mutex<HashMap<[u8; 16], Session>>,
}

impl Server {
    pub fn new(config: EncryptionConfig, limits: Limits) -> Result<Self> {
        let mut keys = Vec::new();
        let mut relays_length = 0;
        for bytes in &config.keys {
            let (secret, public, size) = if bytes.len() == 32 {
                let secret = StaticSecret::from(<[u8; 32]>::try_from(bytes.as_slice())?);
                let public = PublicKey::from(&secret).as_bytes().to_vec();
                (AuthSecret::X25519(secret), public, 32)
            } else {
                let secret = KemSecret::new_from_slice(bytes).context("ML-KEM seed")?;
                let public = secret.encapsulation_key().to_bytes().to_vec();
                (AuthSecret::MlKem(Box::new(secret)), public, 1088)
            };
            relays_length += size + 32;
            keys.push(AuthKey { secret, public });
        }
        relays_length -= 32;
        Ok(Self {
            keys,
            relays_length,
            appearance: config.appearance,
            lifetime: config.lifetime,
            limits,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    pub fn prune(&self) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, s| s.expires > Instant::now());
    }

    fn ticket(&self, pfs: Zeroizing<[u8; 64]>) -> [u8; 16] {
        let mut ticket = [0; 16];
        OsRng.fill_bytes(&mut ticket);
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain(|_, s| s.expires > Instant::now());
        // Do not evict live tickets to make room: that interrupts a valid 0-RTT
        // client. Advertise 1-RTT when the bounded cache cannot accept a ticket.
        let seconds = if sessions.len() < self.limits.max_sessions {
            self.lifetime
        } else {
            0
        };
        ticket[..2].copy_from_slice(&seconds.to_be_bytes());
        if seconds != 0 {
            sessions.insert(
                ticket,
                Session {
                    pfs,
                    expires: Instant::now() + Duration::from_secs(seconds.into()),
                    seen: HashSet::new(),
                },
            );
        }
        ticket
    }

    fn resume(&self, ticket: [u8; 16], nfs: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let s = sessions
            .get_mut(&ticket)
            .context("expired or unknown session ticket")?;
        ensure!(s.expires > Instant::now(), "expired session ticket");
        ensure!(
            s.seen.len() < self.limits.max_resumes_per_session,
            "session replay cache limit reached; renegotiation needed"
        );
        ensure!(s.seen.insert(*nfs), "session replay detected");
        let mut united = Zeroizing::new(Vec::with_capacity(96));
        united.extend_from_slice(&s.pfs[..]);
        united.extend_from_slice(nfs);
        Ok(united)
    }

    pub async fn handshake<S>(&self, mut socket: S) -> Result<(Reader, Writer, bool)>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut hello = vec![0; 16 + self.relays_length];
        socket
            .read_exact(&mut hello)
            .await
            .context("read authentication relay")?;
        let iv: [u8; 16] = hello[..16].try_into()?;
        let relays = &mut hello[16..];
        let mut offset = 0;
        let mut previous: Option<HeaderMask> = None;
        let mut nfs = Zeroizing::new([0; 32]);
        for (j, key) in self.keys.iter().enumerate() {
            let size = match key.secret {
                AuthSecret::X25519(_) => 32,
                AuthSecret::MlKem(_) => 1088,
            };
            if let Some(mask) = &mut previous {
                mask.apply_keystream(&mut relays[offset..offset + 32]);
            }
            if self.appearance != Appearance::Native {
                header_mask(&key.public, &iv).apply_keystream(&mut relays[offset..offset + size]);
            }
            match &key.secret {
                AuthSecret::X25519(secret) => {
                    let peer: [u8; 32] = relays[offset..offset + 32].try_into()?;
                    ensure!(peer[31] <= 127, "noncanonical X25519 authentication key");
                    let shared = secret.diffie_hellman(&PublicKey::from(peer));
                    ensure!(
                        shared.was_contributory(),
                        "invalid X25519 authentication key"
                    );
                    nfs.copy_from_slice(shared.as_bytes());
                }
                AuthSecret::MlKem(secret) => {
                    let shared =
                        Zeroizing::new(secret.decapsulate_slice(&relays[offset..offset + size])?);
                    nfs.copy_from_slice(&shared);
                }
            }
            offset += size;
            if j + 1 < self.keys.len() {
                let mut mask = header_mask(&nfs[..], &iv);
                mask.apply_keystream(&mut relays[offset..offset + 32]);
                ensure!(
                    relays[offset..offset + 32]
                        == blake3::hash(&self.keys[j + 1].public).as_bytes()[..],
                    "authentication relay mismatch"
                );
                offset += 32;
                previous = Some(mask);
            }
        }

        let mut encrypted_length = vec![0; 18];
        socket.read_exact(&mut encrypted_length).await?;
        let mut nfs_aead = Aead::new(&iv, &nfs[..], Algorithm::Aes);
        let mut length_bytes = encrypted_length.clone();
        if nfs_aead.open(&mut length_bytes, &[], None).is_err() {
            nfs_aead = Aead::new(&iv, &nfs[..], Algorithm::ChaCha);
            length_bytes = encrypted_length;
            nfs_aead
                .open(&mut length_bytes, &[], None)
                .context("authentication key/cipher mismatch")?;
        }
        let length = u16::from_be_bytes(length_bytes[..2].try_into()?) as usize;
        let algorithm = nfs_aead.algorithm;
        if length == 32 {
            ensure!(self.lifetime != 0, "0-RTT disabled");
            let mut encrypted_ticket = vec![0; 32];
            socket.read_exact(&mut encrypted_ticket).await?;
            let ticket_context = encrypted_ticket.clone();
            nfs_aead.open(&mut encrypted_ticket, &[], None)?;
            let united = match self.resume(encrypted_ticket.as_slice().try_into()?, &nfs) {
                Ok(key) => key,
                Err(e) => {
                    // A deliberately invalid record header causes official clients
                    // to invalidate their cached ticket and perform a fresh handshake.
                    socket.write_all(&[0; 32]).await?;
                    return Err(e);
                }
            };
            let mut server_random = [0; 16];
            OsRng.fill_bytes(&mut server_random);
            socket.write_all(&server_random).await?;
            let up = Aead::new(&ticket_context, &united, algorithm);
            let down = Aead::new(&server_random, &united, algorithm);
            let (up_mask, down_mask) = if self.appearance == Appearance::Random {
                (
                    Some(header_mask(&united, &iv)),
                    Some(header_mask(&united, &server_random)),
                )
            } else {
                (None, None)
            };
            let united = Arc::new(united);
            let (read, write) = tokio::io::split(socket);
            return Ok((
                Reader::new(read, up, up_mask, united.clone()),
                Writer::new(write, down, down_mask, united),
                true,
            ));
        }

        ensure!(length >= 1232, "hybrid public key exchange too short");
        let mut peer_pfs = vec![0; length];
        socket.read_exact(&mut peer_pfs).await?;
        nfs_aead.open(&mut peer_pfs, &[], None)?;
        let kem = KemPublic::new_from_slice(&peer_pfs[..1184])
            .context("invalid ML-KEM encapsulation key")?;
        let (ciphertext, mlkem_shared) = kem.encapsulate();
        let mlkem_shared = Zeroizing::new(mlkem_shared);
        let peer: [u8; 32] = peer_pfs[1184..1216].try_into()?;
        ensure!(peer[31] <= 127, "noncanonical X25519 ephemeral key");
        let ephemeral = StaticSecret::random_from_rng(OsRng);
        let shared = ephemeral.diffie_hellman(&PublicKey::from(peer));
        ensure!(shared.was_contributory(), "invalid X25519 ephemeral key");
        let mut pfs = Zeroizing::new([0; 64]);
        pfs[..32].copy_from_slice(&mlkem_shared);
        pfs[32..].copy_from_slice(shared.as_bytes());
        let mut server_pfs = ciphertext.to_vec();
        server_pfs.extend_from_slice(PublicKey::from(&ephemeral).as_bytes());
        let mut united = Zeroizing::new(Vec::with_capacity(96));
        united.extend_from_slice(&pfs[..]);
        united.extend_from_slice(&nfs[..]);
        let up = Aead::new(&peer_pfs[..1216], &united, algorithm);
        let mut down = Aead::new(&server_pfs, &united, algorithm);
        let ticket = self.ticket(pfs);
        nfs_aead.seal(&mut server_pfs, &[], Some([255; 12]))?;
        let mut encrypted_ticket = ticket.to_vec();
        down.seal(&mut encrypted_ticket, &[], None)?;
        // Minimum valid encrypted padding = 18-byte length plus a tagged byte.
        // Fixed small padding avoids extra allocations and sleeps; configurable
        // traffic shaping can be added independently of the record protocol.
        let mut pad_len = 17u16.to_be_bytes().to_vec();
        down.seal(&mut pad_len, &[], None)?;
        let mut pad = vec![0];
        OsRng.fill_bytes(&mut pad);
        down.seal(&mut pad, &[], None)?;
        let mut server_hello = server_pfs;
        server_hello.extend_from_slice(&encrypted_ticket);
        server_hello.extend_from_slice(&pad_len);
        server_hello.extend_from_slice(&pad);
        socket.write_all(&server_hello).await?;
        let mut client_pad_len = vec![0; 18];
        socket.read_exact(&mut client_pad_len).await?;
        nfs_aead.open(&mut client_pad_len, &[], None)?;
        let client_pad_len = u16::from_be_bytes(client_pad_len[..2].try_into()?) as usize;
        ensure!(client_pad_len >= 16, "invalid client padding length");
        let mut client_pad = vec![0; client_pad_len];
        socket.read_exact(&mut client_pad).await?;
        nfs_aead.open(&mut client_pad, &[], None)?;
        let (up_mask, down_mask) = if self.appearance == Appearance::Random {
            (
                Some(header_mask(&united, &iv)),
                Some(header_mask(&united, &ticket)),
            )
        } else {
            (None, None)
        };
        let united = Arc::new(united);
        let (read, write) = tokio::io::split(socket);
        Ok((
            Reader::new(read, up, up_mask, united.clone()),
            Writer::new(write, down, down_mask, united),
            false,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn instance(max_sessions: usize) -> Server {
        let config = EncryptionConfig {
            appearance: Appearance::Native,
            lifetime: 600,
            keys: vec![Zeroizing::new(vec![42; 32])],
        };
        let limits = Limits {
            max_sessions,
            ..Limits::default()
        };
        Server::new(config, limits).unwrap()
    }
    #[test]
    fn replay_of_resumed_authentication_is_rejected() {
        let server = instance(2);
        let ticket = server.ticket(Zeroizing::new([41; 64]));
        assert!(server.resume(ticket, &[43; 32]).is_ok());
        assert!(server.resume(ticket, &[43; 32]).is_err());
        assert!(server.resume(ticket, &[44; 32]).is_ok());
    }
    #[test]
    fn full_cache_preserves_live_sessions_and_advertises_one_rtt() {
        let server = instance(1);
        let first = server.ticket(Zeroizing::new([41; 64]));
        let second = server.ticket(Zeroizing::new([42; 64]));
        assert_eq!(&second[..2], &[0, 0]);
        assert!(server.resume(first, &[43; 32]).is_ok());
        assert_eq!(server.sessions.lock().unwrap().len(), 1);
    }
    #[test]
    fn expired_sessions_are_rejected_and_pruned() {
        let server = instance(1);
        let ticket = server.ticket(Zeroizing::new([41; 64]));
        server
            .sessions
            .lock()
            .unwrap()
            .get_mut(&ticket)
            .unwrap()
            .expires = Instant::now() - Duration::from_secs(1);
        assert!(server.resume(ticket, &[43; 32]).is_err());
        server.prune();
        assert!(server.sessions.lock().unwrap().is_empty());
    }
}
