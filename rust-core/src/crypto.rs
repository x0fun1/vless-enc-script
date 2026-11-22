use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInPlace, KeyInit},
};
use anyhow::{Result, bail};
use chacha20poly1305::ChaCha20Poly1305;
use ctr::cipher::{KeyIvInit, StreamCipher};
use zeroize::{Zeroize, Zeroizing};

pub type HeaderMask = ctr::Ctr128BE<aes_gcm::aes::Aes256>;

// Xray uses arbitrary binary BLAKE3 contexts, which the upstream Rust public
// API cannot accept as &str. Use the upstream reference implementation for the
// complete KDF. Never lossily decode the binary context.
pub fn derive_key(context: &[u8], material: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = crate::blake3_reference::Hasher::new_derive_key(context);
    let mut output = Zeroizing::new([0; 32]);
    hasher.update(material);
    hasher.finalize(&mut *output);
    output
}

pub fn header_mask(key: &[u8], iv: &[u8; 16]) -> HeaderMask {
    let k = derive_key(b"VLESS", key);
    HeaderMask::new((&*k).into(), iv.into())
}

#[derive(Clone, Copy, Debug)]
pub enum Algorithm {
    Aes,
    ChaCha,
}

enum Cipher {
    Aes(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

pub struct Aead {
    cipher: Cipher,
    pub nonce: [u8; 12],
    pub algorithm: Algorithm,
}

impl Aead {
    pub fn new(context: &[u8], material: &[u8], algorithm: Algorithm) -> Self {
        let key = derive_key(context, material);
        let cipher = match algorithm {
            Algorithm::Aes => Cipher::Aes(Box::new(Aes256Gcm::new((&*key).into()))),
            Algorithm::ChaCha => Cipher::ChaCha(Box::new(ChaCha20Poly1305::new((&*key).into()))),
        };
        Self {
            cipher,
            nonce: [0; 12],
            algorithm,
        }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        for b in self.nonce.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        self.nonce
    }

    pub fn seal(
        &mut self,
        data: &mut Vec<u8>,
        aad: &[u8],
        explicit: Option<[u8; 12]>,
    ) -> Result<()> {
        let nonce = explicit.unwrap_or_else(|| self.next_nonce());
        let r = match &self.cipher {
            Cipher::Aes(c) => c.encrypt_in_place((&nonce).into(), aad, data),
            Cipher::ChaCha(c) => c.encrypt_in_place((&nonce).into(), aad, data),
        };
        r.map_err(|_| anyhow::anyhow!("AEAD encryption failed"))
    }

    pub fn open(
        &mut self,
        data: &mut Vec<u8>,
        aad: &[u8],
        explicit: Option<[u8; 12]>,
    ) -> Result<()> {
        let nonce = explicit.unwrap_or_else(|| self.next_nonce());
        let r = match &self.cipher {
            Cipher::Aes(c) => c.decrypt_in_place((&nonce).into(), aad, data),
            Cipher::ChaCha(c) => c.decrypt_in_place((&nonce).into(), aad, data),
        };
        if r.is_err() {
            data.zeroize();
            bail!("AEAD authentication failed");
        }
        Ok(())
    }

    pub fn seal_record(&mut self, data: &mut [u8], aad: &[u8]) -> Result<[u8; 16]> {
        let nonce = self.next_nonce();
        let tag = match &self.cipher {
            Cipher::Aes(c) => c.encrypt_in_place_detached((&nonce).into(), aad, data),
            Cipher::ChaCha(c) => c.encrypt_in_place_detached((&nonce).into(), aad, data),
        }
        .map_err(|_| anyhow::anyhow!("record encryption failed"))?;
        Ok(tag.into())
    }
}

pub fn mask_header(mask: &mut Option<HeaderMask>, header: &mut [u8; 5]) {
    if let Some(mask) = mask {
        mask.apply_keystream(header);
    }
}
