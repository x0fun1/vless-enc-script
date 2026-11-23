// SPDX-License-Identifier: MPL-2.0
// Record framing, counters and rekeying follow Xray-core v26.11.9 common.go.
use crate::crypto::{Aead, HeaderMask, mask_header};
use crate::vision::{Decoder as VisionDecoder, Encoder as VisionEncoder, SharedState};
use anyhow::{Result, ensure};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

type Secret = Arc<Zeroizing<Vec<u8>>>;
pub const RECORD_PAYLOAD: usize = 8192;

fn direct_record_length(header: &[u8; 5]) -> Result<usize> {
    ensure!(
        header[..3] == [23, 3, 3],
        "invalid TLS record header after XTLS Vision Direct transition"
    );
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    ensure!(
        (17..=16640).contains(&length),
        "invalid TLS record length after XTLS Vision Direct transition"
    );
    Ok(length)
}

pub struct Reader {
    socket: Box<dyn AsyncRead + Unpin + Send>,
    cipher: Aead,
    mask: Option<HeaderMask>,
    secret: Secret,
    buffer: Zeroizing<Vec<u8>>,
    offset: usize,
    vision: Option<VisionDecoder>,
    direct_header: [u8; 5],
    direct_header_len: usize,
    direct_header_offset: usize,
    direct_body_remaining: usize,
}

impl Reader {
    pub fn algorithm(&self) -> crate::crypto::Algorithm {
        self.cipher.algorithm
    }
    pub fn new(
        socket: impl AsyncRead + Unpin + Send + 'static,
        cipher: Aead,
        mask: Option<HeaderMask>,
        secret: Secret,
    ) -> Self {
        Self {
            socket: Box::new(socket),
            cipher,
            mask,
            secret,
            buffer: Zeroizing::new(Vec::with_capacity(RECORD_PAYLOAD + 16)),
            offset: 0,
            vision: None,
            direct_header: [0; 5],
            direct_header_len: 0,
            direct_header_offset: 0,
            direct_body_remaining: 0,
        }
    }

    pub fn enable_vision(&mut self, uuid: [u8; 16], state: SharedState) -> Result<()> {
        ensure!(self.vision.is_none(), "Vision already enabled");
        let pending = self.buffer[self.offset..].to_vec();
        let mut decoder = VisionDecoder::new(uuid, state, true);
        let decoded = decoder.decode(&pending)?;
        self.buffer = Zeroizing::new(decoded.bytes);
        self.offset = 0;
        self.vision = Some(decoder);
        Ok(())
    }

    async fn read_direct(&mut self, output: &mut [u8]) -> Result<usize> {
        if self.mask.is_none() {
            return Ok(self.socket.read(output).await?);
        }
        let mut written = 0;
        while written < output.len() {
            if self.direct_header_len == 0 && self.direct_body_remaining == 0 {
                let n = self.socket.read(&mut self.direct_header[..1]).await?;
                if n == 0 {
                    return Ok(written);
                }
                self.direct_header_len = n;
                self.socket
                    .read_exact(&mut self.direct_header[self.direct_header_len..])
                    .await?;
                self.direct_header_len = 5;
                self.direct_body_remaining = direct_record_length(&self.direct_header)?;
                mask_header(&mut self.mask, &mut self.direct_header);
            }
            if self.direct_header_offset < self.direct_header_len {
                let n = (output.len() - written)
                    .min(self.direct_header_len - self.direct_header_offset);
                output[written..written + n].copy_from_slice(
                    &self.direct_header[self.direct_header_offset..self.direct_header_offset + n],
                );
                self.direct_header_offset += n;
                written += n;
                if self.direct_header_offset == 5 {
                    self.direct_header_len = 0;
                    self.direct_header_offset = 0;
                }
                continue;
            }
            if self.direct_body_remaining > 0 {
                let available = (output.len() - written).min(self.direct_body_remaining);
                let n = self
                    .socket
                    .read(&mut output[written..written + available])
                    .await?;
                if n == 0 {
                    return Ok(written);
                }
                self.direct_body_remaining -= n;
                written += n;
            }
        }
        Ok(written)
    }

    pub async fn read_some(&mut self, output: &mut [u8]) -> Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if self.offset < self.buffer.len() {
                let count = output.len().min(self.buffer.len() - self.offset);
                output[..count].copy_from_slice(&self.buffer[self.offset..self.offset + count]);
                self.offset += count;
                return Ok(count);
            }
            if self.vision.as_ref().is_some_and(VisionDecoder::is_direct) {
                return self.read_direct(output).await;
            }
            let mut header = [0; 5];
            let n = self.socket.read(&mut header[..1]).await?;
            if n == 0 {
                return Ok(0);
            }
            self.socket.read_exact(&mut header[1..]).await?;
            mask_header(&mut self.mask, &mut header);
            let length = u16::from_be_bytes([header[3], header[4]]) as usize;
            ensure!(
                header[..3] == [23, 3, 3] && (17..=16640).contains(&length),
                "invalid encrypted record header"
            );
            self.buffer.resize(length, 0);
            self.socket.read_exact(&mut self.buffer).await?;
            let rekey = if self.cipher.nonce == [255; 12] {
                let mut context = header.to_vec();
                context.extend_from_slice(&self.buffer);
                Some(Aead::new(&context, &self.secret, self.cipher.algorithm))
            } else {
                None
            };
            self.cipher.open(&mut self.buffer, &header, None)?;
            if let Some(cipher) = rekey {
                self.cipher = cipher;
            }
            self.offset = 0;
            if let Some(vision) = self.vision.as_mut() {
                let decoded = vision.decode(&self.buffer)?;
                self.buffer = Zeroizing::new(decoded.bytes);
            }
            if self.buffer.is_empty() {
                if self.vision.as_ref().is_some_and(VisionDecoder::is_direct) {
                    return self.read_direct(output).await;
                }
                continue;
            }
        }
    }

    pub async fn read_exact(&mut self, mut output: &mut [u8]) -> Result<()> {
        while !output.is_empty() {
            let n = self.read_some(output).await?;
            ensure!(n != 0, "unexpected EOF in encrypted payload");
            output = &mut output[n..];
        }
        Ok(())
    }

    pub async fn byte(&mut self) -> Result<u8> {
        let mut b = [0];
        self.read_exact(&mut b).await?;
        Ok(b[0])
    }
    pub async fn u16(&mut self) -> Result<u16> {
        let mut b = [0; 2];
        self.read_exact(&mut b).await?;
        Ok(u16::from_be_bytes(b))
    }
}

pub struct Writer {
    socket: Box<dyn AsyncWrite + Unpin + Send>,
    cipher: Aead,
    mask: Option<HeaderMask>,
    secret: Secret,
    buffer: Zeroizing<Vec<u8>>,
    vision: Option<VisionEncoder>,
    direct_header: [u8; 5],
    direct_header_len: usize,
    direct_body_remaining: usize,
}

impl Writer {
    pub fn new(
        socket: impl AsyncWrite + Unpin + Send + 'static,
        cipher: Aead,
        mask: Option<HeaderMask>,
        secret: Secret,
    ) -> Self {
        Self {
            socket: Box::new(socket),
            cipher,
            mask,
            secret,
            buffer: Zeroizing::new(Vec::with_capacity(5 + RECORD_PAYLOAD + 16)),
            vision: None,
            direct_header: [0; 5],
            direct_header_len: 0,
            direct_body_remaining: 0,
        }
    }

    pub fn enable_vision(&mut self, uuid: [u8; 16], state: SharedState) -> Result<()> {
        ensure!(self.vision.is_none(), "Vision already enabled");
        self.vision = Some(VisionEncoder::new(uuid, state, false));
        Ok(())
    }

    pub async fn write_response_header(&mut self) -> Result<()> {
        self.write_encrypted(&[0, 0]).await
    }

    async fn write_direct(&mut self, payload: &[u8]) -> Result<()> {
        if self.mask.is_none() {
            self.socket.write_all(payload).await?;
            return Ok(());
        }
        let mut output = Zeroizing::new(Vec::with_capacity(payload.len() + 5));
        let mut position = 0;
        while position < payload.len() {
            if self.direct_body_remaining > 0 {
                let n = (payload.len() - position).min(self.direct_body_remaining);
                output.extend_from_slice(&payload[position..position + n]);
                self.direct_body_remaining -= n;
                position += n;
                continue;
            }
            let take = (5 - self.direct_header_len).min(payload.len() - position);
            self.direct_header[self.direct_header_len..self.direct_header_len + take]
                .copy_from_slice(&payload[position..position + take]);
            self.direct_header_len += take;
            position += take;
            if self.direct_header_len < 5 {
                break;
            }
            self.direct_body_remaining = direct_record_length(&self.direct_header)?;
            mask_header(&mut self.mask, &mut self.direct_header);
            output.extend_from_slice(&self.direct_header);
            self.direct_header_len = 0;
        }
        if !output.is_empty() {
            self.socket.write_all(&output).await?;
        }
        Ok(())
    }

    pub async fn write_all(&mut self, payload: &[u8]) -> Result<()> {
        if let Some(vision) = self.vision.as_mut() {
            if vision.is_direct() {
                self.write_direct(payload).await?;
                return Ok(());
            }
            let encoded = vision.encode(payload)?;
            self.write_encrypted(&encoded.bytes).await?;
            return Ok(());
        }
        self.write_encrypted(payload).await
    }

    async fn write_encrypted(&mut self, payload: &[u8]) -> Result<()> {
        for batch in payload.chunks(4 * RECORD_PAYLOAD) {
            self.buffer.clear();
            for chunk in batch.chunks(RECORD_PAYLOAD) {
                let offset = self.buffer.len();
                let length = (chunk.len() + 16) as u16;
                let mut header = [23, 3, 3, (length >> 8) as u8, length as u8];
                self.buffer.extend_from_slice(&header);
                self.buffer.extend_from_slice(chunk);
                let rekey = self.cipher.nonce == [255; 12];
                let tag = self
                    .cipher
                    .seal_record(&mut self.buffer[offset + 5..], &header)?;
                self.buffer.extend_from_slice(&tag);
                if rekey {
                    self.cipher =
                        Aead::new(&self.buffer[offset..], &self.secret, self.cipher.algorithm);
                }
                mask_header(&mut self.mask, &mut header);
                self.buffer[offset..offset + 5].copy_from_slice(&header);
            }
            self.socket.write_all(&self.buffer).await?;
        }
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.socket.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Limits,
        crypto::{Algorithm, derive_key},
        forward::{self, Activity, Target},
    };
    use tokio::{
        net::{TcpListener, TcpStream},
        time::{Duration, timeout},
    };

    async fn pair(algorithm: Algorithm) -> (Reader, Writer, Reader, Writer) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        client.set_nodelay(true).unwrap();
        server.set_nodelay(true).unwrap();
        let secret = Arc::new(Zeroizing::new(vec![47; 96]));
        let (cr, cw) = client.into_split();
        let (sr, sw) = server.into_split();
        (
            Reader::new(
                cr,
                Aead::new(b"DOWN", &secret, algorithm),
                None,
                secret.clone(),
            ),
            Writer::new(
                cw,
                Aead::new(b"UP", &secret, algorithm),
                None,
                secret.clone(),
            ),
            Reader::new(
                sr,
                Aead::new(b"UP", &secret, algorithm),
                None,
                secret.clone(),
            ),
            Writer::new(sw, Aead::new(b"DOWN", &secret, algorithm), None, secret),
        )
    }

    #[test]
    fn raw_context_kdf_matches_upstream_across_chunk_boundaries() {
        for size in [0, 16, 63, 64, 65, 1023, 1024, 1025, 1216, 16384, 16645] {
            let context = "x".repeat(size);
            let material = [43; 96];
            assert_eq!(
                *derive_key(context.as_bytes(), &material),
                blake3::derive_key(&context, &material)
            );
        }
    }

    #[tokio::test]
    async fn multi_record_payload_and_partial_reads() {
        for algorithm in [Algorithm::Aes, Algorithm::ChaCha] {
            let (_, mut client, mut server, _) = pair(algorithm).await;
            let payload: Vec<_> = (0..131071).map(|n| n as u8).collect();
            let sending = client.write_all(&payload);
            let receiving = async {
                let mut output = vec![0; payload.len()];
                for slice in output.chunks_mut(37) {
                    server.read_exact(slice).await.unwrap();
                }
                assert_eq!(output, payload);
            };
            let (sent, _) = tokio::join!(sending, receiving);
            sent.unwrap();
        }
    }

    #[tokio::test]
    async fn nonce_wrap_rekeys_from_authenticated_record() {
        for algorithm in [Algorithm::Aes, Algorithm::ChaCha] {
            let (_, mut client, mut server, _) = pair(algorithm).await;
            client.cipher.nonce = [255; 12];
            server.cipher.nonce = [255; 12];
            for _ in 0..2 {
                client.write_all(b"rekey test").await.unwrap();
                let mut output = [0; 10];
                server.read_exact(&mut output).await.unwrap();
                assert_eq!(&output, b"rekey test");
            }
        }
    }

    #[tokio::test]
    async fn invalid_header_is_rejected() {
        let (_, mut client, mut server, _) = pair(Algorithm::Aes).await;
        client.socket.write_all(&[0, 0, 0, 255, 255]).await.unwrap();
        let error = server.read_some(&mut [0; 1]).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid encrypted record header")
        );
    }

    #[tokio::test]
    async fn altered_ciphertext_is_rejected() {
        let (_, mut client, mut server, _) = pair(Algorithm::Aes).await;
        let header = [23, 3, 3, 0, 17];
        let mut payload = vec![1];
        client.cipher.seal(&mut payload, &header, None).unwrap();
        payload[0] ^= 1;
        client.socket.write_all(&header).await.unwrap();
        client.socket.write_all(&payload).await.unwrap();
        assert!(server.read_some(&mut [0; 1]).await.is_err());
    }

    #[tokio::test]
    async fn upload_half_close_preserves_delayed_downlink() {
        let (mut client_reader, mut client_writer, server_reader, server_writer) =
            pair(Algorithm::Aes).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let destination = async {
            let (mut socket, _) = target.accept().await.unwrap();
            let mut upload = Vec::new();
            socket.read_to_end(&mut upload).await.unwrap();
            assert_eq!(&upload, b"upload");
            tokio::time::sleep(Duration::from_millis(650)).await;
            socket.write_all(b"delayed ").await.unwrap();
            tokio::time::sleep(Duration::from_millis(650)).await;
            socket.write_all(b"response").await.unwrap();
            socket.shutdown().await.unwrap();
        };
        let limits = Limits {
            allow_private_destinations: true,
            half_close_timeout_secs: 1,
            ..Limits::default()
        };
        let forwarding = forward::tcp(
            server_reader,
            server_writer,
            Target {
                host: address.ip().to_string(),
                port: address.port(),
            },
            &limits,
            Activity::new(),
        );
        let client = async {
            client_writer.write_all(b"upload").await.unwrap();
            client_writer.shutdown().await.unwrap();
            let mut response = Vec::new();
            let mut scratch = [0; 32];
            loop {
                let n = client_reader.read_some(&mut scratch).await.unwrap();
                if n == 0 {
                    break;
                }
                response.extend_from_slice(&scratch[..n]);
            }
            assert_eq!(&response, b"\0\0delayed response");
        };
        timeout(Duration::from_secs(3), async {
            let (_, forwarded, _) = tokio::join!(destination, forwarding, client);
            forwarded.unwrap();
        })
        .await
        .unwrap();
    }
}
