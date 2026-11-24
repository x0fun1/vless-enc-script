// SPDX-License-Identifier: MPL-2.0
// XTLS Vision VLESS addon framing follows Xray-core v26.11.9 proxy/proxy.go.
use anyhow::{Result, ensure};
use rand::{Rng, rngs::OsRng};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

const COMMAND_CONTINUE: u8 = 0;
const COMMAND_END: u8 = 1;
const COMMAND_DIRECT: u8 = 2;
const MAX_FRAME: usize = 8192;
const MAX_CONTENT: usize = MAX_FRAME - 21;
const FILTER_PACKETS: i32 = 8;
const SEED: [usize; 4] = [900, 500, 900, 256];

#[derive(Default)]
struct Direction {
    remaining_command: i32,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: u8,
}

struct Traffic {
    packets_to_filter: i32,
    is_tls: bool,
    is_tls12_or_above: bool,
    enable_direct: bool,
    remaining_server_hello: i32,
    server_hello_capture: Vec<u8>,
    tls_tail: Vec<u8>,
    cipher: u16,
}

impl Default for Traffic {
    fn default() -> Self {
        Self {
            packets_to_filter: FILTER_PACKETS,
            is_tls: false,
            is_tls12_or_above: false,
            enable_direct: false,
            remaining_server_hello: 0,
            server_hello_capture: Vec::new(),
            tls_tail: Vec::with_capacity(5),
            cipher: 0,
        }
    }
}

#[derive(Clone)]
pub struct SharedState(Arc<Mutex<Traffic>>, Arc<AtomicU64>, Arc<AtomicU64>);

impl SharedState {
    pub fn new() -> Self {
        Self(
            Arc::new(Mutex::new(Traffic::default())),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        )
    }

    pub fn direct_transitions(&self) -> u64 {
        self.direct_uplink() + self.direct_downlink()
    }

    pub fn direct_uplink(&self) -> u64 {
        self.1.load(Ordering::Relaxed)
    }

    pub fn direct_downlink(&self) -> u64 {
        self.2.load(Ordering::Relaxed)
    }

    fn mark_direct(&self, uplink: bool) {
        let counter = if uplink { &self.1 } else { &self.2 };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn inspect(&self, bytes: &[u8]) -> (bool, bool, bool) {
        let mut state = self.0.lock().expect("Vision state mutex poisoned");
        let capturing_server_hello = state.remaining_server_hello > 0;
        if state.packets_to_filter > 0 || capturing_server_hello {
            if !capturing_server_hello && state.packets_to_filter > 0 {
                state.packets_to_filter -= 1;
            }

            if capturing_server_hello {
                let take = (state.remaining_server_hello as usize).min(bytes.len());
                state.server_hello_capture.extend_from_slice(&bytes[..take]);
                state.remaining_server_hello -= take as i32;
            } else {
                let tail_len = state.tls_tail.len();
                let mut joined = std::mem::take(&mut state.tls_tail);
                joined.extend_from_slice(bytes);

                if joined.len() >= 6 && joined[..2] == [0x16, 0x03] && joined[5] == 0x01 {
                    state.is_tls = true;
                }

                let candidate = (0..=tail_len.min(joined.len().saturating_sub(6))).find(|&start| {
                    joined[start..start + 3] == [0x16, 0x03, 0x03] && joined[start + 5] == 0x02
                });
                if let Some(start) = candidate {
                    let record_length =
                        u16::from_be_bytes([joined[start + 3], joined[start + 4]]) as usize;
                    if (4..=16_384).contains(&record_length) {
                        let total = 5 + record_length;
                        state.remaining_server_hello = total as i32;
                        state.is_tls = true;
                        state.is_tls12_or_above = true;
                        state.cipher = 0;
                        state.server_hello_capture.clear();
                        state
                            .server_hello_capture
                            .extend_from_slice(&joined[start..(start + total).min(joined.len())]);
                        state.remaining_server_hello -= state.server_hello_capture.len() as i32;
                    }
                }

                if state.remaining_server_hello == 0 {
                    let keep = joined.len().min(5);
                    state
                        .tls_tail
                        .extend_from_slice(&joined[joined.len() - keep..]);
                }
            }

            if state.server_hello_capture.len() >= 46 {
                let session_id_length = state.server_hello_capture[43] as usize;
                let suite_offset = 44 + session_id_length;
                if session_id_length <= 32 && suite_offset + 2 <= state.server_hello_capture.len() {
                    state.cipher = u16::from_be_bytes([
                        state.server_hello_capture[suite_offset],
                        state.server_hello_capture[suite_offset + 1],
                    ]);
                }
            }

            if state
                .server_hello_capture
                .windows(6)
                .any(|w| w == [0, 0x2b, 0, 2, 3, 4])
            {
                if state.cipher != 0 && state.cipher != 0x1305 {
                    state.enable_direct = true;
                }
                state.packets_to_filter = 0;
                state.remaining_server_hello = 0;
            } else if state.remaining_server_hello == 0 && !state.server_hello_capture.is_empty() {
                state.packets_to_filter = 0;
            }
            if state.remaining_server_hello == 0 {
                state.server_hello_capture.clear();
            }
        }
        (state.is_tls, state.is_tls12_or_above, state.enable_direct)
    }
}

impl Default for SharedState {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Decoded {
    pub bytes: Vec<u8>,
}

pub struct Decoder {
    uuid: [u8; 16],
    state: SharedState,
    pending: Vec<u8>,
    started: bool,
    finished: bool,
    direct: bool,
    uplink: bool,
    direction: Direction,
}

impl Decoder {
    pub fn new(uuid: [u8; 16], state: SharedState, uplink: bool) -> Self {
        Self {
            uuid,
            state,
            pending: Vec::new(),
            started: false,
            finished: false,
            direct: false,
            uplink,
            direction: Direction {
                remaining_command: -1,
                remaining_content: -1,
                remaining_padding: -1,
                current_command: 0,
            },
        }
    }

    pub fn is_direct(&self) -> bool {
        self.direct
    }

    pub fn decode(&mut self, input: &[u8]) -> Result<Decoded> {
        if self.direct || self.finished {
            return Ok(Decoded {
                bytes: input.to_vec(),
            });
        }
        self.pending.extend_from_slice(input);
        let mut output = Vec::new();
        let mut pos = 0;
        if !self.started {
            if self.pending.len() < 21 {
                return Ok(Decoded { bytes: output });
            }
            if self.pending[..16] != self.uuid {
                self.finished = true;
                output.extend_from_slice(&self.pending);
                self.pending.clear();
                return Ok(Decoded { bytes: output });
            }
            self.started = true;
            pos = 16;
            self.direction.remaining_command = 5;
        }

        while pos < self.pending.len() {
            if self.direction.remaining_command > 0 {
                self.direction.current_command = match self.direction.remaining_command {
                    5 => self.pending[pos],
                    4 => {
                        self.direction.remaining_content = (self.pending[pos] as i32) << 8;
                        self.direction.current_command
                    }
                    3 => {
                        self.direction.remaining_content |= self.pending[pos] as i32;
                        self.direction.current_command
                    }
                    2 => {
                        self.direction.remaining_padding = (self.pending[pos] as i32) << 8;
                        self.direction.current_command
                    }
                    1 => {
                        self.direction.remaining_padding |= self.pending[pos] as i32;
                        self.direction.current_command
                    }
                    _ => self.direction.current_command,
                };
                self.direction.remaining_command -= 1;
                pos += 1;
                if self.direction.remaining_command == 0 {
                    ensure!(
                        self.direction.current_command <= COMMAND_DIRECT,
                        "invalid XTLS Vision command"
                    );
                    ensure!(
                        self.direction.remaining_content >= 0
                            && self.direction.remaining_padding >= 0
                            && (self.direction.remaining_content as usize)
                                + (self.direction.remaining_padding as usize)
                                <= MAX_CONTENT,
                        "invalid XTLS Vision frame size"
                    );
                }
                continue;
            }
            if self.direction.remaining_content > 0 {
                let n = (self.direction.remaining_content as usize).min(self.pending.len() - pos);
                output.extend_from_slice(&self.pending[pos..pos + n]);
                self.direction.remaining_content -= n as i32;
                pos += n;
                continue;
            }
            if self.direction.remaining_padding > 0 {
                let n = (self.direction.remaining_padding as usize).min(self.pending.len() - pos);
                self.direction.remaining_padding -= n as i32;
                pos += n;
                continue;
            }

            if self.direction.current_command == COMMAND_CONTINUE {
                self.direction.remaining_command = 5;
                continue;
            }
            self.finished = true;
            self.direct = self.direction.current_command == COMMAND_DIRECT;
            if self.direct {
                self.state.mark_direct(self.uplink);
            }
            output.extend_from_slice(&self.pending[pos..]);
            pos = self.pending.len();
        }
        self.pending.drain(..pos);
        if !self.finished
            && self.direction.remaining_command == 0
            && self.direction.remaining_content <= 0
            && self.direction.remaining_padding <= 0
        {
            if self.direction.current_command == COMMAND_CONTINUE {
                self.direction.remaining_command = 5;
            } else {
                self.finished = true;
                self.direct = self.direction.current_command == COMMAND_DIRECT;
                if self.direct {
                    self.state.mark_direct(self.uplink);
                }
            }
        }
        if !output.is_empty() {
            self.state.inspect(&output);
        }
        Ok(Decoded { bytes: output })
    }
}

pub struct Encoded {
    pub bytes: Vec<u8>,
}

pub struct Encoder {
    uuid: [u8; 16],
    state: SharedState,
    uuid_sent: bool,
    finished: bool,
    direct: bool,
    uplink: bool,
}

impl Encoder {
    pub fn new(uuid: [u8; 16], state: SharedState, uplink: bool) -> Self {
        Self {
            uuid,
            state,
            uuid_sent: false,
            finished: false,
            direct: false,
            uplink,
        }
    }

    pub fn is_direct(&self) -> bool {
        self.direct
    }

    pub fn encode(&mut self, input: &[u8]) -> Result<Encoded> {
        if self.direct {
            return Ok(Encoded {
                bytes: input.to_vec(),
            });
        }
        if self.finished || input.is_empty() {
            return Ok(Encoded {
                bytes: input.to_vec(),
            });
        }
        let (is_tls, tls12_or_above, enable_direct) = self.state.inspect(input);
        let complete_app_data =
            input.len() >= 3 && input[..3] == [0x17, 0x03, 0x03] && is_complete_record(input);
        let command = if is_tls && complete_app_data {
            if enable_direct {
                COMMAND_DIRECT
            } else {
                COMMAND_END
            }
        } else if !tls12_or_above
            && self
                .state
                .0
                .lock()
                .expect("Vision state mutex poisoned")
                .packets_to_filter
                <= 1
        {
            COMMAND_END
        } else {
            COMMAND_CONTINUE
        };
        let mut output = Vec::with_capacity(input.len() + 64);
        let chunks = input.chunks(MAX_CONTENT);
        let count = chunks.len();
        for (index, chunk) in chunks.enumerate() {
            let last = index + 1 == count;
            let cmd = if last { command } else { COMMAND_CONTINUE };
            let long_padding = is_tls;
            let content_len = chunk.len();
            let upper = if long_padding && content_len < SEED[0] {
                SEED[1]
            } else {
                SEED[3]
            };
            let mut padding = if long_padding && content_len < SEED[0] {
                OsRng.gen_range(0..upper) + SEED[2] - content_len
            } else {
                OsRng.gen_range(0..upper)
            };
            padding = padding.min(MAX_FRAME - 21 - content_len);
            if !self.uuid_sent {
                output.extend_from_slice(&self.uuid);
                self.uuid_sent = true;
            }
            output.extend_from_slice(&[
                cmd,
                (content_len >> 8) as u8,
                content_len as u8,
                (padding >> 8) as u8,
                padding as u8,
            ]);
            output.extend_from_slice(chunk);
            output.resize(output.len() + padding, 0);
        }
        self.finished = command != COMMAND_CONTINUE;
        self.direct = command == COMMAND_DIRECT;
        if self.direct {
            self.state.mark_direct(self.uplink);
        }
        Ok(Encoded { bytes: output })
    }
}

pub fn is_complete_record(input: &[u8]) -> bool {
    let mut pos = 0;
    while pos < input.len() {
        if input.len() - pos < 5 || input[pos..pos + 3] != [0x17, 0x03, 0x03] {
            return false;
        }
        let len = u16::from_be_bytes([input[pos + 3], input[pos + 4]]) as usize;
        if len == 0 || input.len() - pos - 5 < len {
            return false;
        }
        pos += 5 + len;
    }
    pos == input.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vision_addon_frames_roundtrip_across_arbitrary_boundaries() {
        let uuid = [0x42; 16];
        let mut encoder = Encoder::new(uuid, SharedState::new(), true);
        let mut decoder = Decoder::new(uuid, SharedState::new(), true);
        let payload = vec![0x5a; 19000];
        let frame = encoder.encode(&payload).unwrap();
        let mut decoded = Vec::new();
        for chunk in frame.bytes.chunks(37) {
            decoded.extend_from_slice(&decoder.decode(chunk).unwrap().bytes);
        }
        assert_eq!(decoded, payload);
    }

    #[test]
    fn tls13_server_hello_triggers_direct_command_and_decoder_switch() {
        let uuid = [0x24; 16];
        let state = SharedState::new();
        state.inspect(&[0x16, 0x03, 0x01, 0, 1, 1]);
        let mut server_hello = vec![0; 86];
        server_hello[..6].copy_from_slice(&[0x16, 0x03, 0x03, 0, 81, 2]);
        server_hello[43] = 32;
        server_hello[76..78].copy_from_slice(&0x1301u16.to_be_bytes());
        server_hello[80..86].copy_from_slice(&[0, 0x2b, 0, 2, 3, 4]);
        let (_, _, enabled) = state.inspect(&server_hello);
        assert!(enabled);

        let mut encoder = Encoder::new(uuid, SharedState::new(), false);
        {
            let mut traffic = encoder.state.0.lock().unwrap();
            traffic.is_tls = true;
            traffic.is_tls12_or_above = true;
            traffic.enable_direct = true;
            traffic.packets_to_filter = 0;
        }
        let record = [0x17, 0x03, 0x03, 0, 1, 0xaa];
        let encoded = encoder.encode(&record).unwrap();
        assert_eq!(encoded.bytes[16], COMMAND_DIRECT);
        let mut decoder = Decoder::new(uuid, SharedState::new(), true);
        let decoded = decoder.decode(&encoded.bytes).unwrap();
        assert_eq!(decoded.bytes, record);
        assert!(decoder.is_direct());
    }

    #[test]
    fn tls13_server_hello_detection_survives_every_fragment_boundary() {
        fn server_hello(cipher: u16) -> Vec<u8> {
            let mut hello = vec![0; 86];
            hello[..6].copy_from_slice(&[0x16, 0x03, 0x03, 0, 81, 2]);
            hello[43] = 32;
            hello[76..78].copy_from_slice(&cipher.to_be_bytes());
            hello[80..86].copy_from_slice(&[0, 0x2b, 0, 2, 3, 4]);
            hello
        }

        let hello = server_hello(0x1301);
        for split in 1..hello.len() {
            let state = SharedState::new();
            state.inspect(&[0x16, 0x03, 0x01, 0, 4, 1, 0, 0, 0]);
            state.inspect(&hello[..split]);
            let (_, tls12, direct) = state.inspect(&hello[split..]);
            assert!(tls12, "TLS version was not detected at split {split}");
            assert!(direct, "Direct was not enabled at split {split}");
        }

        let state = SharedState::new();
        state.inspect(&[0x16, 0x03, 0x01, 0, 4, 1, 0, 0, 0]);
        for byte in &hello {
            state.inspect(std::slice::from_ref(byte));
        }
        assert!(
            state.inspect(&[]).2,
            "one-byte TLS fragments did not enable Direct"
        );

        let chacha = server_hello(0x1305);
        let state = SharedState::new();
        state.inspect(&[0x16, 0x03, 0x01, 0, 4, 1, 0, 0, 0]);
        for chunk in chacha.chunks(7) {
            state.inspect(chunk);
        }
        assert!(
            !state.inspect(&[]).2,
            "ChaCha TLS suite must not enable Direct"
        );
    }

    #[test]
    fn tls_record_detection_requires_complete_records() {
        let record = [0x17, 3, 3, 0, 3, 1, 2, 3];
        assert!(is_complete_record(&record));
        assert!(!is_complete_record(&record[..7]));
        assert!(!is_complete_record(&[0x16, 3, 3, 0, 3, 1, 2, 3]));
    }

    #[test]
    fn invalid_vision_command_is_rejected() {
        let uuid = [0x42; 16];
        let mut decoder = Decoder::new(uuid, SharedState::new(), true);
        let mut frame = uuid.to_vec();
        frame.extend_from_slice(&[3, 0, 0, 0, 0]);
        assert!(decoder.decode(&frame).is_err());
    }
}
