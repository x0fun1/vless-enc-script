use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs, net::SocketAddr, path::Path};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Appearance {
    Native,
    XorPub,
    Random,
}

pub struct EncryptionConfig {
    pub appearance: Appearance,
    pub lifetime: u16,
    pub keys: Vec<Zeroizing<Vec<u8>>>,
}

impl EncryptionConfig {
    pub fn parse(value: &str) -> Result<Self> {
        let fields: Vec<_> = value.split('.').collect();
        ensure!(
            fields.len() >= 4 && fields[0] == "mlkem768x25519plus",
            "only VLESS Encryption mlkem768x25519plus is supported"
        );
        let appearance = match fields[1] {
            "native" => Appearance::Native,
            "xorpub" => Appearance::XorPub,
            "random" => Appearance::Random,
            _ => bail!("unsupported encryption appearance"),
        };
        let lifetime = fields[2]
            .strip_suffix('s')
            .context("decryption lifetime must end in s")?
            .parse::<u16>()
            .context("decryption lifetime must be 0..65535 seconds; ranges are not supported")?;
        let mut keys = Vec::new();
        for field in &fields[3..] {
            let key = Zeroizing::new(
                URL_SAFE_NO_PAD
                    .decode(field)
                    .context("invalid private key encoding")?,
            );
            ensure!(
                key.len() == 32 || key.len() == 64,
                "authentication keys must be X25519 (32 bytes) or ML-KEM-768 seed (64 bytes); custom padding is not supported"
            );
            keys.push(key);
        }
        ensure!(
            keys.len() <= 8,
            "at most eight authentication relays are supported"
        );
        Ok(Self {
            appearance,
            lifetime,
            keys,
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_connections: usize,
    pub max_handshakes: usize,
    pub max_sessions: usize,
    pub max_resumes_per_session: usize,
    pub max_mux_streams: usize,
    pub handshake_timeout_secs: u64,
    pub connect_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub half_close_timeout_secs: u64,
    pub keepalive_idle_secs: u64,
    pub keepalive_interval_secs: u64,
    pub keepalive_retries: u32,
    pub allow_private_destinations: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            max_handshakes: 32,
            max_sessions: 1024,
            max_resumes_per_session: 1024,
            max_mux_streams: 32,
            handshake_timeout_secs: 15,
            connect_timeout_secs: 10,
            idle_timeout_secs: 900,
            half_close_timeout_secs: 30,
            keepalive_idle_secs: 60,
            keepalive_interval_secs: 15,
            keepalive_retries: 4,
            allow_private_destinations: false,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub users: Vec<Uuid>,
    pub decryption: String,
    #[serde(default)]
    pub vision: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<crate::reality::RealityConfig>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub log_connections: bool,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = Zeroizing::new(fs::read(path).context("read configuration")?);
        ensure!(bytes.len() <= 1024 * 1024, "configuration exceeds 1 MiB");
        let config: Self = serde_json::from_slice(&bytes)
            .context("parse configuration (use the Rust configuration schema)")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.listen.port() != 0, "listen port cannot be zero");
        ensure!(
            !self.users.is_empty() && self.users.len() <= 4096,
            "users must contain 1..4096 UUIDs"
        );
        ensure!(
            self.users.iter().collect::<HashSet<_>>().len() == self.users.len(),
            "duplicate user UUID"
        );
        let l = &self.limits;
        ensure!(
            (1..=65536).contains(&l.max_connections),
            "invalid max_connections"
        );
        ensure!(
            l.max_handshakes > 0 && l.max_handshakes <= l.max_connections,
            "invalid max_handshakes"
        );
        ensure!(
            l.max_sessions <= 65536 && (1..=4096).contains(&l.max_resumes_per_session),
            "invalid session cache limits"
        );
        ensure!(
            (1..=256).contains(&l.max_mux_streams),
            "invalid max_mux_streams"
        );
        for n in [
            l.handshake_timeout_secs,
            l.connect_timeout_secs,
            l.idle_timeout_secs,
            l.half_close_timeout_secs,
            l.keepalive_idle_secs,
            l.keepalive_interval_secs,
        ] {
            ensure!(
                (1..=86400).contains(&n),
                "timeouts must be 1..86400 seconds"
            );
        }
        ensure!(
            (1..=255).contains(&l.keepalive_retries),
            "invalid keepalive_retries"
        );
        EncryptionConfig::parse(&self.decryption)?;
        if let Some(reality) = &self.reality {
            reality.validate()?;
        }
        Ok(())
    }
}
