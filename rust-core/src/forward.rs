use crate::{
    config::{Config, Limits},
    record::{RECORD_PAYLOAD, Reader, Writer},
};
use anyhow::{Context, Result, bail, ensure};
use socket2::{SockRef, TcpKeepalive};
use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket, lookup_host},
    time::{Instant, sleep, sleep_until, timeout},
};
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

pub struct Request {
    pub command: u8,
    pub target: Option<Target>,
    pub user_id: [u8; 16],
}

fn read_varint(bytes: &[u8], position: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        ensure!(*position < bytes.len(), "truncated VLESS addons varint");
        let byte = bytes[*position];
        *position += 1;
        ensure!(shift < 63 || byte <= 1, "overflow in VLESS addons varint");
        value |= ((byte & 0x7f) as u64).checked_shl(shift).unwrap_or(0);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("overlong VLESS addons varint")
}

fn parse_addons(bytes: &[u8]) -> Result<String> {
    let mut flow = String::new();
    let mut position = 0;
    while position < bytes.len() {
        let key = read_varint(bytes, &mut position)?;
        let field = key >> 3;
        let wire = key & 7;
        ensure!(field != 0, "invalid VLESS addons protobuf field");
        match wire {
            0 => {
                read_varint(bytes, &mut position)?;
            }
            1 => {
                ensure!(
                    bytes.len() - position >= 8,
                    "truncated VLESS addons fixed64 field"
                );
                position += 8;
            }
            2 => {
                let length = usize::try_from(read_varint(bytes, &mut position)?)?;
                ensure!(
                    length <= bytes.len() - position,
                    "truncated VLESS addons bytes field"
                );
                if field == 1 {
                    flow = std::str::from_utf8(&bytes[position..position + length])
                        .context("VLESS flow must be UTF-8")?
                        .to_owned();
                }
                position += length;
            }
            5 => {
                ensure!(
                    bytes.len() - position >= 4,
                    "truncated VLESS addons fixed32 field"
                );
                position += 4;
            }
            _ => bail!("unsupported VLESS addons protobuf wire type {wire}"),
        }
    }
    Ok(flow)
}

pub async fn read_target(reader: &mut Reader) -> Result<Target> {
    let port = reader.u16().await?;
    let host = match reader.byte().await? {
        1 => {
            let mut b = [0; 4];
            reader.read_exact(&mut b).await?;
            Ipv4Addr::from(b).to_string()
        }
        2 => {
            let n = reader.byte().await? as usize;
            ensure!(n != 0, "empty destination domain");
            let mut b = vec![0; n];
            reader.read_exact(&mut b).await?;
            String::from_utf8(b).context("invalid destination domain")?
        }
        3 => {
            let mut b = [0; 16];
            reader.read_exact(&mut b).await?;
            Ipv6Addr::from(b).to_string()
        }
        _ => bail!("invalid destination address type"),
    };
    ensure!(
        port != 0 && !host.as_bytes().contains(&0),
        "invalid destination"
    );
    Ok(Target { host, port })
}

pub async fn request(reader: &mut Reader, config: &Config) -> Result<Request> {
    ensure!(reader.byte().await? == 0, "unsupported VLESS version");
    let mut uuid = [0; 16];
    reader.read_exact(&mut uuid).await?;
    let user_id = config
        .users
        .iter()
        .find(|id| bool::from(uuid.ct_eq(id.as_bytes())))
        .map(|id| *id.as_bytes())
        .context("invalid VLESS user")?;
    let addons_len = reader.byte().await? as usize;
    let mut addons = vec![0; addons_len];
    reader.read_exact(&mut addons).await?;
    let flow = parse_addons(&addons).context("decode VLESS addons")?;
    let command = reader.byte().await?;
    ensure!((1..=3).contains(&command), "unsupported VLESS command");
    if config.vision {
        ensure!(
            flow == "xtls-rprx-vision",
            "this user must use xtls-rprx-vision flow"
        );
        ensure!(command != 2, "XTLS Vision does not support direct UDP");
    } else {
        ensure!(flow.is_empty(), "VLESS flow is not enabled on this node");
    }
    let target = if command == 3 {
        None
    } else {
        Some(read_target(reader).await?)
    };
    Ok(Request {
        command,
        target,
        user_id,
    })
}

pub fn configure_tcp(socket: &TcpStream, limits: &Limits) -> Result<()> {
    socket.set_nodelay(true)?;
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(limits.keepalive_idle_secs))
        .with_interval(Duration::from_secs(limits.keepalive_interval_secs));
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    let keepalive = keepalive.with_retries(limits.keepalive_retries);
    SockRef::from(socket).set_tcp_keepalive(&keepalive)?;
    Ok(())
}

pub async fn resolve(target: &Target, limits: &Limits) -> Result<Vec<SocketAddr>> {
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        ensure!(
            limits.allow_private_destinations || !crate::destination::private_ip(ip),
            "private destination blocked"
        );
        return Ok(vec![SocketAddr::new(ip, target.port)]);
    }
    ensure!(
        limits.allow_private_destinations || !crate::destination::private_domain(&target.host),
        "private destination domain blocked"
    );
    let addresses = timeout(
        Duration::from_secs(limits.connect_timeout_secs),
        lookup_host((target.host.as_str(), target.port)),
    )
    .await
    .context("DNS lookup timeout")?
    .context("DNS lookup failed")?;
    let mut addresses = addresses.take(64).peekable();
    ensure!(addresses.peek().is_some(), "DNS returned no addresses");
    let addresses: Vec<_> = addresses
        .filter(|a| limits.allow_private_destinations || !crate::destination::private_ip(a.ip()))
        .collect();
    ensure!(
        !addresses.is_empty(),
        "private destination blocked (all DNS results)"
    );
    Ok(addresses)
}

async fn staggered_connect<T>(
    primary: impl Future<Output = io::Result<T>>,
    fallback: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::pin!(primary, fallback);
    tokio::select! {
        biased;
        result = &mut primary => return match result {
            Ok(socket) => Ok(socket),
            Err(_) => fallback.await,
        },
        _ = sleep(Duration::from_millis(250)) => {},
    }
    tokio::select! {
        biased;
        result = &mut primary => match result {
            Ok(socket) => Ok(socket),
            Err(_) => fallback.await,
        },
        result = &mut fallback => match result {
            Ok(socket) => Ok(socket),
            Err(_) => primary.await,
        },
    }
}

pub async fn connect_tcp(target: &Target, limits: &Limits) -> Result<TcpStream> {
    let addresses = resolve(target, limits).await?;
    let prefer_ipv4 = addresses[0].is_ipv4();
    let (primary, fallback): (Vec<_>, Vec<_>) = addresses
        .into_iter()
        .partition(|a| a.is_ipv4() == prefer_ipv4);
    let socket = timeout(Duration::from_secs(limits.connect_timeout_secs), async {
        let connect = TcpStream::connect(primary.as_slice());
        if fallback.is_empty() {
            connect.await
        } else {
            // Preserve DNS order within each family. A slow IPv6 (or IPv4)
            // connect must not consume the whole budget for the other family.
            staggered_connect(connect, TcpStream::connect(fallback.as_slice())).await
        }
    })
    .await
    .context("TCP connect timeout")?
    .context("TCP connect failed")?;
    configure_tcp(&socket, limits).context("configure destination TCP")?;
    Ok(socket)
}

pub struct Activity {
    epoch: Instant,
    last: AtomicU64,
}
impl Activity {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            epoch: Instant::now(),
            last: AtomicU64::new(0),
        })
    }
    pub fn touch(&self) {
        self.last
            .fetch_max(self.epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
    async fn wait_idle_since(&self, duration: Duration, not_before: Instant) {
        loop {
            let last = self.epoch + Duration::from_millis(self.last.load(Ordering::Relaxed));
            let deadline = last.max(not_before) + duration;
            if Instant::now() >= deadline {
                return;
            }
            sleep_until(deadline).await;
        }
    }
    pub async fn idle(&self, seconds: u64) -> Result<()> {
        self.wait_idle_since(Duration::from_secs(seconds), self.epoch)
            .await;
        bail!("application idle timeout ({seconds}s)");
    }
    pub async fn drain_after_eof(
        &self,
        transfer: impl Future<Output = Result<()>>,
        seconds: u64,
        direction: &str,
    ) -> Result<()> {
        // Start a fresh idle window at EOF; forwarding in the remaining
        // direction extends it. Do not truncate a busy transfer after FIN.
        let eof_at = Instant::now();
        tokio::select! {
            biased;
            result = transfer => result,
            () = self.wait_idle_since(Duration::from_secs(seconds), eof_at) => {
                bail!("{direction} half-close idle timeout ({seconds}s without forwarding)")
            }
        }
    }
}

pub async fn tcp(
    mut reader: Reader,
    mut writer: Writer,
    target: Target,
    limits: &Limits,
    activity: Arc<Activity>,
) -> Result<()> {
    let socket = connect_tcp(&target, limits)
        .await
        .with_context(|| format!("connect destination {}:{}", target.host, target.port))?;
    writer
        .write_response_header()
        .await
        .context("write client response header")?;
    let (mut read, mut write) = socket.into_split();
    let up = async {
        let mut buffer = Zeroizing::new(vec![0; RECORD_PAYLOAD]);
        loop {
            let n = reader
                .read_some(&mut buffer)
                .await
                .context("read from client")?;
            if n == 0 {
                write
                    .shutdown()
                    .await
                    .context("half-close destination write")?;
                return Ok::<_, anyhow::Error>(());
            }
            write
                .write_all(&buffer[..n])
                .await
                .context("write to destination")?;
            activity.touch();
        }
    };
    let down = async {
        let mut buffer = Zeroizing::new(vec![0; RECORD_PAYLOAD]);
        loop {
            let n = read
                .read(&mut buffer)
                .await
                .context("read from destination")?;
            if n == 0 {
                writer.shutdown().await.context("half-close client write")?;
                return Ok::<_, anyhow::Error>(());
            }
            writer
                .write_all(&buffer[..n])
                .await
                .context("write to client")?;
            activity.touch();
            // Grow only for sustained bulk traffic; idle and small streams
            // retain the initial 8 KiB buffer. At most four records per write.
            if n == buffer.len() && buffer.len() < 4 * RECORD_PAYLOAD {
                let capacity = buffer.len() * 2;
                buffer.resize(capacity, 0);
            }
        }
    };
    tokio::pin!(up, down);
    let grace = limits.half_close_timeout_secs;
    tokio::select! {
        r = &mut up => { r?; activity.drain_after_eof(&mut down, grace, "downlink").await?; },
        r = &mut down => { r?; activity.drain_after_eof(&mut up, grace, "uplink").await?; },
        r = activity.idle(limits.idle_timeout_secs) => { r?; },
    }
    Ok(())
}

pub async fn udp(
    mut reader: Reader,
    mut writer: Writer,
    target: Target,
    limits: &Limits,
    activity: Arc<Activity>,
) -> Result<()> {
    let address = resolve(&target, limits).await?[0];
    let socket = UdpSocket::bind(if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    socket.connect(address).await?;
    writer.write_response_header().await?;
    let up = async {
        let mut buffer = Zeroizing::new(Vec::new());
        loop {
            let mut first = [0];
            if reader.read_some(&mut first).await? == 0 {
                return Ok::<_, anyhow::Error>(());
            }
            let second = reader.byte().await?;
            let n = u16::from_be_bytes([first[0], second]) as usize;
            ensure!(n <= 65507, "UDP datagram too large");
            buffer.resize(n, 0);
            reader.read_exact(&mut buffer).await?;
            socket.send(&buffer).await?;
            activity.touch();
        }
    };
    let down = async {
        let mut buffer = Zeroizing::new(vec![0; 65536]);
        loop {
            let n = socket.recv(&mut buffer).await?;
            if n == 0 {
                continue;
            }
            writer.write_all(&(n as u16).to_be_bytes()).await?;
            writer.write_all(&buffer[..n]).await?;
            activity.touch();
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! { r = up => r, r = down => r, r = activity.idle(limits.idle_timeout_secs) => r }
}
