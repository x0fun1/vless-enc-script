use crate::{
    config::{Config, Limits},
    record::{RECORD_PAYLOAD, Reader, Writer},
};
use anyhow::{Context, Result, bail, ensure};
use socket2::{SockRef, TcpKeepalive};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket, lookup_host},
    time::{sleep, timeout},
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
    ensure!(
        config
            .users
            .iter()
            .any(|id| bool::from(uuid.ct_eq(id.as_bytes()))),
        "invalid VLESS user"
    );
    let addons = reader.byte().await? as usize;
    // This release handles plain Encryption. Reject Vision addons explicitly.
    ensure!(
        addons == 0,
        "Vision/addons are not supported by the plain Rust core"
    );
    let command = reader.byte().await?;
    ensure!((1..=3).contains(&command), "unsupported VLESS command");
    let target = if command == 3 {
        None
    } else {
        Some(read_target(reader).await?)
    };
    Ok(Request { command, target })
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
    .context("DNS timeout")??;
    let addresses: Vec<_> = addresses
        .take(64)
        .filter(|a| limits.allow_private_destinations || !crate::destination::private_ip(a.ip()))
        .collect();
    ensure!(!addresses.is_empty(), "DNS returned no addresses");
    Ok(addresses)
}

pub async fn connect_tcp(target: &Target, limits: &Limits) -> Result<TcpStream> {
    let addresses = resolve(target, limits).await?;
    let socket = timeout(
        Duration::from_secs(limits.connect_timeout_secs),
        TcpStream::connect(addresses.as_slice()),
    )
    .await
    .context("TCP connect timeout")??;
    configure_tcp(&socket, limits)?;
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
            .store(self.epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
    pub async fn idle(&self, seconds: u64) -> Result<()> {
        let duration = Duration::from_secs(seconds);
        loop {
            let last = Duration::from_millis(self.last.load(Ordering::Relaxed));
            let elapsed = self.epoch.elapsed().saturating_sub(last);
            if elapsed >= duration {
                bail!("application idle timeout ({seconds}s)");
            }
            sleep(duration - elapsed).await;
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
        .context("connect destination")?;
    writer.write_all(&[0, 0]).await?;
    let (mut read, mut write) = socket.into_split();
    let up = async {
        let mut buffer = Zeroizing::new(vec![0; RECORD_PAYLOAD]);
        loop {
            let n = reader.read_some(&mut buffer).await?;
            if n == 0 {
                write.shutdown().await?;
                return Ok::<_, anyhow::Error>(());
            }
            write.write_all(&buffer[..n]).await?;
            activity.touch();
        }
    };
    let down = async {
        let mut buffer = Zeroizing::new(vec![0; RECORD_PAYLOAD]);
        loop {
            let n = read.read(&mut buffer).await?;
            if n == 0 {
                writer.shutdown().await?;
                return Ok::<_, anyhow::Error>(());
            }
            writer.write_all(&buffer[..n]).await?;
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
    let grace = Duration::from_secs(limits.half_close_timeout_secs);
    tokio::select! {
        r = &mut up => { r?; timeout(grace, &mut down).await.context("downlink half-close timeout")??; },
        r = &mut down => { r?; timeout(grace, &mut up).await.context("uplink half-close timeout")??; },
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
    writer.write_all(&[0, 0]).await?;
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
