// SPDX-License-Identifier: MPL-2.0
// Metadata format follows Xray-core v26.11.9 common/mux/frame.go.
use crate::{
    config::Limits,
    forward::{self, Activity, Target},
    record::{RECORD_PAYLOAD, Reader, Writer},
};
use anyhow::{Context, Result, bail, ensure};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    sync::{Semaphore, mpsc},
    task::{AbortHandle, JoinSet},
    time::timeout,
};
use zeroize::Zeroizing;

struct Upload {
    target: Option<Target>,
    payload: Zeroizing<Vec<u8>>,
}
struct Stream {
    sender: mpsc::Sender<Upload>,
    task: AbortHandle,
    generation: u64,
}

fn reap_stream(streams: &mut HashMap<u16, Stream>, id: u16, generation: u64) {
    if streams
        .get(&id)
        .is_some_and(|stream| stream.generation == generation)
    {
        streams.remove(&id);
    }
}
struct Frame {
    id: u16,
    status: u8,
    options: u8,
    network: Option<u8>,
    target: Option<Target>,
    payload: Zeroizing<Vec<u8>>,
}

fn parse_target(bytes: &[u8]) -> Result<Target> {
    ensure!(bytes.len() >= 3, "short Mux destination");
    let port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let host = match bytes[2] {
        1 => {
            ensure!(bytes.len() >= 7, "short Mux IPv4");
            Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[3..7])?).to_string()
        }
        2 => {
            ensure!(bytes.len() >= 4 && bytes[3] != 0, "short Mux domain");
            let n = bytes[3] as usize;
            ensure!(bytes.len() >= 4 + n, "short Mux domain");
            String::from_utf8(bytes[4..4 + n].to_vec())?
        }
        3 => {
            ensure!(bytes.len() >= 19, "short Mux IPv6");
            Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[3..19])?).to_string()
        }
        _ => bail!("invalid Mux address type"),
    };
    ensure!(
        port != 0 && !host.as_bytes().contains(&0),
        "invalid Mux destination"
    );
    Ok(Target { host, port })
}

async fn frame(reader: &mut Reader) -> Result<Option<Frame>> {
    let mut first = [0];
    if reader.read_some(&mut first).await? == 0 {
        return Ok(None);
    }
    let second = reader.byte().await?;
    let n = u16::from_be_bytes([first[0], second]) as usize;
    ensure!((4..=512).contains(&n), "invalid Mux metadata length");
    let mut meta = vec![0; n];
    reader.read_exact(&mut meta).await?;
    let id = u16::from_be_bytes([meta[0], meta[1]]);
    let status = meta[2];
    let options = meta[3];
    ensure!(
        (1..=4).contains(&status) && options & !3 == 0,
        "invalid Mux status/options"
    );
    let (network, target) = if status == 1 || (status == 2 && n > 4 && meta[4] == 2) {
        ensure!(
            n >= 8 && (meta[4] == 1 || meta[4] == 2),
            "invalid Mux network"
        );
        (Some(meta[4]), Some(parse_target(&meta[5..])?))
    } else {
        (None, None)
    };
    let mut payload = Zeroizing::new(Vec::new());
    if options & 1 != 0 {
        let size = reader.u16().await? as usize;
        payload.resize(size, 0);
        reader.read_exact(&mut payload).await?;
    }
    Ok(Some(Frame {
        id,
        status,
        options,
        network,
        target,
        payload,
    }))
}

fn end(id: u16, error: bool) -> Vec<u8> {
    vec![
        0,
        4,
        (id >> 8) as u8,
        id as u8,
        3,
        if error { 2 } else { 0 },
    ]
}

fn response(id: u16, payload: &[u8], source: Option<SocketAddr>) -> Vec<u8> {
    let mut meta = vec![(id >> 8) as u8, id as u8, 2, 1];
    if let Some(source) = source {
        meta.push(2);
        meta.extend_from_slice(&source.port().to_be_bytes());
        match source.ip() {
            IpAddr::V4(ip) => {
                meta.push(1);
                meta.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                if let Some(ip) = ip.to_ipv4_mapped() {
                    meta.push(1);
                    meta.extend_from_slice(&ip.octets());
                } else {
                    meta.push(3);
                    meta.extend_from_slice(&ip.octets());
                }
            }
        }
    }
    let mut out = Vec::with_capacity(meta.len() + payload.len() + 4);
    out.extend_from_slice(&(meta.len() as u16).to_be_bytes());
    out.extend_from_slice(&meta);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

async fn tcp_stream(
    id: u16,
    target: Target,
    mut incoming: mpsc::Receiver<Upload>,
    output: mpsc::Sender<Zeroizing<Vec<u8>>>,
    limits: Limits,
    activity: Arc<Activity>,
) -> Result<()> {
    let socket = forward::connect_tcp(&target, &limits).await?;
    let (mut read, mut write) = socket.into_split();
    let up = async {
        while let Some(data) = incoming.recv().await {
            write.write_all(&data.payload).await?;
            activity.touch();
        }
        write.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };
    let down = async {
        let mut buffer = Zeroizing::new(vec![0; RECORD_PAYLOAD]);
        loop {
            let n = read.read(&mut buffer).await?;
            if n == 0 {
                return Ok::<_, anyhow::Error>(());
            }
            output
                .send(Zeroizing::new(response(id, &buffer[..n], None)))
                .await?;
            activity.touch();
        }
    };
    tokio::pin!(up, down);
    tokio::select! {
        r = &mut up => { r?; timeout(Duration::from_secs(limits.half_close_timeout_secs), &mut down).await.context("Mux half-close timeout")??; },
        r = &mut down => { r?; },
    }
    Ok(())
}

async fn udp_stream(
    id: u16,
    default: Target,
    mut incoming: mpsc::Receiver<Upload>,
    output: mpsc::Sender<Zeroizing<Vec<u8>>>,
    limits: Limits,
    activity: Arc<Activity>,
) -> Result<()> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(false)?;
    socket.set_nonblocking(true)?;
    socket.bind(&"[::]:0".parse::<SocketAddr>()?.into())?;
    let socket = UdpSocket::from_std(socket.into())?;
    let allowed = Arc::new(tokio::sync::RwLock::new(HashSet::new()));
    let up = async {
        while let Some(data) = incoming.recv().await {
            ensure!(data.payload.len() <= 65507, "Mux UDP datagram too large");
            let target = data.target.as_ref().unwrap_or(&default);
            let address = forward::resolve(target, &limits).await?[0];
            let address = match address {
                SocketAddr::V4(a) => SocketAddr::new(IpAddr::V6(a.ip().to_ipv6_mapped()), a.port()),
                a => a,
            };
            {
                let mut peers = allowed.write().await;
                ensure!(
                    peers.len() < 64 || peers.contains(&address),
                    "XUDP peer limit reached"
                );
                peers.insert(address);
            }
            socket.send_to(&data.payload, address).await?;
            activity.touch();
        }
        Ok::<_, anyhow::Error>(())
    };
    let down = async {
        let mut buffer = Zeroizing::new(vec![0; 65536]);
        loop {
            let (n, source) = socket.recv_from(&mut buffer).await?;
            if n == 0 || !allowed.read().await.contains(&source) {
                continue;
            }
            output
                .send(Zeroizing::new(response(id, &buffer[..n], Some(source))))
                .await?;
            activity.touch();
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! { r = up => r, r = down => r }
}

pub async fn serve(
    mut reader: Reader,
    mut writer: Writer,
    limits: &Limits,
    activity: Arc<Activity>,
    budget: Arc<Semaphore>,
) -> Result<()> {
    writer.write_all(&[0, 0]).await?;
    let (out, mut outgoing) = mpsc::channel::<Zeroizing<Vec<u8>>>(2);
    let mut tasks = JoinSet::new();
    let mut streams: HashMap<u16, Stream> = HashMap::new();
    let mut generation = 0u64;
    // Read full frames in an owned task. Cancelling read_exact when another
    // stream finishes would lose partially consumed metadata and corrupt Mux.
    let (frames_sender, mut frames) = mpsc::channel(2);
    let mut frame_tasks = JoinSet::new();
    frame_tasks.spawn(async move {
        loop {
            let next = frame(&mut reader).await;
            let finished = !matches!(&next, Ok(Some(_)));
            if frames_sender.send(next).await.is_err() || finished {
                break;
            }
        }
    });
    let write = async {
        while let Some(packet) = outgoing.recv().await {
            writer.write_all(&packet).await?;
            activity.touch();
        }
        Ok::<_, anyhow::Error>(())
    };
    let read = async {
        loop {
            tokio::select! {
                done = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Ok((id, version))) = done { reap_stream(&mut streams, id, version); }
                },
                next = frames.recv() => {
                    let Some(next) = next else { return Ok::<_, anyhow::Error>(()); };
                    let Some(f) = next? else { return Ok::<_, anyhow::Error>(()); };
                    activity.touch();
                    match f.status {
                        1 => {
                            ensure!(!streams.contains_key(&f.id), "duplicate Mux stream id");
                            let permit = if streams.len() < limits.max_mux_streams { budget.clone().try_acquire_owned().ok() } else { None };
                            if permit.is_none() { out.send(Zeroizing::new(end(f.id, true))).await?; continue; }
                            let (sender, receiver) = mpsc::channel(2);
                            let target = f.target.context("missing Mux destination")?;
                            let output = out.clone(); let settings = limits.clone(); let activity = activity.clone();
                            let id = f.id; let network = f.network;
                            generation = generation.wrapping_add(1);
                            let version = generation;
                            let task = tasks.spawn(async move {
                                let _permit = permit;
                                let result = if network == Some(1) { tcp_stream(id, target, receiver, output.clone(), settings, activity).await }
                                else { udp_stream(id, target, receiver, output.clone(), settings, activity).await };
                                if let Err(e) = &result { eprintln!("mux_stream={id} error={e:#}"); }
                                let _ = output.send(Zeroizing::new(end(id, result.is_err()))).await;
                                (id, version)
                            });
                            if f.options & 1 != 0 { sender.send(Upload { target: None, payload: f.payload }).await?; }
                            streams.insert(f.id, Stream { sender, task, generation: version });
                        },
                        2 => {
                            if let Some(stream) = streams.get(&f.id) {
                                if f.options & 1 != 0 && stream.sender.send(Upload { target: f.target, payload: f.payload }).await.is_err() {
                                    out.send(Zeroizing::new(end(f.id, true))).await?;
                                }
                            } else { out.send(Zeroizing::new(end(f.id, false))).await?; }
                        },
                        3 => { if let Some(stream) = streams.remove(&f.id) { stream.task.abort(); } },
                        4 => {},
                        _ => unreachable!(),
                    }
                }
            }
        }
    };
    tokio::select! { r = read => r, r = write => r, r = activity.idle(limits.idle_timeout_secs) => r }
    // Dropping JoinSet aborts all stream tasks and releases global permits.
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn old_completion_does_not_remove_reused_session_id() {
        let mut tasks = JoinSet::<()>::new();
        let task = tasks.spawn(std::future::pending());
        let (sender, _) = mpsc::channel(1);
        let mut streams = HashMap::new();
        streams.insert(
            17,
            Stream {
                sender,
                task,
                generation: 2,
            },
        );
        reap_stream(&mut streams, 17, 1);
        assert!(streams.contains_key(&17));
        reap_stream(&mut streams, 17, 2);
        assert!(!streams.contains_key(&17));
    }
}
