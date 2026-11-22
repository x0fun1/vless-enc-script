#![forbid(unsafe_code)]
#[allow(
    dead_code,
    clippy::chunks_exact_to_as_chunks,
    clippy::explicit_counter_loop
)]
mod blake3_reference;
mod config;
mod crypto;
mod destination;
mod forward;
mod handshake;
mod mux;
mod record;

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use config::{Config, EncryptionConfig, Limits};
use ml_kem::{
    MlKem768,
    kem::{KeyExport, KeyInit},
};
use rand::{RngCore, rngs::OsRng};
use std::{
    env,
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet, time::timeout};
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const REFERENCE: &str = "Xray-core v26.11.9";

fn keypair(auth: &str, appearance: &str) -> Result<(String, String)> {
    ensure!(
        ["native", "xorpub", "random"].contains(&appearance),
        "invalid appearance"
    );
    let mut private = Zeroizing::new(vec![
        0;
        match auth {
            "x25519" => 32,
            "mlkem768" => 64,
            _ => bail!("invalid authentication mode"),
        }
    ]);
    OsRng.fill_bytes(&mut private);
    let public = if private.len() == 32 {
        let secret = StaticSecret::from(<[u8; 32]>::try_from(private.as_slice())?);
        PublicKey::from(&secret).as_bytes().to_vec()
    } else {
        ml_kem::DecapsulationKey::<MlKem768>::new_from_slice(&private)?
            .encapsulation_key()
            .to_bytes()
            .to_vec()
    };
    Ok((
        format!(
            "mlkem768x25519plus.{appearance}.600s.{}",
            URL_SAFE_NO_PAD.encode(&private)
        ),
        format!(
            "mlkem768x25519plus.{appearance}.0rtt.{}",
            URL_SAFE_NO_PAD.encode(public)
        ),
    ))
}

fn write_new_config(path: &Path, config: &Config) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("create configuration (destination must not exist)")?;
    let bytes = Zeroizing::new(serde_json::to_vec_pretty(config)?);
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! { r = tokio::signal::ctrl_c() => r?, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn serve(config: Config) -> Result<()> {
    let server = Arc::new(handshake::Server::new(
        EncryptionConfig::parse(&config.decryption)?,
        config.limits.clone(),
    )?);
    let listener_socket = socket2::Socket::new(
        socket2::Domain::for_address(config.listen),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    if config.listen.is_ipv6() {
        listener_socket.set_only_v6(false)?;
    }
    #[cfg(unix)]
    listener_socket.set_reuse_address(true)?;
    listener_socket.set_nonblocking(true)?;
    listener_socket.bind(&config.listen.into())?;
    listener_socket.listen(256)?;
    let listener = TcpListener::from_std(listener_socket.into())?;
    eprintln!(
        "vless-rust {} reference={} listen={} keepalive={}s/{}s idle={}s",
        env!("CARGO_PKG_VERSION"),
        REFERENCE,
        config.listen,
        config.limits.keepalive_idle_secs,
        config.limits.keepalive_interval_secs,
        config.limits.idle_timeout_secs
    );
    let clients = Arc::new(Semaphore::new(config.limits.max_connections));
    let handshakes = Arc::new(Semaphore::new(config.limits.max_handshakes));
    let outbounds = Arc::new(Semaphore::new(config.limits.max_connections));
    let config = Arc::new(config);
    let mut tasks = JoinSet::new();
    let mut maintenance = tokio::time::interval(Duration::from_secs(30));
    maintenance.tick().await;
    let total = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let resumes = Arc::new(AtomicU64::new(0));
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            r = &mut shutdown => { r?; break; },
            _ = maintenance.tick() => {
                server.prune();
                eprintln!("stats active={} accepted={} errors={} resumed={}", config.limits.max_connections - clients.available_permits(), total.load(Ordering::Relaxed), errors.load(Ordering::Relaxed), resumes.load(Ordering::Relaxed));
            },
            r = tasks.join_next(), if !tasks.is_empty() => { if let Some(Err(error)) = r { eprintln!("connection task failed: {error}"); } },
            result = listener.accept() => {
                let (socket, peer) = match result { Ok(pair) => pair, Err(e) => { eprintln!("accept error: {e}"); tokio::time::sleep(Duration::from_millis(100)).await; continue; } };
                let Ok(client_permit) = clients.clone().try_acquire_owned() else { drop(socket); continue; };
                let server = server.clone(); let config = config.clone(); let handshakes = handshakes.clone(); let outbounds = outbounds.clone();
                let errors = errors.clone(); let resumes = resumes.clone();
                let id = total.fetch_add(1, Ordering::Relaxed) + 1;
                tasks.spawn(async move {
                    let _client = client_permit;
                    let result: Result<()> = async {
                        forward::configure_tcp(&socket, &config.limits).context("configure inbound TCP")?;
                        let ((reader, writer, resumed), req) = timeout(Duration::from_secs(config.limits.handshake_timeout_secs), async {
                            let permit = handshakes.acquire_owned().await?;
                            let (mut reader, writer, resumed) = server.handshake(socket).await.context("encryption handshake")?;
                            let req = forward::request(&mut reader, &config).await.context("VLESS request")?;
                            drop(permit);
                            Ok::<_, anyhow::Error>(((reader, writer, resumed), req))
                        }).await.context("handshake timeout")??;
                        if resumed { resumes.fetch_add(1, Ordering::Relaxed); }
                        if config.log_connections { eprintln!("connection={id} peer={peer} handshake={} cipher={:?}", if resumed { "0rtt" } else { "1rtt" }, reader.algorithm()); }
                        let activity = forward::Activity::new();
                        if req.command == 3 {
                            mux::serve(reader, writer, &config.limits, activity, outbounds).await
                        } else {
                            let _outbound = outbounds.try_acquire_owned().context("outbound connection limit")?;
                            let target = req.target.context("missing destination")?;
                            if req.command == 1 { forward::tcp(reader, writer, target, &config.limits, activity).await }
                            else { forward::udp(reader, writer, target, &config.limits, activity).await }
                        }
                    }.await;
                    if let Err(error) = result { errors.fetch_add(1, Ordering::Relaxed); eprintln!("connection={id} peer={peer} error={error:#}"); }
                });
            }
        }
    }
    drop(listener);
    eprintln!("shutdown: draining active connections for 30 seconds");
    if timeout(Duration::from_secs(30), async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");
    if ["help", "--help", "-h"].contains(&command) {
        println!(
            "vless-rust {} (reference {REFERENCE})\n\nCommands:\n  init --config FILE --host HOST [--port PORT] [--auth x25519|mlkem768] [--mode native|xorpub|random]\n  keygen [--auth x25519|mlkem768] [--mode native|xorpub|random]\n  check --config FILE\n  run --config FILE\n  version\n\nSupports plain VLESS Encryption, TCP/UDP and XUDP. REALITY and Vision are not supported.\nConfiguration contains private keys: keep it private.",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    if command == "version" {
        ensure!(args.len() == 1, "unexpected version arguments");
        println!(
            "vless-rust {} reference {REFERENCE}",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    let mut path = None;
    let mut host = None;
    let mut port = 443u16;
    let mut auth = "x25519";
    let mut mode = "native";
    let mut i = 1;
    while i < args.len() {
        let option = args[i].as_str();
        let value = args.get(i + 1).context("missing option value")?;
        match (command, option) {
            ("run" | "check" | "init", "--config" | "-config") => path = Some(value),
            ("init", "--host") => host = Some(value),
            ("init", "--port") => port = value.parse().context("invalid port")?,
            ("keygen" | "init", "--auth") => auth = value,
            ("keygen" | "init", "--mode") => mode = value,
            _ => bail!("unknown command or option: {command} {option}"),
        }
        i += 2;
    }
    match command {
        "keygen" => {
            let (decryption, encryption) = keypair(auth, mode)?;
            println!(
                "{}",
                serde_json::json!({"decryption": decryption, "encryption": encryption})
            );
        }
        "init" => {
            let path = Path::new(path.context("--config required")?);
            let host = host.context("--host required")?;
            ensure!(
                !host.is_empty()
                    && host
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c)),
                "invalid subscription host"
            );
            let (decryption, encryption) = keypair(auth, mode)?;
            let uuid = Uuid::new_v4();
            let config = Config {
                listen: SocketAddr::new("::".parse()?, port),
                users: vec![uuid],
                decryption,
                limits: Limits::default(),
                log_connections: false,
            };
            config.validate()?;
            write_new_config(path, &config)?;
            let host = if host.contains(':') && !host.starts_with('[') {
                format!("[{host}]")
            } else {
                host.to_owned()
            };
            println!(
                "vless://{uuid}@{host}:{port}?encryption={encryption}&security=none&type=tcp#VLESS-Rust"
            );
        }
        "run" | "check" => {
            let path = Path::new(path.context("--config required")?);
            let config = Config::load(path)?;
            if command == "check" {
                handshake::Server::new(
                    EncryptionConfig::parse(&config.decryption)?,
                    config.limits,
                )?;
                println!("configuration valid");
            } else {
                let workers = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1)
                    .min(4);
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(workers)
                    .enable_all()
                    .build()?
                    .block_on(serve(config))?;
            }
        }
        _ => bail!("unknown command {command}"),
    }
    Ok(())
}
