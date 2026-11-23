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
mod reality;
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
    fs::{self, OpenOptions},
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

fn public_key(private: &[u8]) -> Result<Vec<u8>> {
    if private.len() == 32 {
        let secret = StaticSecret::from(<[u8; 32]>::try_from(private)?);
        Ok(PublicKey::from(&secret).as_bytes().to_vec())
    } else {
        Ok(
            ml_kem::DecapsulationKey::<MlKem768>::new_from_slice(private)?
                .encapsulation_key()
                .to_bytes()
                .to_vec(),
        )
    }
}

fn subscription(config: &Config, host: &str) -> Result<String> {
    ensure!(
        !host.is_empty()
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c)),
        "invalid subscription host"
    );
    let parsed = EncryptionConfig::parse(&config.decryption)?;
    let appearance = match parsed.appearance {
        config::Appearance::Native => "native",
        config::Appearance::XorPub => "xorpub",
        config::Appearance::Random => "random",
    };
    let mut encryption = format!(
        "mlkem768x25519plus.{appearance}.{}",
        if parsed.lifetime == 0 { "1rtt" } else { "0rtt" }
    );
    for key in &parsed.keys {
        encryption.push('.');
        encryption.push_str(&URL_SAFE_NO_PAD.encode(public_key(key)?));
    }
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let uuid = config.users.first().context("missing user UUID")?;
    let security = if let Some(reality) = &config.reality {
        format!(
            "reality&sni={}&fp=chrome&pbk={}&sid={}&spx=%2F",
            reality.server_name,
            reality.public_key()?,
            reality.short_id
        )
    } else {
        "none".to_owned()
    };
    Ok(format!(
        "vless://{uuid}@{host}:{}?encryption={encryption}&security={security}&type=tcp#VLESS-Rust-{}",
        config.listen.port(),
        config.listen.port()
    ))
}

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
    let public = public_key(&private)?;
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

fn replace_config(path: &Path, config: &Config) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("inspect configuration")?;
    ensure!(
        metadata.file_type().is_file(),
        "configuration must be a regular file"
    );
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut file = options
            .open(&temporary)
            .context("create replacement configuration")?;
        let bytes = Zeroizing::new(serde_json::to_vec_pretty(config)?);
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path).context("commit replacement configuration")?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn import_xray_config(
    input: &Path,
    output: &Path,
    listen_host: std::net::IpAddr,
    port: Option<u16>,
) -> Result<()> {
    let source = Zeroizing::new(fs::read(input).context("read existing Xray configuration")?);
    ensure!(
        source.len() <= 1024 * 1024,
        "Xray configuration exceeds 1 MiB"
    );
    let value: serde_json::Value = serde_json::from_slice(&source)?;
    ensure!(value.is_object(), "Xray configuration must be an object");
    let root = value.as_object().context("invalid Xray configuration")?;
    ensure!(
        root.keys()
            .all(|k| ["log", "inbounds", "outbounds"].contains(&k.as_str())),
        "routing, DNS, policy, and other root settings need manual migration"
    );

    let inbounds = root
        .get("inbounds")
        .and_then(serde_json::Value::as_array)
        .context("missing Xray inbounds")?;
    ensure!(
        inbounds.len() == 1,
        "migration requires exactly one Xray inbound"
    );
    let inbound = inbounds[0].as_object().context("invalid Xray inbound")?;
    ensure!(
        inbound.keys().all(|k| [
            "listen",
            "port",
            "protocol",
            "settings",
            "streamSettings",
            "tag"
        ]
        .contains(&k.as_str())),
        "Xray inbound has unsupported extensions"
    );
    ensure!(
        inbound.get("protocol").and_then(serde_json::Value::as_str) == Some("vless"),
        "only a VLESS inbound can be migrated"
    );
    let original_port = inbound
        .get("port")
        .and_then(serde_json::Value::as_u64)
        .context("invalid Xray inbound port")?;
    ensure!(
        (1..=65535).contains(&original_port),
        "invalid Xray inbound port"
    );

    let stream = inbound
        .get("streamSettings")
        .and_then(serde_json::Value::as_object)
        .context("missing Xray stream settings")?;
    ensure!(
        stream
            .keys()
            .all(|k| ["security", "method", "network"].contains(&k.as_str())),
        "custom Xray transport settings cannot be migrated"
    );
    ensure!(
        stream
            .get("security")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("none")
            == "none",
        "Xray REALITY/TLS cannot be migrated to the plain Rust core"
    );
    ensure!(
        matches!(
            stream
                .get("method")
                .or_else(|| stream.get("network"))
                .and_then(serde_json::Value::as_str),
            None | Some("raw") | Some("tcp")
        ),
        "only raw TCP transport can be migrated"
    );

    let settings = inbound
        .get("settings")
        .and_then(serde_json::Value::as_object)
        .context("missing Xray VLESS settings")?;
    ensure!(
        settings
            .keys()
            .all(|k| ["users", "clients", "decryption", "flow"].contains(&k.as_str())),
        "Xray VLESS settings have unsupported extensions"
    );
    ensure!(
        settings
            .get("flow")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .is_empty(),
        "Vision flow cannot be migrated to the plain Rust core"
    );
    let users = settings
        .get("clients")
        .or_else(|| settings.get("users"))
        .and_then(serde_json::Value::as_array)
        .context("missing Xray VLESS users")?;
    ensure!(
        !users.is_empty() && users.len() <= 4096,
        "Xray user count must be 1..4096"
    );
    let mut migrated_users = Vec::with_capacity(users.len());
    for user in users {
        let user = user.as_object().context("invalid Xray VLESS user")?;
        ensure!(
            user.keys()
                .all(|k| ["id", "flow", "email", "level"].contains(&k.as_str())),
            "Xray VLESS user has unsupported extensions"
        );
        ensure!(
            user.get("flow")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .is_empty(),
            "Vision flow cannot be migrated to the plain Rust core"
        );
        ensure!(
            user.get("level")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
                == 0,
            "nonzero Xray user levels require routing migration"
        );
        migrated_users.push(
            user.get("id")
                .and_then(serde_json::Value::as_str)
                .context("missing Xray user UUID")?
                .parse::<Uuid>()
                .context("invalid Xray user UUID")?,
        );
    }

    let outbounds = root
        .get("outbounds")
        .and_then(serde_json::Value::as_array)
        .context("missing Xray outbounds")?;
    ensure!(
        outbounds.len() == 1,
        "migration requires a single direct freedom outbound"
    );
    let outbound = outbounds[0].as_object().context("invalid Xray outbound")?;
    ensure!(
        outbound
            .keys()
            .all(|k| ["protocol", "settings", "streamSettings", "tag"].contains(&k.as_str())),
        "Xray outbound has unsupported extensions"
    );
    ensure!(
        outbound.get("protocol").and_then(serde_json::Value::as_str) == Some("freedom"),
        "only a direct freedom outbound can be migrated"
    );
    let outbound_settings = outbound.get("settings");
    ensure!(
        outbound_settings.is_none()
            || outbound_settings
                .and_then(serde_json::Value::as_object)
                .is_some_and(|settings| settings.is_empty()),
        "custom freedom settings cannot be migrated"
    );
    let outbound_stream = outbound
        .get("streamSettings")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    ensure!(
        outbound_stream == serde_json::json!({})
            || outbound_stream == serde_json::json!({"sockopt":{"domainStrategy":"UseIPv4v6"}}),
        "custom freedom socket settings cannot be migrated"
    );

    let original_decryption = settings
        .get("decryption")
        .and_then(serde_json::Value::as_str)
        .context("missing Xray VLESS decryption key")?;
    EncryptionConfig::parse(original_decryption)
        .context("Xray VLESS decryption is not supported by the Rust core")?;
    let config = Config {
        listen: SocketAddr::new(listen_host, port.unwrap_or(original_port as u16)),
        users: migrated_users,
        decryption: original_decryption.to_owned(),
        reality: None,
        limits: Limits::default(),
        log_connections: false,
    };
    config.validate()?;
    write_new_config(output, &config)
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
    let reality = config
        .reality
        .clone()
        .map(|c| reality::Server::new(c, config.limits.max_sessions))
        .transpose()?
        .map(Arc::new);
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
                let server = server.clone(); let config = config.clone(); let reality = reality.clone(); let handshakes = handshakes.clone(); let outbounds = outbounds.clone();
                let errors = errors.clone(); let resumes = resumes.clone();
                let id = total.fetch_add(1, Ordering::Relaxed) + 1;
                tasks.spawn(async move {
                    let _client = client_permit;
                    let result: Result<()> = async {
                        forward::configure_tcp(&socket, &config.limits).context("configure inbound TCP")?;
                        let request = timeout(Duration::from_secs(config.limits.handshake_timeout_secs), async {
                            let permit = handshakes.acquire_owned().await?;
                            let (mut reader, writer, resumed) = if let Some(reality) = reality {
                                let Some(socket) = reality.accept(socket).await? else { return Ok(None); };
                                if config.log_connections {
                                    eprintln!("connection={id} reality_tls_group={:?}", socket.get_ref().1.negotiated_key_exchange_group().map(|g| g.name()));
                                }
                                server.handshake(socket).await.context("encryption handshake")?
                            } else {
                                server.handshake(socket).await.context("encryption handshake")?
                            };
                            let req = forward::request(&mut reader, &config).await.context("VLESS request")?;
                            drop(permit);
                            Ok::<_, anyhow::Error>(Some(((reader, writer, resumed), req)))
                        }).await.context("handshake timeout")??;
                        let Some(((reader, writer, resumed), req)) = request else { return Ok(()); };
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
            "vless-rust {} (reference {REFERENCE})\n\nCommands:\n  init --config FILE --host HOST [--listen-host IP] [--port PORT] [--uuid UUID] [--auth x25519|mlkem768] [--mode native|xorpub|random] [--reality --server-name DOMAIN [--target HOST:PORT]]\n  configure --config FILE --host HOST [--listen-host IP] [--port PORT] [--uuid UUID] [--rekey] [--auth x25519|mlkem768] [--mode native|xorpub|random]\n  link --config FILE --host HOST\n  keygen [--auth x25519|mlkem768] [--mode native|xorpub|random]\n  check --config FILE\n  run --config FILE\n  version\n  capabilities\n\nSupports VLESS Encryption, TCP/UDP and XUDP, and experimental REALITY over TLS 1.3. Vision, ML-DSA-65 and live-target handshake camouflage are not supported.\nConfiguration contains private keys: keep it private.",
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
    if command == "capabilities" {
        ensure!(args.len() == 1, "unexpected capabilities arguments");
        println!("vless-encryption reality-experimental");
        return Ok(());
    }
    let mut path = None;
    let mut input = None;
    let mut host = None;
    let mut port = None;
    let mut listen_host = None;
    let mut uuid = None;
    let mut auth = None;
    let mut mode = None;
    let mut rekey = false;
    let mut use_reality = false;
    let mut server_name = None;
    let mut target = None;
    let mut i = 1;
    while i < args.len() {
        let option = args[i].as_str();
        if command == "configure" && option == "--rekey" {
            rekey = true;
            i += 1;
            continue;
        }
        if command == "init" && option == "--reality" {
            use_reality = true;
            i += 1;
            continue;
        }
        let value = args.get(i + 1).context("missing option value")?;
        match (command, option) {
            ("run" | "check" | "init" | "configure" | "link", "--config" | "-config") => {
                path = Some(value)
            }
            ("init" | "configure" | "link", "--host") => host = Some(value),
            ("init" | "configure", "--listen-host") => {
                listen_host = Some(
                    value
                        .parse::<std::net::IpAddr>()
                        .context("invalid listen IP")?,
                )
            }
            ("init" | "configure", "--port") => {
                port = Some(value.parse::<u16>().context("invalid port")?)
            }
            ("init" | "configure", "--uuid") => {
                uuid = Some(value.parse::<Uuid>().context("invalid UUID")?)
            }
            ("import-xray", "--input") => input = Some(value),
            ("import-xray", "--output") => path = Some(value),
            ("import-xray", "--listen-host") => {
                listen_host = Some(
                    value
                        .parse::<std::net::IpAddr>()
                        .context("invalid listen IP")?,
                )
            }
            ("import-xray", "--port") => port = Some(value.parse::<u16>().context("invalid port")?),
            ("init", "--server-name") => server_name = Some(value.clone()),
            ("init", "--target") => target = Some(value.clone()),
            ("keygen" | "init" | "configure", "--auth") => auth = Some(value.as_str()),
            ("keygen" | "init" | "configure", "--mode") => mode = Some(value.as_str()),
            _ => bail!("unknown command or option: {command} {option}"),
        }
        i += 2;
    }
    match command {
        "keygen" => {
            let (decryption, encryption) =
                keypair(auth.unwrap_or("x25519"), mode.unwrap_or("native"))?;
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
            let (decryption, _) = keypair(auth.unwrap_or("x25519"), mode.unwrap_or("native"))?;
            let uuid = uuid.unwrap_or_else(Uuid::new_v4);
            let config = Config {
                listen: SocketAddr::new(listen_host.unwrap_or("::".parse()?), port.unwrap_or(443)),
                users: vec![uuid],
                decryption,
                reality: if use_reality {
                    let name = server_name.context("--server-name required with --reality")?;
                    Some(reality::RealityConfig::generate(
                        name.clone(),
                        target.unwrap_or_else(|| format!("{name}:443")),
                    )?)
                } else {
                    ensure!(
                        server_name.is_none() && target.is_none(),
                        "--server-name/--target require --reality"
                    );
                    None
                },
                limits: Limits::default(),
                log_connections: false,
            };
            config.validate()?;
            let link = subscription(&config, host)?;
            write_new_config(path, &config)?;
            println!("{link}");
        }
        "link" => {
            let config = Config::load(Path::new(path.context("--config required")?))?;
            println!(
                "{}",
                subscription(&config, host.context("--host required")?)?
            );
        }
        "configure" => {
            let path = Path::new(path.context("--config required")?);
            let mut config = Config::load(path)?;
            let old = EncryptionConfig::parse(&config.decryption)?;
            let old_auth = if old.keys.first().context("missing auth key")?.len() == 32 {
                "x25519"
            } else {
                "mlkem768"
            };
            let old_mode = match old.appearance {
                config::Appearance::Native => "native",
                config::Appearance::XorPub => "xorpub",
                config::Appearance::Random => "random",
            };
            let new_auth = auth.unwrap_or(old_auth);
            let new_mode = mode.unwrap_or(old_mode);
            ensure!(
                rekey || (new_auth == old_auth && new_mode == old_mode),
                "changing auth or mode requires --rekey"
            );
            if rekey {
                config.decryption = keypair(new_auth, new_mode)?.0;
            }
            config.listen = SocketAddr::new(
                listen_host.unwrap_or(config.listen.ip()),
                port.unwrap_or(config.listen.port()),
            );
            if let Some(uuid) = uuid {
                *config.users.first_mut().context("missing user UUID")? = uuid;
            }
            config.validate()?;
            let link = subscription(&config, host.context("--host required")?)?;
            replace_config(path, &config)?;
            println!("{link}");
        }
        "import-xray" => {
            import_xray_config(
                Path::new(input.context("--input required")?),
                Path::new(path.context("--output required")?),
                listen_host.unwrap_or("::".parse()?),
                port,
            )?;
            println!("Xray configuration imported");
        }
        "run" | "check" => {
            let path = Path::new(path.context("--config required")?);
            let config = Config::load(path)?;
            if command == "check" {
                if let Some(reality) = config.reality.clone() {
                    reality::Server::new(reality, config.limits.max_sessions)?;
                }
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
