# 独立 VLESS Encryption Rust 核心

版本 **0.2.0**。协议参照固定的 **Xray-core v26.11.9**，编译工具链固定为 **Rust 1.100.0**，依赖通过 `Cargo.lock` 锁定。进程自身完成加密握手、记录层和转发，不启动或嵌入 Go Xray。

当前是经过本机互通验证的首版，尚未经过独立安全审计或 Linux 长时间运行验证。Linux systemd 安装脚本已提供，生产环境应先使用独立端口试运行。实际性能记录见 [VALIDATION.md](VALIDATION.md)。

## 已支持的范围

- 普通 VLESS Encryption：`mlkem768x25519plus` 混合密钥交换。
- X25519 / ML-KEM-768 认证，支持最多 8 层混合认证中继。
- `native`、`xorpub`、`random` 外观；AES-256-GCM、ChaCha20-Poly1305。
- 1-RTT、带防重放缓存的 0-RTT 会话恢复、nonce 溢出换钥。
- TCP、普通 UDP、Mux TCP 和 XUDP 转发；IPv4、IPv6、域名目标。
- 入站与出站 TCP keepalive、握手 / 连接 / 空闲超时、TCP 半关闭宽限期。
- 有上限的连接、握手、Mux 子流、会话和防重放缓存；可复用的数据缓冲区。

- 实验性 Reality + VLESS Encryption：TLS 1.3、X25519 / X25519MLKEM768 TLS 密钥交换、ClientHello AES-GCM 认证、Ed25519/HMAC-SHA512 证书证明、时间窗口与有界防重放缓存。
- 多节点管理：独立配置、独立 systemd 模板实例；安装后进入菜单，选择后才创建节点。

暂不支持 Vision、普通 TLS 节点、ML-DSA-65、Reality 目标站 ServerHello / 记录指纹复刻、其他传输、路由 / GeoIP / GeoSite、XUDP 在不同 Mux 连接之间迁移原 UDP socket、自定义握手 padding、会话期限范围。Reality 尚不能视为与官方实现等效的流量伪装或抗探测能力。不兼容的配置会明确拒绝。客户端必须支持 VLESS Encryption；普通 VLESS 客户端无法使用。

握手发送最小 padding，不复现 Xray 默认的随机 padding 和延迟分片；三种外观的密钥和记录处理均可互通，但握手的长度与时序分布不同。

## 构建和独立运行

从仓库根目录执行：

```bash
cd rust-core
cargo build --release --locked
./target/release/vless-rust init --config rust.json --host YOUR_SERVER_IP --port 18443
./target/release/vless-rust check --config rust.json
./target/release/vless-rust run --config rust.json
```

`init` 创建新配置并输出客户端链接；已有文件会被拒绝覆盖。Linux 新文件权限为 `0600`。Windows 二进制名为 `vless-rust.exe`。首次先使用独立端口，并在服务器安全组与防火墙放行对应 TCP 端口。

其他认证或外观：

```bash
./target/release/vless-rust init --config rust.json --host YOUR_SERVER_IP --port 18443 --auth mlkem768 --mode random
```

`keygen` 只输出两端的 Encryption 参数 JSON，不修改文件。配置和生成的链接均含连接凭据。

### 实验性 Reality

```bash
./target/release/vless-rust init --config reality.json --host YOUR_SERVER_IP \
  --port 18444 --reality --server-name www.microsoft.com
```

`--reality` 必须配合 `--server-name DOMAIN`；可选 `--target HOST:PORT`，否则目标为 `DOMAIN:443`。生成新的 Reality X25519 私钥和 8 字节 short ID，客户端链接包含 `security=reality`、`sni`、`fp=chrome`、`pbk`、`sid`、`spx` 和 Encryption 参数，不设置 Vision flow。`link` 重建相同凭据，`configure` 保留已有 Reality 配置和密钥。`capabilities` 输出 `vless-encryption reality-experimental`，管理器不会在不支持的核心上伪造 Reality 节点。

顶层可选 `reality` 配置：

```json
{
  "private_key": "<32-byte X25519 key, base64url without padding>",
  "short_id": "<2..16 hex digits, even length>",
  "server_name": "www.microsoft.com",
  "target": "www.microsoft.com:443",
  "max_time_diff_secs": 300
}
```

省略此字段是普通 Encryption 节点。时间窗口必须为 `1..3600` 秒；服务器应保持时间同步。认证失败、SNI / short ID 不匹配、过期或重放的 ClientHello 不会进入 VLESS 转发，而是把原始连接转发到配置的目标站。此转发受握手超时和连接 / 握手并发限制，因此不是无限期的通用目标站代理。

当前实现以 rustls 完成真正的 TLS 1.3 握手，包括验证客户端 Finished；认证连接不连接目标站，不复制其 ServerHello、记录长度或时序。仅证明协议互通，不能承诺达到参考 Reality 服务端的抗探测效果。已在官方客户端上测试 Chrome、Firefox、Safari 指纹；不支持 ML-DSA-65 额外证明。

## Linux systemd 一键安装

在 Linux systemd 主机以 root 运行仓库根目录的一键脚本：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/x0fun1/vless-enc-script/main/install.sh)
```

可用 `--port`、`--host`、`--auth` 和 `--mode` 设置本次菜单会话中新节点的默认值；它们不直接创建节点或更改旧节点。脚本下载并校验 GitHub Actions 发布的同版本预编译二进制与部署包，安装核心、`venc` 和模板后进入菜单。服务器不需要 Rust/Cargo，也不编译源码。`--no-menu` 仅安装 / 更新。只有用户选择菜单 1 后，才生成独立 UUID、密钥、配置和客户端链接；不填写端口则随机选择 `10000–60000` 内未占用且未分配的 TCP 端口。

菜单 1 先选择普通 Encryption 或实验性 Reality + Encryption，再确认端口；公网地址自动检测，UUID 和密钥自动生成。创建第二个节点不会更改第一个节点。可直接运行 `sudo venc` 管理：1 创建、2 删除指定节点、3 显示指定或全部节点、4 停止指定节点、5 卸载全部、6 启动、7 重启、8 日志、9 状态、10 更新脚本并迁移旧节点、0 退出。选择 10 后需确认；它会执行最新版安装器，更新核心和菜单，并自动迁移旧版单节点（若存在）。

- 新节点目录：`/usr/local/etc/vless-rust/nodes/node-<32位UUID>/`。
- 配置：目录内 `config.json`，`root:vless-rust`、`0640`；目录为 `0750`。
- 公网地址和链接：目录内 `public-host`、`link.txt`，`root`、`0600`。
- 新节点服务：`vless-rust@node-<32位UUID>.service`，独立系统账户，允许监听低端口。
- 旧版单节点自动显示为 `legacy`，仍使用原 `config.json`、`public-host` 和 `vless-rust.service`；选择菜单 10 前不改写。菜单 10 会保留 UUID、端口、Encryption/Reality 凭据及原启停状态，将其迁入节点目录并切换到实例服务。旧版配置缺少公网地址时会提示输入。
- 配置仍存在的已停止节点保留端口分配，防止之后重启时冲突；删除节点才释放分配。
- 创建失败只删除本次新配置，不重启旧节点；无法停止失败的新服务时保留其配置供恢复。
- 安装器和菜单共享文件锁，避免多个会话并发修改节点 / 分配端口。
- 更新保留启用状态与配置，重启之前正在运行的实例，停止的节点不会自动启动。安装或更新失败尝试恢复快照；恢复失败保留报出的 `/tmp/vless-rust-rollback.*`。
- 故障退出 5 秒后重启，60 秒最多 5 次，防止错误配置反复重启。

本地仓库可用 `sudo bash rust-core/install.sh --binary FILE` 仅安装核心及菜单。`--config FILE` 是显式导入旧版单节点的兼容入口；已有单节点配置不同时会拒绝覆盖，不会自动启用或启动导入节点。需要另外保存该节点的 `public-host`，再手动 `systemctl enable --now vless-rust`。

查看与管理：

```bash
systemctl status vless-rust@node-<ID> --no-pager
journalctl -u vless-rust@node-<ID> -f --no-pager
systemctl restart vless-rust@node-<ID>
```

不能与其他服务在相同监听地址和端口同时运行。安装不负责停止原 Xray；更新正在运行的节点会短暂中断已有连接。必须发布 `vless-rust-v0.2.0` 下的二进制、部署包及其 SHA-256 文件后，远程一键入口才能取得本版本。

## 从现有普通节点迁移

在 Linux 使用 Python 3 转换当前脚本生成的普通配置：

```bash
sudo python3 rust-core/tools/import_xray.py --input /usr/local/etc/xray/config.json --output /root/vless-rust.json --listen 0.0.0.0:18443
rust-core/target/release/vless-rust check --config /root/vless-rust.json
sudo bash rust-core/install.sh --config /root/vless-rust.json
printf '%s\n' YOUR_SERVER_IP | sudo tee /usr/local/etc/vless-rust/public-host >/dev/null
sudo chmod 0600 /usr/local/etc/vless-rust/public-host
sudo systemctl enable --now vless-rust
```

转换保留 UUID 和 Encryption 私钥，因此同一端口、同一 IP 下客户端参数可以继续使用；独立端口试运行时需复制节点并改端口。迁移工具拒绝 REALITY、Vision、额外入站、路由、DNS 和自定义出站配置，不会静默丢弃这些功能。DNS 使用操作系统解析器和返回顺序，与原 `UseIPv4v6` 策略可能不同。

## 保活和断流日志

默认 `limits`：

| 参数 | 默认值 | 作用 |
| --- | ---: | --- |
| `keepalive_idle_secs` | 60 | TCP 空闲多久后开始保活 |
| `keepalive_interval_secs` | 15 | TCP 保活探测间隔 |
| `keepalive_retries` | 4 | Linux 等支持平台的失败探测次数 |
| `handshake_timeout_secs` | 15 | 等待握手和认证的最长时间 |
| `connect_timeout_secs` | 10 | DNS / 出站 TCP 连接阶段各自的超时 |
| `idle_timeout_secs` | 900 | 双向均无应用数据的最长时间 |
| `half_close_timeout_secs` | 30 | TCP 一侧关闭后另一侧的宽限时间 |
| `max_connections` | 1024 | 入站连接及全部出站连接分别的总上限 |
| `max_handshakes` | 32 | 同时执行握手的上限 |
| `max_mux_streams` | 32 | 每条 Mux 连接的子流上限 |
| `max_sessions` | 1024 | 保存的 0-RTT 会话上限 |
| `max_resumes_per_session` | 1024 | 每个会话保存的防重放记录上限 |
| `allow_private_destinations` | false | 是否允许内网、回环与特殊用途目标 |

TCP keepalive 不会重置应用空闲计时，也不能维持已经断开的 TCP 会话。需要超过 15 分钟无数据仍保持的应用可增大 `idle_timeout_secs`；增大会让空闲连接占用资源更久。UDP 没有 TCP keepalive。

默认阻止内网 / 特殊用途 IP 和内网域名，范围参照固定 Xray 版本；如果确实需要访问内网，可显式设置 `limits.allow_private_destinations: true`。阻止时立即记录错误并关闭，不使用 Xray 的随机黑洞等待。

每 30 秒输出 `stats active/accepted/errors/resumed`。设置顶层 `log_connections: true` 可记录每次握手使用 `1rtt` / `0rtt` 和密码算法。错误日志区分 `handshake timeout`、`invalid VLESS user`、`AEAD authentication failed`、`private destination blocked`、DNS / 出站超时、应用空闲超时和半关闭超时，不输出私钥。

会话缓存满时，新握手广告为 1-RTT，已有未过期会话继续有效。单个会话超过防重放记录上限时，会要求客户端重新握手；若连接建立非常频繁，可提高该上限或将客户端链接中的 `0rtt` 改成 `1rtt`。

## 验证与复测

```bash
cd rust-core
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
python3 tools/fetch_reference.py
python3 tools/interop.py --rust target/release/vless-rust
python3 tools/interop.py --rust target/release/vless-rust --reality
python3 tools/regression.py
python3 ../tests/regression.py
```

参考下载器固定官方 `v26.11.9`，在解压前核对 GitHub 发布资产的 SHA-256；参考程序只用于测试。测试和测量生成的日志 / JSON 位于仓库 `.build/`，不会提交真实测试凭据。性能脚本只对本机回环的同一客户端与负载做比较，不能代表公网线路或 Linux 生产效果。

协议来源和许可见 [NOTICE.md](NOTICE.md)。
