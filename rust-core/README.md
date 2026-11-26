# 独立 VLESS Encryption Rust 核心

版本 **0.3.2**。协议参照固定的 **Xray-core v26.11.9**，编译工具链固定为 **Rust 1.100.0**，依赖通过 `Cargo.lock` 锁定。进程自身完成加密握手、记录层和转发，不启动或嵌入 Go Xray。

当前功能均以 opt-in 方式启用；v0.3.1 已发布，v0.3.2 尚未发布。本项目尚未经过独立安全审计。普通 Encryption 基线和后续实验功能的验证范围分别记录于 [VALIDATION.md](VALIDATION.md)。Debian 13 上的 v0.3.1 systemd 三节点及 NVIDIA target smoke 已完成；临时节点已删除并恢复原 0.2.0 安装。长时间运行、移动网络、其他公网目标和完整 fingerprint parity 尚未验证；off-host 入站测试未做。

当前工作分支包含发布后的安全修复候选和 IPv4 优先菜单，包版本为 0.3.2，尚未发布。本轮候选的变更与检查结果单独记录于验证文档；2026-11-24 的 Debian 13 / systemd 结果只覆盖已发布基线。

## 已支持的范围

- 普通 VLESS Encryption：`mlkem768x25519plus` 混合密钥交换。
- X25519 / ML-KEM-768 认证，支持最多 8 层混合认证中继。
- `native`、`xorpub`、`random` 外观；AES-256-GCM、ChaCha20-Poly1305。
- 1-RTT、带防重放缓存的 0-RTT 会话恢复、nonce 溢出换钥。
- TCP、普通 UDP、Mux TCP 和 XUDP 转发；IPv4、IPv6、域名目标。
- 入站与出站 TCP keepalive、握手 / 连接 / 空闲超时、TCP 半关闭宽限期。
- 有上限的连接、握手、Mux 子流、会话和防重放缓存；可复用的数据缓冲区。

- 实验性 XTLS Vision + VLESS Encryption：TCP 直连模式，包含 VLESS Addons 帧、Continue / End / Direct 状态处理；支持单 TCP 与官方 Xray v26.11.9 测过的 Mux/XUDP 组合场景。直接 UDP 请求仍拒绝。
- 实验性 REALITY + VLESS Encryption：TLS 1.3、X25519 / X25519MLKEM768 TLS 密钥交换、ClientHello AES-GCM 认证、Ed25519/HMAC-SHA512 证书证明、时间窗口与有界防重放缓存；可选 ML-DSA-65 额外证书证明。支持与 Vision 组合，管理器提供 X25519 / ML-KEM-768 Encryption 认证两种组合。
- REALITY 会为已认证 ClientHello 临时连接配置的目标站，读取目标 ServerHello / CCS / 初始加密记录长度，并以目标协商参数塑形本地握手；之后 VLESS 应用流量仍转发到客户端请求的 destination。只在当前实现支持的完整 ServerHello、套件 / 群组与初始 TLS 1.3 flight 等限制内进行；ML-DSA-65 证书较大，可能超出目标记录长度。
- 多节点管理：独立配置、独立 systemd 模板实例；安装后进入菜单，选择后才创建节点。

暂不支持普通 TLS 节点、其他传输、路由 / GeoIP / GeoSite、XUDP 在不同 Mux 连接之间迁移原 UDP socket、自定义握手 padding、会话期限范围。REALITY 不是完整指纹复刻：当前需要完整 ServerHello 位于单个 TLS record、兼容 CCS、支持的 TLS 1.3 cipher suite（`0x1301..=0x1303`）和 X25519 / X25519MLKEM768 group；不能重现 PSK / resumption 或 post-handshake 行为。目标不可达、返回格式不支持或 profile 不兼容时，已认证连接可能失败。实验互通不能证明完整协议兼容、安全性或抗探测效果。不兼容的配置会明确拒绝。客户端必须支持 VLESS Encryption；普通 VLESS 客户端无法使用。

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
./target/release/vless-rust init --config reality-vision.json --host YOUR_SERVER_IP \
  --port 18444 --reality --vision --auth x25519
```

`--reality` 的默认 SNI / 目标分别为 `www.nvidia.com` / `www.nvidia.com:443`，两者可以通过 `--server-name DOMAIN` 与 `--target HOST:PORT` 单独覆盖。程序随机生成 REALITY 私钥与 short ID、随机 SpiderX 路径，以及对应的公开 `pbk`；私钥不出现在链接中。`--mldsa65` 可选择性添加额外 ML-DSA-65 证明（默认关闭，随机生成 seed；链接 `pqv` 公钥由 seed 派生）。`--vision` 可与 `--reality` 组合，设置 `flow=xtls-rprx-vision`；`--auth x25519|mlkem768` 选择 VLESS Encryption 认证类型。`link` 重建相同凭据，`configure` 保留已有凭据；`capabilities` 报告可用能力。

普通 REALITY 配置例：

```json
{
  "private_key": "<32-byte X25519 key, base64url without padding>",
  "short_id": "<2..16 hex digits, even length>",
  "spider_x": "/<random-path>",
  "server_name": "www.nvidia.com",
  "target": "www.nvidia.com:443",
  "max_time_diff_secs": 300
}
```

省略此字段是普通 Encryption 节点。时间窗口必须为 `1..3600` 秒；服务器应保持时间同步。认证失败、SNI / short ID 不匹配、过期或重放的 ClientHello 不会进入 VLESS 转发，而是把原始连接转发到配置的目标站。此转发受握手超时和连接 / 握手并发限制，因此不是无限期的通用目标站代理。

REALITY authenticated path currently depends on the configured target: it connects there to capture handshake characteristics; unauthenticated connections still relay their original bytes to that target. The separate ALPN/SNI metadata probe validates the target's certificate chain and hostname using platform trust roots; up to 32 profiles are cached for ten minutes, keyed by the selected target address, SNI and ALPN offer. For a private or test target, `target_ca_certificates` may add up to 16 explicitly trusted DER certificates encoded as unpadded base64url. No application data is sent in the probe. Certificate verification on the independent metadata connection does not prove the target handles the capture and probe ClientHello identically. Unavailable or unsupported TLS targets cause the authenticated handshake to fail. The target resolver rejects any resolved address that would loop back to this listener.

本轮候选将 `limits.allow_private_destinations` 同时应用到 REALITY 未认证 fallback、目标握手采样和元数据探测，默认拒绝内网及特殊用途 target。显式设为 `true` 才允许此类目标；此选择也允许未经认证的连接经 fallback 到达配置的内网 target，不能仅按已认证代理流量评估。元数据探测连接使用采样时选中的同一目标地址；本服务监听地址的循环转发检查不受该开关影响。

本机 Windows OpenSSL TLS echo target 实际协商 `X25519`；Debian 的 `www.nvidia.com` target 实际协商 `X25519MLKEM768`。两类 REALITY + Vision 均通过 Xray v26.11.9 客户端；NVIDIA 用例也观察到 SNI acknowledgement 和匹配的 ServerHello / 初始记录长度。其他目标、完整 TLS 流量形态和完整指纹等价仍未验证。

### 实验性 XTLS Vision

```bash
./target/release/vless-rust init --config vision.json --host YOUR_SERVER_IP --port 18445 --vision
```

链接会设置 `flow=xtls-rprx-vision`。Vision 处理 VLESS Addons 帧并识别 TLS 1.3 应用数据后的 Direct 转换；直接 UDP 请求仍拒绝。Vision 可与 REALITY 组合。Xray v26.11.9 localhost 测试验证了 REALITY + Vision 的 30 个认证 / appearance / AEAD / Mux 组合，以及 ML-DSA-65 子集。random appearance 的 raw TLS Direct 数据仍按 Xray 规则掩蔽 record header。Direct 计数只观察到 downlink 转换，uplink Direct 为 0；Mux 开启时 echo 成功但未发生 Direct 转换。不能据此宣称完整 Vision 等价或全功能支持。

普通认证连接的 TLS fingerprint 变换不适用；REALITY + Vision 组合虽可互通，但这些测试不证明完整 TLS 指纹伪装或 Vision 上下行均实现 Direct。

### REALITY 可选 ML-DSA-65 证明

`--mldsa65` 仅能配合 `--reality`。它在原有 Ed25519 TLS CertificateVerify 和 HMAC 证书证明之外，提供 ML-DSA-65 签名；客户端通过链接的 `pqv` 参数配置 `mldsa65Verify`。这与 TLS cipher suite / 密钥协商中的 PQ 支持是两项不同能力。Xray v26.11.9 在 Windows localhost 用例中用正确公钥确认 `uConn.Verified: true`；提供错误的非空验证公钥时，官方客户端没有建立通过代理的测试流。此结果只覆盖互通，不是恶意输入、证书解析或侧信道审计。

## Linux systemd 一键安装

在 Linux systemd 主机以 root 运行仓库根目录的一键脚本：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/x0fun1/vless-enc-script/main/install.sh)
```

可用 `--port`、`--host` 和 `--mode` 设置本次菜单会话中新节点的默认值；`--auth` 默认值只作用于普通类型 1，类型 2 / 3 的 VLESS Encryption 认证固定为 X25519 / ML-KEM-768。这些参数不直接创建节点或更改旧节点。脚本下载并校验 GitHub Actions 发布的同版本预编译二进制与部署包，安装核心、`venc`、IPv4 设置脚本和模板后进入菜单。服务器不需要 Rust/Cargo，也不编译源码。`--no-menu` 仅安装 / 更新。只有用户选择菜单 1 后，才生成独立 UUID、密钥、配置和客户端链接；不填写端口则随机选择 `10000–60000` 内未占用且未分配的 TCP 端口。

菜单类型 1 是普通 Encryption；类型 2 / 3 分别为 REALITY + Vision 的 X25519 / ML-KEM-768 Encryption 认证，ML-DSA-65 可在创建时额外选择开启（默认关闭）。 SNI / 目标默认 `www.nvidia.com` / `www.nvidia.com:443`，可以分别自定义。公网地址自动检测，UUID 和密钥自动生成。创建第二个节点不会更改第一个节点。可直接运行 `sudo venc` 管理：1 创建、2 删除指定节点、3 显示指定或全部节点、4 停止指定节点、5 卸载全部、6 启动、7 重启、8 日志、9 状态、10 更新脚本并迁移旧节点、11 设置 IPv4 优先（保留 IPv6）、0 退出。选择 10 后需确认；它会执行最新版安装器，更新核心和菜单，并自动迁移旧版单节点（若存在）。

菜单 11 在 glibc Linux 上更新 `gai.conf`，为 IPv4 设置较高的地址选择优先级。它备份并保留原有 precedence 规则，IPv6 仍可用。运行 `sudo /usr/local/bin/prefer-ipv4 restore` 可撤销该策略。

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

不能与其他服务在相同监听地址和端口同时运行。安装不负责停止原 Xray；更新正在运行的节点会短暂中断已有连接。必须发布 `vless-rust-v0.3.2` 下的二进制、部署包及其 SHA-256 文件后，远程一键入口才能取得本版本。

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

转换保留 UUID 和 Encryption 私钥；接受 uniform raw-TCP Vision flow，其它流量组合、REALITY / TLS 入站、额外入站、路由、DNS 和自定义出站配置会被拒绝，不会静默丢弃功能。DNS 使用操作系统解析器和返回顺序，与原 `UseIPv4v6` 策略可能不同。

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
| `half_close_timeout_secs` | 30 | 一侧 EOF 后，等待另一侧数据的最长连续空闲时间；仍有数据传输时会延长 |
| `max_connections` | 1024 | 入站连接及全部出站连接分别的总上限 |
| `max_handshakes` | 32 | 同时执行握手的上限 |
| `max_mux_streams` | 32 | 每条 Mux 连接的子流上限 |
| `max_sessions` | 1024 | 保存的 0-RTT 会话上限 |
| `max_resumes_per_session` | 1024 | 每个会话保存的防重放记录上限 |
| `allow_private_destinations` | false | 是否允许代理及 REALITY fallback / 采样 / 探测连接内网、回环与特殊用途目标（REALITY 部分为本轮候选变更） |

TCP keepalive 不会重置应用空闲计时，也不能维持已经断开的 TCP 会话。需要超过 15 分钟无数据仍保持的应用可增大 `idle_timeout_secs`；增大会让空闲连接占用资源更久。UDP 没有 TCP keepalive。

默认阻止内网 / 特殊用途目标 IP 和内网域名，范围参照固定 Xray 版本；如果确实需要访问内网，可显式设置 `limits.allow_private_destinations: true`。阻止时立即记录错误并关闭，不使用 Xray 的随机黑洞等待。此策略限制服务器的出站目标，不限制客户端来源地址：局域网客户端仍可使用服务器内网地址连接本服务，由监听地址、防火墙和客户端认证决定能否访问。对 REALITY 开启该开关还会放行未经认证的 fallback 到配置的内网 target。

每 30 秒输出 `stats active/accepted/errors/resumed/retry`：`retry` 统计服务端拒绝未知 / 过期 0-RTT 票据并通知客户端弃用票据的次数，不计为服务错误；它统计的是服务端发出的回退信号，不保证原请求自动重放。官方 Xray v26.11.9 收到此信号后会清除旧票据，但当前请求可能中断，后续新连接再使用完整握手。设置顶层 `log_connections: true` 可记录每次握手使用 `1rtt` / `0rtt` 和密码算法。错误日志区分 `handshake timeout`、`invalid VLESS user`、`AEAD authentication failed`、`private destination blocked`、DNS / 出站超时、应用空闲超时和半关闭空闲超时，不输出私钥。客户端网络重置单独标明发生在客户端读、写或对端流量路径。

会话缓存满时，新握手广告为 1-RTT，已有未过期会话继续有效。单个会话超过防重放记录上限时，会要求客户端重新握手；若连接建立非常频繁，可提高该上限或将客户端链接中的 `0rtt` 改成 `1rtt`。

## 验证与复测

```bash
cd rust-core
cargo fmt -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked
python3 tools/fetch_reference.py
python3 tools/interop.py --rust target/release/vless-rust
python3 tools/interop.py --rust target/release/vless-rust --reality
python3 tools/interop.py --rust target/release/vless-rust --reality --mldsa65
python3 tools/interop.py --rust target/release/vless-rust --vision
python3 tools/regression.py
python3 ../tests/regression.py
```

参考下载器固定官方 `v26.11.9`，在解压前核对 GitHub 发布资产的 SHA-256；参考程序只用于测试。测试和测量生成的日志 / JSON 位于仓库 `.build/`，不会提交真实测试凭据。性能脚本只对本机回环的同一客户端与负载做比较，不能代表公网线路或 Linux 生产效果。

协议来源和许可见 [NOTICE.md](NOTICE.md)。仓库地图、Windows 开发环境及版本发布步骤见 [CONTRIBUTING.md](../CONTRIBUTING.md)。
