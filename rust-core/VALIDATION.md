# 验证记录

日期：2026 年 11 月 22 日。环境：Windows-11-10.0.26300-SP0，Rust 1.100.0，官方 Xray-core v26.11.9（Go 1.27.3，windows/amd64）。

## 功能验证

最终 release 二进制已通过：

- 30 组官方客户端互通：两种认证 × 三种外观 × 两种密码算法 × Mux 开关，以及 6 组完全关闭 Mux 的普通 UDP 用例。
- 6 组八层混合认证中继互通：三种外观 × 两种密码算法。
- IPv4、域名、IPv6 TCP / UDP、大块传输及 8 路并发；日志确认实际使用的密码算法和 0-RTT 恢复。
- 11 项 Rust 测试：KDF 块边界、密文篡改、异常记录头、nonce 换钥、分块读取、延迟下行半关闭、防重放、会话缓存满与过期，以及 Mux 会话 ID 重用。
- 6 项程序回归：配置拒绝、禁止覆盖已有配置、迁移保留凭据 / 拒绝扩展、握手超时与连接限额、未知 UUID 拒绝、默认内网目标拒绝。
- Release 构建、Clippy 全目标零警告、安装脚本 Bash 语法 / 帮助、Python 语法检查。

机器可读记录：[validation/interop.json](validation/interop.json)。本地 Windows 二进制约 1.29 MiB，其 SHA-256 为：

```text
DB17BA318C5CEC858576B41A5E668204441305A682127B0E80294740225B7833
```

## 内存与效率测量

相同的官方客户端、X25519 / native / AES、0-RTT、64 条已建立的空闲 TCP 连接，再以 4 条并发连接各下载 256 MiB，总计 1 GiB。每个核心独立运行 3 次，以下取中位数。每次下载校验 SHA-256。

回环目标只为测量显式放行；Xray 设置允许回环的 finalRules，Rust 设置 allow_private_destinations。Go 服务端与客户端设置 GOMAXPROCS=4，Rust 最多 4 个运行线程。性能测量期间没有并行运行互通测试。

| 测量 | Rust 0.1.0 | Xray v26.11.9 |
| --- | ---: | ---: |
| 64 条连接时 RSS | 9.17 MiB | 27.14 MiB |
| Windows 私有提交内存 | 4.61 MiB | 56.72 MiB |
| 传输后的 RSS | 9.80 MiB | 31.37 MiB |
| 回环端到端吞吐 | 719.4 MiB/s | 693.7 MiB/s |
| 服务端处理 1 GiB 的 CPU 时间 | 1.656 s | 1.797 s |

本次中位数：RSS 减少 **66.2%**，吞吐增加 **3.7%**，服务端 CPU 时间减少 **7.8%**。样本较少，吞吐也受客户端、Python 目标与哈希校验影响；小幅效率变化不能外推为 Linux 或公网加速保证。内存下降是当前最明确的收益。

原始各轮数据：[validation/windows-benchmark.json](validation/windows-benchmark.json)。复测命令：

```bash
python3 rust-core/tools/benchmark.py
```

## 基线验证边界

2026-11-22 的 Windows 基线记录不覆盖 Linux/systemd 部署和本次 Vision/REALITY 改动。当前 Debian 验证结果见下文；尚未验证长时间运行、移动网络、NAT 空闲断开或其他公网目标。没有原服务器的断流日志，不能确认原现场故障的具体原因。

## 后续实验功能：Vision + REALITY（Windows localhost）

截至 2026-11-24，后续工作树以官方 Xray-core v26.11.9 验证 Vision + REALITY 组合。上游 VLESS Vision outbound 可在 REALITY transport 上运行；本实现曾错误地在配置校验中拒绝组合，现已移除该限制。测试目标均为 Windows localhost TLS echo / echo 服务，不代表公网或 Debian 生产环境。

- 最新 Rust 本地检查：vless-rust **0.3.1 候选**，29 项 Rust tests、strict Clippy、`cargo build --release --locked` 均通过。Windows 的完整互通矩阵针对当前候选重新运行通过。
- 全量普通 Encryption 互通 `python tools/interop.py`：30 个官方 Xray 客户端变体通过；八层混合认证 relay-only 另 6 个通过。
- `python tools/interop.py --quick --reality` 现验证 metadata probe 的平台证书信任和 SNI：测试 CA 签发的 localhost target 正向成功；替换为不相关但有效的 CA 时，服务端报告 `UnknownIssuer`，且代理流未建立。
- `python tools/interop.py --reality --vision`：30 个官方 Xray 变体全通过，覆盖 X25519 / ML-KEM-768、native / xorpub / random、AES / ChaCha、Mux 开 / 关及无 Mux XUDP 用例。random 外观在 Vision Direct 后继续对 TLS record header 使用 Xray 对应的 CTR mask；完整矩阵通过了 TLS echo 与 TCP/UDP 流量。
- `python tools/interop.py --quick --reality --vision --mldsa65`：4 个变体均通过，包括 VLESS Encryption X25519 / ML-KEM-768，以及 Mux 关闭 / 开启；正确 `pqv` 返回 Xray `uConn.Verified: true`，错误但非空公钥触发 TLS `BadCertificate` 且代理 echo 不成功。Xray `is using ML-DSA-65...: true` 仅表示配置了非空密钥，不代表验证成功。
- 另用 `--quick --reality --vision --mldsa65 --appearance random` 验证 ML-DSA-65 + random 外观的 4 个 auth/Mux 变体。
- Windows TLS echo target 实际协商 `X25519`；Debian 的实际 `www.nvidia.com` target 协商 `X25519MLKEM768`，REALITY + Vision systemd client request 通过。其他公网目标 / TLS group 仍未验证。
- `vision_direct_*` 诊断在 Mux 关闭的 TLS echo 用例观察到 downlink Direct 转换；uplink Direct 计数为 0。Mux 开启用例的功能 echo 成功，但未发生 Direct 转换。不能宣称双向 Direct 完整实现。
- 最新 CLI/menu 回归：`rust-core/tools/regression.py` 14 项、`tests/regression.py` 16 项通过（Windows）。验证包含三类 menu、随机默认 SpiderX、NVIDIA SNI/target 默认、ML-DSA 默认为关闭 / 可选启用和 credentials reconfigure。


REALITY 指纹捕获仍仅涵盖完整 ServerHello 位于单个 TLS record、兼容 CCS、当前支持的 TLS 1.3 suite/group 和有限初始记录形态；不匹配 PSK/resumption、post-handshake、完整时序或 ML-DSA-65 大证书导致的记录长度变化。短 / 超长 TLS record 和解析所得地址 self-target 检查已有单元测试。

## Debian 13 / systemd 实机验证（2026-11-24）

主机：Debian GNU/Linux 13 (trixie) x86_64，kernel `6.12.95+deb13-cloud-amd64`；Rust/Cargo `1.100.0`。服务器可解析并连接 `www.nvidia.com:443`。

- Debian 上 `cargo fmt -- --check`、29 项 `cargo test --locked`、`cargo clippy --locked --all-targets -- -D warnings`、`cargo build --release --locked` 均通过；另以 Rust 1.89.0 `cargo check --locked --offline` 验证声明的最低 Rust 版本。v0.3.1 候选 release SHA-256：`0004f93892c0cbcbd7c2aa63b726882c9c1d5d7050b001f18e37a913a99fb6df`。
- `python3 tools/regression.py` 14 项、`python3 tests/regression.py` 16 项通过。
- 官方 Xray v26.11.9：普通 Encryption 30 项、8 层 relay 6 项、REALITY + Vision 全量 30 项通过。REALITY + Vision + ML-DSA-65 的 native / random quick matrix 共 8 项通过，正确公钥验证成功、错误公钥返回 `BadCertificate`。独立 REALITY Chrome / Firefox / Safari 快速用例均通过；不受信任自定义 target CA 用例返回 `UnknownIssuer` 且无代理流量。
- 使用真实菜单分别创建三类 systemd 节点：普通 Encryption、X25519 REALITY + Vision、ML-KEM-768 REALITY + Vision + 可选 ML-DSA-65。官方 Xray 客户端通过各服务访问真实 `www.nvidia.com`，三者均完成 HTTPS 请求（HTTP 307）；ML-DSA 客户端记录 `uConn.Verified: true`。
- 默认 NVIDIA 目标的 systemd 日志出现 `sni_ack=true`、`server_hello_match=true`，ServerHello 后的记录长度与捕获值匹配。REALITY target metadata probe 会校验系统信任根和 SNI 主机名；测试 / 私有目标的自定义信任锚通过 `target_ca_certificates` 显式提供。Xray 关闭连接时未发送 TLS `close_notify`，rustls 因此记录 `UnexpectedEof`；HTTP 请求已成功，但此类关闭仍计入服务 `errors`。
- 本候选 v0.3.1 在 Debian 13 上重新通过上述 build / regression / interop 矩阵。release 二进制 SHA-256 为 `0004f93892c0cbcbd7c2aa63b726882c9c1d5d7050b001f18e37a913a99fb6df`；应用与 vendored rustls 锁文件 SHA-256 分别为 `949886f3205f6919061a64ed3c30f8f5f5e05d30f87daa7316cc0770d2b3fc3c`、`c845884bb7c73dc3384198d0f91584f03dd337ba197cd2c23d6ed51a71f7aa0f`。systemd 上由真实菜单创建三个 v0.3.1 候选节点；官方 Xray 分别访问真实 NVIDIA 目标取得 HTTP 307。使用当前候选再次安装后，三份配置 SHA-256 不变且服务均仍 active；随后删除临时节点、确认测试端口关闭、恢复原 0.2.0 core / manager / unit。原有 `x-ui` 服务仍 active，未改动。此为本机客户端到服务器、经公网目标的 smoke，不是 off-host 入站测试。

本次自动化安全依赖检查：cargo-audit v0.23.0 对应用锁文件（131 个依赖）及 vendored rustls 锁文件（134 个依赖）分别扫描，均无告警 / advisories。RustSec advisory database commit `52384ab5581a4487b62c549eef95cf7ba7e8bad5`（2026-11-23）；扫描未使用 ignore。主构建解析 rustls-webpki 0.103.17；vendor lock 中 rustls-webpki 0.103.17、webpki-roots 1.0.10。RUSTSEC-2024-0437 的 protobuf 不在这两个依赖图中。

开发过程还做了针对 REALITY trust probe / certificate chain / SNI hostname、target DNS self-loop 和 SSRF 边界、ClientHello / TLS length parsing、replay bounds、Vision frame bounds / random header protection、ML-DSA signature key verification 的定向代码审查和负向互通检查；详情仍需由未参与实现的第三方审计方独立复核。
