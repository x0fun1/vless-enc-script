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

- 最新 Rust 本地检查：vless-rust **0.3.0**，26 项 Rust tests、strict Clippy、`cargo build --release --locked` 均通过。
- 全量普通 Encryption 互通 `python tools/interop.py`：30 个官方 Xray 客户端变体通过；八层混合认证 relay-only 另 6 个通过。
- REALITY localhost Xray 快速互通：Chrome、Firefox、Safari 指纹各 1 个通过，ML-DSA-65 的正确密钥验证与错误密钥 `BadCertificate` 拒绝通过。
- `python tools/interop.py --reality --vision`：30 个官方 Xray 变体全通过，覆盖 X25519 / ML-KEM-768、native / xorpub / random、AES / ChaCha、Mux 开 / 关及无 Mux XUDP 用例。random 外观在 Vision Direct 后继续对 TLS record header 使用 Xray 对应的 CTR mask；完整矩阵通过了 TLS echo 与 TCP/UDP 流量。
- `python tools/interop.py --quick --reality --vision --mldsa65`：4 个变体均通过，包括 VLESS Encryption X25519 / ML-KEM-768，以及 Mux 关闭 / 开启；正确 `pqv` 返回 Xray `uConn.Verified: true`，错误但非空公钥触发 TLS `BadCertificate` 且代理 echo 不成功。Xray `is using ML-DSA-65...: true` 仅表示配置了非空密钥，不代表验证成功。
- 另用 `--quick --reality --vision --mldsa65 --appearance random` 验证 ML-DSA-65 + random 外观的 4 个 auth/Mux 变体。
- Windows TLS echo target 实际协商 `X25519`；Debian 的实际 `www.nvidia.com` target 协商 `X25519MLKEM768`，REALITY + Vision systemd client request 通过。其他公网目标 / TLS group 仍未验证。
- `vision_direct_*` 诊断在 Mux 关闭的 TLS echo 用例观察到 downlink Direct 转换；uplink Direct 计数为 0。Mux 开启用例的功能 echo 成功，但未发生 Direct 转换。不能宣称双向 Direct 完整实现。
- 最新 CLI/menu 回归：`rust-core/tools/regression.py` 14 项、`tests/regression.py` 16 项通过（Windows）。验证包含三类 menu、随机默认 SpiderX、NVIDIA SNI/target 默认、ML-DSA 默认为关闭 / 可选启用和 credentials reconfigure。


REALITY 指纹捕获仍仅涵盖完整 ServerHello 位于单个 TLS record、兼容 CCS、当前支持的 TLS 1.3 suite/group 和有限初始记录形态；不匹配 PSK/resumption、post-handshake、完整时序或 ML-DSA-65 大证书导致的记录长度变化。独立 metadata probe 不验证目标证书信任链。短 / 超长 TLS record 和 wildcard-loopback/self-target 检查已有单元测试。

## Debian 13 / systemd 实机验证（2026-11-24）

主机：Debian GNU/Linux 13 (trixie) x86_64，kernel `6.12.95+deb13-cloud-amd64`；Rust/Cargo `1.100.0`。服务器可解析并连接 `www.nvidia.com:443`。

- Debian 上 `cargo fmt -- --check`、26 项 `cargo test --locked`、`cargo clippy --locked --all-targets -- -D warnings`、`cargo build --release --locked` 全通过。release SHA-256：`67dea124ffa0e05368c2f710bd13a52a2997e97f546dd1b5be73edcaef9ef18f`。
- `python3 tools/regression.py` 14 项、`python3 tests/regression.py` 16 项通过。
- 官方 Xray v26.11.9：普通 Encryption 30 项、8 层 relay 6 项、REALITY + Vision 全量 30 项通过。REALITY + Vision + ML-DSA-65 的 native / random quick matrix 共 8 项通过，正确公钥验证成功、错误公钥返回 `BadCertificate`。Chrome / Firefox / Safari REALITY 快速用例均通过。
- 使用真实菜单分别创建三类 systemd 节点：普通 Encryption、X25519 REALITY + Vision、ML-KEM-768 REALITY + Vision + 可选 ML-DSA-65。官方 Xray 客户端通过各服务访问真实 `www.nvidia.com`，三者均完成 HTTPS 请求（HTTP 307）；ML-DSA 客户端记录 `uConn.Verified: true`。
- 默认 NVIDIA 目标的 systemd 日志出现 `sni_ack=true`、`server_hello_match=true`，ServerHello 后的记录长度与捕获值匹配。Xray 关闭连接时未发送 TLS `close_notify`，rustls 因此记录 `UnexpectedEof`；上述 HTTP 请求已成功，但此类关闭仍计入服务 `errors`，不能当作 TLS 完整关闭。
- 在三节点启用期间执行真实 `rust-core/install.sh --binary ...` 升级：安装成功，三份配置 SHA-256 不变，服务仍为 active。随后通过 `venc` 删除三个临时节点并确认测试端口已关闭；将主机原有 0.2.0 core/manager/unit 文件恢复。原有 Xray 服务未停止或改动。

本轮在 Debian `www.nvidia.com` target 另观察到 `reality_tls_group=Some(X25519MLKEM768)`、`sni_ack=true`、`server_hello_match=true`；服务的初始记录长度与目标匹配。REALITY 仍不声称完整指纹等价。
