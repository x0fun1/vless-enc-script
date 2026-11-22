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

## 当前验证边界

当前机器只有 Windows，未验证 Linux 编译、systemd 服务实际启停 / 回滚、长时间运行、真实公网链路、移动网络和 NAT 空闲断开。尚无原服务器的断流日志，因此不能确认原来的具体故障原因，也不能宣称已经解决现场断流。

REALITY、Vision、握手随机 padding / 延迟分片、跨 Mux 的原 UDP socket 迁移不在本版本的验证范围。完整支持范围、默认保活参数、独立安装和迁移步骤见 [README.md](README.md)。
