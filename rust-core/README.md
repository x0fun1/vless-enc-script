# 独立 VLESS Encryption Rust 核心

版本 **0.1.1**。协议参照固定的 **Xray-core v26.11.9**，编译工具链固定为 **Rust 1.100.0**，依赖通过 `Cargo.lock` 锁定。进程自身完成加密握手、记录层和转发，不启动或嵌入 Go Xray。

当前是经过本机互通验证的首版，尚未经过独立安全审计或 Linux 长时间运行验证。Linux systemd 安装脚本已提供，生产环境应先使用独立端口试运行。实际性能记录见 [VALIDATION.md](VALIDATION.md)。

## 已支持的范围

- 普通 VLESS Encryption：`mlkem768x25519plus` 混合密钥交换。
- X25519 / ML-KEM-768 认证，支持最多 8 层混合认证中继。
- `native`、`xorpub`、`random` 外观；AES-256-GCM、ChaCha20-Poly1305。
- 1-RTT、带防重放缓存的 0-RTT 会话恢复、nonce 溢出换钥。
- TCP、普通 UDP、Mux TCP 和 XUDP 转发；IPv4、IPv6、域名目标。
- 入站与出站 TCP keepalive、握手 / 连接 / 空闲超时、TCP 半关闭宽限期。
- 有上限的连接、握手、Mux 子流、会话和防重放缓存；可复用的数据缓冲区。

暂不支持 REALITY、Vision、TLS 外层、其他传输、路由 / GeoIP / GeoSite、XUDP 在不同 Mux 连接之间迁移原 UDP socket、自定义握手 padding、会话期限范围。不兼容的配置会明确拒绝。客户端必须支持 VLESS Encryption；普通 VLESS 客户端无法使用。

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

## Linux systemd 一键安装

在 Linux systemd 主机以 root 运行仓库根目录的一键脚本：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/x0fun1/vless-enc-script/main/install.sh)
```

可用 `--port`、`--host`、`--auth` 和 `--mode` 指定监听端口、公网地址、认证模式与流量外观；省略 `--host` 时尝试自动检测公网地址。脚本下载固定源码并校验关键文件、安装 Rust 1.100.0、构建核心、生成配置和客户端链接，再安装并启动 systemd 服务。链接保存在 `/root/vless-rust_link.txt`。本地仓库也可用 `sudo bash rust-core/install.sh --config FILE` 安装已有配置，或加 `--binary FILE` 安装预构建 Linux 二进制。

安装目标：`/usr/local/bin/vless-rust`。
- 配置：`/usr/local/etc/vless-rust/config.json`，`root:vless-rust`、`0640`。
- 服务：`vless-rust.service`；独立系统账户，允许监听低端口。
- 故障退出 5 秒后重启，60 秒最多 5 次，防止配置错误反复重启。触及限制后，修复问题并运行 `systemctl reset-failed vless-rust && systemctl start vless-rust`。
- 更新会保留已有服务的启用与运行状态；文件替换后启动失败会尝试恢复快照，恢复失败时保留报出的 `/tmp/vless-rust-rollback.*`。

查看与管理：

```bash
systemctl status vless-rust --no-pager
journalctl -u vless-rust -f --no-pager
systemctl restart vless-rust
```

不能与 Xray 在同一地址、同一端口同时监听。使用相同端口切换会中断已有连接；安装脚本不负责停止原 Xray。首次安装会启用并启动 Rust 服务，后续安装保留 Rust 服务原运行状态。

## 从现有普通节点迁移

在 Linux 使用 Python 3 转换当前脚本生成的普通配置：

```bash
sudo python3 rust-core/tools/import_xray.py --input /usr/local/etc/xray/config.json --output /root/vless-rust.json --listen 0.0.0.0:18443
rust-core/target/release/vless-rust check --config /root/vless-rust.json
sudo bash rust-core/install.sh --config /root/vless-rust.json
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
python3 tools/regression.py
python3 tools/benchmark.py
```

参考下载器固定官方 `v26.11.9`，在解压前核对 GitHub 发布资产的 SHA-256；参考程序只用于测试。测试和测量生成的日志 / JSON 位于仓库 `.build/`，不会提交真实测试凭据。性能脚本只对本机回环的同一客户端与负载做比较，不能代表公网线路或 Linux 生产效果。

协议来源和许可见 [NOTICE.md](NOTICE.md)。
