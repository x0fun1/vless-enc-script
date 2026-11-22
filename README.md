# VLESS Encryption Rust

独立 Rust 实现的普通 VLESS Encryption 服务，协议参照 Xray-core `v26.11.9`。支持 TCP、UDP、Mux 和 XUDP；不支持 REALITY、Vision 或 TLS 外层。客户端必须支持 VLESS Encryption 的 `encryption` 参数，普通 VLESS 客户端不适用。

## 一条命令部署

在使用 systemd 的 Linux 主机上以 root 执行。脚本安装 Rust 工具链和构建依赖、下载固定源码、检查关键源码 SHA-256、生成配置和客户端链接、构建核心并安装/启动 systemd 服务：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/x0fun1/vless-enc-script/main/install.sh)
```

可选参数：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/x0fun1/vless-enc-script/main/install.sh) \
  --port 18443 --host YOUR_SERVER_IP --auth x25519 --mode native
```

`--port` 默认 `443`；省略 `--host` 时脚本尝试检测公网 IPv4/IPv6。认证可选 `x25519` 或 `mlkem768`，外观可选 `native`、`xorpub` 或 `random`，客户端设置必须相同。安装成功后链接写入 `/root/vless-rust_link.txt`，配置位于 `/usr/local/etc/vless-rust/config.json`。请在云安全组和主机防火墙放行所选 TCP 端口。

脚本适用于 Linux/systemd，缺少基础工具时自动使用 apt 安装依赖；其他发行版需预先提供 `curl`、`sha256sum`、`tar`、C 编译工具和 `pkg-config`。Rust 工具链固定为 `1.100.0`，Cargo 依赖由 `Cargo.lock` 锁定。已有配置会由 Rust 安装器保留；若该服务已有运行实例，更新后仍按原运行状态处理。

## 服务管理

```bash
systemctl status vless-rust --no-pager
journalctl -u vless-rust -f --no-pager
systemctl restart vless-rust
```

服务以独立的 `vless-rust` 系统账户运行。私钥配置权限为 `root:vless-rust`、`0640`；客户端链接权限为 `0600`。不能与其他服务同时绑定相同监听地址和端口。

## 本地构建与验证

```bash
cd rust-core
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked
python3 tools/regression.py
```

互通测试需要下载固定版本的官方 Xray 测试程序：

```bash
python3 tools/fetch_reference.py
python3 tools/interop.py --rust target/release/vless-rust
```

性能结果和验证范围见 [rust-core/VALIDATION.md](rust-core/VALIDATION.md)。核心尚未经过独立安全审计；上线前建议使用独立端口试运行。

协议实现范围、配置格式及从受支持 Xray 普通节点迁移的方式见 [rust-core/README.md](rust-core/README.md)。
