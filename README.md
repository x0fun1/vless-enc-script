# VLESS Encryption Rust

独立 Rust 实现的 VLESS Encryption 核心，协议参照 Xray-core `v26.11.9`。支持 TCP、UDP、Mux、XUDP；另提供**实验性的 XTLS Vision（直连 TCP）**和 **REALITY + VLESS Encryption**，REALITY 可选 ML-DSA-65 证书证明。不启动或嵌入 Go Xray。客户端必须支持 VLESS Encryption 的 `encryption` 参数。

> 当前公开菜单提供三类节点：普通 Encryption、REALITY + Vision（X25519 Encryption 认证）、REALITY + Vision（ML-KEM-768 Encryption 认证）。后两类均可选择启用额外 ML-DSA-65 证明（默认关闭）。组合已在 Windows localhost 对 Xray-core v26.11.9 完成 30 个官方客户端变体互通，并在 Debian 13 上通过 30 组组合互通及三种 systemd 节点访问 `www.nvidia.com`。ML-DSA-65 另覆盖正确 / 错误验证密钥。Vision 日志只观测到 downlink Direct 转换，uplink Direct 与完整 TLS 指纹等价并未证明。REALITY 仅在已测 TLS 目标形态下复刻 ServerHello / 初始记录特征，不是完整指纹等价、抗探测保证或安全审计。ML-DSA-65 大证书可能导致部分目标的记录长度无法匹配。其他公网目标、长时运行和独立安全审计仍待验证。

## 一条命令安装，菜单中创建节点

在使用 systemd 的 Linux 主机上以 root 执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/x0fun1/vless-enc-script/main/install.sh)
```

脚本下载对应架构的预编译核心和同版本部署包，校验 SHA-256，安装核心、服务模板和 `venc`，随后进入菜单。**安装本身不生成节点、UUID、密钥或客户端链接，也不会覆盖已有节点。** 服务器不需要 Rust/Cargo，不进行编译。

```text
1. 创建节点
2. 删除指定节点
3. 显示节点信息
4. 停止指定节点
5. 卸载核心和全部节点
6. 启动指定节点
7. 重启指定节点
8. 查看节点日志
9. 查看节点状态
10. 更新脚本并迁移旧版节点
0. 退出
```

- `1`：VLESS + Encryption，无 Reality；回车默认选择此类型。
- `2`：VLESS + Encryption + Reality + XTLS Vision，X25519 Encryption 认证。
- `3`：VLESS + Encryption + Reality + XTLS Vision，ML-KEM-768 Encryption 认证。

类型 2 / 3 可选择添加 ML-DSA-65 额外证书证明（默认关闭；启用时随机生成 seed，链接中的 `pqv` 公钥由 seed 派生）。TLS 的 REALITY 密钥、short ID、SpiderX 路径均由核心随机生成；公开 `pbk` 是随机生成私钥对应的 X25519 公钥，私钥不会放进链接。

类型 2 / 3 的 SNI 默认 `www.nvidia.com`，目标默认 `www.nvidia.com:443`；两项可单独输入自定义值。目标必须能从服务器访问且符合 REALITY TLS 1.3 探测支持范围。

每次创建都是**独立节点、独立配置和独立 systemd 服务**。旧节点的端口、UUID、密钥、链接和运行状态保持不变。启动失败只撤销新节点。停止的节点仍保留其端口分配；要释放分配，请删除该节点。

安装后随时运行：

```bash
sudo venc
```

安装参数 `--port`、`--host`、`--mode` 作为本次菜单会话中新节点的默认值；`--auth` 默认值只作用于普通类型 1（x25519 / mlkem768），Reality + Vision 类型 2 / 3 固定选择各自标示的认证模式。它们不会直接创建节点或改变旧节点。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/x0fun1/vless-enc-script/main/install.sh) \
  --host YOUR_SERVER_IP --port 18443 --auth x25519 --mode native
```

外观 `--mode` 支持 `native` / `xorpub` / `random`。仅安装或更新、不进入菜单：加 `--no-menu`。没有交互输入时，安装后展示菜单并退出，不会自动创建节点。

## 多节点文件和服务

每个新节点位于 `/usr/local/etc/vless-rust/nodes/node-<UUID去掉连字符>/`：

- `config.json`：私钥配置，`root:vless-rust`、`0640`。
- `public-host`：该节点的公网地址，`0600`。
- `link.txt`：该节点的客户端分享链接，`0600`。

菜单 **3** 可查看指定节点，回车查看全部；链接从当前配置重新生成，不依赖历史终端输出。菜单 **2 / 4 / 6 / 7 / 8 / 9** 只操作所选节点，**5** 才卸载全部节点。选择 **10** 并确认后，会从项目主分支下载最新安装脚本、更新核心和管理菜单，然后自动迁移旧版单节点（如果存在）。

旧版 `/usr/local/etc/vless-rust/config.json` 节点会显示为 `legacy`，在迁移前继续使用原 `vless-rust.service`、原地址和原凭据；不会被创建新节点覆盖。选择 **10** 更新后，脚本会将旧配置迁入独立节点目录，保留 UUID、端口、Encryption/Reality 凭据及原启停状态，并切换到模板服务。迁移校验或启动失败时会尝试恢复旧服务和配置；若旧节点缺少公网地址，会提示输入以重建分享链接。

新节点使用模板服务：

```bash
systemctl status vless-rust@node-<ID> --no-pager
journalctl -u vless-rust@node-<ID> -f --no-pager
```

服务以独立的 `vless-rust` 系统账户运行。请在云安全组和主机防火墙放行每个节点所选 TCP 端口。更新核心会保留配置及启用状态，并重启原来正在运行的节点，因此会短暂中断这些节点的现有连接；原来停止的节点不会被启动。

## 本地构建与验证

```bash
cd rust-core
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked
python3 tools/regression.py
python3 ../tests/regression.py
```

官方客户端互通测试：

```bash
python3 tools/fetch_reference.py
python3 tools/interop.py --rust target/release/vless-rust
python3 tools/interop.py --rust target/release/vless-rust --reality
python3 tools/interop.py --rust target/release/vless-rust --reality --vision
python3 tools/interop.py --rust target/release/vless-rust --reality --vision --mldsa65
python3 tools/regression.py
```

互通测试使用固定的 Xray-core v26.11.9。Windows localhost 和 Debian 13 / `www.nvidia.com` 的结果不代表其他公网目标兼容或完整 fingerprint parity。v0.3.1 已发布；远程一键安装入口现可获取对应二进制和部署包。核心尚未经过独立安全审计；验证记录见 [rust-core/VALIDATION.md](rust-core/VALIDATION.md)，审计缺口和报告流程见 [SECURITY.md](SECURITY.md)。
