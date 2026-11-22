# vless-encryption

版本：`v26.11.22`

一键安装和管理 Xray 的 **VLESS Encryption**，可选叠加 **REALITY**。客户端及其内核须支持 VLESS Encryption、链接中的 `encryption` 参数和 Vision；仅支持普通 VLESS/REALITY 的客户端不适用。

## 使用

需要 **root、Bash、curl、systemd**，依赖安装支持 apt、dnf 或 yum；在交互终端运行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/x0fun1/vless-enc-script/main/install.sh)
```

选择 `1` 安装，再选择模式：

- **VLESS Encryption**：自身加密，不加 TLS 外层，`security=none` 不代表明文，无需 SNI。
- **VLESS Encryption + REALITY**：增加 TLS 外观；目标仅限 `www.nvidia.com`、`www.amd.com`、`www.intel.com`，须从服务器可达并支持 TLS 1.3 / H2，且不应重定向；无需自有域名或证书。目标可用性和重定向行为取决于服务器地区。

两种模式均使用 Vision，默认端口 `443`、UUID 自动生成。安装后导入节点链接，并在服务器防火墙及云安全组放行所选 **TCP 端口**。

## 管理

再次运行上方命令，按菜单更新、重启、卸载、修改配置 / 切换模式或查看订阅与日志。

- 配置：`/usr/local/etc/xray/config.json`；节点链接：`/root/xray_vless_link.txt`。
- 保存配置时会清除本地缓存的链接文件；如未能自动重新生成，可稍后用菜单 `7` 重试。客户端已导入的链接是否仍可用，取决于连接参数是否改变。
- 客户端参数：`/root/xray_encryption_info.txt`、`/root/xray_reality_info.txt`；含连接凭据，请勿公开。
- 日志：`journalctl -u xray -f --no-pager`，按 Ctrl+C 退出。
- **安装 / 重装覆盖整个 Xray 配置，含自定义内容，请先备份；重装后重新导入节点。**
- 修改只更新首个入站相关字段，保留其他配置；回车保留当前参数。REALITY 仅允许 `www.nvidia.com`、`www.amd.com`、`www.intel.com`，SNI 与 `target` 同步至该域名的 443 端口。域名可达性及重定向行为取决于服务器地区，请先确认目标支持 TLS 1.3 / H2 且不会跳转。
- 新配置使用官方 `users`、`method: raw` 和 REALITY `target` 字段；旧配置仍可读取，修改时迁移相关字段并保留其余内容。
- REALITY 配置已有 `mldsa65Seed` 时，订阅自动附带官方 `pqv` 验证公钥；客户端须支持 ML-DSA-65，默认不启用。
- 保留模式时保留加密密钥；**切换模式按默认 `x25519/native` 重生密钥，必须重新导入节点。** `mlkem768` 可通过 `--auth mlkem768` 显式选择。
- 重装、更新和修改配置保留原运行状态；重装和更新保留服务文件及启用状态（包括仅本次启动启用），失败时尝试回滚。恢复失败时保留快照，当前菜单只允许查看日志或退出。请勿并发运行。
- **卸载清除整个 Xray、配置、日志和客户端信息，含自定义内容；输入 `y` 确认，回车取消。** 成功后也会删除本地执行的脚本；上方远程命令不留下本地脚本。安装 / 更新会拒绝核心、数据、日志文件或安装目录的符号链接，以免官方原地写入修改链接目标。

<details>
<summary>无交互安装与参数</summary>

不带 `--sni` 安装 VLESS Encryption，添加 `--sni www.nvidia.com`、`--sni www.amd.com` 或 `--sni www.intel.com` 则安装 REALITY 模式；均覆盖已有配置，不询问重装确认：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/x0fun1/vless-enc-script/main/install.sh) install --port 12345
```

- `--port` 默认 `443`，`--uuid` 不填自动生成。
- `--sni` 无默认值；交互式 REALITY 安装默认 `www.nvidia.com`。仅允许 NVIDIA、AMD、Intel 这三个指定域名。
- `--short-id` 默认 `20220701`，须为 2–16 位偶数长度十六进制，仅与 `--sni` 同用。
- `--auth` 默认 `x25519`（密钥较短，非后量子认证），可选 `mlkem768`（ML-KEM-768，后量子认证）；两者均使用 `mlkem768x25519plus` 后量子密钥交换。
- `--mode` 默认 `native`（原始格式），可选 `xorpub`（混淆公钥部分）、`random`（全随机外观），客户端须与服务端一致。

一般保持默认认证和外观即可。在首次命令末尾加 `--help` 或 `install --help` 查看帮助。

</details>

回滚失败时保留报出的 `/tmp/xray-rollback.*` 或 `/tmp/xray-install-rollback.*`，按快照恢复配置、客户端信息及对应的核心 / 数据 / 服务文件，核对服务状态后再清理。重新运行不会识别旧快照，勿靠重启脚本绕过恢复。
