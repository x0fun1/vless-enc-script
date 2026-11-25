# 开发与仓库维护

当前包版本仍为 **0.3.1**；本轮安全修复是尚未发布的候选。已发布的 v0.3.1 资产不包含本轮改动，后续发布必须使用新版本和新 tag。实际执行过的检查及平台限制见 [rust-core/VALIDATION.md](rust-core/VALIDATION.md)，不要将历史 Debian / systemd 结果视为候选版本的验证结果。

## 仓库地图

| 路径 | 用途 |
| --- | --- |
| `rust-core/src/` | 独立协议、认证、配置及转发实现 |
| `rust-core/vendor/rustls/` | 带本地补丁的 TLS 实现；补丁范围见 `PATCHES.md`，保留上游许可 |
| `rust-core/tools/` | 固定官方参考下载、互通、CLI 回归、性能测量及配置导入工具 |
| `tests/regression.py` | 使用隔离目录及模拟命令的安装器 / 菜单回归 |
| `install.sh`、`rust-core/install.sh`、`rust-core/venc`、`rust-core/systemd/` | 下载入口、本地安装、多节点管理及 Linux 服务 |
| `.github/workflows/rust-core-release.yml` | Linux x86_64 / aarch64 构建验证及 tag 发布 |
| `SECURITY.md`、`SECURITY_AUDIT_BRIEF.md`、`rust-core/VALIDATION.md` | 安全范围、审查入口和验证记录 |
| `.build/`、`rust-core/target/` | 已忽略的本地下载、日志、临时配置及构建产物 |

配置、客户端链接和测试日志可能含连接凭据。保持生成物位于已忽略的目录，提交前检查差异；不要提交真实节点配置或密钥。

## 开发环境

- 安装 Rust / rustup，使用 `rust-core/rust-toolchain.toml` 固定的 **1.100.0**，并安装 rustfmt、clippy 及平台链接工具。Windows 的 MSVC 工具链需要 Visual Studio C++ Build Tools 和 Windows SDK。
- 安装 Python **3.10 或更新版本**；仓库 Python 工具使用标准库。以下命令用 `python`，Linux 可改为 `python3`。
- Windows 部署回归需要 Git for Windows 的 Git Bash。测试会选择实际的 MSYS Bash，并为模拟命令设置 PATH；Linux 需要 Bash。
- REALITY / Vision TLS 互通需要 PATH 中的 OpenSSL，支持 `req -addext` 和 `x509 -copy_extensions`；可使用 OpenSSL 3。
- 官方参考下载器固定 **Xray-core v26.11.9** 及资产 SHA-256，当前支持 Windows / Linux x86_64；不把生产服务所用 Xray 当作测试依赖。

Windows PowerShell 可按实际安装位置设置 PATH，先确认工具能被发现：

```powershell
$env:Path = "$env:USERPROFILE/.cargo/bin;C:/Program Files/Git/usr/bin;C:/Program Files/Git/bin;" + $env:Path
$env:PYTHONIOENCODING = 'utf-8'
python --version
openssl version
```

## 本地检查

从仓库根目录执行。显式工具链参数保证从根目录也使用相同 Rust 版本：

```text
cargo +1.100.0 fmt --manifest-path rust-core/Cargo.toml -- --check
cargo +1.100.0 test --manifest-path rust-core/Cargo.toml --locked
cargo +1.100.0 clippy --manifest-path rust-core/Cargo.toml --locked --all-targets -- -D warnings
cargo +1.100.0 build --manifest-path rust-core/Cargo.toml --release --locked
python rust-core/tools/fetch_reference.py
python rust-core/tools/regression.py
python tests/regression.py
git diff --check
```

完整 CLI 回归需要先构建 release 二进制并下载固定官方参考。`tests/regression.py` 模拟系统命令，不能代替 Linux 上真实安装、服务启停、迁移回滚和权限检查。所有平台结果应在验证记录中写明；Windows 无法验证 Unix 配置属主 / 属组及 systemd 行为。

Windows 官方客户端互通示例：

```powershell
python rust-core/tools/interop.py --rust rust-core/target/release/vless-rust.exe
python rust-core/tools/interop.py --rust rust-core/target/release/vless-rust.exe --vision
python rust-core/tools/interop.py --rust rust-core/target/release/vless-rust.exe --reality --vision
python rust-core/tools/interop.py --rust rust-core/target/release/vless-rust.exe --quick --reality --vision --mldsa65 --appearance random
```

互通脚本默认使用 release 二进制；显式指定 `--rust` 便于复核。运行时会输出二进制路径、版本和 SHA-256，并按 suite 保存结果及 metadata，便于确认结果对应的程序。

Linux 使用 `python3`，将 `--rust` 后的路径改为 `rust-core/target/release/vless-rust`。互通工具为回环测试目标生成临时凭据，并在临时配置中显式设置 `limits.allow_private_destinations: true`；这不是生产部署默认值。该开关只控制服务器出站目标，局域网客户端连接本服务无需因此放开目标策略。

## CI 的 Node.js 运行时

截至 2026-11-25，Node.js 官方最新 LTS 为 26.13.1。本仓库构建使用 Rust、Python 和 Bash；工作流引用的 `actions/checkout@v7`、`actions/upload-artifact@v7`、`actions/download-artifact@v8` 则由上游 metadata 声明使用 `node24`。Action 自身的 Node 运行时由 GitHub runner 与 `runs.using` 决定，`setup-node` 只改变供后续命令使用的 PATH，不能将这些 Action 切换为 Node 26。更新 CI 时应检查上游 Action 和 runner 的支持范围。来源：[Node.js 下载页](https://nodejs.org/en/download)、[GitHub Action metadata](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax#runsusing-for-javascript-actions)。

Rust 工具链 Action 的 `cache-workspaces` 指向 `rust-core -> target`，让缓存从 `rust-core/Cargo.toml` 读取元数据，并缓存该目录下的 `target/`。仅为 Cargo 命令指定 `working-directory` 不会改变另一个 Action 的缓存目录。

## 版本与发布

当前工作流在涉及核心、部署或工作流的 main / PR 变更，以及 `workflow_dispatch` 手动触发时执行构建和检查。它们不会发布；只有推送 `vless-rust-v*` tag 才进入发布任务，且 tag 必须与 Cargo 包版本完全匹配。新工作流尚需 GitHub 实际运行验证。

后续发布按以下顺序进行：

1. 选择尚未使用的新版本，同步 `rust-core/Cargo.toml`、`rust-core/Cargo.lock` 中本包版本、根目录 `install.sh` 的 `CORE_VERSION`、`rust-core/install.sh` 的版本校验与提示，以及相关文档。CLI 版本由 `CARGO_PKG_VERSION` 派生，部署回归会从 Cargo 包版本检查两层安装器是否一致。
2. 完成本地检查，提交待发布改动，检查 main 上 x86_64 / aarch64 两个构建结果，并按验证缺口补做 Linux 部署和权限检查。
3. 经维护者授权，在待发布提交上创建并推送匹配的新 tag，例如下一版为 0.3.2 时使用 `vless-rust-v0.3.2`。本轮不创建或推送 tag。tag 触发的两个架构构建都成功且版本校验通过后，发布任务才会运行。
4. 核对 release 记录的源码提交、两个架构的二进制、`venc`、部署归档及各自 SHA-256 文件，再检查远程安装入口取得相同新版本。

工作流使用 `gh release create`，已有同 tag release 会报错，不能覆盖既有资产。不要移动已发布 tag 或复用版本；修复已发布版本应再升版。失败后若留下草稿，先核对其源码和资产，由维护者处理后再重试。与资产一起下载的 SHA-256 文件用于完整性核对，不是签名或独立来源认证。
