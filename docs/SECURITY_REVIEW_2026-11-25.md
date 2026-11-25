# 2026-11-25 安全审查与修复记录

本轮为维护性代码审查与修复，由参与实现的自动化助手执行，**不是第三方独立安全审计或渗透测试**。本报告记录已经确认的问题、修复方式、实际验证范围和剩余边界；通过这些检查不能证明不存在其他漏洞。

## 源码与发布范围

| 范围 | 标识 |
| --- | --- |
| 已发布 v0.3.1 功能基线 | `139f908ab1536bbf10ca8a10f658133cbfe0049b` |
| 发布来源文档基线 | `b466bf7e51fbf9045826ebbad41972e15bffd14d` |
| 本轮实现与 CI 修复快照 | `security/vision-fragment-eof` 分支提交 `87c9381e3409164bb48a0515b78e74694ce896d8`；后续文档提交记录其审查范围 |
| 互通参考 | 官方 Xray-core v26.11.9，源码 `676eaf66f8f05d4d558ee7a74b4736623d3feeb9` |

候选包含既有 Vision 补丁 `fc534857ed817982aa5b56db5786e40f1f5e2ecf`、`854802705e1be47edb096e5187d81e1d69d766ec`，但这两个提交不代表当前完整代码。包版本仍为 0.3.1，本轮尚未发布二进制；使用上述实现提交和下文二进制哈希识别候选，不能仅凭版本字符串识别。下文未执行 CI 的描述记录本地审查完成时的状态，推送后的状态以 GitHub 对应提交的检查结果为准。

审查覆盖 Rust 握手、记录层、Vision、Mux、目的地址与 REALITY 边界、配置读写、安装管理脚本和发布流程，并对 vendored rustls 0.23.46 的全部本地源码差异进行检查。实际运行的 TLS provider 是 Ring/std；AWS-LC 相关分支仅审阅源码，未运行。vendored 修改的来源、差异和限制见 [rustls PATCHES.md](../rust-core/vendor/rustls/PATCHES.md)。

## 已确认的问题与修复

### REALITY 固定目标绕过默认私网限制

旧实现的普通转发受 `allow_private_destinations` 控制，REALITY target 连接没有应用同一策略。若运营者配置的固定 target 本来位于私网，或其域名解析被改变为回环、私网或其他特殊用途地址，未认证 fallback 流量可被转发到该固定 host:port。客户端不能自行指定任意目标，因此这不是无条件的任意地址 SSRF。

修复后，REALITY 连接继承同一配置选项：私有或特殊用途域名在 DNS 前拒绝，解析得到的最多 64 个候选地址在发起 TCP 连接前全部检查。任一受限地址都会使连接失败。显式设置为 true 可用于受信任的私有目标和本地测试，但始终不能绕过自监听器检查。target capture 与独立 metadata TLS probe 都经过该连接策略。

验证包括私网 IPv4、IPv6、IPv4-mapped IPv6、特殊域名、公共地址、显式 opt-in、self-listener，以及真实 CLI fallback 的默认拒连和 opt-in 保持。单独 metadata probe 的证书链/SNI 验证不能证明另一条 capture 连接具有完全相同的行为。该策略控制出站目的地址，不限制来自 LAN 的入站客户端。

### 空系统证书库下的自定义 target CA

互通复测还发现，metadata probe 原先在加载系统根证书后立即要求根库非空，导致系统证书库为空时，即使已经配置有效的 `target_ca_certificates` 也会提前失败。现先合并 native roots 与严格解析的 custom roots，再检查最终根库是否为空；证书链和 SNI 验证继续执行。这是依赖部署证书库状态的可用性和配置兼容性问题，不是认证绕过。

新增确定性回归覆盖空系统库加有效自定义 CA、两者均空，以及系统根有效但自定义 CA 损坏时仍返回错误。

### Vision 帧截断与 Direct 记录交互

旧记录层在底层 EOF 时，未检查 Vision decoder 是否仍等待 UUID、命令、内容或填充，可能把不完整帧当成正常半关闭。新 EOF 校验拒绝这些部分帧，同时保留空连接、已完整接收的 Continue 帧和正常 End/Direct 边界的关闭行为。

随机外观的 Direct 读取还会在短 TLS 记录已经完整到达后，继续等待下一条记录以填满调用者缓冲区，使请求响应流量停滞。修复为一次正文读取有进展即返回。带 HeaderMask 的 random 路径会检查 Direct TLS 记录头/正文完整性，其写入端关闭时也会报告未完成的记录头或正文，避免把仍缓存的部分头视为成功发送；native/xorpub 的 Direct 直接透传，TLS 完整性由端点校验。短非 Vision 载荷一旦与 UUID 前缀不符，立即转发，不再等待凑满 21 字节。

回归覆盖每个 Vision 截断位置、完整 Continue 边界、真实 AEAD 记录读路径、双方向保持连接打开的短 Direct 记录，以及未完成的出站 Direct 头/正文。此前已有的分片 ClientHello/ServerHello、随机 header mask 和双向合成 Direct 测试保留。合成双向通过不等于官方客户端已实际验证完整双向 Direct parity。

### 配置限读与安全替换

原配置加载和导入先把整个文件读入内存，再检查 1 MiB 上限。现 Rust 配置读取和 Xray 导入最多读取上限加一个字节，超限立即拒绝；独立 Python 导入工具也采用同一限读方式。输入来自本地文件或特殊文件时，内存使用不再依赖输入的总长度。此修复不把配置文件视为远程未认证接口。

配置替换改为随机临时名并排他创建；仅在本次创建成功后进入写入与失败清理流程，避免清理碰撞文件。写入并同步后原子替换。在 Unix 上保留原 uid/gid，并用原模式与 0640 相交，维持已有服务组读权限，同时移除 world、可执行及组写权限。父目录同步兼容相对配置路径。

Windows 已验证超限配置和导入拒绝、重配置及凭据保留。Unix uid/gid、chmod 与目录同步路径在本轮 Windows 运行中无法验证，专门回归会明确跳过；Linux CI 已加入该用例，尚未形成 GitHub 通过结果。

### 同版本发布资产可被后续提交覆盖

旧工作流在 main push 时以 Cargo 包版本重复发布，并允许覆盖已有资产。源码 tag 可保持原位，二进制或部署包却来自后续提交，削弱版本来源的可追溯性。

工作流现将普通 main/PR/manual 验证与发布条件分开：只有 `vless-rust-v*` tag push 才进入 release，且 tag 必须与 Cargo 版本严格一致。`gh release create --verify-tag` 拒绝复用已有 release；资产先上传到草稿再公布。普通 job 只读仓库内容，写权限限 release job，checkout 不持久保存凭据，同 ref 的任务串行执行。

本地已解析工作流 YAML、检查内嵌 Bash 语法，并测试正确版本 tag 通过、错误 tag 拒绝。新的 GitHub Actions 流程尚未远端执行，本轮没有生成新 release。安装器下载 SHA-256 sidecar 的现有校验可检查同源下载完整性，但它不是签名，也不是独立的来源认证。

## 本轮验证状态

以下为本轮 Windows 工作树结果，历史 Debian/systemd 证据仍归属于此前发布基线。

| 检查 | 本轮结果 |
| --- | --- |
| Rust 单元测试 | 45 项通过 |
| Rust 格式、strict Clippy、locked/offline release build | 全部通过 |
| 核心 CLI/网络回归 | 17 项：16 通过，1 项 Unix ownership/permissions 用例在 Windows 跳过 |
| 部署/菜单回归 | 16 项通过 |
| 官方 Xray 普通 Encryption / Vision / REALITY + Vision | 同一最终 release 各 30 变体，共 90 项通过 |
| 官方 Xray relay-only | 6 项通过 |
| 官方 Xray 独立 REALITY quick | Chrome 1 项通过，含不相关 CA 导致 `UnknownIssuer` 的拒绝检查 |
| 官方 Xray REALITY + Vision + ML-DSA-65 quick | native 4 项、random 4 项通过，每项包含错误 `pqv` 拒绝检查 |
| 脚本与工作流静态检查 | 6 个 Python 文件 AST、1 个 YAML、3 个 Bash 脚本及 10 个工作流 Bash 块通过 |
| 新 Linux CI 与发布流程 | 本地静态检查通过，未在 GitHub 执行 |
| Debian/systemd、最低 Rust 版本、本轮发布包安装 | 本轮未复测 |
| AWS-LC provider | 仅源码检查，未运行 |

本轮 105 个互通用例均使用同一最终 `rust-core/target/release/vless-rust.exe`，其 SHA-256 为 `eea8652a02fb4c61cbc674d8b4efca1d911e7b7f2ec7ca615bf673dfa867c7f2`。排查时发现默认 debug 路径存在旧 0.2.0 二进制，因此该旧二进制得到的普通 30 变体结果不计入本轮候选证据。互通工具现默认 release 路径，并逐 suite 保存二进制版本、哈希及结果，避免组合间相互覆盖。复测命令和本地 JSON 文件名记录于 [VALIDATION.md](../rust-core/VALIDATION.md)。

本轮 REALITY 只测 Chrome 指纹，目标为 Windows localhost TLS echo/echo；没有复测 Firefox/Safari 或 Debian/systemd。历史 NVIDIA 公网目标和 Debian 结果不能作为本轮候选证据。

## 已知依赖漏洞检查

扫描时间为 **2026-11-25 12:53:53 UTC**。从 RustSec 官方 GitHub release 下载 cargo-audit **0.23.0**（2026-11-10 发布），并核对 release API 提供的 SHA-256。数据库使用官方仓库当日 HEAD `b9b8a3c2cb1f2a3c76ab17a551193568c9f8b7a4`（2026-11-25 11:10:30 UTC）固定快照，加载 **1,548** 条 advisory。

| 锁文件 | 总包数 | registry 包数 | 漏洞 | 警告 | 退出码 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `rust-core/Cargo.lock` | 131 | 129 | 0 | 0 | 0 |
| `rust-core/vendor/rustls/Cargo.lock` | 134 | 133 | 0 | 0 | 0 |

扫描未忽略 advisory，也未按 OS/CPU 过滤。参数 `--no-fetch --no-yanked --json` 使扫描使用已固定的数据库快照，并禁用撤回版本检查。vendor lock 包括开发和可选依赖，不全部进入应用运行时。扫描识别已公开依赖公告，不审计本项目代码、密码学设计或 vendored rustls 自定义修改。

可核查的固定来源与校验值：

```text
Tool: https://github.com/rustsec/rustsec/releases/tag/cargo-audit%2Fv0.23.0
Windows ZIP SHA-256: aafeb61206730029601a72e669a12231f8674427e6248d02f6cb382cb36d56b4
Database: https://github.com/RustSec/advisory-db/tree/b9b8a3c2cb1f2a3c76ab17a551193568c9f8b7a4
Database snapshot ZIP SHA-256: a4b7bee2d106f1bd21a0422fcece171182583f12dcb00a419b18a79ad4b646bb
Application Cargo.lock SHA-256: 949886f3205f6919061a64ed3c30f8f5f5e05d30f87daa7316cc0770d2b3fc3c
Vendored Cargo.lock SHA-256: c845884bb7c73dc3384198d0f91584f03dd337ba197cd2c23d6ed51a71f7aa0f
```

数据库 Git clone 因环境网络错误失败后，改用上述固定 SHA 的官方快照成功扫描。因此 cargo-audit 原始 JSON 的 Git metadata 为 null；来源提交、快照哈希和扫描命令另存于本地证据。原始输出为 `.build/security/application-audit.json`、`.build/security/vendored-rustls-audit.json`，来源与命令汇总在 `.build/security/audit-summary.json`。这些下载和运行产物保留在被 Git 忽略的工作目录内。

## 尚需复核的边界

尚未建立任意目标的完整 TLS 指纹兼容性、PSK/resumption 或 post-handshake REALITY parity，也未完成长时间运行、移动网络、NAT 空闲和本轮 off-host ingress 测试。本轮未发现新的鉴权绕过，不代表已经证明鉴权与密码学设计安全。最终发布前仍需新候选的 Linux/systemd 实测、明确版本与源码映射，以及独立审查；范围见 [独立审查 brief](../SECURITY_AUDIT_BRIEF.md)。

