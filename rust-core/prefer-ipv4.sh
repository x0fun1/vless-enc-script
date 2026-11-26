#!/usr/bin/env bash
# Prefer IPv4 in glibc getaddrinfo() without disabling IPv6.
set -Eeuo pipefail
export LC_ALL=C

# VENC_ROOT keeps regression runs isolated from the host's /etc and /run.
PREFIX=${VENC_ROOT:-}
CONFIG=${PREFIX}/etc/gai.conf
LOCK=${PREFIX}/run/prefer-ipv4.lock
readonly BEGIN='# BEGIN prefer-ipv4.sh'
readonly END='# END prefer-ipv4.sh'
readonly SAVED='# prefer-ipv4.sh saved: '
readonly POLICY=$(printf '%s\n' \
    "$BEGIN" \
    'precedence ::1/128       50' \
    'precedence ::/0          40' \
    'precedence 2002::/16     30' \
    'precedence ::/96         20' \
    'precedence ::ffff:0:0/96 100' \
    "$END")
temp=''

die() { printf '错误：%s\n' "$*" >&2; exit 1; }
cleanup() { [[ -z "$temp" ]] || rm -f -- "$temp"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

usage() {
    cat <<'HELP'
用法：sudo prefer-ipv4 [enable|restore|status]

  enable   启用 IPv4 优先并备份当前 /etc/gai.conf 规则
  restore  移除本脚本策略并恢复原有 precedence 规则
  status   查看配置状态，无需 root
  help     显示帮助

适用于使用 glibc 的 Linux 系统。IPv6 仍可用。新进程会读取更新后的配置，
长期运行的服务可能需要重启。
HELP
}

require_platform() {
    [[ "$(uname -s)" == Linux ]] || die '此脚本仅支持 Linux。'
    local libc
    libc=$(getconf GNU_LIBC_VERSION 2>/dev/null) || die '未检测到 glibc。'
    [[ "$libc" == 'glibc '* ]] || die '此系统未使用 glibc。'
}

lock_config() {
    [[ "$(id -u)" == 0 ]] || die '请使用 root 或 sudo 运行。'
    command -v flock >/dev/null || die '缺少 flock 命令，请安装 util-linux。'
    install -d -m 0755 "${LOCK%/*}"
    exec 9>"$LOCK"
    flock -x 9
}

check_file() {
    [[ ! -L "$CONFIG" ]] || die "$CONFIG 是符号链接，请先检查链接目标。"
    [[ ! -e "$CONFIG" || -f "$CONFIG" ]] || die "$CONFIG 不是普通文件。"
    [[ ! -f "$CONFIG" || -r "$CONFIG" ]] || die "无法读取 $CONFIG。"
}

# Reject incomplete or duplicate markers instead of removing an uncertain range.
check_markers() {
    [[ -f "$CONFIG" ]] || return 0
    awk -v b="$BEGIN" -v e="$END" -v s="$SAVED" '
        $0 == b { if (seen || inside) bad = 1; seen++; inside = 1; next }
        $0 == e { if (!inside) bad = 1; ends++; inside = 0; next }
        index($0, s) == 1 { saved = 1; if (inside) bad = 1 }
        END { exit (bad || inside || seen != ends || (saved && !seen)) }
    ' "$CONFIG" || die '管理标记不完整或已损坏，请检查 gai.conf 及其备份。'
}

has_policy() {
    [[ -f "$CONFIG" ]] && grep -Fqx -- "$BEGIN" "$CONFIG"
}

check_policy() {
    local actual
    actual=$(awk -v b="$BEGIN" -v e="$END" '
        $0 == b { inside = 1 }
        inside { print }
        $0 == e { inside = 0 }
    ' "$CONFIG")
    [[ "$actual" == "$POLICY" ]] || die '受管理的策略块已被修改，请检查后再操作。'
}

check_extra_rules() {
    awk -v b="$BEGIN" -v e="$END" '
        $0 == b { inside = 1; next }
        $0 == e { inside = 0; next }
        !inside && /^[[:space:]]*precedence[[:space:]]/ { found = 1 }
        END { exit found }
    ' "$CONFIG" || die '管理块外发现其他 precedence 规则，请先运行 restore，再重新启用。'
}

backup_config() {
    local backup
    if [[ -f "$CONFIG" ]]; then
        backup=$(mktemp "${CONFIG}.prefer-ipv4.backup.$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")
        cp -p -- "$CONFIG" "$backup"
        printf '已创建备份：%s\n' "$backup"
    fi
}

prepare_temp() {
    temp=$(mktemp "${CONFIG}.prefer-ipv4.tmp.XXXXXX")
    if [[ -f "$CONFIG" ]]; then
        cp -p -- "$CONFIG" "$temp"
    else
        chmod 0644 "$temp"
    fi
}

enable_ipv4() {
    if has_policy; then
        check_policy
        check_extra_rules
        printf 'IPv4 优先已启用，无需重复修改。\n'
        return
    fi
    backup_config
    prepare_temp
    if [[ -f "$CONFIG" ]]; then
        awk -v s="$SAVED" '
            /^[[:space:]]*precedence[[:space:]]/ { print s $0; next }
            { print }
        ' "$CONFIG" >"$temp"
    fi
    printf '%s\n' "$POLICY" >>"$temp"
    mv -f -- "$temp" "$CONFIG"
    temp=''
    printf '已启用 IPv4 优先，IPv6 仍可用。\n新进程会读取更新后的配置，长期运行的服务可能需要重启。\n'
}

restore_config() {
    if ! has_policy; then
        printf '未找到本脚本设置的策略，无需恢复。\n'
        return
    fi
    check_policy
    backup_config
    prepare_temp
    awk -v b="$BEGIN" -v e="$END" -v s="$SAVED" '
        $0 == b { inside = 1; next }
        $0 == e { inside = 0; next }
        inside { next }
        index($0, s) == 1 { print substr($0, length(s) + 1); next }
        { print }
    ' "$CONFIG" >"$temp"
    mv -f -- "$temp" "$CONFIG"
    temp=''
    printf '已移除本脚本策略并恢复原有 precedence 规则。\n新进程会读取更新后的配置，长期运行的服务可能需要重启。\n'
}

show_status() {
    if has_policy; then
        check_policy
        check_extra_rules
        printf '状态：已启用本脚本的 IPv4 优先策略。\n'
    else
        printf '状态：未启用本脚本的 IPv4 优先策略，使用系统当前设置。\n'
    fi
    if [[ -f "$CONFIG" ]]; then
        printf '\n当前 precedence 规则：\n'
        awk '/^[[:space:]]*precedence[[:space:]]/ { print }' "$CONFIG"
    fi
    printf '\n此状态仅反映 gai.conf 配置，实际连接顺序还取决于应用和网络环境。\n'
}

main() {
    local action=${1:-enable}
    (( $# <= 1 )) || { usage >&2; exit 2; }
    case "$action" in
        help|-h|--help) usage; return ;;
        enable|restore|status) ;;
        *) usage >&2; exit 2 ;;
    esac
    require_platform
    if [[ "$action" != status ]]; then lock_config; fi
    check_file
    check_markers
    case "$action" in
        enable) enable_ipv4 ;;
        restore) restore_config ;;
        status) show_status ;;
    esac
}

main "$@"
