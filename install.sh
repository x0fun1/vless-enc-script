#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_VERSION="v26.11.26-rust"
CORE_VERSION="0.3.3"
CORE_REFERENCE="Xray-core v26.11.9"
BUILD_ROOT=/usr/local/lib/vless-rust-build
WORK_DIR=''
usage() {
    cat <<EOF
VLESS Encryption Rust installer ${SCRIPT_VERSION}

Usage: sudo bash install.sh [options]
  --port PORT       Default port for this menu session (otherwise random 10000-60000)
  --host HOST       Public IP/hostname for new nodes (auto-detected if omitted)
  --auth MODE       x25519 or mlkem768 (default: x25519)
  --mode MODE       native, xorpub, or random (default: native)
  --no-menu         Install/update only; do not open the interactive menu
  -h, --help        Show this help

Installs the independent Rust core, then opens the venc multi-node menu.
No node or client link is created until you choose Create node.
Supports VLESS Encryption and experimental REALITY + XTLS Vision over direct TCP, with optional ML-DSA-65 certificate proof. The menu offers X25519- and ML-KEM-768-authenticated REALITY + Vision nodes. Target-derived TLS shaping is limited and does not provide full fingerprint parity.
EOF
}
fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
port='' host='' auth=x25519 mode=native menu=true
while (($#)); do
    case "$1" in
        --port|--host|--auth|--mode)
            (($# >= 2)) && [[ -n "$2" && "$2" != -* ]] || fail "Missing value for $1."
            case "$1" in --port) port=$2 ;; --host) host=$2 ;; --auth) auth=$2 ;; --mode) mode=$2 ;; esac
            shift 2 ;;
        --no-menu) menu=false; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "Unknown option: $1" ;;
    esac
done
if [[ -n "$port" ]]; then
    [[ "$port" =~ ^[0-9]{1,5}$ ]] && ((10#$port >= 1 && 10#$port <= 65535)) || fail 'Port must be between 1 and 65535.'
fi
[[ "$auth" == x25519 || "$auth" == mlkem768 ]] || fail 'Auth must be x25519 or mlkem768.'
[[ "$mode" == native || "$mode" == xorpub || "$mode" == random ]] || fail 'Mode must be native, xorpub, or random.'
[[ -z "$host" || "$host" =~ ^[A-Za-z0-9.:-]+$ ]] || fail 'Host contains unsupported characters.'
[[ "$(uname -s)" == Linux ]] || fail 'Linux is required.'
[[ "$(id -u)" == 0 ]] || fail 'Run as root: sudo bash install.sh'
command -v systemctl >/dev/null 2>&1 || fail 'systemd is required.'
for cmd in curl sha256sum tar ss shuf grep flock; do
    command -v "$cmd" >/dev/null 2>&1 && continue
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl coreutils tar iproute2 grep util-linux
        break
    fi
    fail "Missing required command '$cmd'; install it and rerun."
done
for cmd in curl sha256sum tar ss shuf grep flock; do command -v "$cmd" >/dev/null 2>&1 || fail "Required command '$cmd' is unavailable."; done
mkdir -p "$BUILD_ROOT"
chmod 0755 "$BUILD_ROOT"
WORK_DIR=$(mktemp -d "$BUILD_ROOT/deploy.XXXXXX")
cleanup() { local status=$?; [[ -z "$WORK_DIR" ]] || rm -rf -- "$WORK_DIR"; exit "$status"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
case "$(uname -m)" in
    x86_64|amd64) asset_arch=x86_64 ;;
    aarch64|arm64) asset_arch=aarch64 ;;
    *) fail 'Unsupported Linux architecture.' ;;
esac
release_url="https://github.com/x0fun1/vless-enc-script/releases/download/vless-rust-v${CORE_VERSION}"
download_verified() {
    local asset=$1 destination=$2 expected actual
    curl --proto '=https' --tlsv1.2 -fL --retry 3 "$release_url/$asset" -o "$destination"
    expected=$(curl --proto '=https' --tlsv1.2 -fsSL --retry 3 "$release_url/$asset.sha256")
    actual=$(sha256sum "$destination" | awk '{print $1}')
    [[ "$expected" =~ ^[0-9a-f]{64}$ && "$actual" == "$expected" ]] || fail "SHA-256 verification failed: $asset"
}
printf 'Downloading prebuilt vless-rust %s for %s...\n' "$CORE_VERSION" "$asset_arch"
binary=$WORK_DIR/vless-rust
download_verified "vless-rust-linux-${asset_arch}" "$binary"
chmod 0755 "$binary"
[[ "$("$binary" version)" == "vless-rust $CORE_VERSION reference $CORE_REFERENCE" ]] || fail 'Downloaded core version/protocol reference does not match.'
[[ "$("$binary" capabilities)" == *reality-experimental* ]] || fail 'Downloaded core lacks the required REALITY capability.'
# Versioned deployment bundle avoids using an old, pinned single-node installer
# or mixing a newer menu with an older core.
archive=$WORK_DIR/deploy.tar.gz
download_verified vless-rust-deploy.tar.gz "$archive"
mkdir "$WORK_DIR/deploy"
tar --no-same-owner -xzf "$archive" -C "$WORK_DIR/deploy" -- install.sh venc prefer-ipv4.sh systemd/vless-rust.service systemd/vless-rust@.service
for file in install.sh venc prefer-ipv4.sh systemd/vless-rust.service systemd/vless-rust@.service; do
    [[ -f "$WORK_DIR/deploy/$file" && ! -L "$WORK_DIR/deploy/$file" ]] || fail "Invalid deployment file: $file"
done
printf 'Installing core and management menu (no node will be created)...\n'
bash "$WORK_DIR/deploy/install.sh" --binary "$binary"
printf '\n安装完成。已有节点保持不变；请选择菜单 1 自行创建节点。\n以后可运行 sudo venc 管理多个节点。\n'
if [[ "$menu" == true ]]; then
    VENC_DEFAULT_PORT=$port VENC_DEFAULT_HOST=$host VENC_DEFAULT_AUTH=$auth VENC_DEFAULT_MODE=$mode /usr/local/bin/venc
fi
