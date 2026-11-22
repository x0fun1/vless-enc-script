#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_VERSION="v26.11.22-rust"
CORE_VERSION="0.1.1"
CORE_REFERENCE="Xray-core v26.11.9"
CORE_SOURCE_REF="0c794cf6cb5bffa70cf64c76fa7b463df09e5852"
BUILD_ROOT=/usr/local/lib/vless-rust-build
WORK_DIR=""

usage() {
    cat <<EOF
VLESS Encryption Rust installer ${SCRIPT_VERSION}

Usage: sudo bash install.sh [options]
  --port PORT       Listen port (default: random from 10000-60000)
  --host HOST       Public IP or hostname (auto-detected if omitted)
  --auth MODE       x25519 or mlkem768 (default: x25519)
  --mode MODE       native, xorpub, or random (default: native)
  -h, --help        Show this help

Installs the independent plain VLESS Encryption Rust core as a systemd service.
REALITY and Vision are not supported by this core.
EOF
}

fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }

port='' host='' auth=x25519 mode=native
while (($#)); do
    case "$1" in
        --port|--host|--auth|--mode)
            (($# >= 2)) && [[ -n "$2" && "$2" != -* ]] || fail "Missing value for $1."
            case "$1" in
                --port) port=$2 ;;
                --host) host=$2 ;;
                --auth) auth=$2 ;;
                --mode) mode=$2 ;;
            esac
            shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) fail "Unknown option: $1" ;;
    esac
done
if [[ -n "$port" ]]; then
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || fail 'Port must be between 1 and 65535.'
    ((10#$port >= 1 && 10#$port <= 65535)) || fail 'Port must be between 1 and 65535.'
fi
[[ "$auth" == x25519 || "$auth" == mlkem768 ]] || fail 'Auth must be x25519 or mlkem768.'
[[ "$mode" == native || "$mode" == xorpub || "$mode" == random ]] || fail 'Mode must be native, xorpub, or random.'
if [[ -n "$host" ]]; then
    [[ "$host" =~ ^[A-Za-z0-9.:-]+$ ]] || fail 'Host contains unsupported characters.'
fi
[[ "$(uname -s)" == Linux ]] || fail 'Linux is required.'
[[ "$(id -u)" == 0 ]] || fail 'Run as root: sudo bash install.sh'
command -v systemctl >/dev/null 2>&1 || fail 'systemd is required.'

for cmd in curl sha256sum tar ss shuf grep; do
    command -v "$cmd" >/dev/null 2>&1 && continue
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl coreutils tar iproute2 grep
        break
    fi
    fail "Missing required command '$cmd'; install it and rerun."
done
for cmd in curl sha256sum tar ss shuf grep; do command -v "$cmd" >/dev/null 2>&1 || fail "Required command '$cmd' is unavailable."; done
mkdir -p "$BUILD_ROOT"
chmod 0755 "$BUILD_ROOT"

WORK_DIR=$(mktemp -d "$BUILD_ROOT/deploy.XXXXXX")
cleanup() {
    local status=$?
    [[ -z "$WORK_DIR" ]] || rm -rf -- "$WORK_DIR"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

archive="$WORK_DIR/source.tar.gz"
printf 'Downloading Rust core source at %s...\n' "$CORE_SOURCE_REF"
curl --proto '=https' --tlsv1.2 -fL --retry 3 \
    "https://github.com/x0fun1/vless-enc-script/archive/${CORE_SOURCE_REF}.tar.gz" \
    -o "$archive"
mkdir "$WORK_DIR/unpacked"
tar -xzf "$archive" -C "$WORK_DIR/unpacked" --strip-components=1
ROOT="$WORK_DIR/unpacked/rust-core"
[[ -f "$ROOT/Cargo.toml" && -f "$ROOT/install.sh" && -f "$ROOT/systemd/vless-rust.service" ]] || fail 'Pinned archive does not contain a complete rust-core tree.'

# Pin the build inputs independently of the archive transport.
declare -ar CORE_FILES=(
    'Cargo.toml e52e304e2d0fe5e87d82f5e52274ebd2096323cea2cbab29385237074265d0e4'
    'Cargo.lock bd9601e803b61eba2bbbd8ba338663cefc462218d12af039eb50930f40c52c09'
    'rust-toolchain.toml 6b1cf8341d9a08d76c6deb1e9df90a0b208d0ef0d00ee05e0173e9cd4f0f425d'
    'src/blake3_reference.rs 416bab857b6622cee197f4d82955aa29aa42803c47e97f43e131e091a9ce6b6e'
    'src/config.rs 0cb689884d7053dfb495424e2a4b6b30df576a38672e88006a53857f2baf6fe8'
)
for entry in "${CORE_FILES[@]}"; do
    read -r file expected <<< "$entry"
    actual=$(sha256sum "$ROOT/$file" | awk '{print $1}')
    [[ "$actual" == "$expected" ]] || fail "Pinned source checksum mismatch: $file"
done

if [[ -z "$port" ]]; then
    for attempt in {1..100}; do
        candidate=$(shuf -i 10000-60000 -n 1)
        listeners=$(ss -H -ltn "sport = :$candidate") || fail 'Could not inspect listening TCP ports.'
        if [[ -z "$listeners" ]]; then port=$candidate; break; fi
    done
    [[ -n "$port" ]] || fail 'Could not find a free TCP port in 10000-60000.'
else
    listeners=$(ss -H -ltn "sport = :$port") || fail 'Could not inspect listening TCP ports.'
    [[ -z "$listeners" ]] || fail "TCP port $port is already in use."
fi

if [[ -z "$host" ]]; then
    host=$(curl --proto '=https' --tlsv1.2 -4fsS --max-time 8 https://api.ipify.org || true)
    if [[ ! "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        host=$(curl --proto '=https' --tlsv1.2 -6fsS --max-time 8 https://api64.ipify.org || true)
    fi
    [[ -n "$host" ]] || fail 'Could not detect public IP; rerun with --host.'
fi
[[ "$host" =~ ^[A-Za-z0-9.:-]+$ ]] || fail 'Detected host is invalid.'

machine=$(uname -m)
case "$machine" in
    x86_64|amd64) asset_arch=x86_64 ;;
    aarch64|arm64) asset_arch=aarch64 ;;
    *) fail "Unsupported Linux architecture: $machine" ;;
esac
printf 'Downloading prebuilt vless-rust %s for %s...\n' "$CORE_VERSION" "$asset_arch"
release_url="https://github.com/x0fun1/vless-enc-script/releases/download/vless-rust-v${CORE_VERSION}"
binary="$WORK_DIR/vless-rust"
curl --proto '=https' --tlsv1.2 -fL --retry 3 \
    "$release_url/vless-rust-linux-${asset_arch}" -o "$binary"
expected=$(curl --proto '=https' --tlsv1.2 -fsSL --retry 3 \
    "$release_url/vless-rust-linux-${asset_arch}.sha256")
actual=$(sha256sum "$binary" | awk '{print $1}')
[[ "$expected" =~ ^[0-9a-f]{64}$ && "$actual" == "$expected" ]] || fail 'Prebuilt binary SHA-256 verification failed.'
menu_script="$WORK_DIR/venc"
curl --proto '=https' --tlsv1.2 -fL --retry 3 "$release_url/venc" -o "$menu_script"
expected=$(curl --proto '=https' --tlsv1.2 -fsSL --retry 3 "$release_url/venc.sha256")
actual=$(sha256sum "$menu_script" | awk '{print $1}')
[[ "$expected" =~ ^[0-9a-f]{64}$ && "$actual" == "$expected" ]] || fail 'Management command SHA-256 verification failed.'
chmod 0755 "$binary" "$menu_script"
[[ "$("$binary" version)" == "vless-rust $CORE_VERSION reference $CORE_REFERENCE" ]] || fail 'Downloaded core version or protocol reference does not match the deployment pin.'

config="$WORK_DIR/config.json"
link=$("$binary" init --config "$config" --host "$host" --port "$port" --auth "$auth" --mode "$mode")
"$binary" check --config "$config"

printf 'Installing systemd service...\n'
bash "$ROOT/install.sh" --config "$config" --binary "$binary"
systemctl is-enabled --quiet vless-rust || fail 'Service is not enabled.'
systemctl is-active --quiet vless-rust || fail 'Service is not active.'
pid=$(systemctl show --property=MainPID --value vless-rust)
[[ "$pid" =~ ^[1-9][0-9]*$ ]] || fail 'Service has no running main process.'
sleep 3
systemctl is-active --quiet vless-rust || fail 'Service did not remain active.'
[[ "$(systemctl show --property=MainPID --value vless-rust)" == "$pid" ]] || fail 'Service process changed during startup verification.'

install -d -m 0700 /root
link_tmp=$(mktemp /root/vless-rust_link.txt.tmp.XXXXXX)
printf '%s\n' "$link" > "$link_tmp"
chmod 0600 "$link_tmp"
mv -Tf "$link_tmp" /root/vless-rust_link.txt
install -m 0755 "$menu_script" /usr/local/bin/venc
printf '%s\n' "$host" > "$WORK_DIR/public-host"
install -m 0600 "$WORK_DIR/public-host" /usr/local/etc/vless-rust/public-host
uuid=${link#vless://}
uuid=${uuid%%@*}
printf '\nVLESS+ENC configuration installed and active.\n'
printf 'Server IP/host: %s\n' "$host"
printf 'Port: %s/TCP\n' "$port"
printf 'UUID: %s\n' "$uuid"
printf 'Authentication: %s\n' "$auth"
printf 'Traffic mode: %s\n' "$mode"
printf 'Client configuration (VLESS + ENC):\n%s\n' "$link"
printf 'Service logs: journalctl -u vless-rust -f --no-pager\n'
