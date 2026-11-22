#!/usr/bin/env bash
# Install only the independent Rust service. Build and validate before commit.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONFIG=""
BINARY=""
CORE=/usr/local/bin/vless-rust
CONF=/usr/local/etc/vless-rust/config.json
UNIT=/etc/systemd/system/vless-rust.service
SNAPSHOT=""
STAGED_CORE=""
STAGED_CONF=""
COMMITTED=false
WAS_ACTIVE=false
WAS_ENABLED=absent

usage() { printf 'Usage: sudo bash rust-core/install.sh --config FILE [--binary FILE]\n'; }
while [ "$#" -gt 0 ]; do
    case "$1" in
        --config|--binary)
            [ "$#" -ge 2 ] || { usage >&2; exit 2; }
            if [ "$1" = --config ]; then CONFIG=$2; else BINARY=$2; fi
            shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
[ "$(uname -s)" = Linux ] || { printf 'Linux with systemd is required.\n' >&2; exit 1; }
[ "$(id -u)" = 0 ] || { printf 'Run with sudo or root.\n' >&2; exit 1; }
[ -f "$CONFIG" ] || { printf 'An existing Rust configuration is required.\n' >&2; exit 1; }
command -v systemctl >/dev/null
for path in /usr/local/bin /usr/local/etc /usr/local/etc/vless-rust /etc/systemd/system; do
    [ ! -L "$path" ] && { [ ! -e "$path" ] || [ -d "$path" ]; } || { printf 'Invalid install directory: %s\n' "$path" >&2; exit 1; }
done
for path in "$CORE" "$CONF" "$UNIT"; do
    [ ! -L "$path" ] && { [ ! -e "$path" ] || [ -f "$path" ]; } || { printf 'Invalid install target: %s\n' "$path" >&2; exit 1; }
done
if [ -z "$BINARY" ]; then
    command -v cargo >/dev/null || { printf 'Rust 1.89+ and Cargo are required to build.\n' >&2; exit 1; }
    cargo build --manifest-path "$ROOT/Cargo.toml" --locked --release
    BINARY="$ROOT/target/release/vless-rust"
fi
[ -x "$BINARY" ] || { printf 'Binary is not executable.\n' >&2; exit 1; }
case "$("$BINARY" version)" in
    'vless-rust 0.1.1 reference Xray-core v26.11.9') ;;
    *) printf 'Expected vless-rust 0.1.1, reference Xray-core v26.11.9.\n' >&2; exit 1 ;;
esac
"$BINARY" check --config "$CONFIG"

if [ -f "$UNIT" ]; then
    state=$(systemctl show --property=ActiveState --value vless-rust)
    case "$state" in active) WAS_ACTIVE=true ;; inactive|failed) ;; *) printf 'Service is changing state; retry later.\n' >&2; exit 1 ;; esac
    WAS_ENABLED=$(systemctl is-enabled vless-rust 2>/dev/null || true)
    case "$WAS_ENABLED" in enabled|disabled|enabled-runtime) ;; *) printf 'Unsupported existing enablement: %s\n' "$WAS_ENABLED" >&2; exit 1 ;; esac
else
    # Refuse vendor units or residual drop-ins under the same service name.
    for path in /etc/systemd/system/vless-rust.service.d /usr/lib/systemd/system/vless-rust.service /lib/systemd/system/vless-rust.service; do
        [ ! -e "$path" ] && [ ! -L "$path" ] || { printf 'Existing service definition: %s\n' "$path" >&2; exit 1; }
    done
fi

SNAPSHOT=$(mktemp -d /tmp/vless-rust-rollback.XXXXXX)
chmod 700 "$SNAPSHOT"
for kind in core conf unit; do
    case "$kind" in core) path=$CORE ;; conf) path=$CONF ;; unit) path=$UNIT ;; esac
    if [ -f "$path" ]; then cp -p -- "$path" "$SNAPSHOT/$kind"; fi
done

cleanup() {
    local rc=$? failed=false kind path temporary
    trap - EXIT
    if [ "$rc" -ne 0 ] && [ "$COMMITTED" = true ]; then
        printf 'Install failed; restoring Rust service files.\n' >&2
        if ! systemctl stop vless-rust; then
            printf 'Unable to stop service; retain snapshot %s for recovery.\n' "$SNAPSHOT" >&2
            exit "$rc"
        fi
        for kind in core conf unit; do
            case "$kind" in core) path=$CORE ;; conf) path=$CONF ;; unit) path=$UNIT ;; esac
            if [ -f "$SNAPSHOT/$kind" ]; then
                temporary=$(mktemp "${path}.restore.XXXXXX") || { failed=true; continue; }
                cp -p -- "$SNAPSHOT/$kind" "$temporary" && mv -Tf -- "$temporary" "$path" || failed=true
            else rm -f -- "$path" || failed=true; fi
        done
        systemctl daemon-reload || failed=true
        case "$WAS_ENABLED" in
            absent|disabled) systemctl disable vless-rust >/dev/null 2>&1 || true ;;
            enabled) systemctl enable vless-rust || failed=true ;;
            enabled-runtime) systemctl enable --runtime vless-rust || failed=true ;;
        esac
        if [ "$WAS_ACTIVE" = true ]; then systemctl start vless-rust || failed=true; fi
        if [ "$failed" = true ]; then
            printf 'Recovery incomplete. Snapshot: %s\n' "$SNAPSHOT" >&2
            exit "$rc"
        fi
    fi
    [ -z "$STAGED_CORE" ] || rm -f -- "$STAGED_CORE"
    [ -z "$STAGED_CONF" ] || rm -f -- "$STAGED_CONF"
    [ -z "$SNAPSHOT" ] || rm -rf -- "$SNAPSHOT"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! getent group vless-rust >/dev/null; then groupadd --system vless-rust; fi
if ! id vless-rust >/dev/null 2>&1; then
    useradd --system --gid vless-rust --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin vless-rust
fi
install -d -m 0750 -o root -g vless-rust /usr/local/etc/vless-rust
STAGED_CORE=$(mktemp /usr/local/bin/vless-rust.tmp.XXXXXX)
STAGED_CONF=$(mktemp /usr/local/etc/vless-rust/config.json.tmp.XXXXXX)
install -m 0755 "$BINARY" "$STAGED_CORE"
install -m 0640 -o root -g vless-rust "$CONFIG" "$STAGED_CONF"
COMMITTED=true
mv -Tf -- "$STAGED_CORE" "$CORE"
mv -Tf -- "$STAGED_CONF" "$CONF"
install -m 0644 "$ROOT/systemd/vless-rust.service" "$UNIT"
systemctl daemon-reload
if [ "$WAS_ENABLED" = absent ]; then systemctl enable vless-rust; fi
if [ "$WAS_ACTIVE" = true ] || [ "$WAS_ENABLED" = absent ]; then
    systemctl reset-failed vless-rust
    systemctl restart vless-rust
    pid=$(systemctl show --property=MainPID --value vless-rust)
    sleep 3
    [ "$pid" -gt 0 ] && systemctl is-active --quiet vless-rust &&
        [ "$pid" = "$(systemctl show --property=MainPID --value vless-rust)" ] ||
        { printf 'Rust service did not stay running; see journalctl -u vless-rust.\n' >&2; exit 1; }
fi
printf 'Installed vless-rust 0.1.1. Logs: journalctl -u vless-rust -f --no-pager\n'
