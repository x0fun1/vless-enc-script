#!/usr/bin/env bash
# Install the core/manager/template without creating nodes. Existing nodes stay.
set -Eeuo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONFIG='' BINARY='' SNAPSHOT='' COMMITTED=false
CORE=/usr/local/bin/vless-rust
IPV4_HELPER=/usr/local/bin/prefer-ipv4
CONF=/usr/local/etc/vless-rust/config.json
MANAGER=/usr/local/bin/venc
UNIT=/etc/systemd/system/vless-rust.service
TEMPLATE=/etc/systemd/system/vless-rust@.service
ACTIVE=()
STAGED=()
usage() { printf 'Usage: sudo bash rust-core/install.sh [--binary FILE] [--config FILE]\nNo node is created by default. --config explicitly imports a legacy single node.\n'; }
while (($#)); do
    case "$1" in
        --config|--binary)
            (($# >= 2)) && [[ -n "$2" ]] || { usage >&2; exit 2; }
            if [[ "$1" == --config ]]; then CONFIG=$2; else BINARY=$2; fi
            shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
[[ "$(uname -s)" == Linux ]] || { printf 'Linux with systemd is required.\n' >&2; exit 1; }
[[ "$(id -u)" == 0 ]] || { printf 'Run with sudo or root.\n' >&2; exit 1; }
command -v systemctl >/dev/null
for path in /usr/local/bin /usr/local/etc /usr/local/etc/vless-rust /usr/local/etc/vless-rust/nodes /etc/systemd/system; do
    [[ ! -L "$path" && ( ! -e "$path" || -d "$path" ) ]] || { printf 'Invalid install directory: %s\n' "$path" >&2; exit 1; }
done
for path in "$CORE" "$IPV4_HELPER" "$CONF" "$UNIT" "$TEMPLATE" "$MANAGER"; do
    [[ ! -L "$path" && ( ! -e "$path" || -f "$path" ) ]] || { printf 'Invalid install target: %s\n' "$path" >&2; exit 1; }
done
if [[ -z "$BINARY" ]]; then
    command -v cargo >/dev/null || { printf 'Rust/Cargo are required for local builds.\n' >&2; exit 1; }
    cargo build --manifest-path "$ROOT/Cargo.toml" --locked --release
    BINARY="$ROOT/target/release/vless-rust"
fi
[[ -x "$BINARY" && "$("$BINARY" version)" == 'vless-rust 0.3.2 reference Xray-core v26.11.9' ]] || { printf 'Expected vless-rust 0.3.2, reference Xray-core v26.11.9.\n' >&2; exit 1; }
if ! getent group vless-rust >/dev/null; then groupadd --system vless-rust; fi
if ! id vless-rust >/dev/null 2>&1; then useradd --system --gid vless-rust --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin vless-rust; fi
install -d -m 0750 -o root -g vless-rust /usr/local/etc/vless-rust /usr/local/etc/vless-rust/nodes
# Lock before inspecting configurations/service state or taking snapshots.
exec 9>/usr/local/etc/vless-rust/.manager.lock
flock -n 9 || { printf 'Another installer/venc session is running.\n' >&2; exit 1; }
if [[ -n "$CONFIG" ]]; then
    [[ -f "$CONFIG" ]] || { printf 'Configuration not found.\n' >&2; exit 1; }
    "$BINARY" check --config "$CONFIG"
    # Even explicit imports must not silently replace a previous node.
    [[ ! -f "$CONF" ]] || cmp -s "$CONFIG" "$CONF" || { printf 'Existing legacy node differs; create a separate node using venc.\n' >&2; exit 1; }
fi
for config in "$CONF" /usr/local/etc/vless-rust/nodes/node-*/config.json; do
    [[ ! -f "$config" ]] || "$BINARY" check --config "$config"
done
for unit in vless-rust.service vless-rust@.service; do
    path=/etc/systemd/system/$unit
    if [[ ! -f "$path" ]]; then
        for vendor in "/usr/lib/systemd/system/$unit" "/lib/systemd/system/$unit" "/etc/systemd/system/$unit.d"; do
            [[ ! -e "$vendor" && ! -L "$vendor" ]] || { printf 'Existing service definition: %s\n' "$vendor" >&2; exit 1; }
        done
    fi
done
# Record running nodes; do not start stopped nodes or enable unused templates.
units=$(systemctl list-units --all --plain --no-legend 'vless-rust.service' 'vless-rust@*.service')
while read -r unit _; do
    [[ "$unit" == vless-rust.service || "$unit" =~ ^vless-rust@node-[0-9a-f]{32}\.service$ ]] || continue
    state=$(systemctl show --property=ActiveState --value "$unit")
    case "$state" in
        active) ACTIVE+=("$unit") ;;
        inactive|failed) ;;
        *) printf 'Service %s is changing state; retry later.\n' "$unit" >&2; exit 1 ;;
    esac
done <<< "$units"
SNAPSHOT=$(mktemp -d /tmp/vless-rust-rollback.XXXXXX)
PATHS=("$CORE" "$IPV4_HELPER" "$CONF" "$UNIT" "$TEMPLATE" "$MANAGER")
for i in "${!PATHS[@]}"; do [[ ! -f "${PATHS[i]}" ]] || cp -p -- "${PATHS[i]}" "$SNAPSHOT/$i"; done
cleanup() {
    local rc=$? i temporary failed=false
    trap - EXIT
    if ((rc != 0)) && [[ "$COMMITTED" == true ]]; then
        printf 'Install failed; restoring previous files and running nodes.\n' >&2
        for unit in "${ACTIVE[@]}"; do systemctl stop "$unit" || failed=true; done
        if [[ "$failed" == true ]]; then printf 'Could not stop nodes. Recovery snapshot: %s\n' "$SNAPSHOT" >&2; exit "$rc"; fi
        for i in "${!PATHS[@]}"; do
            path=${PATHS[i]}
            if [[ -f "$SNAPSHOT/$i" ]]; then
                temporary=$(mktemp "${path}.restore.XXXXXX") || { failed=true; continue; }
                cp -p -- "$SNAPSHOT/$i" "$temporary" && mv -Tf -- "$temporary" "$path" || failed=true
            else rm -f -- "$path" || failed=true; fi
        done
        systemctl daemon-reload || failed=true
        for unit in "${ACTIVE[@]}"; do systemctl reset-failed "$unit" || true; systemctl start "$unit" || failed=true; done
        if [[ "$failed" == true ]]; then printf 'Recovery incomplete. Snapshot: %s\n' "$SNAPSHOT" >&2; exit "$rc"; fi
    fi
    for temporary in "${STAGED[@]}"; do rm -f -- "$temporary"; done
    [[ -z "$SNAPSHOT" ]] || rm -rf -- "$SNAPSHOT"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
stage_file() {
    local source=$1 destination=$2 mode=$3 group=$4 temporary
    temporary=$(mktemp "${destination}.tmp.XXXXXX")
    STAGED+=("$temporary")
    install -m "$mode" -o root -g "$group" "$source" "$temporary"
    COMMITTED=true
    mv -Tf -- "$temporary" "$destination"
}
stage_file "$BINARY" "$CORE" 0755 root
stage_file "$ROOT/prefer-ipv4.sh" "$IPV4_HELPER" 0755 root
stage_file "$ROOT/venc" "$MANAGER" 0755 root
stage_file "$ROOT/systemd/vless-rust.service" "$UNIT" 0644 root
stage_file "$ROOT/systemd/vless-rust@.service" "$TEMPLATE" 0644 root
if [[ -n "$CONFIG" && ! -f "$CONF" ]]; then stage_file "$CONFIG" "$CONF" 0640 vless-rust; fi
systemctl daemon-reload
for unit in "${ACTIVE[@]}"; do
    systemctl reset-failed "$unit"
    systemctl restart "$unit"
    pid=$(systemctl show --property=MainPID --value "$unit")
    sleep 3
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] && systemctl is-active --quiet "$unit" && [[ "$pid" == "$(systemctl show --property=MainPID --value "$unit")" ]] || { printf 'Node %s did not stay running.\n' "$unit" >&2; exit 1; }
done
printf 'Installed vless-rust 0.3.2, venc and prefer-ipv4. Existing node configurations/enablement retained.\nRun sudo venc to create or manage nodes.\n'
