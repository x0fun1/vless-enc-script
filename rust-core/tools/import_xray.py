"""Convert this repository's plain Xray node to an independent Rust config."""
import argparse
import json
import os
import pathlib

def convert(value, listen=None):
    if set(value) - {"log", "inbounds", "outbounds"}:
        raise ValueError("Custom routing/DNS/policy requires manual migration; refusing silent conversion")
    if len(value.get("inbounds", [])) != 1:
        raise ValueError("Exactly one inbound is required")
    inbound = value["inbounds"][0]
    if set(inbound) - {"listen", "port", "protocol", "settings", "streamSettings", "tag"}:
        raise ValueError("Unsupported inbound extensions")
    if inbound.get("protocol") != "vless":
        raise ValueError("Only VLESS is supported")
    stream = inbound.get("streamSettings", {})
    if stream.get("security", "none") != "none":
        raise ValueError("REALITY/TLS is not supported by this plain Rust core")
    if stream.get("method", stream.get("network", "raw")) not in ("tcp", "raw"):
        raise ValueError("Only raw TCP transport is supported")
    if set(stream) - {"security", "method", "network"}:
        raise ValueError("Custom transport/socket settings require manual migration")
    settings = inbound["settings"]
    if set(settings) - {"clients", "users", "decryption", "flow"}:
        raise ValueError("Unsupported VLESS settings")
    default_flow = settings.get("flow", "") or ""
    if default_flow not in ("", "xtls-rprx-vision"):
        raise ValueError("Unsupported VLESS flow")
    users = settings.get("clients", settings.get("users", []))
    if not users or any(set(u) - {"id", "flow", "email", "level"} or u.get("level", 0) != 0 for u in users):
        raise ValueError("Unsupported user settings")
    flows = [u.get("flow", default_flow) or "" for u in users]
    if any(flow not in ("", "xtls-rprx-vision") for flow in flows):
        raise ValueError("Unsupported VLESS user flow")
    if len(set(flows)) != 1:
        raise ValueError("Mixed per-user flows cannot be represented by this Rust node")
    outbounds = value.get("outbounds", [])
    if len(outbounds) != 1 or outbounds[0].get("protocol") != "freedom":
        raise ValueError("Exactly one direct freedom outbound is required")
    outbound = outbounds[0]
    if set(outbound) - {"protocol", "settings", "streamSettings", "tag"} or outbound.get("settings"):
        raise ValueError("Custom outbound settings require manual migration")
    if outbound.get("streamSettings", {}) not in ({}, {"sockopt": {"domainStrategy": "UseIPv4v6"}}):
        raise ValueError("Custom outbound socket settings require manual migration")
    host = inbound.get("listen", "::")
    address = f"[{host}]:{inbound['port']}" if ":" in host else f"{host}:{inbound['port']}"
    return {"listen": listen or address, "users": [u["id"] for u in users], "decryption": settings["decryption"], "vision": flows[0] == "xtls-rprx-vision"}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, type=pathlib.Path)
    p.add_argument("--output", required=True, type=pathlib.Path)
    p.add_argument("--listen", help="Optional separate test listener, e.g. 127.0.0.1:18443")
    a = p.parse_args()
    result = convert(json.loads(a.input.read_text(encoding="utf-8")), a.listen)
    fd = os.open(a.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    print(f"Converted {len(result['users'])} users; validate with vless-rust check --config {a.output}")

if __name__ == "__main__":
    main()
