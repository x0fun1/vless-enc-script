"""Same official client/load for Rust and Xray; local measurements, not a WAN claim."""
import argparse
import concurrent.futures
import ctypes
import hashlib
import json
import os
import pathlib
import platform
import socketserver
import tempfile
import threading
import time
import uuid
from interop import ROOT, CREATE_FLAGS, port, process, service, socks_connect, wait_port
import subprocess

BLOCK = bytes(range(256)) * 256

class Bulk(socketserver.BaseRequestHandler):
    def handle(self):
        with self.request.makefile("rb") as reader:
            line = reader.readline()
            if line == b"IDLE\n":
                self.request.sendall(b"A")
                reader.read()
                return
            count = int(line)
            while count:
                block = BLOCK[:min(count, len(BLOCK))]
                self.request.sendall(block)
                count -= len(block)

def metrics(pid):
    if os.name != "nt":
        status = pathlib.Path(f"/proc/{pid}/status").read_text()
        rss = int(next(line.split()[1] for line in status.splitlines() if line.startswith("VmRSS:"))) * 1024
        stat = pathlib.Path(f"/proc/{pid}/stat").read_text().split()
        cpu = (int(stat[13]) + int(stat[14])) / os.sysconf("SC_CLK_TCK")
        return {"rss_mib": rss / 2**20, "cpu_secs": cpu}
    from ctypes import wintypes as w
    class Counters(ctypes.Structure):
        _fields_ = [("cb", w.DWORD), ("PageFaultCount", w.DWORD)] + [(x, ctypes.c_size_t) for x in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage", "PrivateUsage")]
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    p = ctypes.WinDLL("psapi", use_last_error=True)
    k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    k.OpenProcess.restype = w.HANDLE
    k.CloseHandle.argtypes = [w.HANDLE]
    k.GetProcessTimes.argtypes = [w.HANDLE] + [ctypes.POINTER(w.FILETIME)] * 4
    p.GetProcessMemoryInfo.argtypes = [w.HANDLE, ctypes.POINTER(Counters), w.DWORD]
    handle = k.OpenProcess(0x410, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        count = Counters()
        count.cb = ctypes.sizeof(count)
        if not p.GetProcessMemoryInfo(handle, ctypes.byref(count), count.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        creation, exit_, kernel, user = [w.FILETIME() for _ in range(4)]
        if not k.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_), ctypes.byref(kernel), ctypes.byref(user)):
            raise ctypes.WinError(ctypes.get_last_error())
        cpu = sum((v.dwHighDateTime << 32) | v.dwLowDateTime for v in (kernel, user)) / 1e7
        return {"rss_mib": count.WorkingSetSize / 2**20, "private_mib": count.PrivateUsage / 2**20, "cpu_secs": cpu}
    finally:
        k.CloseHandle(handle)

def download(socks, target, size):
    with socks_connect(socks, target) as s:
        s.settimeout(60)
        s.sendall(str(size).encode() + b"\n")
        digest = hashlib.sha256()
        count = 0
        while count < size:
            data = s.recv(min(65536, size - count))
            if not data:
                raise EOFError("truncated download")
            digest.update(data)
            count += len(data)
        expected = hashlib.sha256()
        left = size
        while left:
            chunk = BLOCK[:min(left, len(BLOCK))]
            expected.update(chunk)
            left -= len(chunk)
        assert digest.digest() == expected.digest()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--idle-connections", type=int, default=64)
    parser.add_argument("--streams", type=int, default=4)
    parser.add_argument("--mib-per-stream", type=int, default=256)
    args = parser.parse_args()
    rust = ROOT / "rust-core/target/release" / ("vless-rust.exe" if os.name == "nt" else "vless-rust")
    xray = ROOT / ".build/reference" / ("xray.exe" if os.name == "nt" else "xray")
    output = ROOT / ".build/benchmark"
    output.mkdir(parents=True, exist_ok=True)
    results = []
    with service(Bulk) as target:
        for core in ("rust", "xray"):
            for trial in range(args.trials):
                with tempfile.TemporaryDirectory(dir=output) as directory:
                    d = pathlib.Path(directory)
                    keys = json.loads(subprocess.check_output([str(rust), "keygen"], text=True, creationflags=CREATE_FLAGS))
                    uid, node, socks = str(uuid.uuid4()), port(), port()
                    server = {"listen": f"127.0.0.1:{node}", "users": [uid], "decryption": keys["decryption"]} if core == "rust" else {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": node, "protocol": "vless", "settings": {"users": [{"id": uid}], "decryption": keys["decryption"]}, "streamSettings": {"method": "raw", "security": "none"}}], "outbounds": [{"protocol": "freedom", "settings": {}}]}
                    client = {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": socks, "protocol": "socks"}], "outbounds": [{"protocol": "vless", "settings": {"address": "127.0.0.1", "port": node, "id": uid, "encryption": keys["encryption"]}, "streamSettings": {"method": "raw", "security": "none"}}]}
                    if core == "xray":
                        # v26.11.9 blocks private destinations on VLESS by default.
                        # Allow only our loopback benchmark target explicitly.
                        server["outbounds"][0]["settings"] = {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}
                    else:
                        server["limits"] = {"allow_private_destinations": True}
                    (d / "server.json").write_text(json.dumps(server))
                    (d / "client.json").write_text(json.dumps(client))
                    env = os.environ.copy()
                    env["GOMAXPROCS"] = "4"
                    with process(rust if core == "rust" else xray, d / "server.json", output / f"{core}-{trial}-server.log", env) as server_process:
                        wait_port(node, server_process)
                        with process(xray, d / "client.json", output / f"{core}-{trial}-client.log", env) as client_process:
                            wait_port(socks, client_process)
                            download(socks, target, 2**20)
                            idle = []
                            try:
                                for _ in range(args.idle_connections):
                                    s = socks_connect(socks, target)
                                    s.sendall(b"IDLE\n")
                                    assert s.recv(1) == b"A"
                                    idle.append(s)
                                time.sleep(0.3)
                                before = metrics(server_process.pid)
                                start = time.perf_counter()
                                size = args.mib_per_stream * 2**20
                                with concurrent.futures.ThreadPoolExecutor(max_workers=args.streams) as pool:
                                    list(pool.map(lambda _: download(socks, target, size), range(args.streams)))
                                elapsed = time.perf_counter() - start
                                after = metrics(server_process.pid)
                                result = {"core": core, "trial": trial + 1, "idle_memory": before, "post_transfer_memory": after, "elapsed_secs": elapsed, "throughput_mib_s": args.streams * args.mib_per_stream / elapsed, "server_cpu_secs": after["cpu_secs"] - before["cpu_secs"]}
                                results.append(result)
                                print(json.dumps(result), flush=True)
                            finally:
                                for s in idle:
                                    s.close()
    report = {"platform": platform.platform(), "python": platform.python_version(), "reference": "Xray-core v26.11.9", "rust": "vless-rust 0.1.0 release", "load": vars(args), "notes": "Local loopback, same official client, payload hashes checked. RSS includes runtime and warmed pages; no claim about Linux or WAN speed.", "results": results}
    (output / "results.json").write_text(json.dumps(report, indent=2) + "\n")

if __name__ == "__main__":
    main()
