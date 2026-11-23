"""Real Xray-core v26.11.9 client -> independent Rust server, localhost only."""
import argparse
import concurrent.futures
import contextlib
import json
import os
import pathlib
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import uuid
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[2]
CREATE_FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

def exact(sock, n):
    out = bytearray()
    while len(out) < n:
        block = sock.recv(n - len(out))
        if not block:
            raise EOFError(f"short read {len(out)}/{n}")
        out.extend(block)
    return bytes(out)

def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def wait_port(p, process):
    until = time.monotonic() + 10
    while time.monotonic() < until:
        if process.poll() is not None:
            raise RuntimeError(f"process exited: {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", p), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"listener {p} did not start")

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(65536)
            if not data:
                # Delayed final data after upload EOF checks half-close handling.
                time.sleep(0.15)
                with contextlib.suppress(OSError):
                    self.request.sendall(b"HALF-CLOSE-OK")
                return
            self.request.sendall(data)

class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)

class ThreadTcp(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

class ThreadUdp(socketserver.ThreadingUDPServer):
    daemon_threads = True

class ThreadTcpV6(ThreadTcp):
    address_family = socket.AF_INET6

class ThreadUdpV6(ThreadUdp):
    address_family = socket.AF_INET6

@contextlib.contextmanager
def service(handler, udp=False, ipv6=False):
    cls = (ThreadUdpV6 if udp else ThreadTcpV6) if ipv6 else (ThreadUdp if udp else ThreadTcp)
    with cls(("::1" if ipv6 else "127.0.0.1", 0), handler) as s:
        thread = threading.Thread(target=s.serve_forever, daemon=True)
        thread.start()
        try:
            yield s.server_address[1]
        finally:
            s.shutdown()
            thread.join(timeout=2)

@contextlib.contextmanager
def process(binary, config, log, env=None):
    with open(log, "wb") as output:
        p = subprocess.Popen([str(binary), "run", "-config", str(config)], stdout=output, stderr=output, env=env, creationflags=CREATE_FLAGS)
        try:
            yield p
        finally:
            p.terminate()
            try:
                p.wait(timeout=4)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()

def socks_connect(socks, target, domain=False, ipv6=False):
    s = socket.create_connection(("127.0.0.1", socks), timeout=10)
    s.settimeout(15)
    s.sendall(b"\x05\x01\x00")
    assert exact(s, 2) == b"\x05\x00"
    address = b"\x03\x09localhost" if domain else b"\x01\x7f\x00\x00\x01"
    if ipv6:
        address = b"\x04" + socket.inet_pton(socket.AF_INET6, "::1")
    s.sendall(b"\x05\x01\x00" + address + struct.pack("!H", target))
    reply = exact(s, 4)
    assert reply[:2] == b"\x05\x00", reply
    if reply[3] == 1:
        exact(s, 6)
    elif reply[3] == 4:
        exact(s, 18)
    else:
        exact(s, exact(s, 1)[0] + 2)
    return s

def tcp_case(socks, target, domain=False, size=131071, ipv6=False):
    with socks_connect(socks, target, domain, ipv6) as s:
        payload = os.urandom(size)
        # Upload and download simultaneously; exceeds record and OS buffers.
        sender = threading.Thread(target=s.sendall, args=(payload,))
        sender.start()
        assert exact(s, size) == payload
        sender.join(timeout=10)
        assert not sender.is_alive()
        # SOCKS/Xray may close its own full duplex transport on SOCKS EOF.
        # Half-close is verified directly against the Rust forwarding layer.

def udp_case(socks, target, ipv6=False):
    control = socket.create_connection(("127.0.0.1", socks), timeout=10)
    control.settimeout(10)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        control.sendall(b"\x05\x01\x00")
        assert exact(control, 2) == b"\x05\x00"
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        header = exact(control, 4)
        assert header[:2] == b"\x05\x00", header
        if header[3] == 1:
            relay = socket.inet_ntoa(exact(control, 4))
        elif header[3] == 4:
            relay = socket.inet_ntop(socket.AF_INET6, exact(control, 16))
        else:
            relay = exact(control, exact(control, 1)[0]).decode()
        relay_port = struct.unpack("!H", exact(control, 2))[0]
        if relay == "0.0.0.0":
            relay = "127.0.0.1"
        udp.settimeout(10)
        for n in (1, 100, 1400):
            payload = os.urandom(n)
            packet = b"\x00\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", target) + payload
            if ipv6:
                packet = b"\x00\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, "::1") + struct.pack("!H", target) + payload
            udp.sendto(packet, (relay, relay_port))
            reply, _ = udp.recvfrom(65536)
            assert reply[:3] == b"\x00\x00\x00"
            offset = 10 if reply[3] == 1 else 22 if reply[3] == 4 else 7 + reply[4]
            assert reply[offset:] == payload, (len(reply), n)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust", type=pathlib.Path, default=ROOT / "rust-core/target/debug" / ("vless-rust.exe" if os.name == "nt" else "vless-rust"))
    parser.add_argument("--reference", type=pathlib.Path, default=ROOT / ".build/reference" / ("xray.exe" if os.name == "nt" else "xray"))
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--relays-only", action="store_true")
    parser.add_argument("--reality", action="store_true", help="exercise experimental REALITY TLS 1.3 with the official client")
    parser.add_argument("--fingerprint", default="chrome", choices=("chrome", "firefox", "safari"), help="REALITY client TLS fingerprint")
    args = parser.parse_args()
    version = subprocess.check_output([str(args.reference), "version"], text=True, creationflags=CREATE_FLAGS)
    assert version.startswith("Xray 26.11.9 "), version
    output = ROOT / ".build/interop"
    output.mkdir(parents=True, exist_ok=True)
    report = []
    with service(Echo) as target, service(UdpEcho, udp=True) as udp_target:
        variants = [("x25519", "native", "aes", False)] if args.quick else [(a, m, c, mux) for a in ("x25519", "mlkem768") for m in ("native", "xorpub", "random") for c in ("aes", "chacha") for mux in (False, True)]
        if not args.quick:
            variants += [(a, m, "aes", -1) for a in ("x25519", "mlkem768") for m in ("native", "xorpub", "random")]
        if args.relays_only:
            variants = [("relay8", m, c, False) for m in ("native", "xorpub", "random") for c in ("aes", "chacha")]
        for auth, mode, cipher, mux in variants:
            label = f"{'reality-' + args.fingerprint + '-' if args.reality else ''}{auth}-{mode}-{cipher}-mux{int(mux)}"
            with tempfile.TemporaryDirectory(dir=output) as directory:
                d = pathlib.Path(directory)
                if auth == "relay8":
                    pairs = [json.loads(subprocess.check_output([str(args.rust), "keygen", "--auth", "x25519" if i % 2 == 0 else "mlkem768", "--mode", mode], text=True, creationflags=CREATE_FLAGS)) for i in range(8)]
                    keys = {field: ".".join(pairs[0][field].split(".")[:3] + [p[field].split(".")[-1] for p in pairs]) for field in ("decryption", "encryption")}
                else:
                    keys = json.loads(subprocess.check_output([str(args.rust), "keygen", "--auth", auth, "--mode", mode], text=True, creationflags=CREATE_FLAGS))
                node, socks = port(), port()
                uid = str(uuid.uuid4())
                config = {"listen": f"127.0.0.1:{node}", "users": [uid], "decryption": keys["decryption"], "log_connections": True, "limits": {"allow_private_destinations": True}}
                reality_link = None
                if args.reality:
                    reality_link = subprocess.check_output([str(args.rust), "init", "--config", str(d / "reality.json"), "--host", "127.0.0.1", "--reality", "--server-name", "example.com", "--target", f"127.0.0.1:{target}"], text=True, creationflags=CREATE_FLAGS).strip()
                    config["reality"] = json.loads((d / "reality.json").read_text())["reality"]
                (d / "server.json").write_text(json.dumps(config))
                client = {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": socks, "protocol": "socks", "settings": {"udp": True}}], "outbounds": [{"protocol": "vless", "settings": {"address": "127.0.0.1", "port": node, "id": uid, "encryption": keys["encryption"]}, "streamSettings": {"method": "raw", "security": "none"}, "mux": {"enabled": mux, "concurrency": 8}}]}
                if reality_link:
                    query = urllib.parse.parse_qs(urllib.parse.urlsplit(reality_link).query)
                    client["outbounds"][0]["streamSettings"].update({"security": "reality", "realitySettings": {"serverName": "example.com", "fingerprint": args.fingerprint, "publicKey": query["pbk"][0], "shortId": query["sid"][0], "spiderX": "/"}})
                if mux == -1:
                    client["outbounds"][0]["mux"] = {"enabled": False, "concurrency": -1, "xudpConcurrency": -1}
                (d / "client.json").write_text(json.dumps(client))
                environment = os.environ.copy()
                if cipher == "chacha":
                    environment["GODEBUG"] = "cpu.aes=off,cpu.pclmulqdq=off"
                server_log, client_log = output / f"{label}-server.log", output / f"{label}-client.log"
                with process(args.rust, d / "server.json", server_log) as server:
                    wait_port(node, server)
                    with process(args.reference, d / "client.json", client_log, environment) as client_process:
                        wait_port(socks, client_process)
                        try:
                            tcp_case(socks, target)
                            tcp_case(socks, target, domain=True)
                            udp_case(socks, udp_target)
                            if auth == "x25519" and mode == "native" and cipher == "aes":
                                with service(Echo, ipv6=True) as target6, service(UdpEcho, udp=True, ipv6=True) as udp6:
                                    tcp_case(socks, target6, ipv6=True)
                                    udp_case(socks, udp6, ipv6=True)
                            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                                list(pool.map(lambda _: tcp_case(socks, target, size=32769), range(8)))
                        except Exception:
                            print(server_log.read_text(errors="replace"))
                            print(client_log.read_text(errors="replace"))
                            raise
                log = server_log.read_text(errors="replace")
                if args.reality:
                    assert "reality_tls_group=" in log, "REALITY TLS handshake was not exercised"
                expected = "Aes" if cipher == "aes" else "ChaCha"
                assert f"cipher={expected}" in log, log
                if mux is False or mux == -1:
                    assert "handshake=0rtt" in log, "0-RTT resumption was not exercised"
                report.append({"case": label, "result": "passed", "cipher_verified": expected, "resumption_verified": mux is False or mux == -1})
                print(f"PASS {label}", flush=True)
    (output / ("reality-" + args.fingerprint + "-results.json" if args.reality else "relay-results.json" if args.relays_only else "results.json")).write_text(json.dumps(report, indent=2) + "\n")
    print(f"{len(report)} official client variants passed")

if __name__ == "__main__":
    main()
