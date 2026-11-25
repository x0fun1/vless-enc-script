"""Real Xray-core v26.11.9 client -> independent Rust server, localhost only."""
import argparse
import ast
import base64
import concurrent.futures
import contextlib
import hashlib
import json
import os
import pathlib
import re
import socket
import socketserver
import ssl
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
            try:
                data = self.request.recv(65536)
            except OSError:
                return
            if not data:
                # Delayed final data after upload EOF checks half-close handling.
                time.sleep(0.15)
                with contextlib.suppress(OSError):
                    self.request.sendall(b"HALF-CLOSE-OK")
                return
            try:
                self.request.sendall(data)
            except OSError:
                return

class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)

class TlsEcho(Echo):
    context = None

    def setup(self):
        try:
            self.request = self.context.wrap_socket(self.request, server_side=True)
        except (OSError, ssl.SSLError):
            self.handshake_failed = True

    def handle(self):
        if not getattr(self, "handshake_failed", False):
            super().handle()

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

def tls_case(socks, target, size=8193):
    context = ssl._create_unverified_context()
    with socks_connect(socks, target) as raw, context.wrap_socket(raw, server_hostname="localhost") as secure:
        payload = os.urandom(size)
        secure.sendall(payload)
        assert exact(secure, size) == payload

def untrusted_reality_target_ca_case(args, directory, client, server_config, environment, target_port):
    certificate_directory = ROOT / ".build/interop/vision-certificate"
    ca_key, ca_cert = certificate_directory / "untrusted-ca-key.pem", certificate_directory / "untrusted-ca-cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out", str(ca_cert), "-days", "1", "-subj", "/CN=Untrusted test CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    der = ssl.PEM_cert_to_DER_cert(ca_cert.read_text())
    bad_server = json.loads(json.dumps(server_config))
    bad_node = port()
    bad_server["listen"] = f"127.0.0.1:{bad_node}"
    bad_server["reality"]["target_ca_certificates"] = [base64.urlsafe_b64encode(der).decode().rstrip("=")]
    bad_server_config = directory / "server-untrusted-target-ca.json"
    bad_server_config.write_text(json.dumps(bad_server))
    bad_server_log = ROOT / ".build/interop/reality-untrusted-target-ca-server.log"
    bad_client = json.loads(json.dumps(client))
    bad_socks = port()
    bad_client["inbounds"][0]["port"] = bad_socks
    bad_client["outbounds"][0]["settings"]["port"] = bad_node
    bad_client_config = directory / "client-untrusted-target-ca.json"
    bad_client_config.write_text(json.dumps(bad_client))
    bad_client_log = ROOT / ".build/interop/reality-untrusted-target-ca-client.log"
    with process(args.rust, bad_server_config, bad_server_log) as server_process:
        wait_port(bad_node, server_process)
        with process(args.reference, bad_client_config, bad_client_log, environment) as client_process:
            wait_port(bad_socks, client_process)
            request_succeeded = False
            try:
                with socks_connect(bad_socks, target_port) as stream:
                    stream.sendall(b"target certificate trust bypass")
                    stream.settimeout(2)
                    request_succeeded = stream.recv(64) == b"target certificate trust bypass"
            except (AssertionError, EOFError, OSError, TimeoutError):
                pass
    server_output = bad_server_log.read_text(errors="replace")
    assert "UnknownIssuer" in server_output or "invalid peer certificate" in server_output, server_output
    assert not request_succeeded, "REALITY target probe accepted an untrusted certificate and opened proxy traffic"

def create_tls_certificate(directory):
    ca_key, ca_cert = directory / "test-ca-key.pem", directory / "test-ca-cert.pem"
    key, csr, cert = directory / "tls-key.pem", directory / "tls-request.pem", directory / "tls-cert.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key), "-out", str(ca_cert), "-days", "2", "-subj", "/CN=VLESS interoperability test CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,DNS:example.com"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cert), "-days", "1", "-copy_extensions", "copy"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    return context

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
    parser.add_argument("--rust", type=pathlib.Path, default=ROOT / "rust-core/target/release" / ("vless-rust.exe" if os.name == "nt" else "vless-rust"))
    parser.add_argument("--reference", type=pathlib.Path, default=ROOT / ".build/reference" / ("xray.exe" if os.name == "nt" else "xray"))
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--relays-only", action="store_true")
    parser.add_argument("--reality", action="store_true", help="exercise experimental REALITY TLS 1.3 with the official client")
    parser.add_argument("--mldsa65", action="store_true", help="verify REALITY's ML-DSA-65 certificate proof using the official client")
    parser.add_argument("--vision", action="store_true", help="exercise XTLS Vision flow with the official client")
    parser.add_argument("--fingerprint", default="chrome", choices=("chrome", "firefox", "safari"), help="REALITY client TLS fingerprint")
    parser.add_argument("--appearance", choices=("native", "xorpub", "random"), help="filter quick cases to an Encryption appearance")
    args = parser.parse_args()
    args.rust = args.rust.resolve()
    if args.mldsa65 and not args.reality:
        parser.error("--mldsa65 requires --reality")
    version = subprocess.check_output([str(args.reference), "version"], text=True, creationflags=CREATE_FLAGS)
    assert version.startswith("Xray 26.11.9 "), version
    rust_version = subprocess.check_output([str(args.rust), "version"], text=True, creationflags=CREATE_FLAGS).strip()
    rust_sha256 = hashlib.sha256(args.rust.read_bytes()).hexdigest()
    print(f"Rust binary: {args.rust} ({rust_version}; sha256={rust_sha256})", flush=True)
    output = ROOT / ".build/interop"
    output.mkdir(parents=True, exist_ok=True)
    report = []
    tls_context = None
    if args.vision or args.reality:
        certificate_directory = output / "vision-certificate"
        certificate_directory.mkdir(exist_ok=True)
        tls_context = create_tls_certificate(certificate_directory)
        TlsEcho.context = tls_context
    with service(Echo) as target, service(UdpEcho, udp=True) as udp_target, service(TlsEcho) as tls_target:
        if args.quick:
            quick_auth = ("x25519", "mlkem768") if args.reality and args.vision else ("x25519",)
            quick_mux = (False, True) if args.reality and args.vision else (False,)
            variants = [(auth, args.appearance or "native", "aes", mux) for auth in quick_auth for mux in quick_mux]
        else:
            variants = [(a, m, c, mux) for a in ("x25519", "mlkem768") for m in ("native", "xorpub", "random") for c in ("aes", "chacha") for mux in (False, True)]
        if not args.quick:
            variants += [(a, m, "aes", -1) for a in ("x25519", "mlkem768") for m in ("native", "xorpub", "random")]
        if args.relays_only:
            variants = [("relay8", m, c, False) for m in ("native", "xorpub", "random") for c in ("aes", "chacha")]
        for auth, mode, cipher, mux in variants:
            label = f"{'vision-' if args.vision else ''}{'mldsa65-' if args.mldsa65 else ''}{'reality-' + args.fingerprint + '-' if args.reality else ''}{auth}-{mode}-{cipher}-mux{int(mux)}"
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
                if args.vision:
                    config["vision"] = True
                reality_link = None
                if args.reality:
                    reality_args = [str(args.rust), "init", "--config", str(d / "reality.json"), "--host", "127.0.0.1", "--reality", "--server-name", "example.com", "--target", f"127.0.0.1:{tls_target}"]
                    if args.mldsa65:
                        reality_args.append("--mldsa65")
                    reality_link = subprocess.check_output(reality_args, text=True, creationflags=CREATE_FLAGS).strip()
                    reality_config = json.loads((d / "reality.json").read_text())
                    if args.reality:
                        pem = (certificate_directory / "test-ca-cert.pem").read_text()
                        der = ssl.PEM_cert_to_DER_cert(pem)
                        reality_config["reality"]["target_ca_certificates"] = [base64.urlsafe_b64encode(der).decode().rstrip("=")]
                    config["reality"] = reality_config["reality"]
                (d / "server.json").write_text(json.dumps(config))
                user = {"id": uid, "encryption": keys["encryption"]}
                if args.vision:
                    user["flow"] = "xtls-rprx-vision"
                client = {"log": {"loglevel": "debug" if args.vision else "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": socks, "protocol": "socks", "settings": {"udp": True}}], "outbounds": [{"protocol": "vless", "settings": {"address": "127.0.0.1", "port": node, **user}, "streamSettings": {"method": "raw", "security": "none"}, "mux": {"enabled": mux, "concurrency": 8}}]}
                if reality_link:
                    query = urllib.parse.parse_qs(urllib.parse.urlsplit(reality_link).query)
                    reality_settings = {"serverName": "example.com", "fingerprint": args.fingerprint, "publicKey": query["pbk"][0], "shortId": query["sid"][0], "spiderX": query.get("spx", ["/"])[0]}
                    if args.mldsa65:
                        reality_settings["mldsa65Verify"] = query["pqv"][0]
                        reality_settings["show"] = True
                    client["outbounds"][0]["streamSettings"].update({"security": "reality", "realitySettings": reality_settings})
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
                            if args.vision:
                                tls_case(socks, tls_target)
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
                    if args.quick and args.reality and not args.vision and not args.mldsa65:
                        untrusted_reality_target_ca_case(args, d, client, config, environment, tls_target)
                    if args.mldsa65:
                        bad_client = json.loads(json.dumps(client))
                        bad_socks = port()
                        bad_client["inbounds"][0]["port"] = bad_socks
                        bad_settings = bad_client["outbounds"][0]["streamSettings"]["realitySettings"]
                        bad_config = d / "client-bad-mldsa65.json"
                        bad_link = subprocess.check_output(
                            [str(args.rust), "init", "--config", str(d / "bad-reality.json"), "--host", "127.0.0.1", "--reality", "--server-name", "example.com", "--target", f"127.0.0.1:{tls_target}", "--mldsa65"],
                            text=True,
                            creationflags=CREATE_FLAGS,
                        ).strip()
                        bad_public_key = urllib.parse.parse_qs(urllib.parse.urlsplit(bad_link).query)["pqv"][0]
                        bad_settings["mldsa65Verify"] = bad_public_key
                        bad_config.write_text(json.dumps(bad_client))
                        bad_log = output / f"{label}-bad-key-client.log"
                        with process(args.reference, bad_config, bad_log, environment) as bad_process:
                            wait_port(bad_socks, bad_process)
                            bad_request_succeeded = False
                            try:
                                with socks_connect(bad_socks, target) as bad_stream:
                                    payload = b"bad ML-DSA verification key"
                                    bad_stream.sendall(payload)
                                    bad_stream.settimeout(2)
                                    bad_request_succeeded = bad_stream.recv(len(payload)) == payload
                            except (AssertionError, EOFError, OSError, TimeoutError):
                                pass
                        bad_output = bad_log.read_text(errors="replace")
                        assert "is using ML-DSA-65 for cert's extra verification: true" in bad_output, bad_output
                        assert "uConn.Verified: true" not in bad_output, bad_output
                        assert "REALITY TLS handshake: received fatal alert: BadCertificate" in server_log.read_text(errors="replace"), "wrong ML-DSA verification key was not rejected by TLS CertificateVerify handling"
                        assert not bad_request_succeeded, "invalid ML-DSA verification key unexpectedly opened a proxy stream"
                log = server_log.read_text(errors="replace")
                if args.reality:
                    assert "reality_tls_group=" in log, "REALITY TLS handshake was not exercised"
                    fingerprint_lines = re.findall(
                        r"reality_fingerprint sni_ack=(true|false) server_hello=(\d+) target_records=(\[[^]]*\]) server_records=(\[[^]]*\]) server_hello_match=(true|false)",
                        log,
                    )
                    assert fingerprint_lines, "live target fingerprint capture was not exercised"
                    for target_sni_ack, server_hello_len, target_records_text, server_records_text, server_hello_match in fingerprint_lines:
                        target_records = ast.literal_eval(target_records_text)
                        server_records = ast.literal_eval(server_records_text)
                        assert target_sni_ack == "false", "local OpenSSL target SNI profile changed"
                        assert server_hello_match == "true", "ServerHello was not target-derived"
                        assert server_records[:2] == [int(server_hello_len), 6], server_records
                        if not args.mldsa65:
                            assert server_records == [int(server_hello_len), 6, *target_records], (target_records, server_records)
                        else:
                            assert len(server_records) == len(target_records) + 2, (target_records, server_records)
                    if args.mldsa65:
                        client_output = client_log.read_text(errors="replace")
                        assert "is using ML-DSA-65 for cert's extra verification: true" in client_output, client_output
                        assert "uConn.Verified: true" in client_output, client_output
                vision_counts = (0, 0)
                if args.vision:
                    vision_lines = re.findall(
                        r"vision_direct_transitions=(\d+) vision_direct_uplink=(\d+) vision_direct_downlink=(\d+)",
                        log,
                    )
                    assert vision_lines, "Vision direct-transition diagnostics were not emitted"
                    vision_counts = tuple(sum(int(line[index]) for line in vision_lines) for index in (1, 2))
                    assert sum(vision_counts) > 0 or mux or mode == "random", "TLS echo did not exercise an expected Vision direct transition"
                expected = "Aes" if cipher == "aes" else "ChaCha"
                assert f"cipher={expected}" in log, log
                if mux is False or mux == -1:
                    assert "handshake=0rtt" in log, "0-RTT resumption was not exercised"
                report.append({"case": label, "result": "passed", "cipher_verified": expected, "resumption_verified": mux is False or mux == -1, "target_server_hello_verified": args.reality, "target_record_lengths_verified": args.reality and not args.mldsa65, "vision_direct_uplink_transitions": vision_counts[0] if args.vision else None, "vision_direct_downlink_transitions": vision_counts[1] if args.vision else None})
                print(f"PASS {label}", flush=True)
    suite = "-".join(part for part in (
        "vision" if args.vision else "", "mldsa65" if args.mldsa65 else "",
        "reality-" + args.fingerprint if args.reality else "relay" if args.relays_only else "plain",
        "quick" if args.quick else "", args.appearance or "",
    ) if part)
    (output / f"{suite}-results.json").write_text(json.dumps(report, indent=2) + "\n")
    metadata = {"rust_binary": str(args.rust), "rust_version": rust_version,
                "rust_sha256": rust_sha256, "reference_version": version.splitlines()[0],
                "finished_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "arguments": {key: str(value) if isinstance(value, pathlib.Path) else value
                              for key, value in vars(args).items()}, "passed_cases": len(report)}
    (output / f"{suite}-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"{len(report)} official client variants passed")

if __name__ == "__main__":
    main()
