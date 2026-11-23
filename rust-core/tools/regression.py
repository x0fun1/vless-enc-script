"""CLI, migration and real socket resource/authorization regressions."""
import contextlib
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import unittest
import uuid
import urllib.parse
from import_xray import convert
from interop import ROOT, CREATE_FLAGS, Echo, exact, port, process, service, socks_connect, wait_port

RUST = ROOT / "rust-core/target/release" / ("vless-rust.exe" if os.name == "nt" else "vless-rust")
XRAY = ROOT / ".build/reference" / ("xray.exe" if os.name == "nt" else "xray")

class Regression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = json.loads(subprocess.check_output([str(RUST), "keygen"], text=True, creationflags=CREATE_FLAGS))

    def config(self, node, **limits):
        return {"listen": f"127.0.0.1:{node}", "users": [str(uuid.uuid4())], "decryption": self.keys["decryption"], "limits": limits}

    def test_invalid_configuration_is_rejected(self):
        for change in ({"limits": {"max_connections": 0}}, {"limits": {"keepalive_idle_secs": 0}}, {"decryption": "none"}, {"reality": {}}, {"users": []}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                path = pathlib.Path(directory) / "config.json"
                value = self.config(443)
                value.update(change)
                path.write_text(json.dumps(value))
                result = subprocess.run([str(RUST), "check", "--config", str(path)], capture_output=True, text=True, creationflags=CREATE_FLAGS)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(self.keys["decryption"], result.stderr)

    def test_init_does_not_overwrite_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "config.json"
            path.write_text("original")
            result = subprocess.run([str(RUST), "init", "--config", str(path), "--host", "127.0.0.1"], capture_output=True, creationflags=CREATE_FLAGS)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(path.read_text(), "original")

    def test_link_reconstructs_existing_credentials(self):
        for auth in ("x25519", "mlkem768"):
            for appearance in ("native", "xorpub", "random"):
                with self.subTest(auth=auth, mode=appearance), tempfile.TemporaryDirectory() as directory:
                    path = pathlib.Path(directory) / "config.json"
                    keys = json.loads(subprocess.check_output([str(RUST), "keygen", "--auth", auth, "--mode", appearance], text=True, creationflags=CREATE_FLAGS))
                    value = self.config(18443)
                    value["decryption"] = keys["decryption"]
                    path.write_text(json.dumps(value))
                    before = path.read_bytes()
                    link = subprocess.check_output([str(RUST), "link", "--config", str(path), "--host", "2001:db8::1"], text=True, creationflags=CREATE_FLAGS).strip()
                    self.assertIn(f"encryption={keys['encryption']}", link)
                    self.assertIn("@[2001:db8::1]:18443?", link)
                    self.assertEqual(before, path.read_bytes())

    def test_init_accepts_requested_uuid_and_link_roundtrips(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "config.json"
            uid = str(uuid.uuid4())
            created = subprocess.check_output([str(RUST), "init", "--config", str(path), "--host", "example.com", "--uuid", uid], text=True, creationflags=CREATE_FLAGS).strip()
            rebuilt = subprocess.check_output([str(RUST), "link", "--config", str(path), "--host", "example.com"], text=True, creationflags=CREATE_FLAGS).strip()
            self.assertEqual(created, rebuilt)
            self.assertTrue(created.startswith(f"vless://{uid}@"))

    def test_reality_link_roundtrips_and_reconfiguration_preserves_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "config.json"
            created = subprocess.check_output([str(RUST), "init", "--config", str(path), "--host", "2001:db8::1", "--port", "18443", "--reality", "--server-name", "example.com"], text=True, creationflags=CREATE_FLAGS).strip()
            config = json.loads(path.read_text())
            self.assertEqual(config["reality"]["target"], "example.com:443")
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(created).query)
            self.assertEqual(query["security"], ["reality"])
            self.assertEqual(query["sni"], ["example.com"])
            self.assertEqual(query["sid"], [config["reality"]["short_id"]])
            self.assertIn("encryption", query)
            self.assertNotIn(config["reality"]["private_key"], created)
            rebuilt = subprocess.check_output([str(RUST), "link", "--config", str(path), "--host", "2001:db8::1"], text=True, creationflags=CREATE_FLAGS).strip()
            self.assertEqual(created, rebuilt)
            subprocess.check_call([str(RUST), "configure", "--config", str(path), "--host", "example.com", "--port", "18444"], stdout=subprocess.DEVNULL, creationflags=CREATE_FLAGS)
            updated = json.loads(path.read_text())
            self.assertEqual(updated["reality"], config["reality"])
            self.assertEqual(updated["decryption"], config["decryption"])

    def test_reality_unauthenticated_bytes_are_relayed_to_target(self):
        with service(Echo) as target, tempfile.TemporaryDirectory() as directory:
            d = pathlib.Path(directory)
            node = port()
            subprocess.check_call([str(RUST), "init", "--config", str(d / "server.json"), "--host", "127.0.0.1", "--listen-host", "127.0.0.1", "--port", str(node), "--reality", "--server-name", "example.com", "--target", f"127.0.0.1:{target}"], stdout=subprocess.DEVNULL, creationflags=CREATE_FLAGS)
            with process(RUST, d / "server.json", d / "server.log") as server:
                wait_port(node, server)
                for payload in (b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", b"\x16\x03\x03\x00\x05\x01\x00\x00\x01\x00"):
                    with socket.create_connection(("127.0.0.1", node), timeout=5) as s:
                        s.settimeout(5)
                        s.sendall(payload[:3])
                        s.sendall(payload[3:])
                        self.assertEqual(exact(s, len(payload)), payload)
                        s.sendall(b"follow-up")
                        self.assertEqual(exact(s, 9), b"follow-up")

    def test_configure_preserves_keys_until_explicit_rekey(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "config.json"
            keys = json.loads(subprocess.check_output([str(RUST), "keygen", "--auth", "mlkem768", "--mode", "xorpub"], text=True, creationflags=CREATE_FLAGS))
            value = self.config(443)
            value["decryption"] = keys["decryption"]
            path.write_text(json.dumps(value))
            result = subprocess.run([str(RUST), "configure", "--config", str(path), "--host", "example.com", "--auth", "x25519"], capture_output=True, text=True, creationflags=CREATE_FLAGS)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads(path.read_text())["decryption"], keys["decryption"])
            link = subprocess.check_output([str(RUST), "configure", "--config", str(path), "--host", "example.com", "--listen-host", "127.0.0.1", "--port", "18443", "--uuid", str(uuid.uuid4()), "--auth", "x25519", "--mode", "random", "--rekey"], text=True, creationflags=CREATE_FLAGS)
            updated = json.loads(path.read_text())
            self.assertEqual(updated["listen"], "127.0.0.1:18443")
            self.assertNotEqual(updated["decryption"], keys["decryption"])
            self.assertIn("mlkem768x25519plus.random.0rtt.", link)

    def test_migration_preserves_credentials_and_rejects_extensions(self):
        uid = str(uuid.uuid4())
        value = {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "::", "port": 443, "protocol": "vless", "settings": {"users": [{"id": uid}], "decryption": self.keys["decryption"]}, "streamSettings": {"method": "raw", "security": "none"}}], "outbounds": [{"protocol": "freedom", "settings": {}, "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4v6"}}}]}
        migrated = convert(value)
        self.assertEqual(migrated["users"], [uid])
        self.assertEqual(migrated["decryption"], self.keys["decryption"])
        self.assertEqual(migrated["listen"], "[::]:443")
        for mutation in ("reality", "flow", "routing"):
            altered = json.loads(json.dumps(value))
            if mutation == "reality":
                altered["inbounds"][0]["streamSettings"]["security"] = "reality"
            elif mutation == "flow":
                altered["inbounds"][0]["settings"]["users"][0]["flow"] = "xtls-rprx-vision"
            else:
                altered["routing"] = {"rules": []}
            with self.assertRaises(ValueError):
                convert(altered)

    def test_handshake_timeout_and_connection_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            d = pathlib.Path(directory)
            node = port()
            config = self.config(node, max_connections=2, max_handshakes=1, handshake_timeout_secs=1)
            (d / "server.json").write_text(json.dumps(config))
            with process(RUST, d / "server.json", d / "server.log") as server:
                wait_port(node, server)
                time.sleep(0.1)
                sockets = [socket.create_connection(("127.0.0.1", node), timeout=3) for _ in range(3)]
                try:
                    for s in sockets:
                        s.settimeout(3)
                    self.assertEqual(sockets[2].recv(1), b"")
                    self.assertEqual(sockets[0].recv(1), b"")
                    self.assertEqual(sockets[1].recv(1), b"")
                finally:
                    for s in sockets:
                        s.close()
            self.assertIn("handshake timeout", (d / "server.log").read_text())

    def denial(self, wrong_user):
        with service(Echo) as target, tempfile.TemporaryDirectory() as directory:
            d = pathlib.Path(directory)
            node, socks = port(), port()
            config = self.config(node, allow_private_destinations=wrong_user)
            (d / "server.json").write_text(json.dumps(config))
            uid = str(uuid.uuid4()) if wrong_user else config["users"][0]
            client = {"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": socks, "protocol": "socks"}], "outbounds": [{"protocol": "vless", "settings": {"address": "127.0.0.1", "port": node, "id": uid, "encryption": self.keys["encryption"]}, "streamSettings": {"method": "raw", "security": "none"}}]}
            (d / "client.json").write_text(json.dumps(client))
            with process(RUST, d / "server.json", d / "server.log") as server:
                wait_port(node, server)
                with process(XRAY, d / "client.json", d / "client.log") as reference:
                    wait_port(socks, reference)
                    with socks_connect(socks, target) as s:
                        s.settimeout(5)
                        s.sendall(b"forbidden")
                        with contextlib.suppress(ConnectionResetError):
                            self.assertEqual(s.recv(9), b"")
            self.assertIn("invalid VLESS user" if wrong_user else "private destination blocked", (d / "server.log").read_text())

    def test_unknown_user_is_denied(self):
        self.denial(True)

    def test_private_destination_is_denied_by_default(self):
        self.denial(False)

if __name__ == "__main__":
    unittest.main(verbosity=2)
