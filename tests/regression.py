"""Deployment/menu regressions; fake services operate only in a temp directory."""
import json
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"
MANAGER = ROOT / "rust-core/venc"
BASH = shutil.which("bash") or "bash"
if os.name == "nt":
    # Git's bin/bash.exe launcher prepends real system commands to PATH,
    # bypassing the command fakes. Use the actual MSYS Bash binary instead.
    bash_candidates = [pathlib.Path(BASH).parent.parent / "usr/bin/bash.exe"]
    git = shutil.which("git")
    if git:
        bash_candidates.append(pathlib.Path(git).parent.parent / "usr/bin/bash.exe")
    for msys_bash in bash_candidates:
        if msys_bash.is_file():
            BASH = str(msys_bash)
            os.environ["PATH"] = str(msys_bash.parent) + os.pathsep + os.environ.get("PATH", "")
            break

# No real root/systemd/network changes: every external privileged command is
# substituted. The real bash manager and its filesystem operations are tested.
FAKE = r'''
import json, os, pathlib, shutil, sys, uuid
kind, args = sys.argv[1], sys.argv[2:]
root = pathlib.Path(os.environ["VENC_ROOT"])
state_path = root / "fake-state.json"
state = json.loads(state_path.read_text()) if state_path.exists() else {}
def save(): state_path.write_text(json.dumps(state))
if kind == "id": print("0")
elif kind in ("chown", "flock"): pass
elif kind == "install":
    assert "-d" in args, args
    pathlib.Path(args[-1]).mkdir(parents=True, exist_ok=True)
elif kind == "ss":
    if os.environ.get("FAKE_SS_FAILURE"): sys.exit(1)
    if args[-1].endswith(":" + os.environ.get("FAKE_OCCUPIED", "-")): print("occupied")
elif kind == "shuf":
    state["port"] = state.get("port", 20000) + 1; save(); print(state["port"])
elif kind == "curl":
    if "-o" in args:
        source = os.environ.get("FAKE_UPDATE_SCRIPT")
        if not source: sys.exit(2)
        shutil.copyfile(source, args[args.index("-o") + 1])
    else: print("203.0.113.1")
elif kind == "systemctl":
    with (root / "service-calls.jsonl").open("a") as log: log.write(json.dumps(args) + "\n")
    command, unit = args[0], args[-1]
    if command == "enable":
        if os.environ.get("FAKE_START_FAILURE") and unit != "vless-rust": sys.exit(1)
        state["enabled:" + unit] = "enabled-runtime" if "--runtime" in args else "enabled"
        if "--now" in args: state[unit] = "active"
        save()
    elif command == "disable":
        state["enabled:" + unit] = "disabled-runtime" if "--runtime" in args else "disabled"
        if "--now" in args: state[unit] = "inactive"
        save()
    elif command in ("stop", "start", "restart"):
        state[unit] = "inactive" if command == "stop" else "active"; save()
    elif command == "is-active":
        active = state.get(unit) == "active"
        if "--quiet" not in args: print("active" if active else "inactive")
        sys.exit(0 if active else 3)
    elif command == "is-enabled":
        enabled = state.get("enabled:" + unit, "disabled")
        print(enabled)
        sys.exit(0 if enabled.startswith("enabled") else 1)
    elif command == "show":
        if any("ActiveState" in arg for arg in args): print("active" if state.get(unit) == "active" else "inactive")
        else: print("321" if state.get(unit) == "active" else "0")
    elif command in ("status", "reset-failed", "daemon-reload"): pass
    else: raise AssertionError(args)
elif kind == "core":
    command = args[0]
    if command == "capabilities":
        print("vless-encryption xtls-vision" + ("" if os.environ.get("FAKE_NO_REALITY") else " reality-experimental reality-mldsa65"))
        sys.exit(0)
    options = {args[i]: args[i+1] for i in range(1, len(args)-1) if args[i].startswith("--") and args[i] not in ("--reality", "--vision", "--mldsa65")}
    path = pathlib.Path(options["--config"])
    if command == "init":
        if path.exists(): sys.exit(2)
        config = {"listen": "[::]:" + options["--port"], "users": [str(uuid.uuid4())], "decryption": str(uuid.uuid4()), "reality": "--reality" in args, "vision": "--vision" in args, "auth": options.get("--auth", "x25519"), "server_name": options.get("--server-name", "www.nvidia.com"), "target": options.get("--target", "www.nvidia.com:443")}
        if "--mldsa65" in args: config["reality_mldsa65_seed"] = "seed"
        path.write_text(json.dumps(config))
    else: config = json.loads(path.read_text())
    if command in ("init", "link"):
        security = f"reality&sni={config.get('server_name', 'www.nvidia.com')}&pbk=key&sid=abcd&spx=%2Frandom" + ("&pqv=verify-key" if config.get("reality_mldsa65_seed") else "") if config["reality"] else "none"
        flow = "&flow=xtls-rprx-vision" if config.get("vision") else ""
        print(f"vless://{config['users'][0]}@{options['--host']}:{config['listen'].rsplit(':', 1)[1]}?encryption=key&security={security}&type=tcp{flow}")
    elif command == "check": print("configuration valid")
    else: raise AssertionError("must not reconfigure existing nodes")
else: raise AssertionError(kind)
'''


class DeploymentInstallerTests(unittest.TestCase):
    def run_installer(self, *args):
        return subprocess.run([BASH, str(INSTALLER), *args], capture_output=True, encoding="utf-8", timeout=15)

    def test_help_describes_menu_first_and_reality_limits(self):
        result = self.run_installer("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        for text in ("VLESS Encryption Rust installer", "--no-menu", "No node or client link is created", "experimental REALITY + XTLS Vision", "Target-derived TLS shaping is limited", "ML-KEM-768-authenticated"):
            self.assertIn(text, result.stdout)

    def test_invalid_arguments_fail_before_host_checks(self):
        for args in (("--port", "0"), ("--port", "65536"), ("--auth", "invalid"), ("--mode", "invalid"), ("--unknown",), ("--host", "a/b")):
            with self.subTest(args=args):
                result = self.run_installer(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Linux is required", result.stderr)

    def test_versioned_bundle_and_no_automatic_node_creation(self):
        cargo = (ROOT / "rust-core/Cargo.toml").read_text(encoding="utf-8")
        install = (ROOT / "rust-core/install.sh").read_text(encoding="utf-8")
        source = INSTALLER.read_text(encoding="utf-8")
        version = re.search(r'(?m)^version = "([^"]+)"$', cargo).group(1)
        self.assertIn(f"vless-rust {version} reference Xray-core v26.11.9", install)
        self.assertIn(f'CORE_VERSION="{version}"', source)
        self.assertIn('releases/download/vless-rust-v${CORE_VERSION}', source)
        self.assertIn('vless-rust-deploy.tar.gz', source)
        self.assertIn('"$release_url/$asset.sha256"', source)
        self.assertIn('/usr/local/bin/venc', source)
        self.assertNotRegex(source, r'"\$binary" (init|configure)')
        self.assertNotIn('cargo build', source)
        self.assertNotIn('/root/vless-rust_link.txt', source)
        workflow = (ROOT / ".github/workflows/rust-core-release.yml").read_text(encoding="utf-8")
        for text in ("arch: x86_64", "arch: aarch64", "cargo build --locked --release", "vless-rust-deploy.tar.gz", "systemd/vless-rust@.service"):
            self.assertIn(text, workflow)
        self.assertIn('nodes/%i/config.json', (ROOT / "rust-core/systemd/vless-rust@.service").read_text())

    def test_all_install_scripts_parse(self):
        for path in (INSTALLER, ROOT / "rust-core/install.sh", MANAGER):
            with self.subTest(path=path):
                result = subprocess.run([BASH, "-n", str(path)], capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.mock_bin = self.root / "mock-bin"
        self.mock_bin.mkdir()
        fake = self.root / "fake.py"
        fake.write_text(FAKE, encoding="utf-8")
        def wrapper(path, kind):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"#!/usr/bin/env bash\nexec {shlex.quote(sys.executable.replace(chr(92), '/'))} {shlex.quote(fake.as_posix())} {kind} \"$@\"\n", encoding="utf-8", newline="\n")
            path.chmod(0o755)
        for cmd in ("id", "install", "chown", "flock", "ss", "shuf", "curl", "systemctl"):
            wrapper(self.mock_bin / cmd, cmd)
        wrapper(self.root / "usr/local/bin/vless-rust", "core")
        template = self.root / "etc/systemd/system/vless-rust@.service"
        template.parent.mkdir(parents=True)
        template.write_text("fake unit")
        self.nodes = self.root / "usr/local/etc/vless-rust/nodes"
        self.env = os.environ.copy()
        # Bash on Windows uses a POSIX PATH rather than os.pathsep=';'.
        old_path = subprocess.check_output([BASH, "-c", 'printf "%s" "$PATH"'], text=True)
        mock_path = self.mock_bin.as_posix()
        if os.name == "nt":
            # A Windows drive colon would split this entry in Bash's PATH.
            mock_path = subprocess.check_output(
                [BASH, "-c", 'cygpath -u -- "$1"', "bash", mock_path], text=True
            ).strip()
            bash_path = subprocess.check_output(
                [BASH, "-c", 'cygpath -u -- "$1"', "bash", str(pathlib.Path(BASH).parent)], text=True
            ).strip()
            old_path = f"{bash_path}:{old_path}"
        self.env.update(VENC_ROOT=self.root.as_posix(), VENC_VERIFY_DELAY="0", PYTHONIOENCODING="utf-8", PATH=f"{mock_path}:{old_path}")

    def run_menu(self, inputs, **environment):
        result = subprocess.run([BASH, str(MANAGER)], input=inputs.encode("utf-8"), capture_output=True, timeout=30, env=self.env | environment)
        result.stdout = result.stdout.decode("utf-8")
        result.stderr = result.stderr.decode("utf-8")
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def configs(self):
        return {p.parent.name: p.read_bytes() for p in self.nodes.glob("node-*/config.json")}

    def calls(self):
        path = self.root / "service-calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_opening_menu_does_not_create_node(self):
        result = self.run_menu("1\n0\n0\n")
        self.assertIn("1. 创建节点", result.stdout)
        self.assertIn("10. 更新脚本并迁移旧版节点", result.stdout)
        self.assertIn("Reality + XTLS Vision（实验性，X25519）", result.stdout)
        self.assertIn("Reality + XTLS Vision（实验性，ML-KEM-768）", result.stdout)
        self.assertEqual(self.configs(), {})
        self.assertFalse(self.calls())

    def test_multiple_nodes_survive_create_show_and_delete(self):
        self.run_menu("1\n1\n18443\n0\n")
        original = self.configs()
        self.run_menu("1\n2\n18444\nexample.com\nexample.com:443\n\n0\n")
        combined = self.configs()
        self.assertEqual(len(combined), 2)
        for node, content in original.items(): self.assertEqual(combined[node], content)
        result = self.run_menu("3\n\n0\n")
        self.assertIn("18443/TCP", result.stdout)
        self.assertIn("18444/TCP", result.stdout)
        self.assertIn("security=reality", result.stdout)
        self.run_menu("2\n1\ny\n0\n")
        remaining = self.configs()
        self.assertEqual(len(remaining), 1)
        for node, content in remaining.items(): self.assertEqual(content, combined[node])
        for call in self.calls():
            if call[0] in ("enable", "disable"):
                self.assertRegex(call[-1], r"^vless-rust@node-[0-9a-f]{32}$")

    def test_mldsa65_remains_an_explicit_opt_in_for_reality_vision_nodes(self):
        result = self.run_menu("1\n3\n18445\nexample.com\norigin.example.net:443\ny\n0\n")
        configs = [json.loads(content) for content in self.configs().values()]
        self.assertEqual(len(configs), 1)
        self.assertTrue(configs[0]["reality"])
        self.assertTrue(configs[0]["vision"])
        self.assertEqual(configs[0]["auth"], "mlkem768")
        self.assertEqual(configs[0]["server_name"], "example.com")
        self.assertEqual(configs[0]["target"], "origin.example.net:443")
        self.assertEqual(configs[0]["reality_mldsa65_seed"], "seed")
        self.assertIn("flow=xtls-rprx-vision", result.stdout)
        self.assertIn("pqv=verify-key", result.stdout)

    def test_reality_vision_x25519_defaults_and_mldsa_disabled(self):
        self.run_menu("1\n2\n18446\n\n\n\n0\n")
        configs = [json.loads(content) for content in self.configs().values()]
        self.assertEqual(len(configs), 1)
        self.assertTrue(configs[0]["reality"])
        self.assertTrue(configs[0]["vision"])
        self.assertEqual(configs[0]["auth"], "x25519")
        self.assertEqual(configs[0]["server_name"], "www.nvidia.com")
        self.assertEqual(configs[0]["target"], "www.nvidia.com:443")
        self.assertNotIn("reality_mldsa65_seed", configs[0])

    def test_random_port_uuid_keys_and_blank_type(self):
        self.run_menu("1\n\n\n1\n\n\n0\n")
        configs = [json.loads(b) for b in self.configs().values()]
        self.assertEqual(len(configs), 2)
        for field in ("listen", "users", "decryption"):
            self.assertNotEqual(configs[0][field], configs[1][field])
        self.assertTrue(all(10000 <= int(c["listen"].rsplit(":", 1)[1]) <= 60000 for c in configs))

    def test_stopped_node_reserves_port_and_invalid_inputs_do_not_modify(self):
        self.run_menu("1\n1\n18443\n4\n1\n0\n")
        before = self.configs()
        result = self.run_menu("1\n1\n18443\n1\n1\n65536\n0\n")
        self.assertIn("已分配给其他节点", result.stderr)
        self.assertEqual(self.configs(), before)
        self.assertEqual(sum(call[0] == "enable" for call in self.calls()), 1)

    def test_start_failure_removes_only_new_node(self):
        self.run_menu("1\n1\n18443\n0\n")
        before = self.configs()
        result = self.run_menu("1\n1\n18444\n0\n", FAKE_START_FAILURE="1")
        self.assertIn("仅撤销本次创建", result.stderr)
        self.assertEqual(self.configs(), before)
        self.assertFalse(list(self.nodes.glob(".create.*")))

    def test_missing_reality_or_ss_failure_never_creates_node(self):
        result = self.run_menu("1\n2\n0\n", FAKE_NO_REALITY="1")
        self.assertIn("不支持 Reality", result.stderr)
        self.assertFalse(self.configs())
        self.run_menu("1\n1\n18443\n0\n", FAKE_SS_FAILURE="1")
        self.assertFalse(self.configs())

    def test_legacy_configuration_is_not_overwritten(self):
        directory = self.root / "usr/local/etc/vless-rust"
        directory.mkdir(parents=True)
        legacy = directory / "config.json"
        legacy.write_text(json.dumps({"listen": "[::]:443", "users": ["old-uuid"], "decryption": "old-secret", "reality": False}))
        (directory / "public-host").write_text("legacy.example.com\n")
        before = legacy.read_bytes()
        self.run_menu("1\n1\n18443\n0\n", VENC_DEFAULT_HOST="new.example.com")
        self.assertEqual(legacy.read_bytes(), before)
        self.assertEqual((directory / "public-host").read_text(), "legacy.example.com\n")
        result = self.run_menu("3\n\n0\n")
        self.assertIn("legacy.example.com:443", result.stdout)
        self.assertIn("new.example.com:18443", result.stdout)

    def test_legacy_port_reservation_does_not_require_public_host(self):
        directory = self.root / "usr/local/etc/vless-rust"
        directory.mkdir(parents=True)
        legacy = directory / "config.json"
        legacy.write_text(json.dumps({"listen": "[::]:443", "users": ["old-uuid"], "decryption": "old-secret", "reality": False}))
        before = legacy.read_bytes()
        result = self.run_menu("1\n1\n18443\n1\n1\n443\n0\n", VENC_DEFAULT_HOST="new.example.com")
        self.assertIn("端口 443 已被服务占用或已分配", result.stderr)
        self.assertEqual(legacy.read_bytes(), before)
        self.assertEqual(len(self.configs()), 1)

    def prepare_update_with_legacy_node(self):
        directory = self.root / "usr/local/etc/vless-rust"
        directory.mkdir(parents=True)
        node_uuid = "12345678-1234-4234-8234-123456789abc"
        legacy = directory / "config.json"
        legacy.write_text(json.dumps({"listen": "[::]:18443", "users": [node_uuid], "decryption": "old-encryption-secret", "reality": False}))
        (directory / "public-host").write_text("old.example.com\n")
        state = {"vless-rust": "active", "enabled:vless-rust": "enabled"}
        (self.root / "fake-state.json").write_text(json.dumps(state))
        update = self.root / "update-installer.sh"
        update.write_text('#!/usr/bin/env bash\n[[ "$1" == --no-menu ]] || exit 2\nprintf updated > "$VENC_ROOT/update-called"\n', encoding="utf-8")
        return legacy, node_uuid, update

    def test_update_option_migrates_legacy_node_and_keeps_credentials(self):
        legacy, node_uuid, update = self.prepare_update_with_legacy_node()
        before = legacy.read_bytes()
        result = self.run_menu("10\ny\n0\n", FAKE_UPDATE_SCRIPT=update.as_posix())
        node_id = "node-" + node_uuid.replace("-", "")
        migrated = self.nodes / node_id
        self.assertTrue((self.root / "update-called").exists())
        self.assertFalse(legacy.exists())
        self.assertEqual((migrated / "config.json").read_bytes(), before)
        self.assertEqual((migrated / "public-host").read_text(), "old.example.com\n")
        self.assertIn("旧版节点已迁移", result.stdout)
        state = json.loads((self.root / "fake-state.json").read_text())
        self.assertEqual(state["vless-rust"], "inactive")
        self.assertEqual(state["vless-rust@" + node_id], "active")
        self.assertEqual(state["enabled:vless-rust"], "disabled")
        self.assertEqual(state["enabled:vless-rust@" + node_id], "enabled")

    def test_failed_legacy_migration_restores_old_service_and_config(self):
        legacy, _, update = self.prepare_update_with_legacy_node()
        before = legacy.read_bytes()
        result = self.run_menu("10\ny\n0\n", FAKE_UPDATE_SCRIPT=update.as_posix(), FAKE_START_FAILURE="1")
        self.assertIn("旧节点迁移未完成", result.stderr)
        self.assertEqual(legacy.read_bytes(), before)
        self.assertEqual(self.configs(), {})
        state = json.loads((self.root / "fake-state.json").read_text())
        self.assertEqual(state["vless-rust"], "active")
        self.assertEqual(state["enabled:vless-rust"], "enabled")


if __name__ == "__main__":
    unittest.main(verbosity=2)
