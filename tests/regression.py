"""Regression checks for the root Rust deployment entrypoint."""
import hashlib
import pathlib
import re
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"


class DeploymentInstallerTests(unittest.TestCase):
    def run_installer(self, *args):
        return subprocess.run(
            ["bash", str(INSTALLER), *args],
            capture_output=True,
            text=True,
            timeout=15,
        )

    def test_help_describes_supported_rust_install(self):
        result = self.run_installer("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VLESS Encryption Rust installer", result.stdout)
        self.assertIn("--auth MODE", result.stdout)
        self.assertIn("REALITY and Vision are not supported", result.stdout)

    def test_invalid_arguments_fail_before_host_checks(self):
        for args in (("--port", "0"), ("--auth", "invalid"), ("--mode", "invalid"), ("--unknown",)):
            with self.subTest(args=args):
                result = self.run_installer(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Linux is required", result.stderr)

    def test_source_pins_match_checked_in_build_inputs(self):
        source = INSTALLER.read_text(encoding="utf-8")
        pins = dict(re.findall(r"^\s+'([^ ]+) ([0-9a-f]+)'$", source, re.MULTILINE))
        self.assertEqual(set(pins), {
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "src/blake3_reference.rs",
            "src/config.rs",
        })
        for relative, expected in pins.items():
            content = (ROOT / "rust-core" / relative).read_bytes()
            with self.subTest(path=relative):
                self.assertEqual(hashlib.sha256(content).hexdigest(), expected)

    def test_version_pins_are_consistent(self):
        cargo = (ROOT / "rust-core/Cargo.toml").read_text(encoding="utf-8")
        install = (ROOT / "rust-core/install.sh").read_text(encoding="utf-8")
        root_installer = INSTALLER.read_text(encoding="utf-8")
        self.assertRegex(cargo, r'(?m)^version = "0\.1\.1"$')
        self.assertIn("vless-rust 0.1.1 reference Xray-core v26.11.9", install)
        self.assertIn('CORE_VERSION="0.1.1"', root_installer)

    def test_install_scripts_parse(self):
        result = subprocess.run(
            ["bash", "-n", str(INSTALLER), str(ROOT / "rust-core/install.sh")],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
