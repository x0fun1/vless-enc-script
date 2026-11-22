"""Fetch the pinned official interoperability reference; verify before extraction."""
import hashlib
import io
import pathlib
import sys
import urllib.request
import zipfile

VERSION = "v26.11.9"
ASSETS = {
    "win32": ("Xray-windows-64.zip", "1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d", "xray.exe"),
    "linux": ("Xray-linux-64.zip", "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82", "xray"),
}

def main():
    name, digest, executable = ASSETS[sys.platform]
    output = pathlib.Path(__file__).resolve().parents[2] / ".build" / "reference"
    output.mkdir(parents=True, exist_ok=True)
    archive = output / name
    if archive.exists():
        data = archive.read_bytes()
    else:
        url = f"https://github.com/XTLS/Xray-core/releases/download/{VERSION}/{name}"
        with urllib.request.urlopen(url, timeout=120) as response:
            data = response.read(100 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError("Official reference archive SHA-256 mismatch")
    archive.write_bytes(data)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        binary = z.read(executable)
    destination = output / executable
    destination.write_bytes(binary)
    if sys.platform == "linux":
        destination.chmod(0o755)
    print(f"Verified {VERSION}: {destination}")

if __name__ == "__main__":
    main()
