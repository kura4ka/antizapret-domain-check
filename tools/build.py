#!/usr/bin/env python3
"""Build a reproducible installer containing the Python package and units."""

import argparse
import base64
import gzip
import io
from pathlib import Path
import sys
import tarfile


ROOT = Path(__file__).resolve().parents[1]
TOKEN = "@@AZCHECK_PAYLOAD@@"
REQUIRED_MODULES = {"__init__.py", "__main__.py", "checkpoint.py", "cli.py", "domains.py", "probe.py", "scanner.py"}


def payload_files() -> list[Path]:
    modules = sorted((ROOT / "azcheck").glob("*.py"))
    missing = REQUIRED_MODULES - {path.name for path in modules}
    if missing:
        raise ValueError("Package sources are missing: " + ", ".join(sorted(missing)))
    files = modules + [
        ROOT / "systemd/antizapret-domain-check.service",
        ROOT / "systemd/antizapret-domain-check.timer",
    ]
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("Installer payload sources must be regular files.")
    return sorted(files, key=lambda path: path.relative_to(ROOT).as_posix())


def make_payload() -> bytes:
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for path in payload_files():
            data = path.read_bytes().replace(b"\r\n", b"\n")
            info = tarfile.TarInfo(path.relative_to(ROOT).as_posix())
            info.size = len(data)
            info.mode = 0o644
            info.mtime = info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", filename="", mtime=0) as output:
        output.write(archive.getvalue())
    return compressed.getvalue()


def render_installer() -> str:
    template = (ROOT / "tools/install.template.sh").read_text(encoding="utf-8")
    if template.count(TOKEN) != 1:
        raise ValueError("Installer template must contain exactly one payload placeholder.")
    payload = base64.encodebytes(make_payload()).decode("ascii").rstrip()
    return template.replace(TOKEN, payload).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if install.sh differs from its sources")
    args = parser.parse_args()
    try:
        expected = render_installer().encode("utf-8")
        target = ROOT / "install.sh"
        if args.check:
            if not target.is_file() or target.read_bytes() != expected:
                print("install.sh differs from its sources; run python3 tools/build.py", file=sys.stderr)
                return 1
            print("install.sh matches its sources")
        else:
            target.write_bytes(expected)
            print("Built install.sh")
    except (OSError, ValueError) as exc:
        print(f"Cannot build installer: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
