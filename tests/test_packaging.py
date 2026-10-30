"""Verify the downloadable installer actually contains a runnable package."""

import configparser
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash") or r"C:\Program Files\Git\bin\bash.exe"
SPEC = importlib.util.spec_from_file_location("installer_build", ROOT / "tools/build.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


class PackagingTests(unittest.TestCase):
    def test_payload_is_reproducible_despite_source_timestamps(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "azcheck").mkdir()
            (root / "systemd").mkdir()
            for module in build.REQUIRED_MODULES:
                (root / "azcheck" / module).write_bytes(b"# source\r\n")
            for name in ("antizapret-domain-check.service", "antizapret-domain-check.timer"):
                (root / "systemd" / name).write_bytes(b"# unit\r\n")
            with patch.object(build, "ROOT", root):
                first = build.make_payload()
                for source in build.payload_files():
                    os.utime(source, (123456, 123456))
                second = build.make_payload()
            self.assertEqual(first, second)
            with tarfile.open(fileobj=io.BytesIO(first), mode="r:gz") as archive:
                for member in archive.getmembers():
                    self.assertEqual((member.uid, member.gid, member.mtime, member.mode), (0, 0, 0, 0o644))
                    self.assertTrue(member.isfile())
                    self.assertNotIn(b"\r", archive.extractfile(member).read())

    def test_actual_embedded_payload_runs_inventory_in_isolated_python(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with tarfile.open(fileobj=io.BytesIO(build.make_payload()), mode="r:gz") as archive:
                for member in archive.getmembers():
                    self.assertTrue(member.isfile())
                    self.assertNotIn("..", Path(member.name).parts)
                    target = root / member.name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.extractfile(member).read())
            az = root / "native"
            (az / "config").mkdir(parents=True)
            (az / "config/include-hosts.txt").write_bytes(b"# submitted\nUser.Example\n")
            code = "import runpy,sys; sys.path.insert(0, sys.argv.pop(1)); runpy.run_module('azcheck', run_name='__main__')"
            result = subprocess.run([
                sys.executable, "-I", "-c", code, str(root), "inventory", "--az-dir", str(az),
            ], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("user.example\tnormal\t", result.stdout)
            self.assertIn("include-hosts.txt:2", result.stdout)

    def test_installer_initial_config_matches_runtime_defaults(self):
        from azcheck.cli import DEFAULTS

        template = (ROOT / "tools/install.template.sh").read_text(encoding="utf-8")
        match = re.search(r"<<'CONFIG_JSON'\n(.*?)\nCONFIG_JSON", template, re.S)
        self.assertIsNotNone(match)
        self.assertEqual(json.loads(match.group(1)), DEFAULTS)

    def test_upgrade_migrates_old_defaults_and_preserves_backup_and_custom_settings(self):
        template = (ROOT / 'tools/install.template.sh').read_text(encoding='utf-8')
        match = re.search(r"<<'MIGRATE_CONFIG_PY'\n(.*?)\nMIGRATE_CONFIG_PY", template, re.S)
        self.assertIsNotNone(match)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'config.json'
            original = b'{"report_dir":"/var/lib/antizapret-domain-check/reports","include_download":false,"timeout_seconds":12}\n'
            config.write_bytes(original)

            def migrate():
                return subprocess.run([sys.executable, '-I', '-', str(config), str(ROOT)],
                                      input=match.group(1), capture_output=True, text=True, timeout=10)

            result = migrate()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            settings = json.loads(config.read_text())
            self.assertEqual(settings['config_version'], 2)
            self.assertEqual(settings['report_dir'], '/root/antizapret-domain-check/reports')
            self.assertTrue(settings['include_download'])
            self.assertEqual(settings['timeout_seconds'], 12)
            backups = list(config.parent.glob('config.json.before-v0.2.*.bak'))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), original)
            before = config.read_bytes()
            self.assertEqual(migrate().returncode, 0)
            self.assertEqual(config.read_bytes(), before)
            self.assertEqual(len(list(config.parent.glob('config.json.before-v0.2.*.bak'))), 1)
            config.write_text('{"report_dir":"/root/custom-reports","workers":3}')
            self.assertEqual(migrate().returncode, 0)
            settings = json.loads(config.read_text())
            self.assertEqual(settings['report_dir'], '/root/custom-reports')
            self.assertEqual(settings['workers'], 3)

    def test_daily_units_point_to_an_accepted_installed_command(self):
        from azcheck.cli import parser

        service = configparser.ConfigParser(interpolation=None)
        service.read(ROOT / "systemd/antizapret-domain-check.service", encoding="utf-8")
        command = service["Service"]["ExecStart"].split()
        self.assertEqual(command[0], "/usr/local/bin/antizapret-domain-check")
        args = parser().parse_args(command[1:])
        self.assertEqual(args.command, "scan")
        self.assertTrue(args.quiet)
        timer = configparser.ConfigParser(interpolation=None)
        timer.read(ROOT / "systemd/antizapret-domain-check.timer", encoding="utf-8")
        self.assertEqual(timer["Timer"]["OnCalendar"], "daily")
        self.assertEqual(timer["Timer"]["Unit"], "antizapret-domain-check.service")

    def test_help_version_and_bad_flags_do_not_require_installation(self):
        from azcheck import __version__

        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "install.sh"
            script.write_text(build.render_installer(), encoding="utf-8", newline="\n")
            for flag, code in (("--help", 0), ("--version", 0), ("--unknown", 1)):
                with self.subTest(flag=flag):
                    result = subprocess.run([BASH, str(script), flag], capture_output=True,
                                            text=True, timeout=10)
                    self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                    if flag == "--version":
                        self.assertEqual(result.stdout.strip(), __version__)
            result = subprocess.run([BASH, str(script), "--enable-timer", "--uninstall"],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertIn("one installer action", result.stderr)


if __name__ == "__main__":
    unittest.main()
