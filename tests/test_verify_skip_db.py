"""Exercise the actual verify.py CLI in a disposable, stdlib-only repository."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch


class VerifySkipDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="opengate-verify-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = Path(__file__).resolve().parents[1] / "verify.py"
        shutil.copyfile(self.source, self.root / "verify.py")
        reports = ["report.md", "report_v2.md", "report_v3.md", "report_v4.md",
                   "report_v5.md", "report_v5_1.md", "report_v5_2.md",
                   "report_v5_3.md", "report_v5_5.md", "README.md"]
        for name in reports:
            (self.root / name).write_text("Synthetic verification fixture.\n", encoding="utf-8")
        frozen = ["v6_core.py", "v6_pipeline.py", "v6_db.py", "v5_detector.py"]
        for name in frozen:
            (self.root / name).write_text("# Synthetic source; never executed.\n", encoding="utf-8")
        source_bytes = b"".join((self.root / name).read_bytes() for name in frozen)
        protocol_hash = hashlib.sha256(source_bytes).hexdigest()[:16]
        self.write_json("v6_protocol.json", {"protocol_hash": protocol_hash})
        self.write_json("v6_results.json", {"final_status": "SYNTHETIC_FIXTURE"})
        (self.root / "report_v6.md").write_text(
            f"Protocol hash:** `{protocol_hash}`\nSYNTHETIC_FIXTURE\n", encoding="utf-8")
        (self.root / "v6_artifacts").mkdir()
        (self.root / "v7_artifacts").mkdir()
        (self.root / "v7_lattice.py").write_text("# Synthetic source.\n", encoding="utf-8")
        (self.root / "report_v7.md").write_text("SYNTHETIC_CONTROL\n", encoding="utf-8")
        self.write_json("v7_artifacts/v7_controls.json", {
            "protocol": {"alpha": 0.05}, "positive_control": {"p_value": 0.01},
            "null_control": {"p_value": 0.5}, "ingestion_selftest": {"passed": True},
            "calibration_type1": {"calibration_ok": True},
            "sensitivity": {"power_ok": True}, "engine_status": "SYNTHETIC_CONTROL",
        })

    def write_json(self, name, value):
        (self.root / name).write_text(json.dumps(value), encoding="utf-8")

    def run_cli(self, *arguments):
        previous_cwd = Path.cwd()
        output = io.StringIO()
        script = self.root / "verify.py"
        try:
            with patch.object(sys, "argv", [str(script), *arguments]), \
                    patch.object(sys, "pycache_prefix", str(self.root / "cache")), \
                    contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit) as stopped:
                    runpy.run_path(str(script), run_name="__main__")
        finally:
            os.chdir(previous_cwd)
        self.assertEqual(Path.cwd(), previous_cwd)
        return stopped.exception.code, output.getvalue()

    def create_database(self):
        path = self.root / "history_v6.sqlite3"
        connection = sqlite3.connect(path)
        try:
            connection.execute("CREATE TABLE fixture (value INTEGER)")
            connection.commit()
        finally:
            connection.close()
        return path

    def test_skip_db_succeeds_without_external_database(self):
        code, output = self.run_cli("--skip-db")
        self.assertEqual(code, 0, output)
        self.assertIn("V6: §11 deliverables present — 4/4", output)
        self.assertIn("10/10 passed", output)
        self.assertNotIn("== databases ==", output)

    def test_default_still_requires_external_database(self):
        code, output = self.run_cli()
        self.assertEqual(code, 1, output)
        self.assertIn("[FAIL] V6: §11 deliverables present — history_v6.sqlite3", output)

    def test_quick_still_requires_external_database(self):
        code, output = self.run_cli("--quick")
        self.assertEqual(code, 1, output)
        self.assertIn("[FAIL] V6: §11 deliverables present — history_v6.sqlite3", output)

    def test_skip_db_takes_precedence_over_quick(self):
        code, output = self.run_cli("--quick", "--skip-db")
        self.assertEqual(code, 0, output)
        self.assertNotIn("== databases ==", output)

    def test_skip_db_still_requires_each_non_database_deliverable(self):
        for name in ["v6_results.json", "v6_protocol.json", "report_v6.md", "v6_artifacts"]:
            with self.subTest(missing=name):
                path = self.root / name
                is_directory = path.is_dir()
                content = None if is_directory else path.read_bytes()
                path.rmdir() if is_directory else path.unlink()
                try:
                    code, output = self.run_cli("--skip-db")
                    self.assertEqual(code, 1, output)
                    self.assertIn(f"[FAIL] V6: §11 deliverables present — {name}", output)
                finally:
                    path.mkdir() if is_directory else path.write_bytes(content)

    def test_default_checks_real_sqlite_without_mutating_it(self):
        path = self.create_database()
        before = path.read_bytes()
        code, output = self.run_cli()
        self.assertEqual(code, 0, output)
        self.assertIn("5/5", output)
        self.assertIn("tables=1 integrity_check=ok", output)
        self.assertEqual(path.read_bytes(), before)

    def test_quick_runs_quick_check_without_mutating_database(self):
        path = self.create_database()
        before = path.read_bytes()
        code, output = self.run_cli("--quick")
        self.assertEqual(code, 0, output)
        self.assertIn("tables=1 quick_check=ok", output)
        self.assertEqual(path.read_bytes(), before)

    def test_skip_db_does_not_open_malformed_sqlite(self):
        path = self.root / "history_v6.sqlite3"
        path.write_bytes(b"Not an SQLite database.\n")
        before = path.read_bytes()
        code, output = self.run_cli("--skip-db")
        self.assertEqual(code, 0, output)
        self.assertNotIn("== databases ==", output)
        self.assertEqual(path.read_bytes(), before)

    def test_default_and_quick_reject_malformed_sqlite(self):
        (self.root / "history_v6.sqlite3").write_bytes(b"Not an SQLite database.\n")
        for arguments in [(), ("--quick",)]:
            with self.subTest(arguments=arguments):
                code, output = self.run_cli(*arguments)
                self.assertEqual(code, 1, output)
                self.assertIn("[FAIL] db: history_v6.sqlite3", output)

    def test_skip_db_still_rejects_frozen_protocol_drift(self):
        (self.root / "v6_core.py").write_text("# Changed synthetic source.\n", encoding="utf-8")
        code, output = self.run_cli("--skip-db")
        self.assertEqual(code, 1, output)
        self.assertIn("[FAIL] V6: stored protocol_hash matches source", output)


if __name__ == "__main__":
    unittest.main()
