"""CLI regressions using three preserved V6 cache rows in disposable databases."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
INSPECTOR = REPO / "audit_v6_lineage.py"
FIXTURE = Path(__file__).parent / "fixtures" / "v6_lineage_selected.json"
INPUTS = ("v6_core.py", "v6_pipeline.py", "v6_db.py", "v5_detector.py",
          "v6_protocol.json", "v6_results.json", "report_v6.md")
KEY = ("G01_isotropic", "fixed_point", 308136149)


class V6LineageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "evidence"
        self.root.mkdir()
        for name in INPUTS:
            shutil.copyfile(REPO / name, self.root / name)
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.database = self.root / "history_v6.sqlite3"
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.executescript("""
                CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE worlds (gen TEXT, mech TEXT, seed INTEGER, grp TEXT,
                    response_json TEXT, baseline_json TEXT, PRIMARY KEY(gen,mech,seed));
                CREATE TABLE benchmark_results (id INTEGER PRIMARY KEY, test_name TEXT,
                    metric_name TEXT, metric_value REAL, meaning TEXT, run_at TEXT);
            """)
            connection.executemany("INSERT INTO meta VALUES (?,?)", fixture["meta"].items())
            connection.executemany("INSERT INTO worlds VALUES (?,?,?,?,?,?)", fixture["worlds"])
            connection.executemany("INSERT INTO benchmark_results VALUES (?,?,?,?,?,?)", fixture["metrics"])

    def sql(self, statement, parameters=()):
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute(statement, parameters)

    def change_json(self, name, operation):
        path = self.root / name
        value = json.loads(path.read_text(encoding="utf-8"))
        operation(value)
        path.write_text(json.dumps(value), encoding="utf-8")

    def run_cli(self, expected, status, **options):
        args = {"root": str(self.root), "generator": KEY[0], "mechanism": KEY[1], "seed": str(KEY[2])}
        args.update(options)
        before = {str(path.relative_to(self.root)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in self.root.rglob("*") if path.is_file()}
        command = [sys.executable, str(INSPECTOR)]
        for key, value in args.items():
            command.extend(["--" + key, str(value)])
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        self.assertEqual(completed.returncode, expected, completed.stdout.decode() + completed.stderr.decode())
        result = json.loads(completed.stdout)
        self.assertEqual(result["status"], status)
        after = {str(path.relative_to(self.root)): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in self.root.rglob("*") if path.is_file()}
        self.assertEqual(before, after, "audit changed, deleted or created an input")
        self.assertTrue(result["inputsBytePreserved"])
        self.assertFalse(result["limits"]["historicalExecutionAuthenticated"])
        self.assertFalse(result["limits"]["physicalHypothesisValidated"])
        return result

    def test_current_selected_evidence_and_rounding_tolerance(self):
        result = self.run_cli(0, "PASS")
        self.assertEqual(result["sourceProtocolHash"], "99054d610b0d588f")
        self.assertEqual(result["selected"]["seedOffset"], 0)
        self.assertEqual(result["storedMetricsChecked"], 12)
        self.assertGreater(result["controls"]["implementationControlMaxFeatureDelta"], 0)
        self.assertLess(result["controls"]["implementationControlMaxFeatureDelta"], 1e-9)
        self.assertFalse(result["limits"]["rawTrajectoryBitwiseEqualityAuthenticated"])

    def test_healthy_sqlite_with_false_meta_seed_is_rejected(self):
        self.sql("UPDATE meta SET value='20260921' WHERE key='base_seed'")
        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
        self.assertIn("base_seed", self.run_cli(1, "FAIL")["error"])

    def test_altered_paired_baseline_is_rejected(self):
        self.sql("UPDATE worlds SET baseline_json=? WHERE gen=? AND mech=? AND seed=?",
                 ('{"b_mean":2.0,"b_var":0.0,"b_min":1.0,"b_max":1.0,"b_range":0.0}', *KEY))
        self.assertIn("paired baseline", self.run_cli(1, "FAIL")["error"])

    def test_result_hash_cannot_disagree_with_source(self):
        self.change_json("v6_results.json", lambda value: value.update(protocol_hash="0" * 16))
        self.assertIn("hash mismatch", self.run_cli(1, "FAIL")["error"])

    def test_all_metadata_cannot_override_source_base_seed(self):
        for name in ("v6_protocol.json", "v6_results.json"):
            self.change_json(name, lambda value: value.update(base_seed=20260921))
        self.sql("UPDATE meta SET value='20260921' WHERE key='base_seed'")
        self.assertIn("base seed", self.run_cli(1, "FAIL")["error"])

    def test_wrong_group_is_rejected(self):
        self.sql("UPDATE worlds SET grp='holdout' WHERE gen=? AND mech=? AND seed=?", KEY)
        self.assertIn("group mismatch", self.run_cli(1, "FAIL")["error"])

    def test_missing_implementation_control_is_rejected(self):
        self.sql("DELETE FROM worlds WHERE mech='continuous_alt'")
        self.assertIn("control row", self.run_cli(1, "FAIL")["error"])

    def test_mismatched_metric_is_rejected(self):
        self.sql("UPDATE benchmark_results SET metric_value=0.7 WHERE test_name='primary' AND metric_name='accuracy'")
        self.assertIn("metric mismatch", self.run_cli(1, "FAIL")["error"])

    def test_null_metric_block_is_rejected(self):
        self.change_json("v6_results.json", lambda value: value.update(primary=None))
        self.assertIn("metric block", self.run_cli(1, "FAIL")["error"])

    def test_bool_accuracy_is_not_a_number_even_if_db_row_is_removed(self):
        self.change_json("v6_results.json", lambda value: value["primary"].update(accuracy=True))
        self.sql("DELETE FROM benchmark_results WHERE test_name='primary' AND metric_name='accuracy'")
        self.assertIn("metric number", self.run_cli(1, "FAIL")["error"])

    def test_null_feature_json_is_rejected(self):
        self.sql("UPDATE worlds SET response_json=NULL WHERE gen=? AND mech=? AND seed=?", KEY)
        self.assertIn("not text", self.run_cli(1, "FAIL")["error"])

    def test_nonfinite_number_and_boolean_feature_are_rejected(self):
        with closing(sqlite3.connect(self.database)) as connection:
            original = connection.execute("SELECT response_json FROM worlds WHERE gen=? AND mech=? AND seed=?", KEY).fetchone()[0]
        for replacement in ("NaN", "Infinity", "1e309", "true"):
            with self.subTest(replacement=replacement):
                value = json.loads(original)
                value["energy"] = "TOKEN"
                raw = json.dumps(value).replace('"TOKEN"', replacement)
                self.sql("UPDATE worlds SET response_json=? WHERE gen=? AND mech=? AND seed=?", (raw, *KEY))
                self.run_cli(1, "FAIL")

    def test_duplicate_json_key_is_rejected(self):
        self.sql("UPDATE worlds SET baseline_json=? WHERE gen=? AND mech=? AND seed=?",
                 ('{"b_mean":1.0,"b_mean":2.0,"b_var":0.0,"b_min":1.0,"b_max":1.0,"b_range":0.0}', *KEY))
        self.assertIn("duplicate JSON", self.run_cli(1, "FAIL")["error"])

    def test_seed_boundaries_and_off_schedule_seed(self):
        for seed in (-1, 2 ** 31, 308136150, 308146149):
            with self.subTest(seed=seed):
                self.assertIn("seed", self.run_cli(1, "FAIL", seed=seed)["error"])

    def test_sql_looking_generator_does_not_broaden_selection(self):
        self.assertIn("unknown generator", self.run_cli(1, "FAIL", generator="G01_isotropic' OR 1=1 --")["error"])

    def test_missing_db_stays_missing(self):
        self.database.unlink()
        self.assertIn("unavailable", self.run_cli(2, "BLOCKED")["error"])
        self.assertFalse(self.database.exists())

    def test_existing_sidecar_is_blocked_without_opening_or_deleting_it(self):
        Path(str(self.database) + "-wal").write_bytes(b"unowned active WAL sentinel")
        self.assertIn("quiescent", self.run_cli(2, "BLOCKED")["error"])

    def test_database_path_escape_is_rejected(self):
        outside = self.root.parent / "outside.sqlite3"
        outside.write_bytes(b"do not read or rewrite")
        self.assertIn("inside", self.run_cli(1, "FAIL", database="../outside.sqlite3")["error"])
        self.assertEqual(outside.read_bytes(), b"do not read or rewrite")

    def test_project_source_is_parsed_without_execution(self):
        path = self.root / "v6_core.py"
        path.write_bytes(path.read_bytes() + b'\nraise RuntimeError("project module must not execute")\n')
        self.assertIn("hash mismatch", self.run_cli(1, "FAIL")["error"])

    def test_views_cannot_replace_evidence_tables(self):
        self.sql("DROP TABLE worlds")
        self.sql("CREATE VIEW worlds AS SELECT 1 AS gen")
        self.assertIn("replaced by views", self.run_cli(1, "FAIL")["error"])

    def test_integer_configuration_does_not_accept_float(self):
        self.change_json("v6_results.json", lambda value: value.update(n_steps=24.0))
        self.assertIn("configuration mismatch", self.run_cli(1, "FAIL")["error"])


if __name__ == "__main__":
    unittest.main()
