#!/usr/bin/env python3
"""Audit one cached V6 world and its controls without running an experiment.

Exit 0: bounded consistency checks passed. Exit 1: inconsistent evidence.
Exit 2: evidence unavailable (including live WAL/journal files).
Cached features cannot authenticate a past run or prove raw trajectory equality.
"""
import argparse
import ast
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import sys
import zlib


SOURCES = ("v6_core.py", "v6_pipeline.py", "v6_db.py", "v5_detector.py")
MAX_TEXT = 2 * 1024 * 1024
MAX_DB = 16 * 1024 * 1024
SEED_FUNCTION = """def stable_seed(gen, off):
    return (BASE_SEED + off * 1000 + zlib.crc32(gen.encode())) % (2 ** 31)
"""


class Inconsistent(ValueError):
    pass


class Unavailable(OSError):
    pass


def require(ok, message):
    if not ok:
        raise Inconsistent(message)


def finite_number(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result

    def constant(value):
        raise Inconsistent("nonfinite JSON constant: " + value)

    require(isinstance(text, str), "JSON value is not text")
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def static_values(tree, requested):
    """Read literals, tuples and list concatenations; never execute a module."""
    assignments = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name):
            assignments.setdefault(target.id, []).append(node.value)
        elif isinstance(target, ast.Tuple) and isinstance(node.value, ast.Tuple):
            require(len(target.elts) == len(node.value.elts), "unsupported tuple assignment")
            for name, value in zip(target.elts, node.value.elts):
                if isinstance(name, ast.Name):
                    assignments.setdefault(name.id, []).append(value)
    active, cache = set(), {}

    def read(name):
        if name in cache:
            return cache[name]
        require(name not in active, "cyclic source constant: " + name)
        nodes = assignments.get(name, [])
        require(len(nodes) == 1, "missing or repeated source constant: " + name)
        active.add(name)
        value = evaluate(nodes[0])
        active.remove(name)
        cache[name] = value
        return value

    def evaluate(node):
        if isinstance(node, ast.Name):
            return read(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = evaluate(node.left), evaluate(node.right)
            require(type(left) is list and type(right) is list, "unsupported source expression")
            return left + right
        try:
            return ast.literal_eval(node)
        except (ValueError, TypeError, SyntaxError):
            raise Inconsistent("unsupported source constant expression")

    return {name: read(name) for name in requested}


def feature_map(raw, keys):
    value = strict_json(raw)
    require(type(value) is dict and set(value) == set(keys), "cached feature shape mismatch")
    require(all(finite_number(x) for x in value.values()), "cached feature is not a finite number")
    return value


def metric_map(results, groups):
    expected = {}
    numeric_keys = {
        "c6_baseline_null": {"accuracy", "n_pairs", "expected"},
        "primary": {"accuracy", "n_pairs", "null", "in_sample_diagnostic"},
        "C1_equivalent_implementation": {"accuracy", "n_pairs", "expected"},
    }
    for group in groups:
        block = results.get(group)
        require(type(block) is dict, "missing metric block: " + group)
        for key in numeric_keys[group]:
            value = block.get(key)
            require(finite_number(value), "invalid metric number: " + group + "." + key)
            if key == "n_pairs":
                require(type(value) is int and value > 0, "invalid pair count")
            else:
                require(0 <= value <= 1, "metric probability outside [0,1]")
            expected[(group, key)] = value
        if group == "primary":
            values = block.get("ci95")
            require(type(values) is list and len(values) == 2
                    and all(finite_number(x) and 0 <= x <= 1 for x in values)
                    and values[0] <= values[1], "invalid primary confidence interval")
            for index, number in enumerate(values):
                expected[(group, "ci95[{}]".format(index))] = number
    return expected


def audit(root, database, generator, mechanism, seed):
    root = Path(root).resolve()
    fingerprints = {}
    result = {
        "schema": "opengate.v6.selected-lineage.v1", "status": "FAIL", "checks": [],
        "selected": {"generator": generator, "mechanism": mechanism, "seed": seed},
        "limits": {
            "selectedWorldAndTwoControlsOnly": True,
            "rawTrajectoriesStored": False,
            "rawTrajectoryBitwiseEqualityAuthenticated": False,
            "historicalExecutionAuthenticated": False,
            "benchmarkRecomputed": False,
            "physicalHypothesisValidated": False,
        },
    }

    def read(path, limit):
        if not path.is_file():
            raise Unavailable("required file unavailable: " + path.name)
        if path.stat().st_size > limit:
            raise Unavailable("file exceeds bounded audit size: " + path.name)
        with path.open("rb") as source_file:
            raw = source_file.read(limit + 1)
        if len(raw) > limit:
            raise Unavailable("file grew beyond bounded audit size: " + path.name)
        fingerprints[path] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        return raw

    try:
        source = {name: read(root / name, MAX_TEXT) for name in SOURCES}
        protocol_hash = hashlib.sha256(b"".join(source[name] for name in SOURCES)).hexdigest()[:16]
        core_tree = ast.parse(source["v6_core.py"].decode("utf-8"))
        pipeline_tree = ast.parse(source["v6_pipeline.py"].decode("utf-8"))
        core = static_values(core_tree, ["BASE_SEED", "W", "H", "N_STEPS", "TRAIN_GENERATORS",
            "HOLDOUT_GENERATORS", "TRAIN_MECHANISMS", "UNSEEN_MECHANISMS", "OPERATOR_FEATS",
            "RESPONSE_FEATS", "BASELINE_FEATS"])
        pipeline = static_values(pipeline_tree, ["SEEDS_PER_GEN", "EPS_TIE", "REF", "SRC"])
        seed_functions = [node for node in core_tree.body if isinstance(node, ast.FunctionDef)
                          and node.name == "stable_seed"]
        expected_seed_ast = ast.parse(SEED_FUNCTION).body[0]
        require(len(seed_functions) == 1 and ast.dump(seed_functions[0]) == ast.dump(expected_seed_ast),
                "unsupported stable_seed contract; no source code executed")
        require(pipeline["SRC"] == list(SOURCES) and pipeline["REF"] == "continuous",
                "unsupported V6 source/reference contract")
        require(type(core["BASE_SEED"]) is int and 0 <= core["BASE_SEED"] < 2 ** 31, "invalid base seed")
        require(all(type(core[key]) is int and core[key] > 0 for key in ("W", "H", "N_STEPS")),
                "invalid source grid/step configuration")
        require(type(pipeline["SEEDS_PER_GEN"]) is int and 0 < pipeline["SEEDS_PER_GEN"] <= 1000,
                "invalid seeds_per_gen")
        require(finite_number(pipeline["EPS_TIE"]) and pipeline["EPS_TIE"] == 1e-9, "unsupported C1 tolerance")
        for key in ["TRAIN_GENERATORS", "HOLDOUT_GENERATORS", "TRAIN_MECHANISMS", "UNSEEN_MECHANISMS",
                    "OPERATOR_FEATS", "RESPONSE_FEATS", "BASELINE_FEATS"]:
            values = core[key]
            require(type(values) is list and bool(values) and all(type(v) is str for v in values)
                    and len(values) == len(set(values)), "invalid source list: " + key)
        generators = core["TRAIN_GENERATORS"] + core["HOLDOUT_GENERATORS"]
        mechanisms = core["TRAIN_MECHANISMS"] + core["UNSEEN_MECHANISMS"]
        require(len(set(generators)) == len(generators) and len(set(mechanisms)) == len(mechanisms),
                "overlapping train/holdout contract")
        require(generator in generators and mechanism in mechanisms, "unknown generator or computational mechanism")
        require(type(seed) is int and 0 <= seed < 2 ** 31, "seed outside integer V6 domain")
        expected_seeds = [(core["BASE_SEED"] + offset * 1000 + zlib.crc32(generator.encode())) % (2 ** 31)
                          for offset in range(pipeline["SEEDS_PER_GEN"])]
        require(seed in expected_seeds, "selected seed not in source seed schedule")
        result["selected"]["seedOffset"] = expected_seeds.index(seed)
        result["checks"].append("source definitions and selected seed schedule")

        protocol = strict_json(read(root / "v6_protocol.json", MAX_TEXT).decode("utf-8"))
        results = strict_json(read(root / "v6_results.json", MAX_TEXT).decode("utf-8"))
        require(type(protocol) is dict and type(results) is dict, "protocol/results must be objects")
        require(protocol.get("protocol") == "V6_ACTIVE_BLACKBOX_RESPONSE_BENCHMARK"
                and protocol.get("version") == "6.0.0", "unsupported stored V6 protocol")
        require(protocol.get("protocol_hash") == results.get("protocol_hash") == protocol_hash,
                "source/protocol/results hash mismatch")
        require(type(protocol.get("base_seed")) is int and type(results.get("base_seed")) is int
                and protocol["base_seed"] == results["base_seed"] == core["BASE_SEED"], "base seed mismatch")
        require(type(results.get("grid")) is list and all(type(v) is int for v in results["grid"])
                and type(results.get("n_steps")) is int and type(results.get("seeds_per_gen")) is int
                and results["grid"] == [core["W"], core["H"]] and results["n_steps"] == core["N_STEPS"]
                and results["seeds_per_gen"] == pipeline["SEEDS_PER_GEN"], "source/results configuration mismatch")
        require(results.get("generators") == {"train": core["TRAIN_GENERATORS"], "holdout": core["HOLDOUT_GENERATORS"]}
                and results.get("mechanisms") == {"train": core["TRAIN_MECHANISMS"], "unseen": core["UNSEEN_MECHANISMS"],
                                                  "continuous_ref": "continuous"}, "source/results population mismatch")
        require(protocol.get("never_emits") == results.get("never_emits") == "SIMULATION_DETECTED",
                "interpretation boundary mismatch")
        require(type(results.get("branch")) is str and type(results.get("final_status")) is str
                and protocol.get("final_status") == results["final_status"], "branch/status mismatch")
        report = read(root / "report_v6.md", MAX_TEXT).decode("utf-8")
        require(re.findall(r"Protocol hash:\*\*\s*`([0-9a-f]{16})`", report) == [protocol_hash], "report hash mismatch")
        require(re.findall(r"Base seed:\*\*\s*`(\d+)`", report) == [str(core["BASE_SEED"])], "report seed mismatch")
        require(re.findall(r"Final status:\*\*\s*`([^`]+)`", report) == [results["final_status"]], "report status mismatch")
        result["sourceProtocolHash"] = protocol_hash
        result["checks"].append("raw source, protocol, results and report linkage")

        db = (root / database).resolve()
        try:
            db.relative_to(root)
        except ValueError:
            raise Inconsistent("database must remain inside the selected root")
        sidecars = [Path(str(db) + suffix) for suffix in ("-wal", "-shm", "-journal")]
        if any(path.exists() for path in sidecars):
            raise Unavailable("database has WAL/shared-memory/journal; obtain a quiescent copy")
        read(db, MAX_DB)
        connection = sqlite3.connect(db.as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            schema = dict(connection.execute("SELECT name,type FROM sqlite_master WHERE name IN ('meta','worlds','benchmark_results')"))
            require(schema == {name: "table" for name in ("meta", "worlds", "benchmark_results")},
                    "required evidence tables unavailable or replaced by views")
            meta_rows = connection.execute("SELECT key,value FROM meta LIMIT 65").fetchall()
            require(len(meta_rows) <= 64 and all(type(k) is str and type(v) is str for k, v in meta_rows), "invalid DB metadata")
            require(len({k for k, v in meta_rows}) == len(meta_rows), "duplicate DB metadata")
            meta = dict(meta_rows)
            for key in ("branch", "protocol_hash", "base_seed", "final_status", "never_emits"):
                require(meta.get(key) == str(results[key]), "DB metadata mismatch: " + key)
            result["checks"].append("database metadata agrees with source-bound results")

            group = "train" if generator in core["TRAIN_GENERATORS"] else "holdout"
            worlds = {}
            for mech in (mechanism, "continuous", "continuous_alt"):
                rows = connection.execute("SELECT grp,response_json,baseline_json FROM worlds "
                    "WHERE gen=? AND mech=? AND seed=? LIMIT 2", (generator, mech, seed)).fetchall()
                require(len(rows) == 1, "missing or duplicate selected/control row: " + mech)
                require(rows[0][0] == group, "selected/control group mismatch: " + mech)
                worlds[mech] = {"response": feature_map(rows[0][1], core["RESPONSE_FEATS"]),
                                "baseline": feature_map(rows[0][2], core["BASELINE_FEATS"])}
            reference = worlds["continuous"]
            require(all(row["baseline"] == reference["baseline"] for row in worlds.values()), "paired baseline mismatch")
            delta = max(abs(reference["response"][key] - worlds["continuous_alt"]["response"][key])
                        for key in core["OPERATOR_FEATS"])
            require(delta < pipeline["EPS_TIE"], "C1 cached operator features exceed source tie tolerance")
            result["controls"] = {"pairedBaselineFeaturesEqual": True, "implementationControlMaxFeatureDelta": delta,
                                  "implementationControlTolerance": pipeline["EPS_TIE"], "cachedRowsChecked": 3}
            result["checks"].append("finite cached features, seed/group pairing and C1/C6 selected controls")

            groups = ("c6_baseline_null", "primary", "C1_equivalent_implementation")
            expected_metrics = metric_map(results, groups)
            rows = connection.execute("SELECT test_name,metric_name,metric_value FROM benchmark_results "
                "WHERE test_name IN (?,?,?) LIMIT 65", groups).fetchall()
            require(len(rows) <= 64 and all(type(a) is str and type(b) is str and finite_number(v) for a, b, v in rows),
                    "invalid stored metric")
            require(len({(a, b) for a, b, v in rows}) == len(rows), "duplicate stored metric")
            require({(a, b): v for a, b, v in rows} == expected_metrics, "DB/results metric mismatch")
            result["storedMetricsChecked"] = len(rows)
            result["checks"].append("selected aggregate metrics match results JSON; no recomputation")
        finally:
            connection.close()
        require(not any(path.exists() for path in sidecars), "database sidecar appeared during audit")
        result["status"] = "PASS"
    except Unavailable as error:
        result.update(status="BLOCKED", error=str(error))
    except (OSError, sqlite3.Error) as error:
        result.update(status="BLOCKED", error="evidence read failed: " + str(error))
    except (Inconsistent, ValueError, TypeError, KeyError, SyntaxError, RecursionError, OverflowError) as error:
        result.update(status="FAIL", error=str(error))

    preserved = True
    for path, expected in fingerprints.items():
        try:
            with path.open("rb") as source_file:
                current = source_file.read(expected["bytes"] + 1)
            preserved = preserved and len(current) == expected["bytes"] and hashlib.sha256(current).hexdigest() == expected["sha256"]
        except OSError:
            preserved = False
    result["inputsBytePreserved"] = preserved
    result["inputFingerprints"] = {str(path.relative_to(root)): value for path, value in fingerprints.items()}
    if not preserved:
        result.update(status="FAIL", error="an input changed during the audit")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--database", default="history_v6.sqlite3")
    parser.add_argument("--generator", required=True)
    parser.add_argument("--mechanism", required=True)
    parser.add_argument("--seed", required=True, type=int)
    args = parser.parse_args(argv)
    result = audit(args.root, args.database, args.generator, args.mechanism, args.seed)
    print(json.dumps(result, indent=2, allow_nan=False))
    return {"PASS": 0, "FAIL": 1, "BLOCKED": 2}[result["status"]]


if __name__ == "__main__":
    sys.exit(main())
