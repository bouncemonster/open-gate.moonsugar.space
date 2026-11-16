# Codex continuation — OpenGate / proof_of_simulation

Source audit: 2026-11-16, baseline `686619bec326653573bb365021b95618f3b800c2`. This is a dated entry record; check current `git rev-parse HEAD` and `git status --short` before the next change. A later documentation commit does not change the scope of earlier runtime evidence.

Canonical working directory: `J:/project/project-open-gate/proof_of_simulation`.

Continue the read-only evidence-auditor and falsifiability work around the frozen synthetic V6 response-operator benchmark. V1–V5.5 remain closed lineage.

## Read first

[AGENTS.md](AGENTS.md), [README.md](README.md), [report_v6.md](report_v6.md), [v6_protocol.json](v6_protocol.json), [audit_v6_lineage.py](audit_v6_lineage.py) and [tests/test_v6_lineage.py](tests/test_v6_lineage.py). Reports/results own the scientific lineage; this continuation note does not revise them.

## Accepted work and present limits

The selected G01/fixed_point row has its earlier bounded acceptance. On 2026-11-16, a separate existing holdout row G03_drift/modular/seed 878593273 (offset 0) and two continuous controls passed the published auditor: 12 stored metrics matched; all ten inputs retained bytes and mtime. Source was 686619bec326, protocol 99054d610b0d588f, grid 16×16, 24 steps, ten seeds. That wave29 audit is already complete and was not repeated for readiness.

## Small checks

```sh
python -B audit_v6_lineage.py --help
```

For a change to the auditor, the focused suite is `python -B -m unittest discover -s tests -p test_v6_lineage.py -v`; it uses temporary evidence fixtures. Inspect its setup before execution. `verify.py --skip-db` is a broader repository-consistency check and can create compilation cache files. Neither command validates a physical hypothesis.

## Starting the project

There is no service to start for the next task. `v6_pipeline.py` regenerates results/protocol/database/artifacts; it is not an entry smoke test. The original Makefile covers the V1/V2 C kernel only.

## Next concrete task

Turn the accepted G03 holdout/unseen row and its continuous controls into a bounded regression fixture for the auditor, using a disposable SQLite database and the retained metric values. First compare with the existing G01 fixture so coverage is added rather than rerunning the same native audit. Completion requires acceptance of the correct seed/group/control lineage and rejection of one altered metric or missing paired control, with the real frozen sources, reports and databases unchanged.

## Preserve and report

Preserve hash-frozen `v6_core.py`, `v6_pipeline.py`, `v6_db.py`, `v5_detector.py`, protocols/results, archives and all SQLite stores/sidecars. Never reopen a closed experimental branch or delete ignored evidence as cleanup. Raw trajectories are absent from the selected stored response JSON, so no bitwise trajectory/history/full-benchmark claim follows. V6 describes bounded non-additivity signatures, not SIMULATION_DETECTED or observational proof of a simulated universe.

For the next handoff, record the exact source revision, changed files, command and exit status, executed checks and adapters, output identity, preserved local work and one remaining criterion. Keep PASS, FAIL, NOT RUN and environment-dependent acceptance separate. Source-ready means development can continue; it does not certify the whole product or its scientific interpretation.
