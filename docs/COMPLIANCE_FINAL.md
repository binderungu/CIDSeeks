# COMPLIANCE_FINAL — Recovery + UV Migration + Verification (2026-01-30)

## 1) What was missing and why
- Missing files after `git clean -xfd`:  
  - `src/simulation/modules/attacks/behavior_policy.py`  
  - `src/simulation/modules/trust/observation.py`  
  - `src/simulation/utils/rng.py`
- `git log --all -- <path>` showed no history for these paths, and `git check-ignore -v` showed they were not ignored.  
  **Conclusion:** they were untracked and removed by `git clean -xfd`.

## 2) Recovery actions (minimal, paper-aligned interfaces)
- Recreated `behavior_policy.py` with:
  - `BehaviorPolicy.respond(...)` (honest, collusion, sybil, betrayal, PMFA behavior)
  - `PMFAMatchCache` for cross-node PMFA matching
- Recreated `observation.py` as a typed dataclass aligned with docs/03_ATTACK_MODEL.md.
- Recreated `rng.py` with deterministic seed derivation (`derive_seed`, `make_random`, `make_numpy_rng`).
- Added `.venv/` to `.gitignore` (uv sync creates it).

## 3) UV migration
- Added `pyproject.toml` (project metadata + dependencies).
- Generated `uv.lock` via `uv lock`.
- Updated docs:
  - `docs/00_INDEX.md` now includes the quick paper_core command.
  - `docs/01_RUNBOOK.md` notes `uv.lock` is reproducibility-critical.

## 4) Verification commands (executed)
- `uv sync`
- `uv run --locked -- python runner.py --config config.yaml`
- `uv run --locked -- python simulate.py --suite smoke --config configs/experiments/experiments_smoke.yaml`
- `uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments_batch_quick.yaml`

## 5) Evidence: output artifacts (paths containing metadata.json + config_resolved.yaml + summary.csv + metrics_raw.*)

### Runner (single run)
- `results/smoke/run_20260130_141757_seed42/`

### Smoke suite
- `results/smoke/smoke_test_v00_r00_seed42/`

### Paper core (quick subset)
- `results/paper_core/collusion_quick_v00_r00_seed5000/`
- `results/paper_core/pmfa_quick_v00_r00_seed5000/`
- `results/paper_core/sybil_quick_v00_r00_seed5000/`

## 6) Notes
- Smoke suite emitted a warning about method alias `ours` not being available; it fell back to `three_level_challenge` as expected.
