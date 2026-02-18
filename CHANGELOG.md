# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Legacy import guard script (`scripts/qa/check_no_legacy_imports.py`)
- Manifest integrity guard script (`scripts/qa/check_manifest_integrity.py`)
- Publish freeze checklist doc (`docs/09_PUBLISH_FREEZE_CHECKLIST.md`)
- Local freeze gate target (`make publish-freeze-local`)
- Config resolution deprecation tests (`src/tests/test_simulate_config_resolution.py`)
- Make targets for legacy-boundary guardrails (`legacy-import-guard`, `compliance`)
- Initial legacy namespace package (`src/simulation/legacy/`) for staged archival migration
- Legacy subpackages for staged archival migration (`src/simulation/legacy/{scenario,simulator,reporting,visualization}`)
- Legacy config package for staged archival migration (`src/simulation/legacy/config/`)
- Suite configs for robustness_sensitivity and scalability_stress
- Suite-level aggregate plots in `results/<suite>/aggregate_plots`
- Deterministic RNG helpers for reproducible simulations
- Tier-specific challenge payload/proof semantics (basic nonce-ack, advanced context digest, final attestation bundle)
- `experiments_auth_sensitivity.yaml` PMFA-stress template for NoAuth vs Auth-sim sensitivity runs
- Project reorganization following professional best practices
- Trust plugin system with 4 baseline methods (Li23, Meng20, Fuzzy24, Sphinx18)
- Comprehensive evaluation framework
- Performance benchmarking system
- Trust Method Selector UI
- Enhanced metrics collection system
- Trust tier state with rise/fall thresholds for escalation + quarantine
- Deterministic prefix-preserving privacy mapping + k-anonymity parameters
- Hash-chained event details for tamper-evident logs
- Acceptance matrix script for multi-seed attack gap checks (`scripts/qa/acceptance_attack_gap.py`)
- Make targets for staged acceptance matrix profiles (`acceptance-pr`, `acceptance-nightly`)
- GitHub Actions workflow for staged acceptance checks (`.github/workflows/acceptance-matrix.yml`)
- Core CI workflow for lock/test/smoke/stats-gate/artifact checks (`.github/workflows/ci-core.yml`)
- Stats gate checker script (`scripts/qa/check_stats_gate.py`)
- Artifact bundle build + verify scripts (`scripts/artifacts/build_artifact_bundle.py`, `scripts/artifacts/verify_artifact_bundle.py`)
- Local make targets for smoke stats gate and artifact bundle verification
- Paper-core CI gate subset config (`experiments_paper_core_ci_gate.yaml`)
- Dedicated non-smoke fail-fast workflow (`.github/workflows/ci-paper-core-gate.yml`)
- Make targets for local non-smoke gate checks (`paper-core-gate-subset`, `stats-gate-paper-core`, `ci-paper-core-gate-local`)
- Module boundary map for active-vs-legacy runtime files (`src/simulation/modules/README.md`)

### Changed
- `ci-core` targeted pytest step now runs with `uv run --locked --extra dev -- ...` so clean-checkout CI no longer depends on preinstalled dev extras
- `make test` now uses `uv run --locked --extra dev -- pytest -q src/tests` for deterministic local parity with CI
- Smoke suite config (`configs/experiments/experiments_smoke.yaml`) now matches canonical experiment doc baseline (`N=30`, `iterations=200`, 1 benign + 1 malicious scenario)
- README and runbook testing sections now explicitly include `uv sync --extra dev`; removed hard `>90%` coverage claim from README quality standards
- Canonical lint command now uses staged `flake8` critical profile under `--extra dev` (`make lint`, runbook) to match the current locked dev dependency set while gating syntax/undefined-name failures (`--select=E9,F63,F7,F82`)
- AUROC/AUPRC helpers now return `NaN` early for one-class labels to avoid undefined-metric noise in benign-only runs
- Added regression tests for one-class AUROC/AUPRC behavior and smoke-suite config contract (`src/tests/test_enhanced_metrics_edge_cases.py`, `src/tests/test_smoke_config_contract.py`)
- `ci-core` and `ci-paper-core-gate` now execute `make lint` (critical profile) before suite execution; local make CI targets (`ci-core-local`, `ci-paper-core-gate-local`) include the same lint gate
- `ci-core` targeted tests now include one-class metric regression and smoke config contract tests
- Added staged evaluator typecheck gate (`make typecheck-staged`) and wired it into `ci-core`, `ci-paper-core-gate`, and local CI make targets
- Artifact verifier now rejects unsafe tar members (path traversal/symlink entries) and invalid manifest paths; artifact builder now enforces repo-root path boundaries for included files
- Added security regression tests for artifact tar extraction and path-boundary checks (`src/tests/test_artifact_security.py`)
- Added shell-execution guard (`scripts/qa/check_no_shell_true.py`) and unsafe tar extraction guard (`scripts/qa/check_safe_tar_extract.py`), wired into `make compliance`, `ci-core`, and `ci-paper-core-gate`
- Added deterministic RNG guard (`scripts/qa/check_deterministic_rng.py`) to block unseeded `random.Random()` / `numpy.random.default_rng()` constructors in runtime paths
- Added regression tests for security QA guards (`src/tests/test_security_qa_guards.py`)
- RNG fallback paths across runtime/evaluation modules now resolve to deterministic seeded generators (no hidden non-deterministic constructor defaults)
- Canonical output layout now writes run artifacts under `results/<suite>/<run_id>/`
- `simulate.py` now requires `--suite` and writes suite aggregates in canonical paths
- Suite configuration YAMLs moved under `configs/experiments/`; `simulate.py --config <basename>` remains backward-compatible via fallback resolver
- `simulate.py` now emits a deprecation warning when legacy basename fallback is used, to guide migration to canonical `configs/experiments/...` paths
- UI fallback exception paths now use debug logging (instead of silent pass) in key entry/service/viewer paths
- Script utilities are now grouped by purpose (`scripts/qa`, `scripts/artifacts`, `scripts/ui`, `scripts/maintenance`)
- `setup.py` is now a thin compatibility shim; canonical project metadata/dependencies live in `pyproject.toml`
- Scope boundary is now explicitly synchronized across docs/paper draft: Evaluation-2 empirical claims are restricted to Sybil, Collusion, Betrayal, and PMFA
- Package exports in `src/simulation/modules/*/__init__.py` now default to canonical runtime modules and stop eagerly importing legacy manager implementations
- Removed remaining backward-compat symbol aliases from module exports (`IDSModule`, `TrustModule`, `AuthenticationManager`, `AuthManager`, `CollaborationManager`) to keep API surface canonical-only
- Legacy stack compatibility was staged during migration, then removed from the runtime tree
- Canonical attack exports now only include `BehaviorPolicy` and `PMFAMatchCache`; legacy attacker classes/modules were removed
- Core CI gates (`ci-core`, `ci-paper-core-gate`) and local make gates now run legacy import guard before experiment checks
- Legacy import guard now also detects package-relative form (`from . import <legacy_module>`) in protected canonical paths
- Legacy import guard now also blocks imports of removed compatibility symbols (`IDSModule`, `TrustModule`, `AuthenticationManager`, `AuthManager`, `CollaborationManager`) in protected canonical paths
- Removed `simulation.config.experiment_runner` shim and removed `legacy/experiment_runner.py`
- Removed shim directories `simulation/{scenario,simulator,reporting,visualization}` and removed corresponding archived stacks
- Legacy import guard now treats `simulation.config.experiment_runner` as banned in canonical runtime paths
- Legacy import guard now also blocks direct imports of `simulation.legacy` from canonical runtime paths
- Legacy import guard now also protects GUI runtime paths (`src/main.py`, `src/ui/`) from legacy imports
- Removed `simulation.runner` shim; canonical GUI entry point is now only `src.main`
- Legacy import guard now treats `simulation.runner` as banned in canonical runtime paths
- Removed `simulation.config.config_manager` shim and removed `legacy/config/config_manager.py`
- Removed legacy module-manager files: `authentication/{auth_manager.py,core_auth_manager.py}`, `privacy/privacy_manager.py`, `collaboration/collab_manager.py`
- Removed unused `simulation.analysis` package (`experiment_analysis.py`, `experiment_metrics.py`, `result_analyzer.py`, `statistics.py`)
- Removed unused `simulation.export` package (`result_exporter.py`, `data_processor.py`) and moved canonical exporter implementation to `evaluation.export.result_exporter`
- Removed unused `simulation.monitoring` package (`real_time_monitor.py`)
- Removed unused `simulation.models` package (`base.py`)
- Removed unused utility modules (`error_handler.py`, `event_manager.py`, `helpers.py`, `icon_handler.py`, `performance_monitor.py`, `persistence.py`, `simulation_state.py`, `visualization_helper.py`)
- Removed legacy `simulation.modules.database` shims (`database_manager.py`, `database_module.py`) and standardized runtime DB path to `NodeDatabase`
- Removed legacy IDS module implementation (`simulation.modules.ids.ids_module.py`) and kept only canonical `IdsModule`
- Removed unused core legacy files (`simulation.core.simulation_iteration.py`, `simulation.core.simulation_status.py`)
- Removed leftover utility legacy files (`simulation.utils.exceptions`, `simulation.utils.logger`, `simulation.utils.theme`) and simplified `simulation.utils` exports
- GUI setup tab now reads slider defaults/bounds from canonical `config.yaml` instead of legacy `simulation_config.json`
- Legacy import guard now treats `simulation.config.config_manager` as banned in canonical runtime paths
- Removed legacy config package artifacts (`simulation_config.json`, `default_config.yaml`, `experiment_config.yaml`)
- Removed remaining `simulation.legacy` package namespace from source tree
- Trust responses now flow through attack behavior policy (no attack logic in TrustCalculator)
- Moved documentation files to `docs/` directory
- Reorganized scripts to `scripts/` directory
- Improved project structure following Django/Flask patterns
- Metrics classification thresholds now consistently use config `trust_threshold`
- Run metrics logging flushes once per run to avoid metadata leakage
- Run-level summary classification metrics are now threshold-consistent with `FPR_h/FNR_m`, while AUROC/AUPRC remain ranking metrics
- `simulate.py` variant mapper now supports trust fall/rise thresholds, PMFA knobs, extended auth knobs, and privacy/gossip feature sweeps
- `experiments_batch_quick.yaml` now uses longer horizon (`iterations=30`) with calibrated trust thresholds (`tau=0.55`, fall `0.45`, rise `0.50`) to avoid quick-suite threshold collapse
- Auth sensitivity defaults now stress PMFA selective-response (`pmfa_detect_prob`, `pmfa_poison_rate`) so NoAuth vs Auth-sim differences are observable in security metrics (`asr`, `fnrq`, `bypass_rate`)
- Acceptance matrix CI profiles now use calibrated tolerance (`0.04`) with staged PR quick (`2 seeds, 30 iterations`) vs nightly (`3 seeds, 40 iterations`)
- Run identity semantics now split deterministic `experiment_id` and unique `run_uid`; `run_id` is composed as `experiment_id__run_uid`
- Output safety policy now fails by default when run directory already exists; explicit `--overwrite` is required to replace prior artifacts
- Manifest flushing now supports retention policy (`manifest_keep_last`) to prevent unbounded growth in `results/_manifests/`
- UI run index now resolves latest runs only from canonical `results/_manifests/` (legacy `runs/` fallback removed)
- UI artifact discovery now uses canonical `metadata.json` and no longer reads legacy `meta.json`
- Data Analysis tab now resolves latest run strictly from manifest (non-manifest directory scan fallback removed)
- UI run index now rejects manifest targets that are outside `results/` or missing `metadata.json` (partial artifacts are filtered out)
- `make compliance` now includes manifest integrity guard (`scripts/qa/check_manifest_integrity.py`)
- CI workflows (`ci-core`, `ci-paper-core-gate`) and local CI make targets now run manifest integrity guard after suite execution
- PMFA classifier now uses DMPO-aware fingerprint surface and non-random fallback policy (default `assume_challenge`)
- Sybil behavior model now supports runtime virtual identity rotation (identity inflation abstraction)
- Betrayal `on_off` mode now respects `betrayal_start_round` warmup
- `simulate.py` now enforces suite reproducibility gate (default `R>=10` for non-smoke), with explicit YAML override via `reproducibility_gate`
- Suite runs now emit `seed_manifest.json` for resolved seed plans
- `ExperimentAggregator` now exports `stats_gate.json` and aggregate diagnostics (`n_seeds`, `ci_width`, `ci_method`, `power_warning`)
- Run metadata now includes config hash, `uv.lock` hash, git dirty flag, command provenance, platform info, and dependency versions
- Flagship/sensitivity/scalability configs now use broader sweeps with default multi-seed `R=10`
- GUI `Experiment Summary` now supports aggregate scope by loading canonical suite outputs (`aggregate_summary.csv`, `experiments.csv`, `stats.csv`)

### Fixed
- `SimulationEngine.run()` no longer marks interrupted runs as completed (`is_completed` now preserves stop/interruption state)
- `TrustManager` now initializes optional `trust_plugin` hook to prevent latent attribute errors on legacy helper paths (`process_alarm`)
- Benign-only smoke scenario no longer emits massive sklearn undefined-metric warnings from AUPRC/AUROC helper path
- Seeded RNGs across simulation + evaluation bootstraps for deterministic runs
- Added config snapshot + metadata artifacts per run
- Import path issues across multiple modules
- `PYTHONPATH=src` test collection failure caused by hardcoded `src.*` imports in runtime modules (`simulation_engine` + UI entry paths)
- GUI `Experiment Summary` refresh crash (`AttributeError: refresh_in_progress`) caused by duplicate `refresh_analysis` definition override; canonical artifact-based refresh path now remains active
- Removed orphaned DB-refresh methods from `ExperimentSummaryTab` that referenced non-existent `_update_plot` queue path
- Pruned unused legacy DB/comparison plotting methods from `ExperimentSummaryTab` and removed duplicate `_export_pdf` definition override risk
- Missing dependencies in requirements.txt
- PMFA/DMPO privacy logging now records both request and challenge events
- Trust-side REQUEST observations now propagate DMPO metadata (`dmpo_enabled`, variant index, delay window, PMFA surface id) for PMFA coupling

## [1.0.0] - 2024-12-XX

### Added
- Initial release of CIDSeeks simulation platform
- Core CIDS simulation engine
- 3-level challenge trust model implementation
- Attack simulation (PMFA, Collusion, Sybil, Betrayal)
- Basic GUI interface
- Comprehensive test suite 
