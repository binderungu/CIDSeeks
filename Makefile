.PHONY: sync smoke smoke-suite paper-core paper-core-full paper-core-flagship paper-core-flagship-resume paper-core-gate-subset robustness auth-sensitivity scalability acceptance acceptance-pr acceptance-nightly lint typecheck-staged typecheck-orchestrator typecheck-runner typecheck-core-surface typecheck-runtime-modules typecheck-export-qa typecheck-ui-store typecheck-scripts typecheck-repo test reproduce legacy-import-guard shell-safety-guard tar-safety-guard deterministic-rng-guard time-sleep-guard manifest-integrity-guard public-hygiene-guard public-governance-guard compliance stats-gate-smoke stats-gate-paper-core bundle-smoke verify-bundle-smoke bundle-paper-core verify-bundle-paper-core public-snapshot flagship-freeze-final flagship-freeze-final-dry-run ci-core-local ci-paper-core-gate-local publish-freeze-local

UV_RUN = uv run --locked --
EXP_CFG_DIR = configs/experiments

sync:
	uv sync

smoke:
	$(UV_RUN) python runner.py --config config.yaml

smoke-suite:
	$(UV_RUN) python simulate.py --suite smoke --config $(EXP_CFG_DIR)/experiments_smoke.yaml

paper-core:
	$(UV_RUN) python simulate.py --suite paper_core --config $(EXP_CFG_DIR)/experiments_batch_quick.yaml

paper-core-full:
	$(UV_RUN) python simulate.py --suite paper_core --config $(EXP_CFG_DIR)/experiments.yaml

paper-core-flagship:
	$(UV_RUN) python simulate.py --suite paper_core --config $(EXP_CFG_DIR)/experiments_paper_core_flagship.yaml

paper-core-flagship-resume:
	$(UV_RUN) python simulate.py --suite paper_core --config $(EXP_CFG_DIR)/experiments_paper_core_flagship.yaml --resume

paper-core-gate-subset:
	$(UV_RUN) python simulate.py --suite paper_core --config $(EXP_CFG_DIR)/experiments_paper_core_ci_gate.yaml

robustness:
	$(UV_RUN) python simulate.py --suite robustness_sensitivity --config $(EXP_CFG_DIR)/experiments_auth_sensitivity.yaml

auth-sensitivity:
	$(UV_RUN) python simulate.py --suite robustness_sensitivity --config $(EXP_CFG_DIR)/experiments_auth_sensitivity.yaml

scalability:
	$(UV_RUN) python simulate.py --suite scalability_stress --config $(EXP_CFG_DIR)/experiments_scalability_stress.yaml

acceptance:
	$(UV_RUN) python scripts/qa/acceptance_attack_gap.py --seeds 101 202 303 --tolerance 0.04

acceptance-pr:
	$(UV_RUN) python scripts/qa/acceptance_attack_gap.py --seeds 101 202 --nodes 20 --iterations 30 --tolerance 0.04 --report results/acceptance/attack_gap_report_pr.json

acceptance-nightly:
	$(UV_RUN) python scripts/qa/acceptance_attack_gap.py --seeds 101 202 303 --nodes 20 --iterations 40 --tolerance 0.04 --report results/acceptance/attack_gap_report_nightly.json

reproduce: paper-core-full

legacy-import-guard:
	$(UV_RUN) python scripts/qa/check_no_legacy_imports.py

shell-safety-guard:
	$(UV_RUN) python scripts/qa/check_no_shell_true.py

tar-safety-guard:
	$(UV_RUN) python scripts/qa/check_safe_tar_extract.py

deterministic-rng-guard:
	$(UV_RUN) python scripts/qa/check_deterministic_rng.py

time-sleep-guard:
	$(UV_RUN) python scripts/qa/check_no_time_sleep.py

manifest-integrity-guard:
	$(UV_RUN) python scripts/qa/check_manifest_integrity.py

public-hygiene-guard:
	$(UV_RUN) python scripts/qa/check_public_repo_hygiene.py

public-governance-guard:
	$(UV_RUN) python scripts/qa/check_public_repo_governance.py

compliance: legacy-import-guard shell-safety-guard tar-safety-guard deterministic-rng-guard time-sleep-guard manifest-integrity-guard public-hygiene-guard public-governance-guard

lint:
	uv run --locked --extra dev -- flake8 src runner.py simulate.py --select=E9,F63,F7,F82 --statistics

typecheck-staged:
	uv run --locked --extra dev -- mypy src/evaluation/metrics/enhanced_metrics.py src/evaluation/pipeline/run_evaluator.py --ignore-missing-imports

typecheck-orchestrator:
	uv run --locked --extra dev -- mypy simulate.py src/evaluation/export/experiment_aggregator.py --ignore-missing-imports

typecheck-runner:
	uv run --locked --extra dev -- mypy runner.py --ignore-missing-imports

typecheck-core-surface:
	uv run --locked --extra dev -- mypy src/simulation/core/message.py src/simulation/core/network.py src/simulation/core/node.py --ignore-missing-imports --follow-imports=silent

typecheck-runtime-modules:
	uv run --locked --extra dev -- mypy src/simulation/modules/collaboration/gossip_protocol.py src/simulation/modules/collaboration/module.py src/simulation/modules/privacy/module.py src/simulation/modules/authentication/module.py --ignore-missing-imports --follow-imports=silent

typecheck-export-qa:
	uv run --locked --extra dev -- mypy src/evaluation/export/result_exporter.py scripts/qa/check_stats_gate.py scripts/qa/check_manifest_integrity.py --ignore-missing-imports

typecheck-ui-store:
	uv run --locked --extra dev -- mypy src/ui/services/experiment_store.py --ignore-missing-imports

typecheck-scripts:
	uv run --locked --extra dev -- mypy scripts/qa/*.py scripts/artifacts/*.py --ignore-missing-imports

typecheck-repo:
	uv run --locked --extra dev -- mypy src --ignore-missing-imports

test:
	PYTHONPATH=src uv run --locked --extra dev -- pytest -q src/tests

stats-gate-smoke:
	$(UV_RUN) python scripts/qa/check_stats_gate.py --path results/smoke/stats_gate.json

stats-gate-paper-core:
	$(UV_RUN) python scripts/qa/check_stats_gate.py --path results/paper_core/stats_gate.json

bundle-smoke:
	$(UV_RUN) python scripts/artifacts/build_artifact_bundle.py --suite smoke --bundle-path results/artifacts/smoke_artifact_bundle.tar.gz --include-manifests

verify-bundle-smoke:
	$(UV_RUN) python scripts/artifacts/verify_artifact_bundle.py --bundle-path results/artifacts/smoke_artifact_bundle.tar.gz --report results/artifacts/smoke_artifact_bundle_verify.json

bundle-paper-core:
	$(UV_RUN) python scripts/artifacts/build_artifact_bundle.py --suite paper_core --bundle-path results/artifacts/paper_core_flagship_artifact_bundle.tar.gz --include-manifests

verify-bundle-paper-core:
	$(UV_RUN) python scripts/artifacts/verify_artifact_bundle.py --bundle-path results/artifacts/paper_core_flagship_artifact_bundle.tar.gz --report results/artifacts/paper_core_flagship_artifact_bundle_verify.json

public-snapshot:
	$(UV_RUN) python scripts/maintenance/export_public_snapshot.py --dest /tmp/vibe-cids-public --overwrite --include-untracked --init-git

flagship-freeze-final:
	$(UV_RUN) python scripts/maintenance/run_flagship_freeze.py

flagship-freeze-final-dry-run:
	$(UV_RUN) python scripts/maintenance/run_flagship_freeze.py --dry-run --allow-dirty

ci-core-local: sync lint typecheck-staged typecheck-orchestrator typecheck-runner typecheck-core-surface typecheck-runtime-modules typecheck-export-qa typecheck-ui-store typecheck-scripts typecheck-repo legacy-import-guard time-sleep-guard public-governance-guard test smoke smoke-suite manifest-integrity-guard stats-gate-smoke bundle-smoke verify-bundle-smoke

ci-paper-core-gate-local: sync lint typecheck-staged typecheck-orchestrator typecheck-runner typecheck-core-surface typecheck-runtime-modules typecheck-export-qa typecheck-ui-store typecheck-scripts typecheck-repo legacy-import-guard time-sleep-guard public-governance-guard paper-core-gate-subset manifest-integrity-guard stats-gate-paper-core

publish-freeze-local: compliance smoke-suite stats-gate-smoke paper-core-gate-subset stats-gate-paper-core bundle-smoke verify-bundle-smoke
	@echo "publish-freeze-local passed"
