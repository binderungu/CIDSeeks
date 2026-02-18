# Scripts Directory

Folder ini berisi utilitas pendukung, bukan entry point eksperimen paper.

Struktur:
- `scripts/qa/` -> utilitas quality gate, acceptance, dan validasi statistik
- `scripts/artifacts/` -> build/verifikasi artifact bundle
- `scripts/maintenance/` -> housekeeping lokal + migrasi data lama
- `scripts/ui/` -> helper opsional untuk UI

Yang dipakai:
- `scripts/maintenance/clean_workspace.sh` -> bersih-bersih artefak lokal
- `scripts/maintenance/create_metrics_columns.py` -> migrasi DB lama
- `scripts/maintenance/export_public_snapshot.py` -> export snapshot repo public-safe tanpa history privat (opsional init git baru)
- `scripts/ui/enable_interactive_graphs.py` -> helper opsional UI graph
- `scripts/qa/acceptance_attack_gap.py` -> acceptance matrix multi-seed (attack gap)
- `scripts/qa/check_stats_gate.py` -> validasi `stats_gate.json` untuk CI/local gate
- `scripts/qa/check_no_legacy_imports.py` -> guardrail agar jalur runtime canonical tidak mengimpor modul legacy
- `scripts/qa/check_deterministic_rng.py` -> guardrail agar constructor RNG selalu memakai seed eksplisit
- `scripts/qa/check_manifest_integrity.py` -> validasi skema manifest + konsistensi `results_path` terhadap artifact kanonis (`metadata.json`, `summary.csv`)
- `scripts/artifacts/build_artifact_bundle.py` -> packaging artifact reproducibility (tar.gz + SHA manifest)
- `scripts/artifacts/verify_artifact_bundle.py` -> verifikasi integritas artifact bundle

Entry point eksperimen tetap:
- `runner.py` (single run)
- `simulate.py` (suite run)
