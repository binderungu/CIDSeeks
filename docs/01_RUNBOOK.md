# 01_RUNBOOK — Evaluation-2 (SimPy) with uv (canonical)

Tujuan: semua orang (dan AEC) bisa menjalankan eksperimen dengan langkah minimal, deterministik, dan reproducible.

## 0) Prasyarat
- Python sesuai `pyproject.toml` (disarankan pin via `.python-version`).
- uv terpasang.

Install uv:
- macOS (Homebrew): `brew install uv`
- Alternatif installer resmi: `curl -LsSf https://astral.sh/uv/install.sh | sh`

Referensi uv: konsep project, sync, run. :contentReference[oaicite:7]{index=7}

## 1) Setup environment (CANONICAL)
1) Sync deps (buat `.venv/` dan install sesuai lock):
- `uv sync`

2) Verifikasi lock (opsional tapi bagus untuk CI/AE):
- `uv lock --check`

Catatan penting:
- `uv run` melakukan lock+sync otomatis sebelum menjalankan command; untuk mode paper/AE gunakan `--locked` agar tidak mengubah lockfile saat run. :contentReference[oaicite:8]{index=8}
- `uv.lock` adalah artifact reproducibility; update hanya via `uv lock`.

## 2) Determinism rule (WAJIB)
- Setiap run harus punya seed eksplisit.
- Semua RNG harus berasal dari seed (tidak ada random global tanpa seed).
- Semua delay di simulator pakai SimPy `env.timeout`, bukan `time.sleep`.
- Suite `paper_core`, `robustness_sensitivity`, dan `scalability_stress` defaultnya memakai reproducibility gate (`runs_per_variant >= 10`).
  Profil dev/quick boleh override via `reproducibility_gate.enforce: false`.

## 3) Canonical commands (MUST work)

Catatan kompatibilitas:
- File suite config sekarang disimpan di `configs/experiments/`.
- Untuk backward compatibility, `simulate.py` masih menerima basename lama (contoh: `--config experiments_smoke.yaml`), tetapi sejak **10 Februari 2026** mode ini deprecated dan akan menampilkan warning migrasi.

### 3.1 Smoke (single run)
- `uv run --locked -- python runner.py --config config.yaml`
- jika perlu replace output run yang sama: `uv run --locked -- python runner.py --config config.yaml --overwrite`

Expected:
- membuat 1 folder output run
- ada metadata + config snapshot/resolved
- ada summary metrics minimal

### 3.2 Smoke suite (batch kecil)
- `uv run --locked -- python simulate.py --suite smoke --config configs/experiments/experiments_smoke.yaml`

### 3.3 Paper core suite (subset cepat untuk dev)
- `uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments_batch_quick.yaml`

### 3.4 Paper core profiles (recommended)
- CI gate subset (non-smoke fail-fast, `R=10`):
  `uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments_paper_core_ci_gate.yaml`
- Dev profile (eksplorasi cepat):  
  `uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments_paper_core_dev.yaml`
- Balanced profile (draft paper):  
  `uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments_paper_core_balanced.yaml`
- Flagship profile (final confidence):  
  `uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments_paper_core_flagship.yaml`

### 3.5 Full paper core suite (sweep paling luas; mahal)
- `uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments.yaml`

### 3.6 Robustness / Scalability (opsional)
- `uv run --locked -- python simulate.py --suite robustness_sensitivity --config configs/experiments/experiments_auth_sensitivity.yaml`
- `uv run --locked -- python simulate.py --suite scalability_stress --config configs/experiments/experiments_scalability_stress.yaml`

### 3.7 NoAuth vs Auth-sim sensitivity template
- `uv run --locked -- python simulate.py --suite robustness_sensitivity --config configs/experiments/experiments_auth_sensitivity.yaml`

Expected (template default):
- multi-seed `R>=10` per varian
- fokus metrik: `asr`, `fnrq`, `bypass_rate`, `sybil_infiltration_rate`
- durasi lokal tipikal: puluhan menit sampai jam (tergantung CPU dan sweep)

### 3.8 Optional flags (output safety)
- `--overwrite`: default **off**. Jika folder run sudah ada, run gagal untuk mencegah overwrite tak sengaja.
- `--manifest-keep-last N`: simpan hanya N manifest terbaru di `results/_manifests/`.

### 3.9 Acceptance matrix (4 attack × 4 profile, multi-seed)
- `uv run --locked -- python scripts/qa/acceptance_attack_gap.py --seeds 101 202 303 --tolerance 0.04`
- Profil yang dibandingkan: `full`, `no_dmpo`, `no_3lc`, `no_auth`.
- Output report: `results/acceptance/attack_gap_report.json`.
- Kriteria gap: `mean(AUROC_full) >= mean(AUROC_ablation) - 0.04`.
- Profil CI PR quick:
  - `make acceptance-pr`
  - setara dengan: `uv run --locked -- python scripts/qa/acceptance_attack_gap.py --seeds 101 202 --nodes 20 --iterations 30 --tolerance 0.04 --report results/acceptance/attack_gap_report_pr.json`
- Profil CI nightly:
  - `make acceptance-nightly`
  - setara dengan: `uv run --locked -- python scripts/qa/acceptance_attack_gap.py --seeds 101 202 303 --nodes 20 --iterations 40 --tolerance 0.04 --report results/acceptance/attack_gap_report_nightly.json`

### 3.10 Stats gate + manifest integrity + artifact bundle + legacy import guard
- Cek guard import legacy (wajib untuk perubahan boundary modul):
  - `uv run --locked -- python scripts/qa/check_no_legacy_imports.py`
- Cek guard determinisme RNG (larang RNG constructor tanpa seed eksplisit):
  - `uv run --locked -- python scripts/qa/check_deterministic_rng.py`
- Cek integritas manifest run + konsistensi artifact kanonis:
  - `uv run --locked -- python scripts/qa/check_manifest_integrity.py`
- Cek gate statistik suite:
  - `uv run --locked -- python scripts/qa/check_stats_gate.py --path results/<suite>/stats_gate.json`
- Build bundle artifact:
  - `uv run --locked -- python scripts/artifacts/build_artifact_bundle.py --suite <suite> --bundle-path results/artifacts/<suite>_artifact_bundle.tar.gz --include-manifests`
- Verifikasi bundle artifact:
  - `uv run --locked -- python scripts/artifacts/verify_artifact_bundle.py --bundle-path results/artifacts/<suite>_artifact_bundle.tar.gz`

### 3.11 Publish freeze (local)
- One-command gate:
  - `make publish-freeze-local`
- Checklist terstruktur:
  - lihat `09_PUBLISH_FREEZE_CHECKLIST.md`

## 4) Lint/type/tests (jika tool tersedia di dev deps)
- install dev tools sekali:
  - `uv sync --extra dev`
- `uv run --locked --extra dev -- flake8 src runner.py simulate.py --select=E9,F63,F7,F82 --statistics`
- `uv run --locked --extra dev -- mypy src/evaluation/metrics/enhanced_metrics.py src/evaluation/pipeline/run_evaluator.py --ignore-missing-imports`
- `uv run --locked --extra dev -- black .`
- `uv run --locked --extra dev -- pytest -q src/tests`

## 5) Compliance guardrail (opsional)
Jika target tersedia di Makefile:
- `make compliance`
  - mencakup: `check_no_legacy_imports.py` + `check_no_shell_true.py` + `check_safe_tar_extract.py` + `check_deterministic_rng.py` + `check_manifest_integrity.py` + `check_public_repo_hygiene.py`
- `make reproduce`
- `make ci-core-local`
- `make ci-paper-core-gate-local`

## 6) Output yang harus muncul (minimal per run)
- `results/<suite>/<run_id>/`
  - `metadata.json` (seed list, hash config/lock, start/end time, python+deps version, git hash, git dirty, platform, command)
  - `config_resolved.yaml` (resolved defaults + overrides)
  - `summary.csv` (1 baris per seed)
  - `metrics_raw.(parquet|csv)`
  - `figures/` (untuk suite paper_core minimal)
- `results/<suite>/seed_manifest.json` (rencana seed resolved untuk semua run suite)
- `results/<suite>/stats_gate.json` (hasil gate reproducibility/statistics)
- manifest run terbaru: `results/_manifests/run_*.json`

Catatan run identity:
- `experiment_id` = identifier deterministik (berdasarkan skenario/varian/seed).
- `run_uid` = identifier unik per eksekusi.
- `run_id` = gabungan `experiment_id__run_uid` untuk mencegah overwrite saat rerun.

Catatan layout:
- Folder utama yang dipakai untuk analisis paper adalah `results/`.
- `runs/` dan `results/default/` adalah layout legacy yang sudah dipensiunkan dari repo.

## 7) Debug protocol (thread [DEBUG])
Sertakan:
- command + config/experiments
- seed / seed list
- traceback lengkap
- expected vs actual
- OS + python version
- commit hash (jika ada)
