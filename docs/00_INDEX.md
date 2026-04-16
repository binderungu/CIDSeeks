# 00_INDEX — AI Knowledge Base Index (Evaluation-2: SimPy)

Dokumen ini adalah peta cepat untuk Codex dan manusia.
Scope: **Evaluasi-2 (SimPy end-to-end)**.
Environment canonical: **uv** (lihat 01_RUNBOOK).

## Urutan baca minimum (wajib)
1) 01_RUNBOOK.md
2) 02_SYSTEM_SPEC.md
3) 03_ATTACK_MODEL.md
4) 04_EXPERIMENTS.md

## Navigasi cepat (repo)
- Entry points: runner.py, simulate.py (lihat 01_RUNBOOK)
- Konfigurasi: `config.yaml`, `configs/experiments/*.yaml` (fallback basename lama masih ada sementara, tetapi sudah deprecated dengan warning)
- Core: src/simulation/
- Output (kanonis): results/
  - artifacts per run: results/<suite>/<run_id>/
  - aggregate suite: results/<suite>/{experiments.csv,aggregate_summary.csv,...}
  - run manifest: results/_manifests/run_*.json
  - legacy lama `results/default/` dan `runs/` sudah dipensiunkan dari repo

## Quickstart (canonical, uv)
- Setup: `uv sync`
- Smoke sanity: `uv run --locked -- python simulate.py --suite smoke --config configs/experiments/experiments_smoke.yaml`
- Smoke DMPO-X runtime: `uv run --locked -- python simulate.py --suite smoke --config configs/experiments/experiments_smoke_dmpox.yaml`
- Paper core (quick dev): `uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments_batch_quick.yaml`
- Paper core (CI gate subset): `uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments_paper_core_ci_gate.yaml`
- Paper core (dev profile): `uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments_paper_core_dev.yaml`
- Paper core (balanced profile): `uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments_paper_core_balanced.yaml`
- Paper core (flagship profile): `uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments_paper_core_flagship.yaml`
- Flagship freeze wrapper (run + validate + bundle + snapshot): `uv run --locked -- python scripts/maintenance/run_flagship_freeze.py`
- Flagship freeze wrapper (dry-run): `uv run --locked -- python scripts/maintenance/run_flagship_freeze.py --dry-run --allow-dirty`
- Paper core (full):      `uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments.yaml`
- Robustness/auth sensitivity template: `uv run --locked -- python simulate.py --suite robustness_sensitivity --config configs/experiments/experiments_auth_sensitivity.yaml`
- Scalability:   `uv run --locked -- python simulate.py --suite scalability_stress --config configs/experiments/experiments_scalability_stress.yaml`

## Aturan inti (ringkas)
- Semua randomness seeded dari config (reproducible runs).
- CHALLENGE vs REQUEST adalah konsep penting (lihat 03_ATTACK_MODEL).
- Framing paper canonical: **CIDSeeks = obfuscation + attribution**.
- DMPO-X menurunkan stream-level distinguishability; trust engine mengubah residual fingerprintability menjadi evidence attribution melalui `FIBD`, `SplitFail`, dan `CoalCorr` (lihat 02_SYSTEM_SPEC, 03_ATTACK_MODEL, 04_EXPERIMENTS).
- Scope serangan Evaluasi-2 terkunci pada 4 insider attacks (Sybil, Collusion, Betrayal, PMFA); topik lain (mis. newcomer/pollution) hanya konteks literatur kecuali ada suite baru eksplisit.
- Repo ini adalah **canonical Evaluation-2 repository** dan generator trace untuk Eval-3; Evaluasi-1 trust-core dan Evaluasi-4 mini-testbed bukan jalur klaim utama repo ini.
- Jangan ubah kontrak output tanpa update docs/04_EXPERIMENTS.md + CHANGELOG.md.
- Setelah perubahan core: jalankan smoke suite (01_RUNBOOK).

## Dokumen lain
- 05_REVIEW_CHECKLIST.md: checklist reviewer (untuk /review)
- 08_REPO_LAYOUT.md: layout folder kanonis + mapping legacy
- 09_PUBLISH_FREEZE_CHECKLIST.md: gate final sebelum buka publik
- 10_FLAGSHIP_FREEZE_RUNBOOK.md: runbook eksekusi freeze final (private -> snapshot -> mirror publik)
- 11_EVAL2_REFACTOR_PLAN.md: rencana refactor bertahap untuk menyelaraskan repo dengan draft paper pada scope Evaluasi-2
