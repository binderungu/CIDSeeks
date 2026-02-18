# 08_REPO_LAYOUT — Canonical folder tree and output policy

Dokumen ini menjawab kebingungan “yang dipakai yang mana” untuk repo Evaluasi-2.

## 1) Folder yang dipakai aktif (kanonis)

Root code:
- `src/` — implementasi simulator/evaluator/UI
- `config.yaml` — single-run config (runner/smoke)
- `configs/experiments/*.yaml` — batch suite config (`simulate.py`)
- `runner.py` — single run
- `simulate.py` — batch suite
- `docs/` — single source of truth

Output eksperimen:
- `results/<suite>/<run_id>/` — artifacts per run
- `results/<suite>/` — aggregate per suite
- `results/_manifests/` — run manifest JSON untuk UI

## 2) Jalur modul aktif vs legacy (code-level)

Jalur modul aktif (dipakai entry point canonical):
- `src/simulation/modules/ids/module.py`
- `src/simulation/modules/trust/{calculator.py,manager.py,challenge_manager.py}`
- `src/simulation/modules/authentication/module.py`
- `src/simulation/modules/privacy/module.py`
- `src/simulation/modules/collaboration/module.py`
- `src/simulation/modules/attacks/behavior_policy.py`

Jalur legacy (arsip; jangan jadi target perubahan utama):
- `src/simulation/runner.py` sudah dihapus; GUI canonical ada di `src/main.py`
- `src/simulation/modules/authentication/{auth_manager.py,core_auth_manager.py}` sudah dihapus; gunakan `authentication/module.py`
- `src/simulation/modules/privacy/privacy_manager.py` sudah dihapus; gunakan `privacy/module.py`
- `src/simulation/modules/collaboration/collab_manager.py` sudah dihapus; gunakan `collaboration/module.py`
- `src/simulation/modules/attacks/{pmfa.py,collusion.py,sybil.py,betrayal.py,core_attacks.py,attack_coordinator.py}` sudah dihapus
- `src/simulation/modules/database/{database_manager.py,database_module.py}` sudah dihapus; gunakan `database/node_database.py`
- `src/simulation/modules/ids/ids_module.py` sudah dihapus; gunakan `ids/module.py`
- `src/simulation/{simulator,scenario,reporting,visualization}/` sudah dihapus total
- `src/simulation/config/{config_manager.py,experiment_runner.py}` sudah dihapus total
- `src/simulation/{analysis,export,monitoring}/` sudah dihapus total
- `src/simulation/models/` sudah dihapus total
- `src/simulation/core/{simulation_iteration.py,simulation_status.py}` sudah dihapus total
- `src/simulation/utils/{error_handler,event_manager,helpers,icon_handler,performance_monitor,persistence,simulation_state,visualization_helper,exceptions,logger,theme}.py` sudah dihapus total
- `src/simulation/legacy/{simulator,scenario,reporting,visualization,config}/` sudah dihapus total
- `src/simulation/legacy/` sudah dihapus total
- `src/evaluation/export/result_exporter.py` adalah lokasi exporter kanonis saat ini

Referensi cepat: `src/simulation/modules/README.md`.

## 3) Folder legacy (arsip, bukan sumber angka final paper)

- `results/default/` — layout lama pre-canonical (retired)
- `runs/` — manifest lama pre-canonical (retired)
- `Post-Experiment/` — tooling pasca-eksperimen lama (retired)

Status:
- Tidak lagi disimpan sebagai folder aktif di repo.
- UI kini hanya membaca manifest dari `results/_manifests/` (fallback `runs/` sudah dipensiunkan).
- UI artifact index tidak lagi memindai `meta.json` legacy; kontrak kanonis adalah `summary.csv` + `metadata.json`.
- Pemilihan "latest run" pada tab analisis mengikuti manifest kanonis saja (tanpa scan direktori non-manifest).
- Run dianggap valid untuk UI hanya jika `results_path` pada manifest berada di dalam `results/` dan memiliki `metadata.json`.
- Tidak dipakai sebagai sumber utama hasil final paper.

## 4) Cara mencari hasil final paper

Untuk `paper_core` final:
1) Jalankan:
   - `uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments.yaml`
2) Ambil hasil dari:
   - per-run: `results/paper_core/<run_id>/summary.csv`
   - aggregate: `results/paper_core/experiments.csv`
   - aggregate: `results/paper_core/aggregate_summary.csv`
   - statistik uji: `results/paper_core/stats.csv`
   - ringkas per attack: `results/paper_core/attack_summary.csv`

## 5) Struktur minimum per run (kanonis)

`results/<suite>/<run_id>/` harus berisi minimal:
- `config_resolved.yaml`
- `metadata.json`
- `summary.csv`
- `metrics_raw.csv` (dan opsional `metrics_raw.parquet`)
- `events.jsonl`
- `figures/`

## 6) Scripts folder dipakai untuk apa

- `scripts/qa/*` — acceptance matrix dan quality gates (`stats_gate`)
- `scripts/qa/check_manifest_integrity.py` — validasi manifest + konsistensi `results_path` terhadap artifact kanonis
- `scripts/artifacts/*` — build/verifikasi artifact bundle
- `scripts/maintenance/*` — housekeeping lokal dan migrasi DB lama
- `scripts/ui/*` — utilitas opsional UI graph

Catatan: scripts tersebut bukan entry point eksperimen paper; entry point eksperimen tetap `runner.py` dan `simulate.py`.

## 7) Generated files (jangan di-commit)

- `vibe_cids.egg-info/` — metadata build setuptools (generated)
- `.coverage` — artifact coverage lokal

Keduanya aman dihapus lokal dan akan diregenerasi saat diperlukan.
