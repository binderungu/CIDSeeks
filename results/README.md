# Results Layout (Canonical)

Folder hasil eksperimen yang dipakai aktif:

```text
results/
├── paper_core/              # hasil utama final paper
├── robustness_sensitivity/  # robustness / auth-sensitivity
├── smoke/                   # sanity-check cepat
└── _manifests/              # pointer run terbaru (dipakai UI)
```

## Yang dipakai untuk angka final paper

Gunakan isi `results/paper_core/`:
- `experiments.csv` -> ringkasan per-run
- `aggregate_summary.csv` -> agregasi metrik utama
- `stats.csv` -> uji statistik
- `stats_gate.json` -> hasil gate reproducibility/statistics (untuk CI)
- `seed_manifest.json` -> rencana seed resolved per run suite
- `attack_summary.csv` -> ringkasan per jenis serangan
- `<run_id>/summary.csv` -> detail satu run

## Suite yang aktif

- `smoke`
- `paper_core`
- `robustness_sensitivity`
- `scalability_stress`

## Catatan penting

- Layout legacy `results/default/` dan root `runs/` sudah dipensiunkan.
- Folder `_manifests/` bukan sumber angka paper; ini metadata pointer untuk UI.
