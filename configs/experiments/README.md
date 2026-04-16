# Experiment Configs

Folder ini adalah lokasi kanonis untuk konfigurasi suite `simulate.py`.

File yang tersedia:
- `experiments_smoke.yaml`
- `experiments_batch_quick.yaml`
- `experiments_paper_core_ci_gate.yaml`
- `experiments_paper_core_dev.yaml`
- `experiments_paper_core_balanced.yaml`
- `experiments_paper_core_flagship.yaml`
- `experiments_auth_sensitivity.yaml`
- `experiments_scalability_stress.yaml`
- `experiments.yaml`

Kontrak Phase F:
- Profil `paper_core*` sekarang memposisikan `dmpo_x` sebagai runtime kanonis Eval-2.
- Skenario PMFA utama memakai perbandingan `privacy_strategy: [dmpo_legacy, dmpo_x]`.
- Ablation attribution dinyatakan via `attribution_profile`:
  - `full`
  - `no_fibd`
  - `no_split_fail`
  - `no_coalcorr`
- Profil `robustness_sensitivity` dan `scalability_stress` memakai `dmpo_x` + attribution runtime sebagai baseline kanonis, bukan fallback ke default lama.

Kompatibilitas:
- `simulate.py` masih menerima basename lama, misalnya `--config experiments_smoke.yaml`, tetapi mode ini deprecated dan akan menampilkan warning.
- Untuk kontribusi baru, gunakan path eksplisit `configs/experiments/<file>.yaml`.
