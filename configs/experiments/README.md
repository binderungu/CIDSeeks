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

Kompatibilitas:
- `simulate.py` masih menerima basename lama, misalnya `--config experiments_smoke.yaml`, tetapi mode ini deprecated dan akan menampilkan warning.
- Untuk kontribusi baru, gunakan path eksplisit `configs/experiments/<file>.yaml`.
