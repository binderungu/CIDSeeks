# 10_FLAGSHIP_FREEZE_RUNBOOK — Final Flagship Freeze (Private -> Public Mirror)

Dokumen ini melengkapi `09_PUBLISH_FREEZE_CHECKLIST.md` dengan workflow operasional untuk eksekusi **run final flagship** yang mahal (durasi panjang), lalu handoff ke repo publik.

Target pembaca:
- maintainer yang bekerja di repo private (`vibe-cids`)
- mirror/publik repo (`CIDSeeks`)

## 1) Klarifikasi penting: "worktree dirty" itu apa?

`worktree dirty` berarti ada perubahan lokal yang belum di-commit (`git status` tidak bersih).  
Ini **normal** untuk eksplorasi harian.

Kenapa tetap penting saat freeze final?
- Snapshot publik (`make public-snapshot`) menulis metadata `source_commit` dari `HEAD`.
- Jika worktree private masih dirty, isi snapshot bisa memuat perubahan yang **belum** ada di commit `HEAD`.
- Akibatnya, `source_commit` tidak lagi merepresentasikan isi snapshot secara penuh (reproducibility/audit trail melemah).

Kesimpulan praktis:
- **Eksplorasi**: dirty boleh.
- **Flagship freeze final (untuk evidence reviewer/paper)**: gunakan commit private bersih.

## 2) Workflow harian (eksplorasi) — valid & direkomendasikan

Jika tujuan Anda adalah iterasi cepat dan sync ke mirror publik, pola berikut aman:

### A. Di repo private (`vibe-cids`)
1. Selesaikan coding.
2. Disarankan commit private dulu (lebih aman untuk rollback/audit).
3. Jalankan:
   - `make public-snapshot`
4. Sync ke mirror publik:
   - `rsync -a --delete --exclude '.git' /private/tmp/vibe-cids-public/ ~/Developer/GitHub/research/CIDSeeks/`

### B. Di repo publik (`CIDSeeks`)
1. Review perubahan (`git status`, `git diff --stat`)
2. Commit + push:
   - `git add -A`
   - `git commit -m "sync from private repo"`
   - `git push`

## 3) Workflow flagship freeze final (yang disarankan reviewer)

Untuk pengarsipan final sebelum submission/revisi paper, gunakan workflow yang lebih ketat.

### Opsi cepat (direkomendasikan): wrapper satu command

Repo menyediakan wrapper operasional yang menjalankan urutan:
- `simulate.py` flagship (dengan `--resume`)
- `stats_gate`
- build bundle artifact
- verify bundle artifact
- `public-snapshot`
- report evidence freeze (`results/artifacts/FLAGSHIP_FREEZE_REPORT_*.{json,md}`)

Command:
- `make flagship-freeze-final`

Dry-run (cek preflight + command plan tanpa eksekusi):
- `make flagship-freeze-final-dry-run`

Catatan:
- Wrapper akan **gagal preflight** jika worktree dirty (kecuali `--allow-dirty`).
- Untuk eksplorasi / simulasi workflow, boleh jalankan:
  - `uv run --locked -- python scripts/maintenance/run_flagship_freeze.py --dry-run --allow-dirty`

### A. Siapkan freeze candidate di repo private
1. Pastikan semua hardening/gates sudah lulus (lihat `09_PUBLISH_FREEZE_CHECKLIST.md`).
2. Pastikan commit private bersih:
   - `git status`
3. Commit/tag candidate:
   - `git add -A`
   - `git commit -m "freeze: paper_core flagship candidate"`
   - (opsional) `git tag preflagship-freeze-YYYYMMDD`

### B. Jalankan flagship final (long run, resumable)
Gunakan `--resume` agar rerun hanya mengerjakan titik eksperimen yang belum lengkap.

Command kanonis:
- `uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments_paper_core_flagship.yaml --resume`

Alternatif wrapper (menjalankan validasi + bundle + snapshot sekaligus):
- `uv run --locked -- python scripts/maintenance/run_flagship_freeze.py`

Saran operasional:
- Jalankan di `tmux`/`screen` atau shell yang tahan disconnect.
- Simpan log stdout/stderr ke file.
- Jika terhenti (restart mesin/terminal), jalankan command yang sama lagi dengan `--resume`.

Contoh log capture:
- `uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments_paper_core_flagship.yaml --resume 2>&1 | tee logs/flagship_freeze_run.log`

## 4) Validasi setelah flagship selesai

### 4.1 Stats gate (wajib)
- `uv run --locked -- python scripts/qa/check_stats_gate.py --path results/paper_core/stats_gate.json`

### 4.2 Bundle artifact flagship (disarankan kuat)
Build:
- `uv run --locked -- python scripts/artifacts/build_artifact_bundle.py --suite paper_core --bundle-path results/artifacts/paper_core_flagship_artifact_bundle.tar.gz --include-manifests`

Verify:
- `uv run --locked -- python scripts/artifacts/verify_artifact_bundle.py --bundle-path results/artifacts/paper_core_flagship_artifact_bundle.tar.gz --report results/artifacts/paper_core_flagship_artifact_bundle_verify.json`

## 5) Freeze evidence yang harus diarsipkan

Minimal arsipkan:
- `results/paper_core/stats_gate.json`
- `results/paper_core/seed_manifest.json`
- `results/paper_core/aggregate_summary.csv`
- `results/paper_core/experiments.csv`
- `results/artifacts/paper_core_flagship_artifact_bundle_verify.json` (jika bundle dibuat)
- log run flagship (`logs/flagship_freeze_run.log`) jika tersedia

Catatan:
- Simpan juga commit hash private yang menjadi sumber run final.

## 6) Handoff ke repo publik (mirror snapshot)

Setelah flagship final tervalidasi:

### A. Di repo private
1. (Opsional tapi disarankan) commit metadata/report finalisasi:
   - report checksum / log / docs final
2. Jalankan snapshot:
   - `make public-snapshot`
3. Verifikasi cepat snapshot:
   - cek `/tmp/vibe-cids-public/PUBLIC_EXPORT_REPORT.json`
   - pastikan file internal tidak ikut
   - pastikan placeholder non-canonical Eval-1/Eval-4 juga tidak ikut
4. Sync ke mirror publik:
   - `rsync -a --delete --exclude '.git' /private/tmp/vibe-cids-public/ ~/Developer/GitHub/research/CIDSeeks/`

### B. Di repo publik
1. Review perubahan:
   - `git status`
   - `git diff --stat`
2. Validasi `PUBLIC_EXPORT_REPORT.json`:
   - `source_commit` harus sesuai commit private freeze yang Anda maksud
3. Commit + push publik:
   - `git add -A`
   - `git commit -m "sync from private repo (flagship freeze)"`
   - `git push`

## 7) Checklist keputusan (singkat)

Gunakan tabel mental ini:

- **Repo private dirty?**
  - Eksplorasi: OK
  - Freeze final: commit dulu

- **Run panjang terputus?**
  - Jalankan ulang dengan `--resume`

- **Mau mirror ke publik?**
  - Gunakan `make public-snapshot` + `rsync`, bukan push langsung dari repo private

## 8) Failure modes umum (dan respons cepat)

1. `simulate.py` berhenti di tengah run panjang
- Jalankan ulang command yang sama dengan `--resume`.
- Jika memakai wrapper, jalankan ulang wrapper yang sama; step `simulate` tetap memakai `--resume` by default.

2. `stats_gate` gagal
- Jangan freeze.
- Audit `results/paper_core/stats_gate.json`, `aggregate_summary.csv`, dan config suite yang dipakai.

3. Snapshot publik mengandung file internal
- Hentikan proses publikasi.
- Periksa deny/allow patterns di `scripts/maintenance/export_public_snapshot.py`.

4. Snapshot report `source_commit` tidak cocok dengan perubahan aktual
- Itu biasanya karena worktree private dirty saat snapshot dibuat.
- Ulangi dari commit private bersih.
