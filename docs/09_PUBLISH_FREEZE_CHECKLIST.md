# 09_PUBLISH_FREEZE_CHECKLIST — Final Pre-Publication Gate

Gunakan checklist ini sebelum repo dibuka publik atau sebelum pengiriman revisi paper.

## 1) Environment lock
- `uv sync`
- (opsional) `uv lock --check`

## 2) Boundary + artifact compliance
- `make compliance`

Expected:
- `legacy import guard passed`
- `time.sleep guard passed`
- `manifest integrity guard passed`
- `public repo hygiene guard passed`
- `public repo governance guard passed`

## 3) Canonical run sanity
- Smoke suite:
  - `uv run --locked -- python simulate.py --suite smoke --config configs/experiments/experiments_smoke.yaml`
  - `uv run --locked -- python scripts/qa/check_stats_gate.py --path results/smoke/stats_gate.json`
- Paper-core gate subset:
  - `uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments_paper_core_ci_gate.yaml`
  - `uv run --locked -- python scripts/qa/check_stats_gate.py --path results/paper_core/stats_gate.json`

## 4) Artifact bundle integrity
- Build:
  - `uv run --locked -- python scripts/artifacts/build_artifact_bundle.py --suite smoke --bundle-path results/artifacts/smoke_artifact_bundle.tar.gz --include-manifests`
- Verify:
  - `uv run --locked -- python scripts/artifacts/verify_artifact_bundle.py --bundle-path results/artifacts/smoke_artifact_bundle.tar.gz --report results/artifacts/smoke_artifact_bundle_verify.json`

## 5) One-command local freeze gate
- `make publish-freeze-local`

## 6) Documentation consistency checks
- Scope lock tetap menyatakan Evaluasi-2 hanya: Sybil, Collusion, Betrayal, PMFA.
- Kontrak output tetap di jalur `results/<suite>/<run_id>/` + `results/_manifests/run_*.json`.
- Governance/public metadata tersedia dan konsisten:
  - `SECURITY.md`
  - `CODE_OF_CONDUCT.md`
  - `CITATION.cff`
  - `.github/CODEOWNERS`
  - `.github/dependabot.yml`
- Dokumen internal (`AGENTS.md`, `docs/06_CODEX_RULES.md`, `docs/07_THREAD_STARTERS.md`) tidak ikut tracked di branch public.
- Folder `references/` menyisakan `references/README.md` sebagai policy placeholder; catatan draft/literatur tetap lokal.
- Catatan kompatibilitas:
  - Basename config lama (mis. `--config experiments_smoke.yaml`) masih diterima sementara, tetapi deprecated dan memunculkan warning.

## 7) Evidence to archive
- Simpan log command gate yang dijalankan.
- Simpan file berikut minimal:
  - `results/smoke/stats_gate.json`
  - `results/paper_core/stats_gate.json`
  - `results/artifacts/smoke_artifact_bundle_verify.json`
- Jika flagship PMFA menjadi angka paper final, arsipkan juga minimal satu contoh `results/<suite>/<run_id>/eval3_pmfa/{*_closed_world.json,*_open_world.json,*_drift.json}` untuk audit attacker-side evidence.

## 8) Public history safety
- Pastikan file internal/sensitif tidak hanya dihapus dari working tree, tetapi juga tidak terekspos di history publik.
- Jika file sensitif pernah ter-commit, lakukan rewrite history (`git filter-repo`/repo baru bersih) sebelum mengubah visibility menjadi public.

## 9) Public snapshot handoff (disarankan)
- Buat snapshot repo publik bersih (tanpa history privat):
  - `make public-snapshot`
- Hasil default ada di:
  - `/tmp/vibe-cids-public`
- Verifikasi cepat:
  - cek report `/tmp/vibe-cids-public/PUBLIC_EXPORT_REPORT.json`
  - pastikan tidak ada file internal (`AGENTS.md`, `docs/06_CODEX_RULES.md`, `docs/07_THREAD_STARTERS.md`, `references/*.md`)
  - pastikan placeholder non-canonical tidak ikut (`src/eval1_trust_core/*`, `src/eval4_minitestbed/*`)

## 10) Flagship final freeze (operational runbook)
- Untuk eksekusi final profile `flagship` (long run + `--resume`) dan handoff private -> mirror publik:
  - lihat `10_FLAGSHIP_FREEZE_RUNBOOK.md`
- Wrapper otomatis (disarankan untuk operator):
  - `make flagship-freeze-final`
- Dry-run preflight/plan:
  - `make flagship-freeze-final-dry-run`
- Catatan penting:
  - repo private boleh dirty untuk eksplorasi
  - tetapi untuk **freeze final**, snapshot sebaiknya dibuat dari commit private bersih agar `source_commit` di `PUBLIC_EXPORT_REPORT.json` benar-benar merepresentasikan isi snapshot
