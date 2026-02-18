# 05_REVIEW_CHECKLIST — What "review" must verify

Gunakan checklist ini untuk thread [REVIEW] atau perintah /review.

## 1) Konsistensi dengan paper + docs
- Apakah perubahan menggeser batas modul? (lihat 02_SYSTEM_SPEC)
- Apakah attack tetap sesuai definisi? (lihat 03_ATTACK_MODEL)
- Apakah klaim empiris tetap sinkron dengan scope Evaluasi-2 (hanya Sybil/Collusion/Betrayal/PMFA)?
- Apakah output contract berubah? Jika ya: docs + changelog ikut berubah.

## 2) Reproducibility
- Semua randomness seeded dari config
- run_meta + config_snapshot ada
- tidak ada time.sleep / blocking loop di core SimPy

## 3) Validitas eksperimen
- Metrik dihitung konsisten dan masuk akal (range valid, tidak NaN)
- Jika numeric outcome berubah: ada penjelasan “apa berubah, kenapa, impact ekspektasi”

## 4) Kualitas implementasi
- Tidak ada stub pada jalur eksekusi
- Diff kecil dan mudah diaudit
- Penamaan konsisten (English identifiers, PascalCase/snake_case)
- Perubahan fitur utama tidak ditempatkan di file legacy (`*manager.py` lama / `attacks/*.py` lama)

## 5) Testing
- Ada unit test untuk logika kritis yang disentuh (trust/attack/evaluator)
- Smoke run lulus (01_RUNBOOK)

## 6) Performance sanity
- Tidak ada I/O berat di per-event hot path
- Logging tetap terkendali (tidak spam per event tanpa opsi)

## 7) Publish freeze readiness
- `make compliance` lulus
- `make publish-freeze-local` lulus (atau ekuivalen command di `09_PUBLISH_FREEZE_CHECKLIST.md`)
- `stats_gate.json` smoke + paper_core tersedia dan valid
