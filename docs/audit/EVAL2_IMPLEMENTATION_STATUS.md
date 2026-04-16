# Eval-2 Implementation Status (Audit Snapshot)

Tanggal audit snapshot: **2026-04-15**.

Dokumen ini menjawab pertanyaan: **"apakah semua poin audit sudah diimplementasikan?"**

## Ringkasan cepat
- **Belum semua**.
- Untuk jalur **engineering Eval-2**, banyak poin sudah terpasang.
- Untuk status **top-venue final artifact**, masih ada blocker konsistensi klaim paper vs scope implementasi.

## Status per poin audit

### Sudah diimplementasikan (Eval-2 engineering)
1. **`privacy_strategy` terhubung dari suite ke runtime** (`dmpo_legacy` / `dmpo_x`).
2. **Sender-side trust gating** aktif sebelum disseminasi.
3. **Fan-out membaca policy `f_t`**.
4. **PMFA evaluator** memisahkan `baseline_no_privacy`, `legacy_dmpo`, `dmpo_x`.
5. PMFA evaluator memakai **train/test split** (bukan train=test).
6. **Backward compatibility** schema PMFA lama/baru tersedia.
7. `run_eval2.py` **memanggil `run_scenarios()`** (bukan stub).

### Belum sepenuhnya (blocker top-venue final)
1. **Konsistensi paper vs code**: klaim naratif paper masih lebih besar dibanding canonical Eval-2 path saat ini.
2. **DMPO-X masih level lite** (belum full recipient-scoped/opaque stealth/hidden family penuh).
3. **PMFA evaluator masih proxy ringan** (fitur terbatas, model sederhana) untuk klaim attacker-side kuat.
4. **Simulator masih hybrid SimPy + round barrier**, belum event-faithful penuh.
5. **Hygiene/polish**: warning handling masih perlu dirapikan agar artefak final lebih bersih.

## Batas interpretasi
- Status di atas khusus **Evaluasi 2**.
- **Evaluasi 1** dan **Evaluasi 3** belum bisa dianggap selesai hanya dari status ini.
