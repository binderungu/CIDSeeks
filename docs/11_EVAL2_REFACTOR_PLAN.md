# 11_EVAL2_REFACTOR_PLAN — Canonical Refactor Plan for Evaluation-2

Dokumen ini membekukan arah refactor repo agar selaras dengan draft paper **tanpa mencampur scope Evaluasi-2 dengan Evaluasi-1/Evaluasi-3/Evaluasi-4**.

## 1) Target akhir repo ini
Repo ini harus menjadi:
- **canonical Evaluation-2 repository** untuk simulator end-to-end berbasis SimPy,
- **trace generator yang bersih** untuk attacker-side metadata evaluation (Eval-3),
- dan **bukan** repo yang overclaim bahwa seluruh paket evaluasi paper sudah selesai.

## 2) Batas scope
Yang harus selesai di repo ini:
- asynchronous protocol simulation,
- topology-aware dissemination,
- trust-gated forwarding,
- auth/no-auth sensitivity,
- DMPO-X runtime path,
- reproducible output artifacts,
- trace export yang siap dipakai Eval-3.

Yang tidak boleh dipresentasikan sebagai “selesai” di repo ini sebelum benar-benar dibangun:
- controlled trust-only harness penuh (Eval-1),
- strong attacker-side benchmark final (Eval-3 flagship-grade),
- mini-testbed / PCAP realism (Eval-4).

## 3) Diagnosis gap saat ini
### Sudah kuat
- Entry points canonical sudah ada: `runner.py`, `simulate.py`.
- SimPy engine + topology + auth + trust + privacy + attacks sudah terhubung.
- Output artifacts dan aggregator suite sudah berjalan.
- DMPO-X runtime path sudah ada dalam bentuk **lite runtime path**.

### Masih lemah / harus dirombak
- Simulator masih **hybrid**: event-driven shell, tetapi trust/interaction masih banyak bergaya round barrier.
- `REQUEST` dan `CHALLENGE` belum sepenuhnya menjadi wire-faithful protocol artifacts.
- DMPO-X masih lebih tepat disebut **runtime-lite**, belum full canonical paper path.
- Eval-3 pipeline masih lightweight/proxy, belum cukup untuk klaim attacker-side kuat.
- Eval-1 dan Eval-4 masih placeholder dan tidak boleh tampak seperti implementasi siap pakai.
- Beberapa summary field masih memberi framing yang terlalu besar dibanding implementasi.

## 4) Fase refactor
### Phase A — Contract Freeze and Cleanup
Tujuan:
- membekukan kontrak Eval-2,
- membersihkan overclaim,
- menandai komponen non-Eval-2 secara jujur,
- menyiapkan basis refactor berikutnya.

Deliverables:
- dokumen ini,
- framing evaluator yang lebih jujur,
- placeholder Eval-1/Eval-4 diturunkan statusnya,
- indeks dokumen diperbarui.

### Phase B — Protocol Runtime Refactor
Tujuan:
- membuat message flow lebih faithful terhadap draft paper.

Fokus file:
- `src/simulation/core/simulation_engine.py`
- `src/simulation/core/node.py`
- `src/simulation/modules/collaboration/module.py`
- `src/simulation/core/message.py`

Deliverables:
- `REQUEST` dan `CHALLENGE` menjadi protocol artifacts eksplisit,
- trust update dipicu event interaksi nyata,
- relay, quarantine, auth, verifier handling berada di jalur event yang jelas.

### Phase C — DMPO-X Canonicalization
Tujuan:
- menaikkan DMPO-X dari runtime-lite ke path canonical Eval-2.

Fokus file:
- `src/simulation/modules/privacy/strategies/dmpo_x.py`
- `src/simulation/modules/privacy/policy_controller.py`
- `src/simulation/modules/privacy/aliasing.py`
- `src/simulation/modules/privacy/stealth_header.py`
- `src/simulation/modules/privacy/family_renderer.py`
- `src/simulation/modules/privacy/cover_traffic.py`

Deliverables:
- recipient-scoped aliasing,
- epoch-scoped aliasing,
- hidden family rendering,
- stealth header opaque,
- `K_t` dan `f_t` independen,
- cover traffic dan budget-aware policy selection berjalan eksplisit.

### Phase D — Trust Attribution Alignment
Tujuan:
- menyelaraskan trust engine dengan narasi paper.

Fokus file:
- `src/simulation/modules/trust/manager.py`
- `src/simulation/modules/trust/fibd.py`
- `src/simulation/modules/trust/split_verifier.py`
- `src/simulation/modules/trust/coalcorr.py`

Deliverables:
- FIBD, SplitFail, CoalCorr menjadi sinyal attribution yang eksplisit,
- advanced tier memakai agregat `P_apmfa`,
- final tier memakai penalti verifier reconstruction (`SplitFail`) secara auditable,
- ablation switch per komponen tersedia.

### Phase E — Evaluator and Output Contract Cleanup
Tujuan:
- memastikan artifact Eval-2 hanya menyatakan klaim yang benar-benar didukung run.

Fokus file:
- `src/evaluation/pipeline/run_evaluator.py`
- `src/evaluation/export/experiment_aggregator.py`

Deliverables:
- summary field tidak overclaim,
- agregasi suite lebih terkontrol dan punya provenance batch yang eksplisit,
- output canonical stabil untuk paper dan artifact evaluation.

### Phase F — Config Matrix, Tests, and Paper-Core Validation
Tujuan:
- mengunci matrix eksperimen paper.

Fokus file:
- `config.yaml`
- `configs/experiments/*.yaml`
- `src/tests/**`

Deliverables:
- `smoke`, `paper_core`, `robustness_sensitivity`, `scalability_stress` konsisten dengan paper,
- subset `paper_core` lulus,
- smoke contract dan output contract lulus.

## 5) Definition of Done
Repo ini dianggap selaras dengan draft paper pada **scope Evaluasi-2** jika:
- `uv run --locked -- python runner.py --config config.yaml` lulus,
- `uv run --locked -- python simulate.py --suite smoke --config configs/experiments/experiments_smoke.yaml` lulus,
- subset `paper_core` lulus dan menghasilkan artifact canonical,
- DMPO-X runtime benar-benar policy-driven,
- protocol flow `REQUEST/CHALLENGE` tidak lagi semata abstraksi internal trust,
- summary/aggregate tidak lagi overclaim Eval-3/Eval-4,
- docs `00_INDEX`, `01_RUNBOOK`, `02_SYSTEM_SPEC`, `03_ATTACK_MODEL`, `04_EXPERIMENTS` konsisten dengan implementasi.

## 6) Guardrails selama refactor
- Jangan ubah kontrak output tanpa update dokumentasi.
- Jangan campur logic attack ke `TrustCalculator`.
- Jangan hilangkan backward compatibility tanpa catatan deprecation yang jelas.
- Jangan mengklaim “full DMPO-X” atau “full Eval-3 attacker pipeline” sebelum implementasi memang sampai ke level itu.
