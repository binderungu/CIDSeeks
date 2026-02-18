# 04_EXPERIMENTS — Experimental Design (Evaluation-2: SimPy Platform)

## Scope (WAJIB dibaca)
Dokumen ini mengatur eksperimen untuk **Evaluasi-2: simulasi full protocol CIDSeeks berbasis SimPy**.
- Fokus: dinamika end-to-end (asynchronous messaging, topologi jaringan, gossip fanout, privacy guard, trust gating, authentication, dan efek serangan).
- Tidak termasuk: eksperimen “round-based core model validation” (Evaluasi-1) dan tidak termasuk simulator lain di project berbeda.
- Batas threat model untuk klaim empiris di repo ini: **Sybil, Collusion, Betrayal, PMFA**. Referensi serangan lain (mis. newcomer/pollution) diperlakukan sebagai konteks literatur, bukan hasil eksperimen canonical.

Tujuan dokumen: menjadi kontrak implementasi untuk Codex agar:
1) eksperimen mudah dijalankan ulang (reproducible),
2) klaim paper terikat langsung ke metrik dan figure,
3) semua output terstruktur untuk analisis dan artifact evaluation.

Reproducibility target mengikuti praktik AE modern (S&P, USENIX Security, CCS, ACM policy):
- artifacts konsisten dengan paper, lengkap, terdokumentasi, mudah dijalankan.  
  Referensi: S&P AE, USENIX Security CF artifacts, CCS AE, ACM artifact policy.  
  (lihat: https://sp2026.ieee-security.org/cfartifacts.html, https://www.usenix.org/conference/usenixsecurity26/call-for-artifacts, https://www.sigsac.org/ccs/CCS2025/call-for-artifacts/, https://www.acm.org/publications/policies/artifact-review-badging)

---

## 1. Sistem yang disimulasikan (model ringkas)

### 1.1 Mesin simulasi
Simulator menggunakan **SimPy (discrete-event)** untuk mengatur antrian event dan global clock, sehingga proses jaringan berjalan asynchronous (send/recv, delay, gossip, refresh).  
Paper menyebut SimPy 4.0 dan event queue untuk asynchronous network processes.

### 1.2 Node dan modul
Setiap node menjalankan modul: IDS, Collaborator, Authentication, Trust, Privacy, Database (sesuai arsitektur paper).
Kebijakan kolaborasi:
- Saat IDS lokal memicu alarm, node memilih peer yang trust-nya di atas threshold τ (trust gating).
- Dissemination memakai controlled gossip, fan-out kira-kira √N.
- Privacy guard membuat **3 varian sintaks** per alarm, plus random delay Δ untuk mengaburkan timing/fingerprint.
- Ada periodic refresh trust table setiap P ticks, off the critical path.

(Ini semua harus tercermin dalam event dan metrik end-to-end.)

---

## 2. Klaim yang harus dibuktikan (Claim → Experiment → Metric)

### C1 — Effectiveness (deteksi/ketepatan agregasi)
CIDSeeks meningkatkan kualitas keputusan agregasi alarm (lebih sedikit FP/FN) dibanding baseline tanpa trust gating atau tanpa modul tertentu.

### C2 — Resilience to insider strategies
CIDSeeks tetap stabil di bawah 4 serangan insider:
- Collusion
- Sybil
- Betrayal (On-Off)
- PMFA (Passive Message-Fingerprint Attack, termasuk gaya “selective response” pada challenge vs normal)
Catatan: PMFA literatur menunjukkan node jahat bisa menjaga trust di atas threshold sambil menaikkan false rate alarm aggregation, jadi simulasi harus bisa memunculkan efek ini bila proteksi dimatikan. (rationale threat realism)

### C3 — Scalability envelope (N besar)
Biaya komputasi per message tetap ringan, traffic sub-linear mengikuti desain (√N fanout, 3 varian, refresh periodik P), dan runtime masih masuk akal sampai N besar (misal 10^4) pada laptop komoditas.

### C4 — Privacy-overhead tradeoff
Privacy guard (delay Δ dan 3 varian) menurunkan peluang fingerprinting dan linkage, dengan overhead latensi/traffic yang terukur.

### C5 — Robustness (sensitivity)
Hasil tidak “rapuh” terhadap variasi topologi (random/small-world/scale-free/mesh/hybrid), rate alarm, rasio malicious, dan parameter trust/refresh.

Setiap klaim di atas HARUS punya:
- konfigurasi eksperimen,
- metrik utama,
- plot/tabel yang eksplisit,
- dan path output yang reproducible.

---

## 3. Faktor eksperimen (yang DISWEEP)

Di semua sweep, gunakan **seed eksplisit** dan jalankan replikasi multi-seed.

### 3.1 Skala dan komposisi
- N (jumlah node): {50, 100, 200, 500, 1k, 2k, 5k, 10k}
- malicious_ratio: {0.0, 0.05, 0.1, 0.2, 0.3}
- placement: random uniform; opsi “hub-biased” untuk topology scale-free (malicious jadi hub)

### 3.2 Topologi jaringan (NetworkX)
Topologi minimal yang harus ada (dipilih via config):
- random: Erdos–Renyi G(n,p)
- small_world: Watts–Strogatz G(n,k,p)
- scale_free: Barabasi–Albert G(n,m)
- mesh: complete graph G(n)
- hybrid: backbone stokastik + meshed core overlay

Parameter default yang aman (boleh disesuaikan):
- random: p = 0.02 .. 0.1 (pilih supaya graf connected dengan probabilitas tinggi)
- small_world: k=4 atau 6, rewiring p=0.05..0.2
- scale_free: m=2 atau 3
- hybrid: core_ratio=0.1..0.3, bridge_probability=0.1..0.4

Wajib: validasi konektivitas (largest connected component) sebelum run.

### 3.3 Workload dan timing
- tick_interval (simulated time unit): default 10ms
- duration: cukup panjang untuk steady state (misal 2000–10000 ticks tergantung N)
- local_alert_rate A: {0.1/s, 0.5/s, 1/s, 2/s}
- refresh_period P: {20, 50, 100} ticks
- gossip_fanout: default √N (sesuai paper), plus ablation {log N, N} untuk stress

### 3.4 Parameter trust dan privacy
- trust_threshold τ: {0.55, 0.6, 0.7, 0.8}
- trust_fall_threshold / trust_rise_threshold (opsional): eskalasi tier dan quarantine
- trust_weighting (basic/advanced/final): baseline dari config, lalu sensitivity ±20%
- privacy_delay Δ: {0, 0.5s, 1s, 2s} (Δ=0 untuk ablation “no privacy delay”)
- variants_per_alarm: {1, 3} (3 default sesuai desain)
- privacy_prefix_bits: {16, 24} (prefix-preserving hash)
- privacy_k_anonymity: {8, 16, 32} (k-anon untuk atribut sensitif)
- dmpo_pmfa_guard: {true, false} (aktifkan/disable PMFA fingerprint surface masking)

Kalibrasi profil quick (dev):
- Gunakan `trust_threshold=0.55`, `trust_fall_threshold=0.45`, `trust_rise_threshold=0.50`
  untuk mencegah collapse `FPR_h=1.0` pada horizon singkat.
- Profil ini untuk evaluasi cepat/ablation; hasil paper final tetap perlu sweep multi-τ dan multi-seed.

---

## 4. Skenario serangan (system-level, bukan hanya “callback”)

Semua serangan harus mempengaruhi:
- konten feedback/challenge response,
- pola forwarding,
- dan outcome agregasi alarm.
Bukan sekadar log.

### 4.1 Collusion
- malicious nodes membentuk ring/cluster ukuran k (misal k=5..20).
- strategi: saling menaikkan trust internal, dan memberi feedback menyesatkan untuk target honest nodes.
- variasi: “naive collusion” vs “stealth collusion” (lebih jarang bohong agar tidak drop di trust).

### 4.2 Sybil
- attacker memiliki s sybil identities (misal s = 2x sampai 10x dari 1 attacker).
- strategi: sybil saling memberi reputasi dan mencoba masuk set trusted peers.
- dua mode:
  - no-auth ablation (sybil mudah)
  - auth-enabled (sybil harus “dibatasi” sesuai desain PKI)

### 4.3 Betrayal (On-Off)
- malicious berperilaku baik selama warmup T_good, lalu beralih buruk (atau periodic on-off).
- parameter: switch_time (ticks) dan duty_cycle (good vs bad ratio).

### 4.4 PMFA / selective-response fingerprinting
Model minimal:
- attacker mencoba membedakan challenge vs normal request dan merespons selektif.
- efek yang ingin terlihat saat proteksi lemah: trust attacker tetap di atas threshold sambil false rate alarm aggregation naik (baseline literatur).
Model proteksi CIDSeeks:
- privacy delay Δ dan varian pesan harus menurunkan keberhasilan fingerprinting dan linkage.
- fallback klasifikasi saat bukti lemah:
  - `pmfa_fallback_mode`: `assume_challenge | prior`
  - `pmfa_request_prior`: prior REQUEST saat mode `prior`
  - `pmfa_dmpo_resistance`: skala reduksi keberhasilan fingerprint saat DMPO aktif

Catatan: PMFA threat realism bisa diikat ke observasi literatur bahwa malicious dapat mempertahankan trust di atas threshold sambil menaikkan false rate dalam agregasi.

### 4.5 Sybil identity inflation (abstraction)
- parameter: `sybil_virtual_identities` (>=1), `sybil_identity_rotation`, `sybil_allow_identity_with_auth`
- rekomendasi evaluasi: aktifkan identity inflation terutama pada skenario `NoAuth` untuk memisahkan efek autentikasi.

---

## 5. Baseline dan ablation (wajib untuk reviewer top venue)

### 5.1 Sistem yang dibandingkan
Minimal wajib:
1) Full CIDSeeks (semua modul aktif)
2) No Trust Gating (gossip ke √N random peers tanpa threshold τ)
3) No Privacy Guard (Δ=0 dan variants=1)
4) No Authentication (auth score selalu “pass” atau dimatikan)
5) “Flat Trust” baseline (hanya basic trust, advanced/final dimatikan)

Tujuan: reviewer bisa lihat kontribusi tiap komponen (ablation clarity).

---

## 6. Metrik (apa yang disimpan per run)

### 6.1 Correctness / security outcomes
- Aggregation accuracy:
  - TPR, FPR, FNR, precision, F1 (event-level)
- Trust separation:
  - distribusi trust honest vs malicious
  - time-to-detect (ticks sampai malicious turun di bawah τ)
- Attack impact:
  - delta FP/FN vs baseline
  - fraction malicious yang lolos threshold τ

Semantic guardrail:
- `accuracy/precision/recall/FPR/FNR` = threshold metrics pada `trust_threshold` (snapshot final round).
- `AUROC/AUPRC` = ranking metrics lintas skor trust (bukan threshold metric), jadi tidak harus numerik sama dengan accuracy/FPR.
- Untuk studi `NoAuth vs Auth-sim`, prioritaskan juga `asr`, `fnrq`, `bypass_rate`, dan
  `sybil_infiltration_rate` agar efek autentikasi terlihat walau AUROC sama-sama tinggi.

### 6.2 Performance and overhead
- message_count per node (sent/recv)
- bytes_estimate (optional, jika message size dimodelkan)
- latency:
  - alarm propagation latency (origin → first trusted peer; origin → quorum)
- runtime:
  - wall-clock per run
  - peak memory (opsional, tapi bagus untuk paper)

### 6.3 Privacy proxy metrics (praktis untuk simulasi)
- fingerprint_success_rate:
  - peluang attacker menebak “challenge vs normal” lebih baik dari random
  - atau linkage success antar varian alarm bila delay/varian dimatikan

Konvensi nilai non-applicable:
- Metrik spesifik skenario (mis. collusion amplification di run non-collusion) boleh bernilai `NaN`.
- `NaN` harus ditafsirkan sebagai *not applicable*, bukan error runtime.

---

## 7. Statistik dan pelaporan (aturan main)

- Semua eksperimen non-smoke: minimal **R = 10 seeds** (lebih baik 20) per titik konfigurasi.
- Laporkan mean dan 95% CI (bootstrap atau t-interval).
- Untuk time series: plot mean dengan band CI; untuk histogram: gunakan agregasi per-seed agar tidak bias.
- Untuk suite non-smoke, gunakan gate otomatis (`stats_gate.json`) agar CI bisa fail-fast saat seed kurang atau CI terlalu lebar.

### 7.1 Profil run yang direkomendasikan (praktis)

Tidak ada angka tunggal yang “wajib” untuk semua venue flagship. Praktik yang biasanya diharapkan reviewer:
- multi-scale `N` (minimal 3 titik skala),
- horizon iterasi cukup untuk steady-state (umumnya 100+; untuk hasil final lebih aman 200-500),
- replikasi multi-seed (`R=5` untuk draft internal, `R>=10` untuk angka final paper).

Preset yang disediakan di repo:

| Profil | Config | N | Iterations | Runs/variant | Tujuan |
|---|---|---|---|---|---|
| CI Gate | `experiments_paper_core_ci_gate.yaml` | 30 | 40 | 10 | validasi fail-fast non-smoke (`stats_gate`) di CI |
| Dev | `experiments_paper_core_dev.yaml` | 50, 100 | 60, 120 | 2 | debugging + arah tren cepat |
| Balanced | `experiments_paper_core_balanced.yaml` | 50, 100, 200 | 120, 240 | 5 | draf paper / iterasi analisis |
| Flagship | `experiments_paper_core_flagship.yaml` | 50, 100, 200, 500 (+ sweep topology/sensitivity) | 200, 500 | 10 | angka final berkepercayaan tinggi |

Estimasi runtime (single worker, model kalibrasi lokal 12 run tanggal **February 7, 2026**):
- `experiments_paper_core_dev.yaml`: ~2.0 jam (rentang kasar 1.6-2.4 jam)
- `experiments_paper_core_balanced.yaml`: ~105.8 jam (rentang kasar 84.9-126.7 jam)
- `experiments_paper_core_flagship.yaml`: ~577.6 jam (rentang kasar 466.6-688.6 jam)
- `experiments.yaml` (sweep terluas): ~4169 jam (single worker), jadi sebaiknya dijalankan terdistribusi/bertahap.

Catatan:
- Estimasi di atas adalah inferensi dari profil runtime repo saat ini; angka riil tergantung CPU, I/O, dan topologi.
- Jika ingin mendorong `N` sangat besar (>=1000), pertimbangkan topologi sparse (degree dijaga konstan) agar biaya tidak kuadratik.

### 7.2 Model runtime per attack (kalibrasi lokal)

Model yang dipakai untuk estimasi:
`cpu_time_ms ~= k * N^a * iterations^b`

| Attack | Baseline @ N=50, iter=30 | Eksponen N (`a`) | Eksponen iterations (`b`) |
|---|---:|---:|---:|
| Collusion | ~25.8 s | 1.9580 | 1.2456 |
| PMFA | ~25.1 s | 2.0614 | 1.1528 |
| Sybil | ~27.6 s | 1.8308 | 0.9951 |
| Betrayal | ~29.7 s | 1.7708 | 1.1771 |

Implikasi praktis:
- Dalam setup default yang cenderung dense, biaya naik superlinear terhadap `N`.
- PMFA/Collusion biasanya paling mahal saat skala `N` naik; Betrayal cenderung mahal saat iterasi panjang.

Wajib: setiap output figure menyimpan metadata:
- config hash
- git commit hash
- seed list
- timestamp
- versi python dan dependency

---

## 8. Suites eksperimen (untuk workflow Codex)

Definisikan suites agar sekali jalan menghasilkan paket output yang siap dimasukkan ke paper.

### 8.1 `smoke`
Tujuan: validasi cepat pipeline.
- N=30, duration=200 ticks, 1 seed
- 1 skenario benign + 1 skenario malicious ringan

Output: sanity plots + summary.json

### 8.2 `paper_core`
Tujuan: figure utama paper.
- Gunakan salah satu profil:
  - `experiments_paper_core_dev.yaml` (cepat)
  - `experiments_paper_core_balanced.yaml` (draft paper)
  - `experiments_paper_core_flagship.yaml` (final confidence)
  - `experiments.yaml` (sweep terluas dan paling mahal)
- attacks: Collusion, PMFA, Sybil, Betrayal
- trust model: `three_level_challenge`

Output: figures/
- fig_accuracy_vs_malicious_ratio.pdf
- fig_overhead_vs_N.pdf
- fig_latency_vs_N.pdf
- fig_trust_separation.pdf
- fig_pmfa_resistance.pdf

### 8.3 `robustness_sensitivity`
Tujuan: meyakinkan reviewer “hasil tidak rapuh”.
- sweep τ, P, A, Δ, topology (tambah scale_free/mesh/hybrid)
- subset N: {200, 1000, 5000}
- termasuk template `NoAuth vs Auth-sim` (lihat `experiments_auth_sensitivity.yaml`):
  PMFA selective-response stress, `N=50`, `iterations=30`, `auth_mode={disabled,required}`,
  dan sweep `pmfa_detect_prob` + `pmfa_poison_rate` untuk menampakkan gap autentikasi.
Output: appendix figures + table sensitivity.

### 8.4 `scalability_stress`
Tujuan: push limit.
- N sampai 20000 (opsional jika runtime masuk akal)
- A=2/s, duration dipendekkan
Output: throughput/traffic envelope, runtime.

---

## 9. Kontrak output (struktur folder yang wajib)

Setiap run menyimpan:
results/<suite>/<run_id>/
- config_resolved.yaml
- metadata.json  (git hash, git dirty, config/lock hash, python+deps, platform, seeds, command, start/end time)
- metrics_raw.parquet  (atau csv bila perlu)
- summary.csv           (1 baris per seed)
- figures/              (png/pdf)
- logs/                 (optional, ringkas)

Identitas run:
- `experiment_id` bersifat deterministik (skenario/varian/seed).
- `run_uid` bersifat unik per eksekusi.
- `run_id = experiment_id__run_uid` untuk menghindari overwrite saat rerun.

Aggregate suite:
results/<suite>/
- aggregate_summary.csv
- stats_gate.json
- seed_manifest.json
- aggregate_plots/
- README.md (cara reproduce suite ini)

Manifest (opsional untuk UI):
results/_manifests/
- run_*.json (pointer ke `results_path` run terakhir)
- retention policy `manifest_keep_last` direkomendasikan untuk batch panjang.

Catatan kompatibilitas:
- `results/default/` dan `runs/` adalah legacy artifact layout yang dipensiunkan.
- Sumber angka final paper harus dari `results/`.

---

## 10. Instruksi implementasi untuk Codex (actionable)

Codex harus memastikan hal berikut ada dan konsisten:

### 10.1 Entry points
- `runner.py`: menjalankan 1 config (untuk smoke atau debug)
- `simulate.py`: batch runner yang membaca `configs/experiments/*.yaml` dan menjalankan suite

### 10.2 Config flow
- Semua parameter di dokumen ini harus bisa di-set via YAML, tanpa edit code.
- Resolusi config (defaults + override) disimpan sebagai `config_resolved.yaml`.
- Gate policy juga dikontrol via YAML:
  - `reproducibility_gate.*` (enforce/min runs/seed policy)
  - `stats_gate.*` (min seeds, required metrics, max CI width)

### 10.3 Determinism
- Semua randomness lewat RNG seeded dari config (per-seed).
- Tidak ada `time.sleep` di core; semua delay pakai `env.timeout`.

### 10.4 Logging dan metrics
- Hot loop tidak boleh melakukan plotting.
- Metrics dikoleksi in-memory, flush di akhir run.
- Minimal collector: message counters, latency, trust snapshots, aggregation outcomes.

### 10.5 Make targets (opsional tapi disarankan)
- `make smoke`
- `make paper-core`
- `make robustness`
- `make scalability`
- `make reproduce` (jalankan paper_core + generate semua figures)

---

## 11. Definisi “done” (acceptance criteria)
Eksperimen dianggap siap paper bila:
1) `make paper-core` menghasilkan figures yang konsisten dan bisa diulang dari clean checkout.
2) Output menyimpan metadata yang cukup untuk audit (config + git hash + seeds).
3) Ada ablation yang jelas (NoTrustGate, NoPrivacy, NoAuth, FlatTrust).
4) Attack scenarios mempengaruhi outcome, bukan kosmetik.
