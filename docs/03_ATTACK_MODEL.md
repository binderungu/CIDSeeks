# 03_ATTACK_MODEL — Insider Attacks (paper-aligned, 4 attacks only)

Dokumen ini mendefinisikan *serangan insider* yang WAJIB didukung oleh simulator VIBE-CIDS/CIDSeeks,
sesuai scope threat model paper: **Sybil, Collusion, Betrayal (on-off), PMFA**.

Tujuan:
1) Attack punya *perilaku operasional* yang jelas (bukan hanya “turunkan trust”).
2) Attack mempengaruhi state/metrik: kualitas agregasi alarm, evolusi trust, dan akurasi deteksi (AUC).
3) Semua perilaku attack *configurable*, deterministic via seed, dan terpisah dari TrustCalculator.

Catatan scope paper vs repo:
- Naskah utama (`references/cids.md`) membahas landscape serangan yang lebih luas.
- Repo Evaluasi-2 ini sengaja membatasi validasi implementasi pada **4 insider attacks** di atas agar eksperimen end-to-end tetap auditable dan reproducible.
- Jika cakupan diperluas (mis. pollution/newcomer), tambahkan dokumen threat model dan suite eksperimen terpisah sebelum klaim paper dinaikkan.

Non-goal (di file ini):
- “pollution attack” pada data/traffic/ML poisoning (kalau diperlukan, buat file terpisah: `ATTACK_POLLUTION.md`).
- DDoS eksternal, kompromi kripto, adaptive ML poisoning (paper juga mengecualikan ini).

---

## 0) Terminologi & Primitif Simulator (wajib ada agar attack realistis)

### Message kinds
Simulator harus membedakan minimal dua jenis pesan (secara internal, walau attacker berusaha menebak):
- **CHALLENGE**: pesan uji untuk evaluasi trust (ground truth label tersedia bagi pengirim).
- **REQUEST** (normal request): permintaan ranking/alarm-severity untuk agregasi.

Catatan: PMFA bekerja karena attacker dapat mengklasifikasikan REQUEST vs CHALLENGE dengan fingerprint,
misalnya lewat kesamaan alarm-set yang tersebar ke beberapa node (bandingkan antar penerima) dan/atau invariants timing/metadata.

### Observation record (kontrak minimal antara Simulator dan TrustCalculator)
Setiap interaksi menghasilkan `Observation` yang dicatat oleh simulator (ini yang dipakai TrustCalculator):
- round_id
- src_id (pengirim request/challenge)
- dst_id (responder)
- msg_kind: CHALLENGE | REQUEST
- alarm_set_id (hash dari alarm IDs; untuk CHALLENGE boleh unik per dst)
- true_label (opsional): “jawaban benar” menurut ground truth pengirim
- response_value: nilai yang diberikan dst (inilah yang dimanipulasi attacker)
- response_latency (opsional): untuk studi side-channel ringan
- flags: {was_forwarded, was_dropped, was_fabricated_alarm, ...}

Attack dianggap “diimplementasikan” hanya jika ia mengubah minimal satu dari:
- response_value (ranking/feedback)
- forwarding/dropping behavior
- fabricated alarms rate
- latency pattern (opsional)

---

## 1) Global knobs (wajib di config/experiments)

### Populasi & assignment
- `malicious_ratio`: float [0..1]
- `attack_mix`: distribusi tipe attack, contoh:
  - `{sybil: 0.10, collusion: 0.10, betrayal: 0.05, pmfa: 0.05}`
- `seed`: integer (wajib untuk reproducibility)

### Shared parameters (recommended defaults)
- `rating_scale`: [0.0 .. 1.0]
- `honest_rating_mean`: 0.8
- `honest_rating_std`: 0.05
- `malicious_high`: 0.9
- `malicious_low`: 0.1
- `attack_targeting`: `random | targeted_high_trust | targeted_specific_ids`

### Betrayal knobs
- `betrayal_start_round`: int
- `betrayal_mode`: `two_phase | on_off`
- jika `on_off`:
  - `on_off_period`: int
  - `on_off_duty_cycle`: float (0..1) proporsi waktu “malicious”

### Sybil/collusion structure
- `sybil_cluster_size`: int (>=2)
- `sybil_virtual_identities`: int (>=1, untuk identity inflation abstraction)
- `sybil_identity_rotation`: `round_robin | random`
- `sybil_allow_identity_with_auth`: bool (default false, sehingga identity inflation terutama terlihat pada NoAuth)
- `collusion_group_size`: int (>=2)

### PMFA knobs (inti)
- `pmfa_detect_prob`: float [0..1]
  - probabilitas attacker berhasil mengklasifikasikan sebuah pesan sebagai REQUEST (normal) vs CHALLENGE.
- `pmfa_collusion_enabled`: bool (true untuk model “fingerprint via info exchange”)
- `pmfa_match_window_rounds`: int (mis. 1..3)
- `pmfa_min_matches`: int (mis. 2)
- `pmfa_strategy`: `honest_on_challenge_malicious_on_request | partial_poisoning`
- jika `partial_poisoning`:
  - `pmfa_poison_rate`: float [0..1] peluang memberi jawaban jahat pada REQUEST (lebih realistis, meniru “occasionally untruthful”).
- fallback saat bukti PMFA tidak cukup:
  - `pmfa_fallback_mode`: `assume_challenge | prior` (hindari coin-flip acak)
  - `pmfa_request_prior`: prior REQUEST jika mode `prior`
- coupling defense:
  - `pmfa_dmpo_resistance`: float [0..1], seberapa kuat DMPO menurunkan keberhasilan fingerprinting.

---

## 2) Attack definitions (paper-aligned)

Semua attack di bawah harus memanipulasi perilaku node pada *response pipeline*:
`respond(msg_kind, alarm_set_id, true_label, context) -> response_value (+ optional flags)`

### 2.1 Sybil Attack
Intuisi: satu adversary “tampil” sebagai banyak identitas untuk mempengaruhi trust dan agregasi.

Model minimal (simulasi):
- Node malicious tipe `sybil` diberi `controller_id`.
- Semua node dengan `controller_id` sama bertindak sebagai satu cluster.
- Perilaku response:
  - ke sesama sybil-cluster: return `malicious_high`
  - ke honest: return `malicious_low`
- Perilaku jaringan (opsional tapi disarankan agar terlihat di metrik agregasi):
  - `fabricated_alarm_rate` lebih tinggi dari honest
  - forward alarm palsu dari cluster lebih sering

Expected signature:
- baseline trust yang terlalu “reputation-only” mudah tertipu di awal.
- metode multi-signal/time-aware harus memisahkan cluster lebih cepat.

Referensi konsep Sybil klasik: Douceur (2002). (konsep umum; implementasi disesuaikan simulator)

### 2.2 Collusion Attack (naive collusion, maximal-harm)
Intuisi: sekelompok malicious kompak saling mendukung dan merusak agregasi alarm.

Model minimal:
- Node malicious tipe `collusion` diberi `collusion_group_id`.
- Response:
  - intra-group: `malicious_high` konsisten
  - ke honest: `malicious_low` (atau “opposite of true_label” jika kamu punya label ordinal)
- Forwarding:
  - forward alarm dari group lebih sering, dari honest lebih jarang (opsional)

Catatan realism:
- Literatur membedakan “naive/maximal-harm” vs strategi lebih halus.
- Untuk paper kamu cukup “naive collusion” sebagai baseline collusion (dan PMFA sebagai advanced).

### 2.3 Betrayal Attack (on-off)
Intuisi: attacker membangun trust dengan perilaku jujur, lalu mengkhianati.

Model A (two-phase, paling sederhana dan cukup untuk paper):
- round < betrayal_start_round: behave like honest (sample ~N(honest_mean, honest_std))
- round >= betrayal_start_round: switch ke malicious:
  - ke honest: `malicious_low`
  - ke sesama malicious: `malicious_high`

Model B (on-off, lebih faithful ke “special on-off” family):
- Attack state toggling berdasar period + duty cycle:
  - pada fase ON: behave honest-like
  - pada fase OFF: behave malicious
- Wajib deterministic (seeded).

Expected signature:
- trust drift: trust awal tinggi lalu turun ketika OFF muncul.
- metode yang “time-aware” (mis. forgetting factor) harus lebih cepat menangkap perubahan.

### 2.4 PMFA (Passive Message Fingerprint Attack)
Intuisi inti (literatur):
- Challenge-based trust mengandalkan attacker tidak bisa membedakan CHALLENGE vs REQUEST.
- PMFA mematahkan asumsi itu: attacker *pasif* mengumpulkan pesan dan, via fingerprint,
  mengklasifikasikan REQUEST (normal alarm-ranking request) vs CHALLENGE.
  Contoh mekanisme: REQUEST berisi alarm-set yang sama dan dikirim ke banyak node, sehingga
  malicious nodes bisa membandingkan pesan yang mereka terima dan mencari match; jika match,
  itu kemungkinan REQUEST, bukan CHALLENGE.

Threat capability (simulator-level):
- Attacker tidak mengubah payload terenkripsi, tetapi dapat mengamati pola/invariant (timing, metadata),
  atau melakukan “match” antar penerima lewat kolusi.

Implementasi yang disarankan (paper-aligned, tapi tetap sederhana):
1) Simulator mengisi `alarm_set_id` pada setiap pesan.
2) Untuk REQUEST: `alarm_set_id` cenderung sama bagi beberapa dst dalam window kecil.
   Untuk CHALLENGE: `alarm_set_id` unik per dst (atau dibuat “hard to match”).
3) Attacker melakukan klasifikasi:
   - Dengan probabilitas `pmfa_detect_prob`, attacker berhasil menilai apakah pesan itu REQUEST.
   - Jika `pmfa_collusion_enabled`:
     - attacker menyimpan `alarm_set_id` yang ia lihat, dan dapat “melihat” cache group dalam `pmfa_match_window_rounds`;
     - Jika jumlah match >= `pmfa_min_matches` maka classify sebagai REQUEST.

Response strategy (wajib salah satu):
- `honest_on_challenge_malicious_on_request`:
  - jika classify REQUEST: kirim jawaban jahat (mis. `malicious_low` ke honest)
  - else: jawab honest-like agar lolos challenge
- `partial_poisoning`:
  - jika classify REQUEST: jawab jahat dengan probabilitas `pmfa_poison_rate`
  - else: honest-like

Why this matters:
- Under PMFA, trust value attacker bisa “bertahan tinggi” (challenge tidak memukulnya),
  tapi agregasi alarm rusak, sehingga baseline cenderung AUC ~ chance.
- Defense paper kamu mengklaim bisa tetap memisahkan attacker dan mencapai AUC tinggi
  meski attacker “occasionally honest”.

Acceptance checks:
- Dengan PMFA aktif dan baseline sederhana, trust attacker tidak drop cepat.
- Dengan CIDSeeks defense aktif, trust separation jelas dan AUC meningkat per round.

---

## 3) Implementation rules (agar Codex tidak salah tempat naruh logika)

1) Attack logic HARUS ada di modul/kelas terpisah, contoh: `attacks/*.py`.
2) TrustCalculator hanya menerima `Observation` dan mengeluarkan trust update.
   Ia tidak boleh “if attack_type == ...” di dalamnya.
3) Node pipeline:
   - Node menerima pesan
   - Node memanggil `AttackPolicy` (atau `BehaviorPolicy`) untuk menghasilkan response_value/flags
   - Simulator mencatat Observation
   - TrustCalculator mengupdate trust berdasarkan Observation
4) Semua randomness harus seeded dari `seed` + node_id (deterministic per eksperimen).

---

## 4) Minimal tests (wajib)

- Betrayal:
  - sebelum start_round: distribusi response mirip honest
  - setelah start_round: mean response turun signifikan untuk target honest

- PMFA:
  - dengan seed fixed, proporsi “malicious on REQUEST, honest on CHALLENGE” sesuai parameter
  - jika `pmfa_detect_prob=0`, PMFA tereduksi jadi attacker yang tidak bisa bedakan (harus lebih mudah terdeteksi)
  - jika `pmfa_detect_prob=1`, PMFA paling sulit (baseline paling terpukul)

- Sybil/Collusion:
  - intra-cluster/group feedback tinggi konsisten
  - ke honest rendah konsisten
