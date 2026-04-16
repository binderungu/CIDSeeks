# 02_SYSTEM_SPEC — Paper-aligned system specification (Evaluation-2: SimPy)

Dokumen ini menggabungkan project brief + arsitektur simulator untuk Evaluasi-2:
- batas modul (separation of concerns)
- flow protokol (trust-gated dissemination + DMPO)
- disiplin SimPy (determinisme + event scheduling)
- kontrak internal (apa yang boleh/tdk boleh diubah)

## 1) Scope dan alignment ke paper
CIDSeeks menyatukan:
- multi-layer trust (three-tier challenges)
- authentication (PKI-backed, disimulasikan)
- privacy via DMPO-X untuk menurunkan stream-level distinguishability terhadap A-PMFA
- trust attribution untuk mengubah residual fingerprintability menjadi bukti eksplisit
Simulator:
- SimPy-based hybrid discrete-event engine untuk async messaging
- NetworkX topology (ER/WS/BA + mesh/hybrid) dengan validasi konektivitas (LCC)
- Logging + metrics untuk analisis reproducible
- Scope privacy canonical saat ini: `dmpo_x` menjalankan **DMPO-X runtime path** (recipient-scoped aliasing, epoch-scoped alias rotation, opaque stealth header, hidden family rendering, budget-aware policy selection).
- Scope trust canonical saat ini: advanced/final tier membawa **A-PMFA attribution evidence** berupa `FIBD`, `SplitFail`, `CoalCorr`, dan agregat `P_apmfa`.
- Scope leakage evidence canonical saat ini: attacker-side evidence diturunkan post-run oleh **Eval-3 metadata attacker pipeline** dari `privacy_pmfa_logs`; repo ini tetap diposisikan sebagai **Evaluation-2 protocol simulator** dan trace generator.

## 2) Komponen utama (boundary)
### Entry points
- runner.py: single config run / smoke
- simulate.py: batch suites (smoke, paper_core, robustness, scalability)

### Core simulation (dumb + deterministic)
- SimulationEngine: SimPy Environment, global clock, scheduling
- Node: state, trust table, inbox/outbox, module hooks
- Network/Topology: graph generation + neighbor routing
- Message types minimal:
  - Alarm, Feedback
  - **CHALLENGE** dan **REQUEST** sebagai artefak protokol trust yang eksplisit
    (dicatat pada protocol inbox/outbox node dan event trust; detail di 03_ATTACK_MODEL)
  - challenge payload bertingkat:
    - basic: nonce + expected ack token
    - advanced: context digest + corroboration fields
    - final: auth nonce + behavior commitment (attestation bundle)

### Pluggable modules (separation of concerns)
- IDS: menghasilkan alarm (sesuai workload)
- Collaboration: gossip dissemination + trust gating (relay hanya jika trust >= τ)
- Trust: three-tier scoring + update trust table (input: Observations)
  - advanced tier mengonsumsi `R_j(t)`, `C_j(t)`, penalty runtime, dan `P_apmfa(t)`
  - final tier menggabungkan auth/verifier evidence dengan penalti `SplitFail`
- Privacy (DMPO): message variations + randomized delay Δ + numbering/sequence internal
- Authentication: simulated PKI-style module (mode required/disabled, revocation, false-accept/reject, transport-failure)
- Attacks: Sybil/Collusion/Betrayal/PMFA (attack policy hanya di modul attacks)
- Metrics/Logging: koleksi counters/latency/trust snapshots + output run artifacts

Rule: Jangan campur logika Trust ke Collaboration/Privacy, dst.

## 3) Workflow simulator (event-driven)
Per alarm event:
1) IDS menghasilkan alarm
2) Privacy membungkus alarm jadi V varian + schedule delay Δ (SimPy timeout)
3) Collaboration memilih peers (fanout ≈ √N) dan mengirim (trust-gated)
4) Receiver memproses:
   - authenticate (simulated)
   - menerima artefak protokol **REQUEST/CHALLENGE** yang eksplisit
   - verifikasi proof sesuai tier challenge (basic/advanced/final)
   - trust evaluation (3-tier) terhadap pengirim/info
     - advanced tier membentuk `P_apmfa` dari `FIBD`, `SplitFail`, `CoalCorr`
     - final tier menahan skor jika verifier-share reconstruction gagal
   - decide: accept/ignore/relay
5) Observation dicatat; trust diupdate; metrics counters bertambah
6) Periodic refresh: trust table refresh setiap P ticks (off critical path)
7) Post-run: agregasi summary + figures dari output artifacts

## 4) Trust model invariants
- score_1/2/3 dan total trust dipotong ke [0,1]
- weights w1,w2,w3 dan threshold τ berasal dari config (no hardcode)
- tidak boleh NaN/negatif
- trust_rise_threshold / trust_fall_threshold (jika ada) mengatur eskalasi tier dan quarantine
- advanced tier mengikuti bentuk operasional:
  - `T_adv = α T_prev + β R_j(t) + γ C_j(t) - δ(P_runtime + P_apmfa)`
  - `P_apmfa` dibentuk dari `FIBD`, `SplitFail`, `CoalCorr`, lalu diproyeksikan ke `[0,1]`
- final tier mengikuti bentuk operasional:
  - `T_final = θ T_prev + ϵ A_j(t) + ζ B_j(t) - P_split`
  - `P_split` berasal dari failure rate verifier reconstruction pada challenge bertier final
- event trust canonical (`observation`, `challenge_*`, `challenge_outcome`) harus memancarkan sinyal attribution itu secara eksplisit agar audit paper tidak bergantung pada state internal

## 5) DMPO invariants (penting untuk PMFA)
Tujuan DMPO-X: meminimalkan fingerprint/linkage pada level stream, bukan menjanjikan anonymity absolut.
Elemen minimum:
- field obfuscation pada alarm payload
- deterministic mapping (prefix-preserving hash) + k-anonymity untuk atribut sensitif
- **V varian** per alarm (default V=3)
- numbering/sequence internal untuk korelasi tanpa bocor pola
- hash-anchored family/variant IDs agar varian dapat dikorelasi secara aman
- randomized delivery delay Δ (SimPy timeout)
- gossip forwarding dengan fanout sub-linear (default √N)
- policy controller memilih tuple `(K_t, f_t, ell_t, d_t, r_t)` berdasar objective privacy-vs-budget

## 6) SimPy discipline
- Semua delay pakai `env.timeout(...)` (no time.sleep di core)
- Proses via `env.process(...)`
- I/O berat dan plotting hanya post-processing

## 7) Output/reproducibility invariants
- setiap run menyimpan config_resolved + metadata (seed list, version)
- output layout mengikuti docs/04_EXPERIMENTS.md
- manifest run ditulis ke `results/_manifests/run_*.json`
- agregasi/plot dibuat dari artifacts, bukan state in-memory
