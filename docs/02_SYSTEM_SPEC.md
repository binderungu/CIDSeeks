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
- privacy via DMPO untuk melawan PMFA
Simulator:
- SimPy discrete-event engine untuk async messaging
- NetworkX topology (ER/WS/BA + mesh/hybrid) dengan validasi konektivitas (LCC)
- Logging + metrics untuk analisis reproducible

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
  - **CHALLENGE** dan **REQUEST** (konsep wajib untuk PMFA; detail di 03_ATTACK_MODEL)
  - challenge payload bertingkat:
    - basic: nonce + expected ack token
    - advanced: context digest + corroboration fields
    - final: auth nonce + behavior commitment (attestation bundle)

### Pluggable modules (separation of concerns)
- IDS: menghasilkan alarm (sesuai workload)
- Collaboration: gossip dissemination + trust gating (relay hanya jika trust >= τ)
- Trust: three-tier scoring + update trust table (input: Observations)
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
   - klasifikasi konteks CHALLENGE/REQUEST (secara internal)
   - verifikasi proof sesuai tier challenge (basic/advanced/final)
   - trust evaluation (3-tier) terhadap pengirim/info
   - decide: accept/ignore/relay
5) Observation dicatat; trust diupdate; metrics counters bertambah
6) Periodic refresh: trust table refresh setiap P ticks (off critical path)
7) Post-run: agregasi summary + figures dari output artifacts

## 4) Trust model invariants
- score_1/2/3 dan total trust dipotong ke [0,1]
- weights w1,w2,w3 dan threshold τ berasal dari config (no hardcode)
- tidak boleh NaN/negatif
- trust_rise_threshold / trust_fall_threshold (jika ada) mengatur eskalasi tier dan quarantine

## 5) DMPO invariants (penting untuk PMFA)
Tujuan DMPO: menurunkan fingerprint/linkage.
Elemen minimum:
- field obfuscation pada alarm payload
- deterministic mapping (prefix-preserving hash) + k-anonymity untuk atribut sensitif
- **V varian** per alarm (default V=3)
- numbering/sequence internal untuk korelasi tanpa bocor pola
- hash-anchored family/variant IDs agar varian dapat dikorelasi secara aman
- randomized delivery delay Δ (SimPy timeout)
- gossip forwarding dengan fanout sub-linear (default √N)

## 6) SimPy discipline
- Semua delay pakai `env.timeout(...)` (no time.sleep di core)
- Proses via `env.process(...)`
- I/O berat dan plotting hanya post-processing

## 7) Output/reproducibility invariants
- setiap run menyimpan config_resolved + metadata (seed list, version)
- output layout mengikuti docs/04_EXPERIMENTS.md
- manifest run ditulis ke `results/_manifests/run_*.json`
- agregasi/plot dibuat dari artifacts, bukan state in-memory
