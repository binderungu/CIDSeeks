# CIDSeeks - Evaluation-2 SimPy Protocol Simulator

CIDSeeks di repo ini adalah **canonical Evaluation-2 repository** untuk paper: simulator protokol end-to-end berbasis SimPy yang mengevaluasi kolaborasi IDS dengan **obfuscation + attribution**. Jalur runtime yang dikunci di sini meliputi topologi jaringan, gossip dissemination, trust gating, authentication abstraction, privacy strategy (`dmpo_legacy` / `dmpo_x`), dan 4 insider attacks canonical.

## Scope Lock

- Klaim empiris repo ini dibatasi pada **PMFA, Collusion, Sybil, Betrayal**.
- Repo ini diposisikan sebagai **Evaluation-2 protocol simulator** dan generator trace untuk **Eval-3 metadata attacker pipeline** (`results/<suite>/<run_id>/eval3_pmfa/`).
- Framing sistem yang dipakai sekarang: **DMPO-X menurunkan stream-level distinguishability, trust engine mengubah residual leakage menjadi attribution evidence** (`FIBD`, `SplitFail`, `CoalCorr`, `P_apmfa`).
- Evaluasi-1 trust-core dan Evaluasi-4 mini-testbed **bukan jalur klaim canonical repo ini**.

## Canonical Docs

Urutan baca utama:
- [docs/00_INDEX.md](docs/00_INDEX.md)
- [docs/01_RUNBOOK.md](docs/01_RUNBOOK.md)
- [docs/02_SYSTEM_SPEC.md](docs/02_SYSTEM_SPEC.md)
- [docs/03_ATTACK_MODEL.md](docs/03_ATTACK_MODEL.md)
- [docs/04_EXPERIMENTS.md](docs/04_EXPERIMENTS.md)

Docs di atas adalah source of truth. Jika README dan docs bertentangan, ikuti `docs/`.

## Quick Start

### 1. Setup

```bash
uv sync
```

### 2. Canonical commands

```bash
# Single-run smoke
uv run --locked -- python runner.py --config config.yaml

# Smoke suite
uv run --locked -- python simulate.py --suite smoke --config configs/experiments/experiments_smoke.yaml

# Targeted DMPO-X smoke
uv run --locked -- python simulate.py --suite smoke --config configs/experiments/experiments_smoke_dmpox.yaml

# Paper-core CI gate subset
uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments_paper_core_ci_gate.yaml
```

Validation helpers:

```bash
uv run --locked -- python scripts/qa/check_stats_gate.py --path results/smoke/stats_gate.json
uv run --locked -- python scripts/qa/check_stats_gate.py --path results/paper_core/stats_gate.json
make publish-freeze-local
```

### 3. Optional GUI

```bash
uv run --locked -- python src/main.py
```

Catatan:
- GUI memakai runtime canonical yang sama, tetapi repo ini dioptimalkan untuk artifact CLI/reviewer path.
- Jalur kanonis config suite adalah `configs/experiments/`.
- Jalur kanonis artifact adalah `results/<suite>/<run_id>/`.
- Basename config lama masih diterima sementara, tetapi deprecated.

## Public Snapshot Policy

- Snapshot publik dibuat via `make public-snapshot`.
- Snapshot publik mengecualikan file internal dan jalur non-canonical, termasuk `AGENTS.md`, `docs/06_CODEX_RULES.md`, `docs/07_THREAD_STARTERS.md`, `references/*.md`, serta placeholder `src/eval1_trust_core/*` dan `src/eval4_minitestbed/*`.
- Untuk freeze final, jalankan `make publish-freeze-local` dulu lalu ekspor snapshot dari commit private yang bersih.

## Project Structure

```
CIDSeeks/
├── config.yaml
├── configs/
│   └── experiments/
│       ├── experiments_smoke.yaml
│       ├── experiments_batch_quick.yaml
│       ├── experiments_auth_sensitivity.yaml
│       └── experiments.yaml
├── runner.py
├── simulate.py
├── src/
├── docs/
├── scripts/
│   ├── qa/
│   ├── artifacts/
│   ├── maintenance/
│   └── ui/
└── results/
    ├── <suite>/<run_id>/             # run artifacts
    ├── <suite>/seed_manifest.json    # resolved seed plan
    ├── <suite>/stats_gate.json       # reproducibility/statistics gate
    ├── <suite>/*.csv                 # suite aggregate outputs
    └── _manifests/run_*.json         # latest run pointers for UI
```

---

## Packaging Metadata Policy
- `pyproject.toml` adalah **single source of truth** untuk metadata paket dan dependencies.
- `uv.lock` adalah artifact reproducibility yang dipakai workflow canonical (`uv sync`, `uv run --locked -- ...`).
- `setup.py` dipertahankan sebagai shim kompatibilitas tooling lama; jangan menaruh metadata duplikat di file itu.
- `requirements*.txt` hanya untuk kompatibilitas legacy; workflow utama tetap berbasis `uv`.

---

## ⚙️ **Configuration**

### **Main Configuration (config.yaml):**
```yaml
simulation:
  total_nodes: 20
  malicious_ratio: 0.3
  iterations: 100
  
trust_model:
  method: "CIDSeeks" # Proposed method
  learning_rate: 0.3
  weights:
    alpha: 0.4
    beta: 0.3
    gamma: 0.2
    
attack:
  type: "pmfa"  # pmfa, collusion, sybil, betrayal
  intensity: 0.5
```

### **Available Trust Methods:**
- **`three_level_challenge`**: The proposed CIDSeeks trust model (default).
- **`honey`**: Optional honey-challenge variant built on top of the CIDSeeks flow.

---

## 📊 **Evaluation & Research**

### **Performance Metrics:**
- **Detection Accuracy**: Precision, Recall, F1-Score
- **Trust Convergence**: Time-to-demote, stability
- **Attack Resilience**: PMFA, Collusion, Sybil, Betrayal resistance
- **Computational Performance**: Execution time, memory usage, throughput

### **Statistical Analysis:**
- **Significance Testing**: t-test, Mann-Whitney U
- **Effect Size**: Cohen's d, Cliff's delta
- **Confidence Intervals**: 95% CI for all metrics
- **Multiple Comparisons**: Bonferroni correction

---

## 🔌 **Extending CIDSeeks**

The simulator focuses on the 3-Level Challenge trust workflow. If you need
variants, subclass `ThreeLevelChallengeMethod` (see `src/simulation/methods/proposed_method/honey_challenge.py`
for an example) and register it via `MethodFactory.register_method`. The legacy
plugin system has been retired along with the external baseline implementations.

---

## 🧪 **Testing**

### **Run All Tests:**
```bash
# Install dev tooling (pytest, flake8, mypy, black)
uv sync --extra dev

# Core functionality tests
uv run --locked --extra dev -- pytest -q src/tests

# Staged typecheck gate (evaluator modules)
uv run --locked --extra dev -- mypy src/evaluation/metrics/enhanced_metrics.py src/evaluation/pipeline/run_evaluator.py --ignore-missing-imports

# With coverage
uv run --locked --extra dev -- pytest --cov=src src/tests
```

### **Performance Testing:**
```bash
# Benchmark trust methods
uv run --locked -- python evaluation/benchmarks/benchmark_trust_methods.py

# Memory profiling
uv run --locked -- python -m memory_profiler runner.py
```

---

## 📈 **Research Applications**

### **Academic Use Cases:**
1. **Trust Model Evaluation**: Assess CIDSeeks across attack scenarios
2. **Attack Resilience Analysis**: Test against various attack scenarios  
3. **Scalability Studies**: Performance analysis with different network sizes
4. **Parameter Sensitivity**: Optimize trust model parameters
5. **Publication Research**: Generate publication-quality results

### **Supported Research Areas:**
- **Collaborative Intrusion Detection**
- **Trust Management in P2P Networks**
- **Insider Attack Detection**
- **Privacy-Preserving Security**
- **Distributed Consensus Mechanisms**

---

## 🤝 **Contributing**

### **Development Workflow:**
1. Fork repository
2. Create feature branch: `git checkout -b feature/new-trust-method`
3. Follow coding standards: `black`, `flake8`, `mypy`
4. Add comprehensive tests
5. Update documentation
6. Submit pull request

### **Code Quality Standards:**
- **Type Hints**: Full type annotation
- **Documentation**: Comprehensive docstrings
- **Testing**: Deterministic unit tests + smoke/non-smoke CI gates must pass
- **Linting**: Pass all quality checks

---

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📞 **Support**

- **Documentation**: `docs/`
- **Canonical Docs**: `docs/00_INDEX.md`
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions

**🎓 Developed for doctoral research in Collaborative Intrusion Detection Systems**
