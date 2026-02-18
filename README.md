# CIDSeeks - Collaborative Intrusion Detection System Simulation

## 🎯 Project Overview

CIDSeeks is a comprehensive simulation platform for a **Collaborative Intrusion Detection System (CIDS)** that implements an innovative **3-level challenge trust model**. This project was developed as part of doctoral research to evaluate the effectiveness of the trust model in detecting various insider attacks (PMFA, Collusion, Sybil, Betrayal) within a collaborative P2P network.

**Applied Standard**: A complete simulation platform for academic research compliant with international publication standards.

### 🔬 Research Objectives:
- Evaluate the performance of the proposed **3-level challenge trust model**.
- Analyze resilience against various types of attacks.
- Provide a reproducible evaluation framework for academic research.

### 📌 Scope Lock (Evaluation-2)
- Empirical claims in this repo are restricted to 4 insider attacks: **PMFA, Collusion, Sybil, Betrayal**.
- Broader attack taxonomy in `references/cids.md` (e.g., newcomer/pollution) is treated as literature context unless a dedicated experiment suite is added.

---

## ✨ **Key Features**

### **🏗️ Core Architecture:**
- **CIDSeeks Trust Engine**: Hierarchical 3-level challenge calculations
- **Attack Simulation**: PMFA, Collusion, Sybil, Betrayal attacks
- **SimPy-based Engine**: Discrete-event simulation framework

### **📊 Evaluation Framework:**
- **Performance Benchmarking**: Head-to-head method comparison
- **Academic Analysis Tools**: Statistical significance testing
- **Comprehensive Metrics**: Detection, convergence, resilience metrics
- **Visualization Suite**: Interactive network graphs dan performance plots

### **🎨 User Interface:**
- **Modern GUI**: CustomTkinter-based interface
- **Real-time Monitoring**: Live simulation progress
- **Interactive Visualization**: Network topology dan trust evolution
- **Method Configuration**: Easy trust method selection dan parameter tuning

### **🔐 Security & Privacy:**
- **Authentication Module**: CA-based node authentication
- **Privacy Protection**: Alarm obfuscation dan variation
- **Cryptographic Security**: RSA encryption untuk secure communication

---

## 📁 **Project Structure**

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

## 🚀 **Quick Start**

### **1. Installation**
```bash
uv sync
```

### **2. Run GUI Application**
```bash
uv run --locked -- python src/main.py
```
Catatan:
- GUI aktif (`src/main.py` + `src/ui/`) memakai `simulation.core.simulation_engine` (jalur canonical).
- UI setup sekarang mengambil baseline slider dari `config.yaml` canonical (dengan fallback default aman).
- Path lama `simulation.{scenario,simulator,reporting,visualization}` dan seluruh namespace `simulation.legacy` sudah dihapus.
- `src/simulation/runner.py` sudah dihapus; entry GUI canonical adalah `src/main.py`.

### **3. Run CLI Simulation**
```bash
uv run --locked -- python runner.py --config config.yaml

# Quick paper-core subset
uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments_batch_quick.yaml

# Full paper-core (final numbers)
uv run --locked -- python simulate.py --suite paper_core --config configs/experiments/experiments.yaml
```

### **4. Run Evaluation Framework**
```bash
# Smoke suite
uv run --locked -- python simulate.py --suite smoke --config configs/experiments/experiments_smoke.yaml

# Validate suite gate
uv run --locked -- python scripts/qa/check_stats_gate.py --path results/smoke/stats_gate.json
```

Catatan:
- Jalur kanonis hasil eksperimen: `results/`.
- Jalur kanonis suite config: `configs/experiments/`.
- Basename lama (mis. `--config experiments_smoke.yaml`) masih didukung sementara, tetapi sudah deprecated dan akan memunculkan warning migrasi.
- Layout lama `results/default/` dan `runs/` sudah dipensiunkan dari repo.
- Panduan cepat folder: lihat `results/README.md` dan `scripts/README.md`.

### **5. Packaging Metadata Policy**
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
