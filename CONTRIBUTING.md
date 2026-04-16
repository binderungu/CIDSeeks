# Contributing to CIDSeeks

Thank you for your interest in contributing to CIDSeeks! This document provides guidelines for contributing to the project.

## 🚀 Getting Started

### Prerequisites
- Python 3.11 or higher (see `pyproject.toml`)
- `uv` (canonical environment/dependency runner)
- Git

### Development Setup
1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/CIDSeeks.git
   cd CIDSeeks
   ```
3. Sync project environment (canonical):
   ```bash
   uv sync --extra dev
   ```

4. Optional lock verification:
   ```bash
   uv lock --check
   ```

## 📝 Development Guidelines

### Code Style
- Follow PEP 8 guidelines
- Use meaningful variable and function names
- Add docstrings to all functions and classes
- Keep functions focused and small

### Testing
- Write tests for new features
- Ensure all tests pass before submitting PR
- Run tests with canonical command: `make test`
- Aim for high test coverage

### Documentation
- Update documentation for new features
- Use clear and concise language
- Include code examples where appropriate

## 🔄 Contribution Process

### 1. Create an Issue
- Check existing issues first
- Clearly describe the problem or feature request
- Use appropriate labels

### 2. Create a Branch
```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 3. Make Changes
- Follow the coding guidelines
- Write tests for your changes
- Update documentation if needed

### 4. Test Your Changes
```bash
# Critical lint gate (matches CI)
make lint

# Staged typecheck gate (matches CI)
make typecheck-staged

# Orchestrator + aggregator typecheck gate (matches CI)
make typecheck-orchestrator

# Runner contract typecheck gate (matches CI)
make typecheck-runner

# Core surface typecheck gate (matches CI, import graph silenced)
make typecheck-core-surface

# Runtime collaboration/auth/privacy typecheck gate (matches CI, import graph silenced)
make typecheck-runtime-modules

# Export + QA checker typecheck gate (matches CI)
make typecheck-export-qa

# UI artifact store typecheck gate (matches CI)
make typecheck-ui-store

# QA + artifact scripts typecheck gate (matches CI)
make typecheck-scripts

# Repo-wide typecheck gate (matches CI)
make typecheck-repo

# Test suite (matches CI)
make test

# Smoke suite sanity (recommended for runtime/core changes)
make smoke-suite
```

### 5. Submit a Pull Request
- Use a clear and descriptive title
- Describe your changes in detail
- Reference related issues
- Ensure CI checks pass

## 🏗️ Project Structure

```
CIDSeeks/
├── src/                    # Source code (simulation + evaluation + UI)
├── src/tests/              # Test files (canonical)
├── docs/                   # Canonical docs/runbook/spec/experiments
├── configs/experiments/    # Suite experiment configs
├── scripts/                # QA, artifacts, maintenance, UI scripts
├── results/                # Canonical output artifacts
├── pyproject.toml          # Canonical metadata/dependencies
└── uv.lock                 # Reproducibility lockfile
```

## 🐛 Bug Reports

When reporting bugs, please include:
- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Error messages (if any)

## 💡 Feature Requests

For feature requests, please:
- Describe the feature clearly
- Explain the use case
- Consider implementation complexity
- Discuss potential alternatives

## 📚 Research Contributions

For research-related contributions:
- Ensure scientific rigor
- Provide proper citations
- Include experimental validation
- Document methodology clearly

## 🤝 Code of Conduct

- See `CODE_OF_CONDUCT.md` for repository-wide policy.

## 📞 Getting Help

- Check the documentation first
- Search existing issues
- Create a new issue for questions
- Join our discussions

## 🔐 Security Reports

- Please use the process in `SECURITY.md` for vulnerability reporting.

Thank you for contributing to CIDSeeks! 
