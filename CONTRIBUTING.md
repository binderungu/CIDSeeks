# Contributing to CIDSeeks

Thank you for your interest in contributing to CIDSeeks! This document provides guidelines for contributing to the project.

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- Git
- Virtual environment (recommended)

### Development Setup
1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/CIDSeeks.git
   cd CIDSeeks
   ```
3. Create a virtual environment:
   ```bash
   python -m venv env
   source env/bin/activate  # On Windows: env\Scripts\activate
   ```
4. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
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
- Run tests with: `pytest`
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
# Run tests
pytest

# Check code style
ruff check .

# Run type checking (if applicable)
mypy src/
```

### 5. Submit a Pull Request
- Use a clear and descriptive title
- Describe your changes in detail
- Reference related issues
- Ensure CI checks pass

## 🏗️ Project Structure

```
CIDSeeks/
├── src/                    # Source code
├── tests/                  # Test files
├── docs/                   # Documentation
├── evaluation/             # Research evaluation
├── scripts/                # Utility scripts
└── requirements*.txt       # Dependencies
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

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Maintain professional communication

## 📞 Getting Help

- Check the documentation first
- Search existing issues
- Create a new issue for questions
- Join our discussions

Thank you for contributing to CIDSeeks! 