"""Authentication exports for Evaluation-2 runtime.

Canonical implementation lives in `module.py` (`AuthenticationModule`).
Legacy manager files were removed; use canonical `AuthenticationModule`.
"""

from .module import AuthenticationModule

__all__ = ["AuthenticationModule"]
