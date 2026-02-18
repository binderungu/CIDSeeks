"""Legacy setuptools shim.

Canonical project metadata lives in `pyproject.toml`.
This file exists only for compatibility with older tooling that still invokes
`python setup.py ...`.
Do not duplicate name/version/dependencies here.
"""

from setuptools import setup


if __name__ == "__main__":
    setup()
