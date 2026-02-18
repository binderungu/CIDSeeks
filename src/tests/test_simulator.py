import pytest


pytest.skip(
    "Legacy simulator test depends on deprecated network_simulator stack.",
    allow_module_level=True,
)
