import pytest


pytest.skip(
    "Legacy integration test depends on deprecated network_simulator stack.",
    allow_module_level=True,
)
