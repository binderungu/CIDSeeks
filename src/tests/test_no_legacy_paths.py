from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys


def _is_module_missing(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is None
    except ModuleNotFoundError:
        return True


def _legacy_guard_script_path() -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "qa" / "check_no_legacy_imports.py"
    return script_path


def test_removed_legacy_paths_are_not_importable():
    removed_paths = [
        "simulation.legacy",
        "simulation.legacy.attacks",
        "simulation.config.config_manager",
        "simulation.config.experiment_runner",
        "simulation.runner",
        "simulation.scenario",
        "simulation.simulator",
        "simulation.reporting",
        "simulation.visualization",
        "simulation.export",
        "simulation.export.result_exporter",
        "simulation.export.data_processor",
        "simulation.monitoring",
        "simulation.monitoring.real_time_monitor",
        "simulation.models",
        "simulation.models.base",
        "simulation.utils.error_handler",
        "simulation.utils.event_manager",
        "simulation.utils.helpers",
        "simulation.utils.icon_handler",
        "simulation.utils.performance_monitor",
        "simulation.utils.persistence",
        "simulation.utils.simulation_state",
        "simulation.utils.visualization_helper",
        "simulation.modules.authentication.auth_manager",
        "simulation.modules.authentication.core_auth_manager",
        "simulation.modules.privacy.privacy_manager",
        "simulation.modules.collaboration.collab_manager",
        "simulation.modules.attacks.sybil",
        "simulation.modules.attacks.collusion",
        "simulation.modules.attacks.betrayal",
        "simulation.modules.attacks.pmfa",
        "simulation.modules.attacks.core_attacks",
        "simulation.modules.attacks.attack_coordinator",
        "simulation.modules.database.database_manager",
        "simulation.modules.database.database_module",
        "simulation.modules.ids.ids_module",
        "simulation.core.simulation_iteration",
        "simulation.core.simulation_status",
        "simulation.utils.exceptions",
        "simulation.utils.logger",
        "simulation.utils.theme",
    ]
    assert all(_is_module_missing(path) for path in removed_paths)


def test_legacy_import_guard_script_passes():
    completed = subprocess.run(
        [sys.executable, str(_legacy_guard_script_path())],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "legacy import guard passed" in completed.stdout


def test_legacy_alias_exports_are_removed():
    import simulation.modules as modules_pkg
    import simulation.modules.authentication as auth_pkg
    import simulation.modules.collaboration as collab_pkg
    import simulation.modules.ids as ids_pkg

    assert hasattr(modules_pkg, "IdsModule")
    assert hasattr(modules_pkg, "TrustManager")
    assert hasattr(auth_pkg, "AuthenticationModule")
    assert hasattr(collab_pkg, "CollaborationModule")
    assert hasattr(ids_pkg, "IdsModule")

    assert not hasattr(modules_pkg, "IDSModule")
    assert not hasattr(modules_pkg, "TrustModule")
    assert not hasattr(auth_pkg, "AuthenticationManager")
    assert not hasattr(auth_pkg, "AuthManager")
    assert not hasattr(collab_pkg, "CollaborationManager")
    assert not hasattr(ids_pkg, "IDSModule")
