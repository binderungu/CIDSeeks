from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _guard_script(script_name: str) -> Path:
    return Path(__file__).resolve().parents[2] / "scripts" / "qa" / script_name


def _run_guard(script_name: str, target: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(_guard_script(script_name)),
            "--path",
            str(target),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_no_shell_true_guard_rejects_shell_keyword(tmp_path: Path) -> None:
    sample = tmp_path / "unsafe_shell.py"
    sample.write_text(
        "import subprocess\nsubprocess.run('echo hi', shell=True)\n",
        encoding="utf-8",
    )
    completed = _run_guard("check_no_shell_true.py", sample)
    assert completed.returncode == 1
    assert "unsafe shell" in completed.stdout


def test_no_shell_true_guard_rejects_os_system(tmp_path: Path) -> None:
    sample = tmp_path / "unsafe_os.py"
    sample.write_text(
        "import os\nos.system('echo hi')\n",
        encoding="utf-8",
    )
    completed = _run_guard("check_no_shell_true.py", sample)
    assert completed.returncode == 1
    assert "os.system/os.popen" in completed.stdout


def test_no_shell_true_guard_accepts_safe_subprocess(tmp_path: Path) -> None:
    sample = tmp_path / "safe.py"
    sample.write_text(
        "import subprocess\nsubprocess.run(['echo', 'hi'], check=False)\n",
        encoding="utf-8",
    )
    completed = _run_guard("check_no_shell_true.py", sample)
    assert completed.returncode == 0
    assert "shell safety guard passed" in completed.stdout


def test_tar_safety_guard_rejects_unsafe_extractall(tmp_path: Path) -> None:
    sample = tmp_path / "unsafe_tar.py"
    sample.write_text(
        "def f(tar, path):\n    tar.extractall(path=path)\n",
        encoding="utf-8",
    )
    completed = _run_guard("check_safe_tar_extract.py", sample)
    assert completed.returncode == 1
    assert "unsafe tar.extractall call" in completed.stdout


def test_tar_safety_guard_accepts_members_parameter(tmp_path: Path) -> None:
    sample = tmp_path / "safe_tar.py"
    sample.write_text(
        "def f(tar, path, members):\n    tar.extractall(path=path, members=members)\n",
        encoding="utf-8",
    )
    completed = _run_guard("check_safe_tar_extract.py", sample)
    assert completed.returncode == 0
    assert "tar extraction safety guard passed" in completed.stdout


def test_deterministic_rng_guard_rejects_unseeded_constructors(tmp_path: Path) -> None:
    sample = tmp_path / "unsafe_rng.py"
    sample.write_text(
        "import random\n"
        "import numpy as np\n"
        "a = random.Random()\n"
        "b = np.random.default_rng()\n",
        encoding="utf-8",
    )
    completed = _run_guard("check_deterministic_rng.py", sample)
    assert completed.returncode == 1
    assert "requires explicit non-None seed" in completed.stdout


def test_deterministic_rng_guard_accepts_seeded_constructors(tmp_path: Path) -> None:
    sample = tmp_path / "safe_rng.py"
    sample.write_text(
        "import random\n"
        "import numpy as np\n"
        "a = random.Random(123)\n"
        "b = np.random.default_rng(456)\n",
        encoding="utf-8",
    )
    completed = _run_guard("check_deterministic_rng.py", sample)
    assert completed.returncode == 0
    assert "deterministic RNG guard passed" in completed.stdout
