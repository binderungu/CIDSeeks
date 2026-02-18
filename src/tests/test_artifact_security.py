import hashlib
import importlib.util
import io
import tarfile
import tempfile
from pathlib import Path


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_verify_bundle_rejects_tar_path_traversal() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    module = _load_module(
        repo_root / "scripts" / "artifacts" / "verify_artifact_bundle.py",
        "verify_artifact_bundle",
    )

    with tempfile.TemporaryDirectory() as tmp:
        tar_path = Path(tmp) / "bundle.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            bad = tarfile.TarInfo(name="../escape.txt")
            payload = b"boom"
            bad.size = len(payload)
            tar.addfile(bad, io.BytesIO(payload))

        with tarfile.open(tar_path, "r:gz") as tar:
            try:
                module._safe_extract_tar(tar, Path(tmp) / "extract")  # noqa: SLF001
                assert False, "expected ValueError for unsafe tar member path"
            except ValueError as exc:
                assert "unsafe tar member path" in str(exc)


def test_verify_files_marks_invalid_manifest_path() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    module = _load_module(
        repo_root / "scripts" / "artifacts" / "verify_artifact_bundle.py",
        "verify_artifact_bundle",
    )

    with tempfile.TemporaryDirectory() as tmp:
        bundle_root = Path(tmp) / "artifact_bundle"
        bundle_root.mkdir(parents=True, exist_ok=True)
        payload = b"ok"
        ok_path = bundle_root / "ok.txt"
        ok_path.write_bytes(payload)
        ok_sha = hashlib.sha256(payload).hexdigest()

        manifest = {
            "files": [
                {"path": "ok.txt", "sha256": ok_sha},
                {"path": "../outside.txt", "sha256": "deadbeef"},
            ]
        }
        mismatches, manifest_paths = module._verify_files(bundle_root, manifest)  # noqa: SLF001

        assert "ok.txt" in manifest_paths
        assert "../outside.txt" in manifest_paths
        invalid = [m for m in mismatches if m.get("reason") == "invalid_path"]
        assert invalid, "expected invalid_path mismatch for traversal path"


def test_build_bundle_rejects_paths_outside_repo() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    module = _load_module(
        repo_root / "scripts" / "artifacts" / "build_artifact_bundle.py",
        "build_artifact_bundle",
    )

    try:
        module._resolve_within_repo(repo_root, Path("../outside"))  # noqa: SLF001
        assert False, "expected ValueError for path outside repo root"
    except ValueError as exc:
        assert "path escapes repository root" in str(exc)

