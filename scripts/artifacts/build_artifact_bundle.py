"""Create reproducibility artifact bundles for third-party evaluation."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_hash(repo_root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except Exception:
        return None


def _resolve_within_repo(repo_root: Path, path: Path) -> Path:
    candidate = (repo_root / path).resolve() if not path.is_absolute() else path.resolve()
    if not candidate.is_relative_to(repo_root):
        raise ValueError(f"path escapes repository root: {path}")
    return candidate


def _copy_path(src: Path, dst_root: Path, rel_path: Path) -> None:
    dst = dst_root / rel_path
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)
    else:
        shutil.copy2(src, dst)


def _iter_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_file():
            yield path


def _build_manifest(bundle_root: Path, manifest_relpath: str = "manifest_sha256.json") -> Dict[str, object]:
    records: List[Dict[str, object]] = []
    manifest_path = bundle_root / manifest_relpath
    for file_path in _iter_files(bundle_root):
        rel = file_path.relative_to(bundle_root).as_posix()
        if rel == manifest_relpath:
            continue
        records.append(
            {
                "path": rel,
                "sha256": _sha256_file(file_path),
                "bytes": int(file_path.stat().st_size),
            }
        )
    payload: Dict[str, object] = {
        "schema": "cidseeks-artifact-manifest-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "files": records,
    }
    manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build CIDSeeks artifact bundle")
    parser.add_argument("--suite", default="paper_core", help="Suite name under results/")
    parser.add_argument("--results-root", default="results", help="Results root directory")
    parser.add_argument(
        "--bundle-path",
        default=None,
        help="Target bundle path (.tar.gz). Default: dist/artifacts/<suite>_artifact_bundle.tar.gz",
    )
    parser.add_argument(
        "--include-manifests",
        action="store_true",
        help="Include results/_manifests in the bundle",
    )
    parser.add_argument(
        "--extra-path",
        action="append",
        default=[],
        help="Extra repo-relative file/dir to include (repeatable)",
    )
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    repo_root = Path.cwd().resolve()
    results_root = _resolve_within_repo(repo_root, Path(args.results_root))
    suite_dir = _resolve_within_repo(repo_root, results_root / args.suite)
    if not suite_dir.exists():
        raise FileNotFoundError(f"suite directory not found: {suite_dir}")

    default_bundle = Path("dist") / "artifacts" / f"{args.suite}_artifact_bundle.tar.gz"
    bundle_path = Path(args.bundle_path) if args.bundle_path else default_bundle
    bundle_path.parent.mkdir(parents=True, exist_ok=True)

    default_extra_paths = [
        Path("pyproject.toml"),
        Path("uv.lock"),
        Path("docs/01_RUNBOOK.md"),
        Path("docs/04_EXPERIMENTS.md"),
        Path("CHANGELOG.md"),
    ]
    extra_paths = [Path(p) for p in args.extra_path] if args.extra_path else default_extra_paths

    with tempfile.TemporaryDirectory(prefix="cidseeks_bundle_") as tmp_dir:
        tmp_root = Path(tmp_dir)
        bundle_root = tmp_root / "artifact_bundle"
        bundle_root.mkdir(parents=True, exist_ok=True)

        include_paths: List[Path] = [suite_dir]
        manifests_dir = _resolve_within_repo(repo_root, results_root / "_manifests")
        if args.include_manifests and manifests_dir.exists():
            include_paths.append(manifests_dir)
        for extra_path in extra_paths:
            resolved = _resolve_within_repo(repo_root, extra_path)
            if resolved.exists():
                include_paths.append(resolved)

        for src_path in include_paths:
            rel_path = src_path.relative_to(repo_root)
            _copy_path(src_path, bundle_root, rel_path)

        metadata = {
            "schema": "cidseeks-artifact-bundle-v1",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "suite": args.suite,
            "command": " ".join(sys.argv),
            "python_version": sys.version,
            "repo_root": str(repo_root),
            "git_hash": _git_hash(repo_root),
            "included_paths": [str(path.relative_to(repo_root)) for path in include_paths],
        }
        (bundle_root / "bundle_metadata.json").write_text(
            json.dumps(metadata, indent=2),
            encoding="utf-8",
        )

        _build_manifest(bundle_root)

        with tarfile.open(bundle_path, "w:gz") as tar:
            tar.add(bundle_root, arcname="artifact_bundle")

    bundle_sha = _sha256_file(bundle_path)
    print(json.dumps({
        "bundle_path": str(bundle_path),
        "bundle_sha256": bundle_sha,
        "suite": args.suite,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
