"""Verify reproducibility artifact bundle integrity via SHA-256 manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, List, Tuple


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_manifest(bundle_root: Path) -> Dict[str, object]:
    manifest_path = bundle_root / "manifest_sha256.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"manifest not found: {manifest_path}")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("manifest payload must be a JSON object")
    return payload


def _safe_join(bundle_root: Path, rel_path: str) -> Path:
    candidate_rel = Path(rel_path)
    if candidate_rel.is_absolute():
        raise ValueError(f"absolute path is not allowed in manifest: {rel_path}")
    normalized = (bundle_root / candidate_rel).resolve()
    root_resolved = bundle_root.resolve()
    if not normalized.is_relative_to(root_resolved):
        raise ValueError(f"path traversal detected in manifest path: {rel_path}")
    return normalized


def _verify_files(bundle_root: Path, manifest: Dict[str, object]) -> Tuple[List[Dict[str, object]], List[str]]:
    file_entries = manifest.get("files", [])
    if not isinstance(file_entries, list):
        raise ValueError("manifest.files must be a list")

    mismatches: List[Dict[str, object]] = []
    manifest_paths: List[str] = []

    for entry in file_entries:
        if not isinstance(entry, dict):
            continue
        rel_path = entry.get("path")
        expected_sha = entry.get("sha256")
        if not isinstance(rel_path, str) or not isinstance(expected_sha, str):
            continue
        manifest_paths.append(rel_path)
        try:
            abs_path = _safe_join(bundle_root, rel_path)
        except ValueError as exc:
            mismatches.append(
                {
                    "path": rel_path,
                    "reason": "invalid_path",
                    "error": str(exc),
                }
            )
            continue
        if not abs_path.exists():
            mismatches.append({
                "path": rel_path,
                "reason": "missing_file",
                "expected_sha256": expected_sha,
            })
            continue
        observed_sha = _sha256_file(abs_path)
        if observed_sha != expected_sha:
            mismatches.append({
                "path": rel_path,
                "reason": "sha_mismatch",
                "expected_sha256": expected_sha,
                "observed_sha256": observed_sha,
            })

    return mismatches, manifest_paths


def _safe_extract_tar(tar: tarfile.TarFile, extract_root: Path) -> None:
    safe_members: List[tarfile.TarInfo] = []
    for member in tar.getmembers():
        member_path = Path(member.name)
        if member_path.is_absolute() or ".." in member_path.parts:
            raise ValueError(f"unsafe tar member path: {member.name}")
        if member.issym() or member.islnk():
            raise ValueError(f"tar links are not allowed: {member.name}")
        safe_members.append(member)

    try:
        tar.extractall(path=extract_root, members=safe_members, filter="data")
    except TypeError:
        tar.extractall(path=extract_root, members=safe_members)


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify CIDSeeks artifact bundle checksums")
    parser.add_argument(
        "--bundle-path",
        required=True,
        help="Path to artifact bundle tar.gz or extracted artifact_bundle directory",
    )
    parser.add_argument(
        "--report",
        default=None,
        help="Optional JSON report output path",
    )
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    bundle_input = Path(args.bundle_path)

    temp_context = None
    if bundle_input.is_file():
        temp_context = tempfile.TemporaryDirectory(prefix="cidseeks_bundle_verify_")
        extract_root = Path(temp_context.name)
        with tarfile.open(bundle_input, "r:gz") as tar:
            _safe_extract_tar(tar, extract_root)
        bundle_root = extract_root / "artifact_bundle"
    else:
        bundle_root = bundle_input

    try:
        manifest = _load_manifest(bundle_root)
        mismatches, manifest_paths = _verify_files(bundle_root, manifest)

        observed_files = sorted(
            p.relative_to(bundle_root).as_posix()
            for p in bundle_root.rglob("*")
            if p.is_file() and p.name != "manifest_sha256.json"
        )
        extras = sorted(set(observed_files) - set(manifest_paths))

        report = {
            "bundle_root": str(bundle_root),
            "manifest_entries": len(manifest_paths),
            "observed_files": len(observed_files),
            "mismatches": mismatches,
            "extra_files": extras,
            "passed": len(mismatches) == 0,
        }

        if args.report:
            report_path = Path(args.report)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        print(json.dumps(report, indent=2))
        return 0 if report["passed"] else 1
    finally:
        if temp_context is not None:
            temp_context.cleanup()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
