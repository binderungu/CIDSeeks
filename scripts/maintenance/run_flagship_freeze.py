#!/usr/bin/env python3
"""Orchestrate flagship freeze finalization steps and write an evidence report."""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence


DEFAULT_SUITE = "paper_core"
DEFAULT_FLAGSHIP_CONFIG = "configs/experiments/experiments_paper_core_flagship.yaml"
DEFAULT_RESULTS_ROOT = "results"
DEFAULT_SNAPSHOT_DEST = "/tmp/vibe-cids-public"


@dataclass
class StepResult:
    name: str
    command: List[str]
    status: str
    returncode: int | None
    started_at_utc: str
    finished_at_utc: str
    duration_sec: float
    error: str | None = None


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _isoformat(dt: datetime) -> str:
    return dt.isoformat()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_git(repo_root: Path, args: Sequence[str]) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _git_info(repo_root: Path) -> Dict[str, Any]:
    try:
        status_lines = _run_git(repo_root, ["status", "--porcelain"]).splitlines()
        dirty_entries = [line for line in status_lines if line.strip()]
        return {
            "branch": _run_git(repo_root, ["branch", "--show-current"]),
            "commit": _run_git(repo_root, ["rev-parse", "HEAD"]),
            "dirty": bool(dirty_entries),
            "dirty_count": len(dirty_entries),
            "dirty_entries_preview": dirty_entries[:20],
            "git_available": True,
        }
    except Exception:
        return {
            "branch": "N/A",
            "commit": "N/A",
            "dirty": False,
            "dirty_count": 0,
            "dirty_entries_preview": [],
            "git_available": False,
        }


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run flagship freeze finalization steps (simulate/resume, stats gate, "
            "bundle, verify, snapshot) and write an evidence report."
        )
    )
    parser.add_argument("--suite", default=DEFAULT_SUITE, help="Suite name (default: paper_core)")
    parser.add_argument(
        "--config",
        default=DEFAULT_FLAGSHIP_CONFIG,
        help="Experiment config path for flagship run.",
    )
    parser.add_argument(
        "--results-root",
        default=DEFAULT_RESULTS_ROOT,
        help="Results root directory (default: results).",
    )
    parser.add_argument(
        "--resume",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Resume incomplete experiments during flagship run (default: true).",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow running even when git worktree is dirty (not recommended for final freeze).",
    )
    parser.add_argument(
        "--runner",
        choices=("uv", "python"),
        default="uv",
        help="Command runner for Python scripts (default: uv).",
    )
    parser.add_argument(
        "--python-bin",
        default=sys.executable,
        help="Python interpreter path used when --runner=python (default: current interpreter).",
    )
    parser.add_argument(
        "--run-simulate",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Run flagship simulate.py step (default: true).",
    )
    parser.add_argument(
        "--run-stats-gate",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Run stats gate validation after simulation (default: true).",
    )
    parser.add_argument(
        "--build-bundle",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Build artifact bundle for suite results (default: true).",
    )
    parser.add_argument(
        "--verify-bundle",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Verify artifact bundle checksum manifest (default: true).",
    )
    parser.add_argument(
        "--public-snapshot",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Export public snapshot after validations (default: true).",
    )
    parser.add_argument(
        "--snapshot-dest",
        default=DEFAULT_SNAPSHOT_DEST,
        help=f"Destination for public snapshot (default: {DEFAULT_SNAPSHOT_DEST}).",
    )
    parser.add_argument(
        "--snapshot-include-untracked",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include untracked non-ignored files in public snapshot (default: true).",
    )
    parser.add_argument(
        "--snapshot-init-git",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Initialize fresh git repo in snapshot destination (default: true).",
    )
    parser.add_argument(
        "--bundle-path",
        default=f"{DEFAULT_RESULTS_ROOT}/artifacts/paper_core_flagship_artifact_bundle.tar.gz",
        help="Bundle output path for artifact tar.gz.",
    )
    parser.add_argument(
        "--verify-report",
        default=(
            f"{DEFAULT_RESULTS_ROOT}/artifacts/"
            "paper_core_flagship_artifact_bundle_verify.json"
        ),
        help="JSON report path for bundle verification.",
    )
    parser.add_argument(
        "--report-json",
        default=None,
        help="Output path for freeze JSON report (default: results/artifacts autogenerated).",
    )
    parser.add_argument(
        "--report-md",
        default=None,
        help="Output path for freeze Markdown report (default: alongside JSON report).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not execute commands; write planned steps and preflight metadata only.",
    )
    return parser.parse_args(list(argv))


def _python_command(args: argparse.Namespace, script: str, script_args: Sequence[str]) -> List[str]:
    if args.runner == "uv":
        return ["uv", "run", "--locked", "--", "python", script, *script_args]
    return [args.python_bin, script, *script_args]


def _build_steps(args: argparse.Namespace) -> List[tuple[str, List[str]]]:
    steps: List[tuple[str, List[str]]] = []
    suite = args.suite
    suite_stats_gate = Path(args.results_root) / suite / "stats_gate.json"

    if args.run_simulate:
        simulate_args = [
            "simulate.py",
            "--suite",
            suite,
            "--config",
            args.config,
        ]
        if args.resume:
            simulate_args.append("--resume")
        steps.append(
            ("simulate_flagship", _python_command(args, simulate_args[0], simulate_args[1:])),
        )

    if args.run_stats_gate:
        steps.append(
            (
                "stats_gate",
                _python_command(
                    args,
                    "scripts/qa/check_stats_gate.py",
                    ["--path", str(suite_stats_gate)],
                ),
            )
        )

    if args.build_bundle:
        steps.append(
            (
                "build_bundle",
                _python_command(
                    args,
                    "scripts/artifacts/build_artifact_bundle.py",
                    [
                        "--suite",
                        suite,
                        "--bundle-path",
                        args.bundle_path,
                        "--include-manifests",
                    ],
                ),
            )
        )

    if args.verify_bundle:
        steps.append(
            (
                "verify_bundle",
                _python_command(
                    args,
                    "scripts/artifacts/verify_artifact_bundle.py",
                    [
                        "--bundle-path",
                        args.bundle_path,
                        "--report",
                        args.verify_report,
                    ],
                ),
            )
        )

    if args.public_snapshot:
        snapshot_args: List[str] = [
            "--dest",
            args.snapshot_dest,
            "--overwrite",
        ]
        if args.snapshot_include_untracked:
            snapshot_args.append("--include-untracked")
        if args.snapshot_init_git:
            snapshot_args.append("--init-git")
        steps.append(
            (
                "public_snapshot",
                _python_command(
                    args,
                    "scripts/maintenance/export_public_snapshot.py",
                    snapshot_args,
                ),
            )
        )

    return steps


def _run_step(repo_root: Path, name: str, command: List[str], dry_run: bool) -> StepResult:
    started = _now_utc()
    start_t = time.perf_counter()
    if dry_run:
        finished = _now_utc()
        return StepResult(
            name=name,
            command=command,
            status="planned",
            returncode=None,
            started_at_utc=_isoformat(started),
            finished_at_utc=_isoformat(finished),
            duration_sec=round(time.perf_counter() - start_t, 6),
        )

    completed = subprocess.run(
        command,
        cwd=repo_root,
        check=False,
    )
    finished = _now_utc()
    status = "passed" if completed.returncode == 0 else "failed"
    return StepResult(
        name=name,
        command=command,
        status=status,
        returncode=int(completed.returncode),
        started_at_utc=_isoformat(started),
        finished_at_utc=_isoformat(finished),
        duration_sec=round(time.perf_counter() - start_t, 6),
        error=None if completed.returncode == 0 else f"command exited with {completed.returncode}",
    )


def _artifact_hashes(args: argparse.Namespace) -> Dict[str, Dict[str, Any]]:
    suite_dir = Path(args.results_root) / args.suite
    snapshot_report = Path(args.snapshot_dest) / "PUBLIC_EXPORT_REPORT.json"
    candidates = {
        "stats_gate": suite_dir / "stats_gate.json",
        "seed_manifest": suite_dir / "seed_manifest.json",
        "aggregate_summary_csv": suite_dir / "aggregate_summary.csv",
        "experiments_csv": suite_dir / "experiments.csv",
        "bundle": Path(args.bundle_path),
        "bundle_verify_report": Path(args.verify_report),
        "public_snapshot_report": snapshot_report,
    }
    payload: Dict[str, Dict[str, Any]] = {}
    for key, path in candidates.items():
        record: Dict[str, Any] = {"path": str(path), "exists": path.exists()}
        if path.exists() and path.is_file():
            record["sha256"] = _sha256_file(path)
            record["bytes"] = int(path.stat().st_size)
        payload[key] = record
    return payload


def _default_report_paths(repo_root: Path) -> tuple[Path, Path]:
    stamp = _now_utc().strftime("%Y%m%dT%H%M%SZ")
    json_path = repo_root / "results" / "artifacts" / f"FLAGSHIP_FREEZE_REPORT_{stamp}.json"
    md_path = repo_root / "results" / "artifacts" / f"FLAGSHIP_FREEZE_REPORT_{stamp}.md"
    return json_path, md_path


def _render_markdown_report(report: Dict[str, Any]) -> str:
    git_info = report.get("git", {})
    suite = report.get("suite")
    status = report.get("status")
    lines: List[str] = []
    lines.append("# FLAGSHIP_FREEZE_REPORT")
    lines.append("")
    lines.append(f"- generated_at_utc: `{report.get('generated_at_utc')}`")
    lines.append(f"- status: `{status}`")
    lines.append(f"- dry_run: `{report.get('dry_run')}`")
    lines.append(f"- suite: `{suite}`")
    lines.append(f"- config: `{report.get('config')}`")
    lines.append(f"- runner: `{report.get('runner')}`")
    lines.append(f"- git_branch: `{git_info.get('branch')}`")
    lines.append(f"- git_commit: `{git_info.get('commit')}`")
    lines.append(f"- git_dirty: `{git_info.get('dirty')}`")
    lines.append(f"- git_dirty_count: `{git_info.get('dirty_count')}`")
    if git_info.get("dirty_entries_preview"):
        lines.append("- git_dirty_preview:")
        for item in git_info["dirty_entries_preview"]:
            lines.append(f"  - `{item}`")
    if report.get("preflight_error"):
        lines.append(f"- preflight_error: `{report['preflight_error']}`")

    lines.append("")
    lines.append("## Steps")
    for step in report.get("steps", []):
        cmd = " ".join(shlex.quote(part) for part in step.get("command", []))
        lines.append(
            f"- `{step.get('name')}`: status=`{step.get('status')}` "
            f"returncode=`{step.get('returncode')}` duration_sec=`{step.get('duration_sec')}`"
        )
        lines.append(f"  - cmd: `{cmd}`")
        if step.get("error"):
            lines.append(f"  - error: `{step.get('error')}`")

    lines.append("")
    lines.append("## Artifact Hashes")
    for key, record in report.get("artifact_hashes", {}).items():
        lines.append(
            f"- `{key}`: exists=`{record.get('exists')}` path=`{record.get('path')}`"
        )
        if record.get("sha256"):
            lines.append(f"  - sha256: `{record.get('sha256')}`")
        if record.get("bytes") is not None:
            lines.append(f"  - bytes: `{record.get('bytes')}`")

    lines.append("")
    lines.append("## Notes")
    lines.append("- Freeze final idealnya dijalankan pada commit private bersih (git_dirty=false).")
    lines.append("- Jika run terputus, ulangi command wrapper yang sama; simulate step memakai `--resume` secara default.")
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    repo_root = Path(__file__).resolve().parents[2]

    report_json_path, report_md_path = _default_report_paths(repo_root)
    if args.report_json:
        report_json_path = (repo_root / args.report_json).resolve()
    if args.report_md:
        report_md_path = (repo_root / args.report_md).resolve()
    elif args.report_json:
        report_md_path = report_json_path.with_suffix(".md")

    report_json_path.parent.mkdir(parents=True, exist_ok=True)
    report_md_path.parent.mkdir(parents=True, exist_ok=True)

    git_info = _git_info(repo_root)
    report: Dict[str, Any] = {
        "generated_at_utc": _isoformat(_now_utc()),
        "repo_root": str(repo_root),
        "suite": args.suite,
        "config": args.config,
        "results_root": args.results_root,
        "runner": args.runner,
        "python_bin": args.python_bin,
        "resume": bool(args.resume),
        "allow_dirty": bool(args.allow_dirty),
        "dry_run": bool(args.dry_run),
        "git": git_info,
        "steps": [],
        "status": "pending",
        "preflight_error": None,
    }

    if git_info["dirty"] and not args.allow_dirty:
        report["status"] = "preflight_failed"
        report["preflight_error"] = (
            "git worktree is dirty; commit/stash changes before final freeze "
            "(or rerun with --allow-dirty for exploratory/preflight runs)"
        )
        report["artifact_hashes"] = _artifact_hashes(args)
        report_json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        report_md_path.write_text(_render_markdown_report(report), encoding="utf-8")
        print(report["preflight_error"])
        print(f"JSON report: {report_json_path}")
        print(f"MD report:   {report_md_path}")
        return 1

    exit_code = 0
    for name, command in _build_steps(args):
        step_result = _run_step(repo_root, name, command, dry_run=args.dry_run)
        report["steps"].append(asdict(step_result))
        if step_result.status == "failed":
            exit_code = int(step_result.returncode or 1)
            break

    report["artifact_hashes"] = _artifact_hashes(args)
    if args.dry_run and exit_code == 0:
        report["status"] = "planned"
    elif exit_code == 0:
        report["status"] = "passed"
    else:
        report["status"] = "failed"

    report_json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report_md_path.write_text(_render_markdown_report(report), encoding="utf-8")

    print(f"JSON report: {report_json_path}")
    print(f"MD report:   {report_md_path}")
    if report["status"] != "passed":
        print(f"status={report['status']}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
