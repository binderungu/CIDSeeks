"""
Lightweight interactive graph viewer process.

Usage:
    python -m src.ui.tools.graph_viewer --html /abs/path/to/graph.html

Behavior:
    - If pywebview is available, open the HTML via a WebView window
    - Otherwise, fallback to system browser

This tool is optional; main app will gracefully fallback if launch fails.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
import webbrowser


def _open_with_pywebview(uri: str) -> None:
    try:
        import webview  # type: ignore
    except Exception as e:  # pragma: no cover – optional dep
        raise RuntimeError(f"pywebview not available: {e}")

    try:
        webview.create_window("CIDSeeks Graph", uri)
        webview.start()
    except Exception as e:
        raise RuntimeError(f"pywebview failed to open: {e}")


def _fallback_browser(uri: str) -> None:
    webbrowser.open_new_tab(uri)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CIDSeeks Graph Viewer")
    parser.add_argument("--html", required=True, help="Absolute path to HTML file")
    args = parser.parse_args(argv)

    html_path = Path(args.html).resolve()
    if not html_path.exists():
        print(f"Error: HTML not found: {html_path}")
        return 2

    uri = html_path.as_uri()
    try:
        _open_with_pywebview(uri)
    except Exception:
        _fallback_browser(uri)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


