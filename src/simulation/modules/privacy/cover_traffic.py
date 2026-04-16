from __future__ import annotations

from typing import Dict, Any, List


def _cover_body(seed_message: str, index: int) -> str:
    base = str(seed_message or "cover")
    prefix = base.split()[0] if base else "cover"
    return f"{prefix} sync frame {index}"


def build_cover_messages(rate: float, baseline_payload: Dict[str, Any], *, count_hint: int = 1) -> List[Dict[str, Any]]:
    if rate <= 0:
        return []
    count = max(1, int(round(max(1, count_hint) * min(1.0, rate))))
    return [
        {
            "is_cover": True,
            "current_destination_ip": baseline_payload.get("current_destination_ip", "0.0.0.0"),
            "current_port": "any",
            "current_msg": _cover_body(baseline_payload.get("current_msg", "<cover>"), idx + 1),
        }
        for idx in range(count)
    ]
