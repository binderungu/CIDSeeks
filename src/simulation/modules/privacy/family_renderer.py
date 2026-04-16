from __future__ import annotations

from typing import Any, Dict


_SIZE_LIMITS = {
    "small": 32,
    "medium": 96,
    "large": 160,
}


def _normalize_message(message: str) -> str:
    return " ".join(str(message).strip().split())


def _transform_message(message: str, family_index: int) -> str:
    slot = family_index % 4
    if slot == 0:
        return message.replace("_", " ")
    if slot == 1:
        return message.replace("_", "-")
    if slot == 2:
        return message.replace("_", "/").lower()
    return message.replace("_", ".")


def render_family_variant(original_alarm: Dict[str, Any], family_index: int, size_bucket: str) -> Dict[str, Any]:
    msg = _normalize_message(str(original_alarm.get("original_message_body", "")))
    msg = _transform_message(msg, family_index)
    limit = _SIZE_LIMITS.get(size_bucket, _SIZE_LIMITS["medium"])
    msg = msg[:limit]

    return {
        "current_destination_ip": original_alarm.get("original_destination_ip", "0.0.0.0"),
        "current_port": original_alarm.get("original_destination_port", "any"),
        "current_msg": msg,
    }
