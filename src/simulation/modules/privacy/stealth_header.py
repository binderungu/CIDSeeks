from __future__ import annotations

import hashlib
import json


def make_stealth_header(
    *,
    base_salt: bytes,
    sender_id: int,
    recipient_id: int | None,
    policy_id: str,
    family_token: str,
    epoch: int,
    is_cover: bool = False,
) -> str:
    payload = {
        "sender_id": int(sender_id),
        "recipient_id": int(recipient_id) if recipient_id is not None else -1,
        "policy_id": str(policy_id),
        "family_token": str(family_token),
        "epoch": int(epoch),
        "is_cover": int(bool(is_cover)),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(base_salt + encoded).hexdigest()
    return f"sh1:{digest}"
