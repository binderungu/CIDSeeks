from __future__ import annotations

import hashlib


def scoped_alias(base_salt: bytes, sender_id: int, recipient_id: int | None, epoch: int, value: str) -> str:
    scoped = b"|".join(
        [
            base_salt,
            str(sender_id).encode("utf-8"),
            str(recipient_id if recipient_id is not None else -1).encode("utf-8"),
            str(epoch).encode("utf-8"),
            str(value).encode("utf-8"),
        ]
    )
    return hashlib.sha256(scoped).hexdigest()
