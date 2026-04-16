from __future__ import annotations

from collections import defaultdict
from typing import DefaultDict, Optional


class SplitVerifierTracker:
    """Tracks verifier reconstruction failures attributable to peers.

    The tracker keeps both overall and per-tier failure rates so the advanced
    tier can consume a stable historical score while the final tier can focus on
    verifier-share reconstruction failures from attestation-heavy challenges.
    """

    def __init__(self) -> None:
        self._ok: DefaultDict[int, int] = defaultdict(int)
        self._fail: DefaultDict[int, int] = defaultdict(int)
        self._tier_ok: DefaultDict[str, DefaultDict[int, int]] = defaultdict(lambda: defaultdict(int))
        self._tier_fail: DefaultDict[str, DefaultDict[int, int]] = defaultdict(lambda: defaultdict(int))

    def observe(self, peer_id: int, reconstruction_ok: bool, *, tier: Optional[str] = None) -> None:
        pid = int(peer_id)
        if reconstruction_ok:
            self._ok[pid] += 1
        else:
            self._fail[pid] += 1
        if tier is not None:
            tier_key = str(tier).strip().lower() or "unknown"
            if reconstruction_ok:
                self._tier_ok[tier_key][pid] += 1
            else:
                self._tier_fail[tier_key][pid] += 1

    def fail_rate(self, peer_id: int, *, tier: Optional[str] = None) -> float:
        pid = int(peer_id)
        if tier is None:
            total = self._ok[pid] + self._fail[pid]
            if total <= 0:
                return 0.0
            return self._fail[pid] / total

        tier_key = str(tier).strip().lower() or "unknown"
        total = self._tier_ok[tier_key][pid] + self._tier_fail[tier_key][pid]
        if total <= 0:
            return 0.0
        return self._tier_fail[tier_key][pid] / total
