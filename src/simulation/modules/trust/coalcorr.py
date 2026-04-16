from __future__ import annotations

from collections import defaultdict
from typing import DefaultDict


class CoalitionCorrelationTracker:
    """Context-conditioned residual coordination score.

    CoalCorr captures whether a peer keeps showing suspicious behavior in a
    context where the residual coordination score of the surrounding peers stays
    lower. This operationalizes the coalition-aware correlation term in the
    paper without pushing attack-specific logic into the calculator.
    """

    def __init__(self) -> None:
        # context -> peer -> [scores]
        self._ctx_peer_scores: DefaultDict[str, DefaultDict[int, list[float]]] = defaultdict(lambda: defaultdict(list))

    def observe(self, peer_id: int, context_bin: str, suspicious_score: float) -> None:
        score = max(0.0, min(1.0, float(suspicious_score)))
        self._ctx_peer_scores[str(context_bin)][int(peer_id)].append(score)

    def score(self, peer_id: int, context_bin: str) -> float:
        ctx = self._ctx_peer_scores.get(str(context_bin), {})
        peer_scores = ctx.get(int(peer_id), [])
        if not peer_scores:
            return 0.0
        peer_mean = sum(peer_scores) / len(peer_scores)
        others = []
        for pid, vals in ctx.items():
            if pid == int(peer_id) or not vals:
                continue
            others.append(sum(vals) / len(vals))
        if not others:
            return 0.0
        residual = max(0.0, peer_mean - (sum(others) / len(others)))
        return max(0.0, min(1.0, residual))
