from __future__ import annotations

from collections import defaultdict
from typing import DefaultDict, Dict, Optional, Tuple


class FIBDTracker:
    """Family-conditioned inter-behavior divergence tracker.

    FIBD operationalizes the paper narrative that a selective insider may keep
    per-message trust superficially stable while responding differently across
    hidden-equivalent message families. The tracker therefore stores a compact
    behavior signature per family and measures cross-family distribution drift
    inside the same protocol context.
    """

    def __init__(self) -> None:
        # peer -> context -> family -> response_tuple -> count
        self._counts: DefaultDict[int, DefaultDict[str, DefaultDict[str, DefaultDict[Tuple[str, int, str, str, str], int]]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
        )

    @staticmethod
    def _response_tuple(
        response_value: float,
        supportive_action: bool,
        *,
        proof_valid: Optional[bool] = None,
        pmfa_predicted_kind: Optional[str] = None,
        pmfa_response: Optional[str] = None,
    ) -> Tuple[str, int, str, str, str]:
        rv = max(0.0, min(1.0, float(response_value)))
        if rv < 0.33:
            value_bucket = 'low'
        elif rv < 0.66:
            value_bucket = 'mid'
        else:
            value_bucket = 'high'

        if proof_valid is True:
            proof_bucket = 'valid'
        elif proof_valid is False:
            proof_bucket = 'invalid'
        else:
            proof_bucket = 'none'

        predicted_bucket = str(pmfa_predicted_kind or 'unknown').strip().lower()
        response_bucket = str(pmfa_response or 'na').strip().lower()
        return (
            value_bucket,
            1 if supportive_action else 0,
            proof_bucket,
            predicted_bucket,
            response_bucket,
        )

    def observe(
        self,
        peer_id: int,
        context_bin: str,
        family_id: str,
        response_value: float,
        supportive_action: bool,
        *,
        proof_valid: Optional[bool] = None,
        pmfa_predicted_kind: Optional[str] = None,
        pmfa_response: Optional[str] = None,
    ) -> None:
        key = self._response_tuple(
            response_value=response_value,
            supportive_action=supportive_action,
            proof_valid=proof_valid,
            pmfa_predicted_kind=pmfa_predicted_kind,
            pmfa_response=pmfa_response,
        )
        self._counts[int(peer_id)][str(context_bin)][str(family_id)][key] += 1

    @staticmethod
    def _normalized(counter: Dict[Tuple[str, int, str, str, str], int]) -> Dict[Tuple[str, int, str, str, str], float]:
        total = float(sum(counter.values()))
        if total <= 0:
            return {}
        return {k: v / total for k, v in counter.items()}

    @staticmethod
    def _l1_distance(
        a: Dict[Tuple[str, int, str, str, str], float],
        b: Dict[Tuple[str, int, str, str, str], float],
    ) -> float:
        keys = set(a.keys()) | set(b.keys())
        if not keys:
            return 0.0
        return sum(abs(a.get(k, 0.0) - b.get(k, 0.0)) for k in keys) / 2.0

    def score(self, peer_id: int, context_bin: str) -> float:
        family_buckets = self._counts.get(int(peer_id), {}).get(str(context_bin), {})
        if len(family_buckets) < 2:
            return 0.0
        fams = list(family_buckets.items())
        distances = []
        for i in range(len(fams)):
            for j in range(i + 1, len(fams)):
                _, ci = fams[i]
                _, cj = fams[j]
                distances.append(self._l1_distance(self._normalized(ci), self._normalized(cj)))
        if not distances:
            return 0.0
        return max(0.0, min(1.0, sum(distances) / len(distances)))
