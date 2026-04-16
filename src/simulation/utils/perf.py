"""Light-weight global performance logger for runtime metrics.

Do NOT import heavy libs here; only store primitives.  One instance (`metric_logger`)
is created and reused across modules.
"""
from __future__ import annotations

from typing import List, Dict, Any, Optional

class MetricLogger:
    def __init__(self):
        # Detection latency (ticks) list
        self.latencies: List[float] = []
        # Blockchain ledger sizes in bytes (sampled)
        self.ledger_sizes: List[int] = []
        # Block commit latencies (seconds simulated / real time depending on hook)
        self.block_commit_latencies: List[float] = []
        # PMFA/DMPO privacy logs – list of minimal metadata dicts
        self.privacy_pmfa_logs: List[Dict[str, Any]] = []
        # Message-level telemetry for overhead analysis
        self.message_events: List[Dict[str, Any]] = []
        # Collaboration latencies recorded per round (ms)
        self.collab_latency: Dict[int, List[float]] = {}

    # -- helpers -------------------------------------------------------------
    def reset(self):
        self.latencies.clear()
        self.ledger_sizes.clear()
        self.block_commit_latencies.clear()
        self.privacy_pmfa_logs.clear()
        self.message_events.clear()
        self.collab_latency.clear()

    def log_privacy_event(self, event: Dict[str, Any]) -> None:
        """Append a PMFA/DMPO privacy event.
        Expected keys: delay_ms, payload_size, variant_id, is_challenge, dmpo_enabled,
        sender_id, receiver_id, iteration, message_id, alarm_hash
        """
        event.setdefault("event_scope", "wire")
        self.privacy_pmfa_logs.append(event)

    def log_message(
        self,
        *,
        iteration: int,
        sender_id: int,
        receiver_id: int,
        message_type: str,
        direction: str,
        payload_bytes: int,
        latency_ms: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record a message exchange for overhead measurements."""
        record = {
            'iteration': int(iteration),
            'sender_id': int(sender_id),
            'receiver_id': int(receiver_id),
            'message_type': message_type,
            'direction': direction,
            'payload_bytes': int(max(0, payload_bytes)),
        }
        if latency_ms is not None:
            record['latency_ms'] = float(latency_ms)
            self.collab_latency.setdefault(int(iteration), []).append(float(latency_ms))
        if metadata:
            record.update(metadata)
        self.message_events.append(record)

    def snapshot(self) -> Dict[str, Any]:
        """Return a shallow copy snapshot of collected runtime metrics."""
        return {
            'latencies': list(self.latencies),
            'ledger_sizes': list(self.ledger_sizes),
            'block_commit_latencies': list(self.block_commit_latencies),
            'privacy_pmfa_logs': list(self.privacy_pmfa_logs),
            'message_events': list(self.message_events),
            'collab_latency': {rnd: list(vals) for rnd, vals in self.collab_latency.items()},
        }

# Global singleton
metric_logger = MetricLogger()
