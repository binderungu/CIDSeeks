from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from typing import Any, Dict, Optional


def _default_timestamp() -> float:
    return datetime.now().timestamp()


def _message_prefix(message_type: str) -> str:
    lowered = str(message_type or "message").strip().lower()
    return lowered.replace(" ", "_") or "message"


@dataclass
class Message:
    """Base class for protocol and alarm messages in the simulation."""

    id: str
    type: str
    source_node: str
    target_node: str
    data: Dict[str, Any]
    timestamp: Optional[float] = None
    iteration: Optional[int] = None
    correlation_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.timestamp is None:
            self.timestamp = _default_timestamp()
        self.source_node = str(self.source_node)
        self.target_node = str(self.target_node)
        if not isinstance(self.data, dict):
            self.data = {"value": self.data}

    def to_payload(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "source_node": self.source_node,
            "target_node": self.target_node,
            "data": dict(self.data),
            "timestamp": self.timestamp,
            "iteration": self.iteration,
            "correlation_id": self.correlation_id,
        }

    @property
    def payload_bytes(self) -> int:
        try:
            return len(json.dumps(self.to_payload(), sort_keys=True).encode("utf-8"))
        except Exception:
            return len(str(self.to_payload()).encode("utf-8"))


class Alarm(Message):
    """Alarm message for reporting suspicious behavior."""

    def __init__(
        self,
        source_node: str,
        target_node: str,
        data: Dict[str, Any],
        *,
        message_id: Optional[str] = None,
        timestamp: Optional[float] = None,
        iteration: Optional[int] = None,
        correlation_id: Optional[str] = None,
    ):
        super().__init__(
            id=message_id or f"alarm_{_default_timestamp()}",
            type="alarm",
            source_node=source_node,
            target_node=target_node,
            data=dict(data),
            timestamp=timestamp,
            iteration=iteration,
            correlation_id=correlation_id,
        )


class Challenge(Message):
    """Challenge message for trust verification."""

    def __init__(
        self,
        source_node: str,
        target_node: str,
        data: Dict[str, Any],
        *,
        message_id: Optional[str] = None,
        timestamp: Optional[float] = None,
        iteration: Optional[int] = None,
        correlation_id: Optional[str] = None,
    ):
        payload = dict(data)
        payload.setdefault("msg_kind", "CHALLENGE")
        super().__init__(
            id=message_id or f"challenge_{_default_timestamp()}",
            type="challenge",
            source_node=source_node,
            target_node=target_node,
            data=payload,
            timestamp=timestamp,
            iteration=iteration,
            correlation_id=correlation_id,
        )


class TrustRequest(Message):
    """Explicit REQUEST protocol artifact for trust evaluation."""

    def __init__(
        self,
        source_node: str,
        target_node: str,
        *,
        alarm_set_id: str,
        data: Optional[Dict[str, Any]] = None,
        message_id: Optional[str] = None,
        timestamp: Optional[float] = None,
        iteration: Optional[int] = None,
        correlation_id: Optional[str] = None,
    ):
        payload = dict(data or {})
        payload.setdefault("msg_kind", "REQUEST")
        payload["alarm_set_id"] = alarm_set_id
        super().__init__(
            id=message_id or f"request_{_default_timestamp()}",
            type="trust_request",
            source_node=source_node,
            target_node=target_node,
            data=payload,
            timestamp=timestamp,
            iteration=iteration,
            correlation_id=correlation_id,
        )


class TrustResponse(Message):
    """Explicit response artifact for trust requests or challenges."""

    def __init__(
        self,
        source_node: str,
        target_node: str,
        *,
        msg_kind: str,
        response_value: float,
        flags: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        message_id: Optional[str] = None,
        timestamp: Optional[float] = None,
        iteration: Optional[int] = None,
        correlation_id: Optional[str] = None,
    ):
        resolved_kind = str(msg_kind or "REQUEST").upper()
        message_type = "challenge_response" if resolved_kind.startswith("CHALLENGE") else "request_response"
        payload = dict(data or {})
        payload["msg_kind"] = resolved_kind
        payload["response_value"] = float(response_value)
        payload["flags"] = dict(flags or {})
        super().__init__(
            id=message_id or f"{_message_prefix(message_type)}_{_default_timestamp()}",
            type=message_type,
            source_node=source_node,
            target_node=target_node,
            data=payload,
            timestamp=timestamp,
            iteration=iteration,
            correlation_id=correlation_id,
        )
