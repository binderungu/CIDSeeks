from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class Observation:
    round_id: int
    src_id: int
    dst_id: int
    msg_kind: str
    alarm_set_id: str
    true_label: Optional[float] = None
    response_value: Optional[float] = None
    response_latency: Optional[float] = None
    challenge_tier: Optional[str] = None
    challenge_payload: Optional[Dict[str, Any]] = None
    flags: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.msg_kind:
            self.msg_kind = str(self.msg_kind).upper()
        if self.challenge_tier:
            self.challenge_tier = str(self.challenge_tier).lower()

    @property
    def is_challenge(self) -> bool:
        return self.msg_kind.startswith("CHALLENGE")

    @property
    def is_request(self) -> bool:
        return self.msg_kind == "REQUEST"
