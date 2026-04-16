from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List


class PrivacyStrategy(ABC):
    """Interface for privacy alarm rendering strategies."""

    strategy_name = "base"

    def __init__(self, module: Any):
        self.module = module

    @abstractmethod
    def generate_alarm_variations(
        self,
        original_alarm: Dict[str, Any],
        *,
        recipient_id: int | None = None,
        policy: Any = None,
        include_cover: bool = True,
    ) -> List[Dict[str, Any]]:
        """Generate alarm dissemination payloads."""
        raise NotImplementedError
