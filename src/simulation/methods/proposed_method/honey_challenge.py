from __future__ import annotations

from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .three_level_challenge import ThreeLevelChallengeMethod

if TYPE_CHECKING:
    from ...core.node import Node
    from ...core.message import Message


class HoneyChallengeMethod(ThreeLevelChallengeMethod):
    """Variant of the 3-level challenge method with Honey-Challenge extensions.

    The implementation reuses the core trust flow but tags alarms and challenges
    with honey metadata so downstream analytics can differentiate this variant.
    """

    def __init__(self, method_name: str = "honey", config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(method_name=method_name, config=config or {})
        # Ensure method name is stored consistently for loggers/analytics.
        self.method_name = method_name
        self.logger.info("Initialized Honey Challenge method")

    def process_alarm(self, alarm: Dict[str, Any], node: "Node", **kwargs: Any) -> List[Dict[str, Any]]:
        """Obfuscate alarms and mark them so evaluators know honey mode is active."""
        variations = super().process_alarm(alarm, node, **kwargs)
        for entry in variations:
            entry.setdefault("metadata", {})
            entry["metadata"]["honey_challenge"] = True
        return variations

    def handle_challenge(self, challenge: "Message", node: "Node", **kwargs: Any) -> Optional[Dict[str, Any]]:
        """Augment challenge responses with honey identifiers."""
        response = super().handle_challenge(challenge, node, **kwargs)
        if isinstance(response, dict):
            response.setdefault("metadata", {})
            response["metadata"]["honey_challenge"] = True
        return response

    def initialize_node(self, node: "Node") -> None:
        """Attach honey-specific flags to nodes before simulation starts."""
        super().initialize_node(node)
        setattr(node, "honey_challenge_enabled", True)
        if hasattr(node, "feature_config"):
            honey_flags = node.feature_config.setdefault("honey", {})
            honey_flags["enabled"] = True
