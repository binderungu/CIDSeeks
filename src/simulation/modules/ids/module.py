import logging
import random
from typing import TYPE_CHECKING, Optional, Dict, Any

if TYPE_CHECKING:
    from ...core.node import Node

class IdsModule:
    """Handles internal attack detection for a node.

    Generates alarms probabilistically based on config, using deterministic RNG.
    """

    def __init__(self, node: 'Node'):
        self.node = node
        self.logger = logging.getLogger(f"IdsModule-Node{self.node.id}")
        self.rng = getattr(self.node, 'rng', None) or random.Random(int(getattr(self.node, 'id', 0) or 0))
        # self.detection_probability = 0.3 # No longer used here

    def detect_attack(self) -> Optional[Dict[str, Any]]:
        """Generate an alarm with probability configured in feature_config."""
        probability = float(self.node.feature_config.get('detection_event_probability', 0.05))
        if self.rng.random() >= probability:
            return None

        self.node.alarm_counter += 1
        alarm_id = f"alarm_{self.node.id}_{self.node.current_iteration}_{self.node.alarm_counter}"
        confidence = max(0.0, min(1.0, self.rng.random()))
        alarm = {
            'message_id': alarm_id,
            'timestamp': float(getattr(self.node.env, 'now', 0)),
            'analyzer_node_id': self.node.id,
            'classification_text': 'suspicious_activity',
            'assessment': {'confidence': confidence},
            'original_destination_ip': f"10.0.{self.node.id % 255}.1",
            'original_destination_port': int(1024 + (self.node.id % 1000)),
            'original_message_body': f"alert_{alarm_id}",
        }
        self.logger.debug("Generated alarm %s with confidence %.3f", alarm_id, confidence)
        return alarm
