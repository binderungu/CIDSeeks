import logging
from typing import Any, TYPE_CHECKING, Dict, Optional
from ...utils.perf import metric_logger

if TYPE_CHECKING:
    from ...core.node import Node
    from ...core.message import Message

class ChallengeManager:
    """Manages the initiation and handling of trust challenges (Basic, Advanced, Final).

    This class is responsible for deciding when to issue a challenge,
    generating the appropriate challenge message based on the level,
    sending the challenge, and potentially processing the response
    (although response processing might also involve the TrustManager).
    """

    def __init__(self, node: 'Node'):
        self.node = node
        self.logger = logging.getLogger(f"ChallengeManager-Node{self.node.id}")
        self.rng = getattr(node, 'rng', None)

    def maybe_initiate_challenge(self, target_node: 'Node') -> Optional['Message']:
        """Decides if a challenge should be sent to the target node and initiates it."""
        if self._should_challenge(target_node):
            challenge_level = self._determine_challenge_level(target_node)
            challenge_message_data = self._generate_challenge(target_node, challenge_level)
            if challenge_message_data:
                # Assuming send_message needs the payload dictionary
                # Log PMFA point: challenge messages are is_challenge=True with zero delay and DMPO N/A
                try:
                    metric_logger.log_privacy_event({
                        'delay_ms': 0.0,
                        'payload_size': len(str(challenge_message_data).encode('utf-8')),
                        'variant_id': None,
                        'is_challenge': True,
                        'dmpo_enabled': False,
                        'sender_id': self.node.id,
                        'receiver_id': target_node.id,
                        'iteration': getattr(self.node, 'current_iteration', 0),
                        'message_id': challenge_message_data.get('id'),
                        'alarm_hash': None,
                        'event_scope': 'internal',
                    })
                except Exception:
                    self.logger.debug("Challenge privacy logging failed", exc_info=True)
                send_message = getattr(self.node, "send_message", None)
                if callable(send_message):
                    send_message(target_node.id, challenge_message_data)
                    self.logger.debug(f"Initiated {challenge_level} challenge to Node {target_node.id}")
                else:
                    self.logger.debug(
                        "Node %s has no send_message API; challenge payload generated but not sent.",
                        self.node.id,
                    )
        return None  # Message creation/sending is handled via node.send_message.

    def _should_challenge(self, target_node: 'Node') -> bool:
        """Determines if a challenge is warranted for the target node."""
        # Current default: probabilistic trigger with seeded RNG.
        if self.rng:
            return self.rng.random() < 0.1
        return False

    def _determine_challenge_level(self, target_node: 'Node') -> str:
        """Determines the appropriate challenge level (basic, advanced, final)."""
        # Current default: choose challenge level uniformly via node RNG.
        if self.rng:
            return self.rng.choice(['basic', 'advanced', 'final'])
        return 'basic'

    def _generate_challenge(self, target_node: 'Node', level: str) -> Optional[Dict[str, Any]]:
        """Generates the challenge message content (payload dictionary) based on the level."""
        challenge_data = {
            'type': 'challenge',
            'level': level,
            'timestamp': self.node.env.now,
            'source_node': self.node.id,
        }
        # Basic challenge includes nonce to avoid replay-like response reuse.
        if level == 'basic':
             challenge_data['nonce'] = self._generate_nonce()

        self.logger.debug(f"Generated {level} challenge payload for Node {target_node.id}")
        return challenge_data

    def handle_challenge_response(self, response_message: 'Message'):
        """Processes the response received for a challenge."""
        # Response validation and trust update are handled by trust pipeline modules.
        response_data = response_message.data
        source_id = response_message.source_node
        level = response_data.get('level')
        self.logger.debug(f"Received {level} challenge response from {source_id}: {response_data}")

    def _generate_nonce(self, length: int = 16) -> str:
        """Generates a random nonce."""
        if self.rng:
            return "".join(self.rng.choice("0123456789abcdef") for _ in range(length * 2))
        return "0" * (length * 2)
