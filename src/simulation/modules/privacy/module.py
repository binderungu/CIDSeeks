import logging
import random
import hashlib
import json
from typing import TYPE_CHECKING, Dict, Any, List, Optional
from ...utils.perf import metric_logger

if TYPE_CHECKING:
    from ...core.node import Node

class PrivacyModule:
    """Handles privacy mechanisms based on user's journal description.
    
    Generates variations of an original alarm by obfuscating IP/port/message, 
    assigns a common hash ID and unique sequence numbers to variations.
    """

    def __init__(self, node: 'Node'):
        self.node = node
        self.logger = logging.getLogger(f"PrivacyModule-Node{self.node.id}")
        node_rng = getattr(node, 'rng', None)
        self.rng = node_rng if node_rng is not None else random.Random(int(getattr(node, 'id', 0) or 0))
        feature_cfg = getattr(node, 'feature_config', {}) or {}
        salt = feature_cfg.get('privacy_salt')
        if salt is None:
            # Deterministic fallback derived from node id (engine should override with global salt)
            salt = f"cidseeks-salt-{self.node.id}"
        if isinstance(salt, bytes):
            self._salt = salt
        else:
            self._salt = str(salt).encode('utf-8')
        self._prefix_bits = int(feature_cfg.get('privacy_prefix_bits', 24) or 24)
        self._k_anonymity = int(feature_cfg.get('privacy_k_anonymity', 16) or 16)

    def _calculate_alarm_hash(self, original_content: Dict) -> str:
        """Calculates a SHA256 hash based on the original alarm content."""
        # Create a stable string representation (e.g., sorted JSON)
        try:
            # Sort keys for consistent hashing
            content_str = json.dumps(original_content, sort_keys=True)
            return hashlib.sha256(content_str.encode('utf-8')).hexdigest()
        except Exception as e:
            self.logger.error(f"Error creating hash for alarm content: {e}")
            # Fallback hash if serialization fails
            return hashlib.sha256(str(original_content).encode('utf-8')).hexdigest()

    @staticmethod
    def _ip_to_int(ip_address: str) -> Optional[int]:
        try:
            parts = [int(p) for p in ip_address.split('.')]
        except Exception:
            return None
        if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
            return None
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

    @staticmethod
    def _int_to_ip(value: int) -> str:
        value = int(value) & 0xFFFFFFFF
        return '.'.join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))

    def _prefix_preserving_hash(self, ip_address: str) -> str:
        """Prefix-preserving hash (simulation-friendly)."""
        ip_int = self._ip_to_int(ip_address)
        if ip_int is None:
            return "0.0.0.0"

        prefix_bits = max(0, min(32, int(self._prefix_bits)))
        host_bits = 32 - prefix_bits
        if prefix_bits == 0:
            prefix_mask = 0
        else:
            prefix_mask = (0xFFFFFFFF << host_bits) & 0xFFFFFFFF

        prefix_val = ip_int & prefix_mask
        host_val = ip_int & (~prefix_mask & 0xFFFFFFFF)

        # k-anonymity on host part (bucket by size k)
        k = max(1, min(256, int(self._k_anonymity)))
        if host_bits > 0:
            host_bucket = (host_val // k) * k
        else:
            host_bucket = 0

        prefix_bytes = prefix_val.to_bytes(4, byteorder='big') + prefix_bits.to_bytes(1, byteorder='big')
        prefix_hash = hashlib.sha256(self._salt + prefix_bytes).digest()
        pseudo_prefix = int.from_bytes(prefix_hash, byteorder='big') & prefix_mask

        host_bytes = host_bucket.to_bytes(4, byteorder='big') + prefix_val.to_bytes(4, byteorder='big')
        host_hash = hashlib.sha256(self._salt + host_bytes + b'host').digest()
        pseudo_host = int.from_bytes(host_hash, byteorder='big')
        if host_bits > 0:
            pseudo_host &= (1 << host_bits) - 1
        else:
            pseudo_host = 0

        return self._int_to_ip(pseudo_prefix | pseudo_host)

    def _obfuscate_ip(self, ip_address: str) -> str:
        """Deterministic prefix-preserving obfuscation."""
        if not isinstance(ip_address, str):
            return "0.0.0.0"
        return self._prefix_preserving_hash(ip_address)

    def _obfuscate_port(self, port: Any) -> str:
        """Example port obfuscation: Returns 'any'"""
        return "any"

    def _obfuscate_msg(self, msg: str) -> str:
        """Example message obfuscation: Adds random noise/tag."""
        if not isinstance(msg, str):
             return "<obfuscated_non_string>"
        return f"{msg} [var:{self.rng.randint(100,999)}]"

    def _variant_id_hash(self, alarm_hash: str, variant_index: int) -> str:
        payload = f"{alarm_hash}:{variant_index}".encode('utf-8')
        return hashlib.sha256(self._salt + payload).hexdigest()

    def generate_alarm_variations(self, original_alarm: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generates multiple variations of the original alarm based on journal description."""
        variations = []
        
        # 1. Extract original content for hashing and as base for variations
        # We assume original_alarm contains the necessary 'original_*' fields
        original_content_for_hash = {
            k: v for k, v in original_alarm.items() 
            if k.startswith('original_') or k in ['timestamp', 'analyzer_node_id', 'classification_text']
        }
        original_alarm_hash = self._calculate_alarm_hash(original_content_for_hash)
        self.logger.debug(f"Generated original_alarm_hash: {original_alarm_hash[:8]}... for alarm {original_alarm.get('message_id')}")

        base_alarm = original_alarm.copy()
        base_alarm['original_alarm_hash'] = original_alarm_hash
        base_alarm['alarm_family_id'] = original_alarm_hash
        base_alarm['original_message_id'] = original_alarm.get('message_id')
        # Mark obfuscation feature flag (DMPO enabled)
        base_alarm['dmpo_enabled'] = True
        
        # 2. Create Variations (configurable count, default 3)
        variants_per_alarm = int(self.node.feature_config.get('variants_per_alarm', 3))
        variants_per_alarm = max(1, min(variants_per_alarm, 4))

        templates = [
            lambda: {
                'current_destination_ip': self._obfuscate_ip(original_alarm.get('original_destination_ip')),
                'current_port': original_alarm.get('original_destination_port'),
                'current_msg': original_alarm.get('original_message_body'),
            },
            lambda: {
                'current_destination_ip': self._obfuscate_ip(original_alarm.get('original_destination_ip')),
                'current_port': original_alarm.get('original_destination_port'),
                'current_msg': original_alarm.get('original_message_body'),
            },
            lambda: {
                'current_destination_ip': self._obfuscate_ip(original_alarm.get('original_destination_ip')),
                'current_port': self._obfuscate_port(original_alarm.get('original_destination_port')),
                'current_msg': original_alarm.get('original_message_body'),
            },
            lambda: {
                'current_destination_ip': self._obfuscate_ip(original_alarm.get('original_destination_ip')),
                'current_port': self._obfuscate_port(original_alarm.get('original_destination_port')),
                'current_msg': self._obfuscate_msg(original_alarm.get('original_message_body')),
            },
        ]

        for idx in range(variants_per_alarm):
            var = base_alarm.copy()
            var['variation_sequence_number'] = idx + 1
            var['variant_id_hash'] = self._variant_id_hash(original_alarm_hash, idx + 1)
            var['message_id'] = var['variant_id_hash']
            var.update(templates[idx]())
            variations.append(var)
        
        self.logger.info(f"Generated {len(variations)} variations for alarm {original_alarm.get('message_id')} with hash {original_alarm_hash[:8]}...")

        # Log PMFA/DMPO metadata for each variation (no delay known here; payload size known)
        try:
            for v in variations:
                payload_str = str({
                    'current_destination_ip': v.get('current_destination_ip'),
                    'current_port': v.get('current_port'),
                    'current_msg': v.get('current_msg'),
                })
                event = {
                    'delay_ms': None,  # will be filled on send path
                    'payload_size': len(payload_str.encode('utf-8')),
                    'variant_id': v.get('variation_sequence_number'),
                    'is_challenge': False,  # alarm is not a trust challenge message
                    'dmpo_enabled': True,
                    'sender_id': self.node.id,
                    'receiver_id': None,  # known when sending
                    'iteration': getattr(self.node, 'current_iteration', 0),
                    'message_id': v.get('message_id'),
                    'alarm_hash': original_alarm_hash,
                }
                metric_logger.log_privacy_event(event)
        except Exception:
            self.logger.debug("Failed to log privacy events", exc_info=True)
        return variations

    # --- Deprecated Methods (can be removed later) --- 
    def obfuscate_alarm(self, alarm: Dict[str, Any]) -> Dict[str, Any]:
        """DEPRECATED: Basic alarm obfuscation. Use generate_alarm_variations."""
        self.logger.warning("Deprecated obfuscate_alarm called. Use generate_alarm_variations.")
        # Keep basic confidence noise for backward compatibility if needed, but ideally remove
        modified_alarm = alarm.copy()
        assessment = modified_alarm.get('assessment', {})
        original_confidence = assessment.get('confidence', 0.5) 
        noise = self.rng.uniform(-0.05, 0.05)
        new_confidence = max(0.0, min(1.0, original_confidence + noise))
        if 'assessment' not in modified_alarm: 
            modified_alarm['assessment'] = {}
        modified_alarm['assessment']['confidence'] = new_confidence
        return modified_alarm

    def vary_alarm(self, alarm: Dict[str, Any]) -> Dict[str, Any]:
        """DEPRECATED: Basic alarm variation. Use generate_alarm_variations."""
        self.logger.warning("Deprecated vary_alarm called. Use generate_alarm_variations.")
        modified_alarm = alarm.copy()
        modified_alarm['variation_time'] = self.node.env.now + self.rng.uniform(0.01, 0.1)
        return modified_alarm
