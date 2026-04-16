from __future__ import annotations

from typing import Any, Dict, List

from .base import PrivacyStrategy


class LegacyDMPOPrivacyStrategy(PrivacyStrategy):
    strategy_name = "dmpo_legacy"

    def generate_alarm_variations(
        self,
        original_alarm: Dict[str, Any],
        *,
        recipient_id: int | None = None,
        policy: Any = None,
        include_cover: bool = True,
    ) -> List[Dict[str, Any]]:
        module = self.module
        variations = []
        original_content_for_hash = {
            k: v
            for k, v in original_alarm.items()
            if k.startswith("original_") or k in ["timestamp", "analyzer_node_id", "classification_text"]
        }
        original_alarm_hash = module._calculate_alarm_hash(original_content_for_hash)
        base_alarm = original_alarm.copy()
        base_alarm["original_alarm_hash"] = original_alarm_hash
        base_alarm["alarm_family_id"] = original_alarm_hash
        base_alarm["original_message_id"] = original_alarm.get("message_id")
        base_alarm["dmpo_enabled"] = True
        base_alarm["is_cover"] = False
        base_alarm["privacy_strategy"] = self.strategy_name

        variants_per_alarm = int(module.node.feature_config.get("variants_per_alarm", 3))
        variants_per_alarm = max(1, min(variants_per_alarm, 4))

        templates = [
            lambda: {
                "current_destination_ip": module._obfuscate_ip(original_alarm.get("original_destination_ip")),
                "current_port": original_alarm.get("original_destination_port"),
                "current_msg": original_alarm.get("original_message_body"),
            },
            lambda: {
                "current_destination_ip": module._obfuscate_ip(original_alarm.get("original_destination_ip")),
                "current_port": original_alarm.get("original_destination_port"),
                "current_msg": original_alarm.get("original_message_body"),
            },
            lambda: {
                "current_destination_ip": module._obfuscate_ip(original_alarm.get("original_destination_ip")),
                "current_port": module._obfuscate_port(original_alarm.get("original_destination_port")),
                "current_msg": original_alarm.get("original_message_body"),
            },
            lambda: {
                "current_destination_ip": module._obfuscate_ip(original_alarm.get("original_destination_ip")),
                "current_port": module._obfuscate_port(original_alarm.get("original_destination_port")),
                "current_msg": module._obfuscate_msg(original_alarm.get("original_message_body")),
            },
        ]

        for idx in range(variants_per_alarm):
            var = base_alarm.copy()
            var["variation_sequence_number"] = idx + 1
            var["variant_id_hash"] = module._variant_id_hash(original_alarm_hash, idx + 1)
            var["message_id"] = var["variant_id_hash"]
            var.update(templates[idx]())
            variations.append(var)
        return variations
