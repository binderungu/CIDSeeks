import hashlib
import json
import logging
import random
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from ...utils.perf import metric_logger
from .policy_controller import DisseminationPolicy
from .strategies import DMPOXPrivacyStrategy, LegacyDMPOPrivacyStrategy, PrivacyStrategy

if TYPE_CHECKING:
    from ...core.node import Node


class PrivacyModule:
    """Privacy orchestration with strategy switch: dmpo_legacy or dmpo_x."""

    def __init__(self, node: "Node"):
        self.node = node
        self.logger = logging.getLogger(f"PrivacyModule-Node{self.node.id}")
        node_rng = getattr(node, "rng", None)
        self.rng = node_rng if node_rng is not None else random.Random(int(getattr(node, "id", 0) or 0))
        feature_cfg = getattr(node, "feature_config", {}) or {}
        self._privacy_cfg = feature_cfg.get("privacy", {}) or {}
        salt = feature_cfg.get("privacy_salt", f"cidseeks-salt-{self.node.id}")
        self._salt = salt if isinstance(salt, bytes) else str(salt).encode("utf-8")
        self._prefix_bits = int(feature_cfg.get("privacy_prefix_bits", 24) or 24)
        self._k_anonymity = int(feature_cfg.get("privacy_k_anonymity", 16) or 16)
        self._alias_epoch_rounds = max(
            1,
            int(
                feature_cfg.get("privacy_alias_epoch_rounds")
                or self._privacy_cfg.get("alias_epoch_rounds")
                or 5
            ),
        )
        self._last_policy_trace: Dict[str, Any] = {}
        self.strategy: PrivacyStrategy = self._build_strategy(feature_cfg)

    def _build_strategy(self, feature_cfg: Dict[str, Any]) -> PrivacyStrategy:
        strategy_name = str(
            feature_cfg.get("privacy_strategy")
            or feature_cfg.get("privacy", {}).get("strategy")
            or "dmpo_legacy"
        ).lower()
        if strategy_name == "dmpo_x":
            self.logger.info("Using privacy strategy: dmpo_x")
            return DMPOXPrivacyStrategy(self)
        self.logger.info("Using privacy strategy: dmpo_legacy")
        return LegacyDMPOPrivacyStrategy(self)

    def _calculate_alarm_hash(self, original_content: Dict[str, Any]) -> str:
        try:
            content_str = json.dumps(original_content, sort_keys=True)
            return hashlib.sha256(content_str.encode("utf-8")).hexdigest()
        except Exception:
            return hashlib.sha256(str(original_content).encode("utf-8")).hexdigest()

    @staticmethod
    def _ip_to_int(ip_address: str) -> Optional[int]:
        try:
            parts = [int(p) for p in ip_address.split(".")]
        except Exception:
            return None
        if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
            return None
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

    @staticmethod
    def _int_to_ip(value: int) -> str:
        value = int(value) & 0xFFFFFFFF
        return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))

    def _prefix_preserving_hash(self, ip_address: str) -> str:
        ip_int = self._ip_to_int(ip_address)
        if ip_int is None:
            return "0.0.0.0"
        prefix_bits = max(0, min(32, int(self._prefix_bits)))
        host_bits = 32 - prefix_bits
        prefix_mask = 0 if prefix_bits == 0 else (0xFFFFFFFF << host_bits) & 0xFFFFFFFF
        prefix_val = ip_int & prefix_mask
        host_val = ip_int & (~prefix_mask & 0xFFFFFFFF)
        k = max(1, min(256, int(self._k_anonymity)))
        host_bucket = (host_val // k) * k if host_bits > 0 else 0

        prefix_bytes = prefix_val.to_bytes(4, byteorder="big") + prefix_bits.to_bytes(1, byteorder="big")
        pseudo_prefix = int.from_bytes(hashlib.sha256(self._salt + prefix_bytes).digest(), byteorder="big") & prefix_mask
        host_bytes = host_bucket.to_bytes(4, byteorder="big") + prefix_val.to_bytes(4, byteorder="big")
        pseudo_host = int.from_bytes(hashlib.sha256(self._salt + host_bytes + b"host").digest(), byteorder="big")
        pseudo_host = (pseudo_host & ((1 << host_bits) - 1)) if host_bits > 0 else 0
        return self._int_to_ip(pseudo_prefix | pseudo_host)

    def _obfuscate_ip(self, ip_address: Any) -> str:
        if not isinstance(ip_address, str):
            return "0.0.0.0"
        return self._prefix_preserving_hash(ip_address)

    @staticmethod
    def _obfuscate_port(_port: Any) -> str:
        return "any"

    def _obfuscate_msg(self, msg: Any) -> str:
        if not isinstance(msg, str):
            return "<obfuscated_non_string>"
        return f"{msg} [var:{self.rng.randint(100, 999)}]"

    def _variant_id_hash(self, alarm_hash: str, variant_index: int) -> str:
        payload = f"{alarm_hash}:{variant_index}".encode("utf-8")
        return hashlib.sha256(self._salt + payload).hexdigest()

    @property
    def alias_epoch_rounds(self) -> int:
        return int(self._alias_epoch_rounds)

    def alias_epoch(self, iteration: int) -> int:
        return max(0, int(iteration) // self.alias_epoch_rounds)

    def last_policy_trace(self) -> Dict[str, Any]:
        return dict(self._last_policy_trace)

    @staticmethod
    def _clamp_unit(value: Any, default: float = 0.5) -> float:
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            numeric = default
        return max(0.0, min(1.0, numeric))

    def _estimate_attacker_risk(self, original_alarm: Dict[str, Any], trust_scores: Optional[List[float]] = None, node_load: float = 0.0) -> float:
        assessment = original_alarm.get("assessment", {}) if isinstance(original_alarm.get("assessment"), dict) else {}
        severity = self._clamp_unit(assessment.get("confidence", 0.5), default=0.5)
        trust_score = sum(trust_scores) / len(trust_scores) if trust_scores else 0.5
        trust_score = self._clamp_unit(trust_score, default=0.5)
        attack_cfg = getattr(self.node, "attack_config", {}) or {}
        pmfa_detect_prob = self._clamp_unit(attack_cfg.get("pmfa_detect_prob", 0.5), default=0.5)
        pmfa_resistance = self._clamp_unit(attack_cfg.get("pmfa_dmpo_resistance", 0.5), default=0.5)
        guard_enabled = 1.0 if bool(self.node.feature_config.get("dmpo_pmfa_guard", False)) else 0.0
        return self._clamp_unit(
            0.35 * pmfa_detect_prob
            + 0.20 * severity
            + 0.15 * (1.0 - trust_score)
            + 0.15 * self._clamp_unit(node_load, default=0.0)
            + 0.15 * guard_enabled
            - 0.10 * pmfa_resistance,
            default=0.5,
        )

    def select_dissemination_policy(
        self,
        original_alarm: Dict[str, Any],
        *,
        trust_scores: Optional[List[float]] = None,
        neighbor_count: Optional[int] = None,
    ) -> DisseminationPolicy:
        if hasattr(self.strategy, "select_policy"):
            assessment = original_alarm.get("assessment", {}) if isinstance(original_alarm.get("assessment"), dict) else {}
            severity = self._clamp_unit(assessment.get("confidence", 0.5), default=0.5)
            trust_score = sum(trust_scores) / len(trust_scores) if trust_scores else 0.5
            trust_score = self._clamp_unit(trust_score, default=0.5)
            total_nodes = max(1, int(self.node.feature_config.get("total_nodes", len(getattr(self.node, "neighbors", [])) or 1)))
            node_load = self._clamp_unit((neighbor_count or 0) / total_nodes, default=0.0)
            attacker_risk = self._estimate_attacker_risk(original_alarm, trust_scores=trust_scores, node_load=node_load)
            policy = self.strategy.select_policy(
                original_alarm,
                severity=severity,
                trust_score=trust_score,
                node_load=node_load,
                attacker_risk=attacker_risk,
            )
            trace_getter = getattr(self.strategy, "last_policy_trace", None)
            if callable(trace_getter):
                try:
                    self._last_policy_trace = dict(trace_getter())
                except Exception:
                    self._last_policy_trace = {}
            else:
                self._last_policy_trace = {}
            return policy

        variants = self.strategy.generate_alarm_variations(original_alarm)
        fanout = len(variants) if neighbor_count is None else min(len(variants), max(1, neighbor_count))
        self._last_policy_trace = {}
        return DisseminationPolicy(
            policy_id="legacy",
            K_t=max(1, len(variants)),
            f_t=max(1, fanout),
            ell_t="legacy",
            d_t="uniform",
            r_t=0.0,
        )

    def generate_alarm_variations(
        self,
        original_alarm: Dict[str, Any],
        *,
        recipient_id: int | None = None,
        policy: DisseminationPolicy | None = None,
        include_cover: bool = True,
    ) -> List[Dict[str, Any]]:
        variations = self.strategy.generate_alarm_variations(
            original_alarm,
            recipient_id=recipient_id,
            policy=policy,
            include_cover=include_cover,
        )
        primary_variations = [v for v in variations if isinstance(v, dict) and not bool(v.get("is_cover", False))]
        if not primary_variations and include_cover:
            self.logger.info(
                "Privacy strategy %s produced no primary payloads for sender=%s recipient=%s; regenerating without cover.",
                getattr(self.strategy, "strategy_name", "unknown"),
                getattr(self.node, "id", None),
                recipient_id,
            )
            variations = self.strategy.generate_alarm_variations(
                original_alarm,
                recipient_id=recipient_id,
                policy=policy,
                include_cover=False,
            )
            primary_variations = [
                v for v in variations if isinstance(v, dict) and not bool(v.get("is_cover", False))
            ]
        if not primary_variations:
            self.logger.error(
                "Privacy strategy %s failed to produce a primary payload for sender=%s recipient=%s.",
                getattr(self.strategy, "strategy_name", "unknown"),
                getattr(self.node, "id", None),
                recipient_id,
            )
        try:
            for i, v in enumerate(variations, start=1):
                payload_str = str(
                    {
                        "current_destination_ip": v.get("current_destination_ip"),
                        "current_port": v.get("current_port"),
                        "current_msg": v.get("current_msg"),
                    }
                )
                metric_logger.log_privacy_event(
                    {
                        "delay_ms": None,
                        "payload_size": len(payload_str.encode("utf-8")),
                        "variant_id": v.get("variation_sequence_number", i),
                        "is_challenge": False,
                        "dmpo_enabled": bool(v.get("dmpo_enabled", True)),
                        "sender_id": self.node.id,
                        "receiver_id": recipient_id,
                        "iteration": getattr(self.node, "current_iteration", 0),
                        "message_id": v.get("message_id"),
                        "alarm_hash": v.get("original_alarm_hash"),
                        "privacy_strategy": v.get("privacy_strategy", "dmpo_legacy"),
                        "privacy_policy": v.get("privacy_policy"),
                        "privacy_policy_decision": v.get("privacy_policy_decision", self.last_policy_trace()),
                        "privacy_alias_scope": v.get("privacy_alias_scope"),
                        "privacy_alias_epoch": v.get("privacy_alias_epoch"),
                        "privacy_alias_epoch_rounds": v.get("privacy_alias_epoch_rounds"),
                        "stealth_header": v.get("stealth_header"),
                        "is_cover": bool(v.get("is_cover", False)),
                        "event_scope": "render",
                    }
                )
        except Exception:
            self.logger.debug("Failed to log privacy events", exc_info=True)
        return variations

    def obfuscate_alarm(self, alarm: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.warning("Deprecated obfuscate_alarm called. Use generate_alarm_variations.")
        modified_alarm = alarm.copy()
        assessment = modified_alarm.get("assessment", {})
        original_confidence = assessment.get("confidence", 0.5)
        noise = self.rng.uniform(-0.05, 0.05)
        new_confidence = max(0.0, min(1.0, original_confidence + noise))
        if "assessment" not in modified_alarm:
            modified_alarm["assessment"] = {}
        modified_alarm["assessment"]["confidence"] = new_confidence
        return modified_alarm

    def vary_alarm(self, alarm: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.warning("Deprecated vary_alarm called. Use generate_alarm_variations.")
        modified_alarm = alarm.copy()
        modified_alarm["variation_time"] = self.node.env.now + self.rng.uniform(0.01, 0.1)
        return modified_alarm
