from __future__ import annotations

from typing import Any, Dict, List

from .base import PrivacyStrategy
from ..aliasing import scoped_alias
from ..cover_traffic import build_cover_messages
from ..family_renderer import render_family_variant
from ..policy_controller import DMPOXPolicyController, DisseminationPolicy
from ..stealth_header import make_stealth_header


class DMPOXPrivacyStrategy(PrivacyStrategy):
    strategy_name = "dmpo_x"

    def __init__(self, module: Any):
        super().__init__(module)
        self.controller = DMPOXPolicyController(module.node.feature_config)
        self._last_policy_trace: Dict[str, Any] = {}

    @staticmethod
    def _policy_metadata(policy: DisseminationPolicy) -> Dict[str, Any]:
        return {
            "policy_id": policy.policy_id,
            "K_t": policy.K_t,
            "f_t": policy.f_t,
            "ell_t": policy.ell_t,
            "d_t": policy.d_t,
            "r_t": policy.r_t,
        }

    def select_policy(
        self,
        original_alarm: Dict[str, Any],
        *,
        severity: float = 0.5,
        trust_score: float = 0.5,
        node_load: float = 0.0,
        attacker_risk: float = 0.5,
    ) -> DisseminationPolicy:
        policy, trace = self.controller.select_with_trace(
            severity=severity,
            trust_score=trust_score,
            node_load=node_load,
            attacker_risk=attacker_risk,
        )
        self._last_policy_trace = dict(trace)
        return policy

    def last_policy_trace(self) -> Dict[str, Any]:
        return dict(self._last_policy_trace)

    def _render_primary_variation(
        self,
        original_alarm: Dict[str, Any],
        *,
        recipient_id: int | None,
        iteration: int,
        policy: DisseminationPolicy,
        base_alarm_hash: str,
        family_idx: int,
    ) -> Dict[str, Any]:
        module = self.module
        alias_epoch = module.alias_epoch(iteration)
        family_token = scoped_alias(
            module._salt,
            module.node.id,
            recipient_id,
            alias_epoch,
            f"family:{base_alarm_hash}:{family_idx}",
        )
        rendered = render_family_variant(original_alarm, family_idx, policy.ell_t)
        var = original_alarm.copy()
        var.update(rendered)
        var["current_destination_ip"] = module._obfuscate_ip(original_alarm.get("original_destination_ip"))
        if family_idx % 2 == 1:
            var["current_port"] = module._obfuscate_port(original_alarm.get("original_destination_port"))
        var["message_id"] = scoped_alias(
            module._salt,
            module.node.id,
            recipient_id,
            alias_epoch,
            f"msg:{base_alarm_hash}:{family_idx}",
        )
        var["dmpo_enabled"] = True
        var["is_cover"] = False
        var["privacy_strategy"] = self.strategy_name
        var["privacy_policy"] = self._policy_metadata(policy)
        var["privacy_policy_decision"] = self.last_policy_trace()
        var["privacy_alias_scope"] = "recipient_epoch"
        var["privacy_alias_epoch"] = alias_epoch
        var["privacy_alias_epoch_rounds"] = module.alias_epoch_rounds
        var["stealth_header"] = make_stealth_header(
            base_salt=module._salt,
            sender_id=module.node.id,
            recipient_id=recipient_id,
            policy_id=policy.policy_id,
            family_token=family_token,
            epoch=alias_epoch,
            is_cover=False,
        )
        var["original_alarm_hash"] = base_alarm_hash
        return var

    def _render_cover_variation(
        self,
        cover_payload: Dict[str, Any],
        *,
        recipient_id: int | None,
        iteration: int,
        policy: DisseminationPolicy,
        base_alarm_hash: str,
        cover_idx: int,
    ) -> Dict[str, Any]:
        module = self.module
        alias_epoch = module.alias_epoch(iteration)
        family_token = scoped_alias(
            module._salt,
            module.node.id,
            recipient_id,
            alias_epoch,
            f"cover:{base_alarm_hash}:{cover_idx}",
        )
        var = dict(cover_payload)
        var["message_id"] = scoped_alias(
            module._salt,
            module.node.id,
            recipient_id,
            alias_epoch,
            f"cover-msg:{base_alarm_hash}:{cover_idx}",
        )
        var["dmpo_enabled"] = True
        var["privacy_strategy"] = self.strategy_name
        var["privacy_policy"] = self._policy_metadata(policy)
        var["privacy_policy_decision"] = self.last_policy_trace()
        var["privacy_alias_scope"] = "recipient_epoch"
        var["privacy_alias_epoch"] = alias_epoch
        var["privacy_alias_epoch_rounds"] = module.alias_epoch_rounds
        var["stealth_header"] = make_stealth_header(
            base_salt=module._salt,
            sender_id=module.node.id,
            recipient_id=recipient_id,
            policy_id=policy.policy_id,
            family_token=family_token,
            epoch=alias_epoch,
            is_cover=True,
        )
        var["original_alarm_hash"] = base_alarm_hash
        return var

    def generate_alarm_variations(
        self,
        original_alarm: Dict[str, Any],
        *,
        recipient_id: int | None = None,
        policy: Any = None,
        include_cover: bool = True,
    ) -> List[Dict[str, Any]]:
        module = self.module
        iteration = int(getattr(module.node, "current_iteration", 0))
        if not isinstance(policy, DisseminationPolicy):
            policy = self.select_policy(original_alarm)
        base_alarm_hash = module._calculate_alarm_hash(original_alarm)

        variations = [
            self._render_primary_variation(
                original_alarm,
                recipient_id=recipient_id,
                iteration=iteration,
                policy=policy,
                base_alarm_hash=base_alarm_hash,
                family_idx=family_idx,
            )
            for family_idx in range(policy.K_t)
        ]

        if variations and include_cover:
            cover_payloads = build_cover_messages(policy.r_t, variations[0], count_hint=policy.f_t)
            for cover_idx, cover_payload in enumerate(cover_payloads, start=1):
                variations.append(
                    self._render_cover_variation(
                        cover_payload,
                        recipient_id=recipient_id,
                        iteration=iteration,
                        policy=policy,
                        base_alarm_hash=base_alarm_hash,
                        cover_idx=cover_idx,
                    )
                )
        return variations
