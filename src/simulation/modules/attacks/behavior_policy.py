from __future__ import annotations

import hashlib
import random
from typing import Any, Dict, Optional, Tuple


class PMFAMatchCache:
    """Shared cache for PMFA collusion matching across malicious nodes."""

    def __init__(self) -> None:
        self._records: Dict[str, list[tuple[int, int]]] = {}

    def record(self, alarm_set_id: str, round_id: int, node_id: int) -> None:
        if not alarm_set_id:
            return
        self._records.setdefault(alarm_set_id, []).append((int(round_id), int(node_id)))

    def match_count(self, alarm_set_id: str, round_id: int, window: int) -> int:
        if alarm_set_id not in self._records:
            return 0
        window = max(0, int(window))
        cutoff = int(round_id) - window
        kept = [(r, n) for (r, n) in self._records[alarm_set_id] if r >= cutoff]
        self._records[alarm_set_id] = kept
        return len({n for (r, n) in kept})

    def has_match(self, alarm_set_id: str, round_id: int, window: int, min_matches: int) -> bool:
        return self.match_count(alarm_set_id, round_id, window) >= int(min_matches)


class BehaviorPolicy:
    """Encapsulates attacker behavior for trust-response generation."""

    def __init__(
        self,
        node: Any,
        attack_config: Optional[Dict[str, Any]] = None,
        rng: Optional[random.Random] = None,
        pmfa_cache: Optional[PMFAMatchCache] = None,
    ) -> None:
        self.node = node
        self.attack_config = attack_config or {}
        node_seed = int(getattr(self.node, "id", 0) or 0)
        self.rng = rng or random.Random(node_seed)
        self.pmfa_cache = pmfa_cache

        self.attack_type = self._normalize_attack(
            getattr(node, "attack_type", None) or self.attack_config.get("type")
        )

        # Rating bounds and distributions
        self.rating_min = float(self.attack_config.get("rating_min", 0.0))
        self.rating_max = float(self.attack_config.get("rating_max", 1.0))
        if self.rating_min > self.rating_max:
            self.rating_min, self.rating_max = self.rating_max, self.rating_min
        self.honest_rating_mean = float(self.attack_config.get("honest_rating_mean", 0.8))
        self.honest_rating_std = float(self.attack_config.get("honest_rating_std", 0.05))
        self.malicious_high = float(self.attack_config.get("malicious_high", 0.9))
        self.malicious_low = float(self.attack_config.get("malicious_low", 0.1))

        # Collusion / Sybil grouping
        self.sybil_cluster_size = int(self.attack_config.get("sybil_cluster_size", 3) or 3)
        self.collusion_group_size = int(self.attack_config.get("collusion_group_size", 5) or 5)
        self.sybil_controller_id = self._group_id(self.node.id, self.sybil_cluster_size)
        self.collusion_group_id = self._group_id(self.node.id, self.collusion_group_size)
        self.sybil_virtual_identities = max(
            1,
            int(
                self.attack_config.get(
                    "sybil_virtual_identities",
                    self.attack_config.get("sybil_identities_per_node", 1),
                ) or 1
            ),
        )
        self.sybil_identity_rotation = str(
            self.attack_config.get("sybil_identity_rotation", "round_robin")
        ).strip().lower()
        self.sybil_allow_identity_with_auth = bool(
            self.attack_config.get("sybil_allow_identity_with_auth", False)
        )
        self._sybil_identity_prefix = f"sybil-c{self.sybil_controller_id}-n{self.node.id}"

        # Betrayal config
        self.betrayal_start_round = int(
            self.attack_config.get("betrayal_start_round", self.attack_config.get("betrayal_iteration", 0)) or 0
        )
        self.betrayal_mode = str(self.attack_config.get("betrayal_mode", "two_phase")).strip().lower()
        self.on_off_period = int(self.attack_config.get("on_off_period", 10) or 10)
        self.on_off_duty_cycle = float(self.attack_config.get("on_off_duty_cycle", 0.5) or 0.5)

        # PMFA config
        self.pmfa_detect_prob = float(self.attack_config.get("pmfa_detect_prob", 0.6))
        self.pmfa_collusion_enabled = bool(self.attack_config.get("pmfa_collusion_enabled", False))
        self.pmfa_match_window_rounds = int(self.attack_config.get("pmfa_match_window_rounds", 2) or 2)
        self.pmfa_min_matches = int(self.attack_config.get("pmfa_min_matches", 2) or 2)
        self.pmfa_strategy = str(
            self.attack_config.get("pmfa_strategy", "honest_on_challenge_malicious_on_request")
        ).strip().lower()
        self.pmfa_poison_rate = float(self.attack_config.get("pmfa_poison_rate", 0.5))
        self.pmfa_fallback_mode = str(
            self.attack_config.get("pmfa_fallback_mode", "assume_challenge")
        ).strip().lower()
        self.pmfa_request_prior = self._clamp01(self.attack_config.get("pmfa_request_prior", 0.65))
        self.pmfa_dmpo_resistance = self._clamp01(self.attack_config.get("pmfa_dmpo_resistance", 0.50))

        if getattr(self.node, "attack_start_tick", None) is None:
            if self.attack_type == "betrayal":
                self.node.attack_start_tick = self.betrayal_start_round
            elif getattr(self.node, "is_malicious", False):
                self.node.attack_start_tick = 0

    def respond(self, observation: Any, source_is_malicious: bool = False) -> Tuple[float, Dict[str, Any]]:
        flags: Dict[str, Any] = {}
        if not getattr(self.node, "is_malicious", False) or not self.attack_type or self.attack_type == "none":
            response = self._honest_response()
        elif self.attack_type == "pmfa":
            response, flags = self._respond_pmfa(observation, source_is_malicious)
        elif self.attack_type == "collusion":
            response, flags = self._respond_collusion(observation, source_is_malicious)
        elif self.attack_type == "sybil":
            response, flags = self._respond_sybil(observation, source_is_malicious)
        elif self.attack_type == "betrayal":
            response, flags = self._respond_betrayal(observation, source_is_malicious)
        else:
            flags["attack_type"] = self.attack_type
            response = self._malicious_response(source_is_malicious)

        if bool(getattr(observation, "is_challenge", False)):
            proof_flags = self._build_challenge_proof(observation, response, source_is_malicious)
            flags.update(proof_flags)
            if not bool(proof_flags.get("challenge_proof_valid", False)):
                response = min(response, self.malicious_low)

        return self._clamp(response), flags

    def _normalize_attack(self, value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        lowered = str(value).strip().lower()
        aliases = {
            "pmfa": "pmfa",
            "collusion": "collusion",
            "sybil": "sybil",
            "betrayal": "betrayal",
            "none": "none",
        }
        return aliases.get(lowered, lowered)

    def _group_id(self, node_id: int, size: int) -> int:
        size = int(size) if size else 0
        if size <= 0:
            return int(node_id)
        return int(node_id) // size

    def _clamp(self, value: float) -> float:
        return max(self.rating_min, min(self.rating_max, float(value)))

    @staticmethod
    def _clamp01(value: Any) -> float:
        try:
            casted = float(value)
        except Exception:
            return 0.0
        return max(0.0, min(1.0, casted))

    def _honest_response(self) -> float:
        if self.honest_rating_std > 0:
            value = self.rng.gauss(self.honest_rating_mean, self.honest_rating_std)
        else:
            value = self.honest_rating_mean
        return self._clamp(value)

    def _malicious_response(self, source_is_malicious: bool) -> float:
        value = self.malicious_high if source_is_malicious else self.malicious_low
        return self._clamp(value)

    def _respond_collusion(self, observation: Any, source_is_malicious: bool) -> Tuple[float, Dict[str, Any]]:
        source_group = self._group_id(getattr(observation, "src_id", -1), self.collusion_group_size)
        same_group = source_is_malicious and source_group == self.collusion_group_id
        flags = {
            "collusion_boost": bool(same_group),
        }
        if same_group:
            return self._clamp(self.malicious_high), flags
        return self._clamp(self.malicious_low), flags

    def _effective_sybil_identity_pool(self) -> int:
        if self.sybil_virtual_identities <= 1:
            return 1
        require_auth = bool(getattr(self.node, "require_auth", True))
        if require_auth and not self.sybil_allow_identity_with_auth:
            return 1
        return self.sybil_virtual_identities

    def _select_sybil_identity(self, observation: Any) -> Tuple[str, int, int]:
        pool_size = self._effective_sybil_identity_pool()
        if pool_size <= 1:
            return f"{self._sybil_identity_prefix}-0", 0, 1
        round_id = int(getattr(observation, "round_id", 0))
        if self.sybil_identity_rotation == "random":
            idx = self.rng.randint(0, pool_size - 1)
        else:
            # Default deterministic round-robin identity rotation.
            idx = round_id % pool_size
        return f"{self._sybil_identity_prefix}-{idx}", idx, pool_size

    def _respond_sybil(self, observation: Any, source_is_malicious: bool) -> Tuple[float, Dict[str, Any]]:
        source_group = self._group_id(getattr(observation, "src_id", -1), self.sybil_cluster_size)
        same_controller = source_is_malicious and source_group == self.sybil_controller_id
        identity_id, identity_index, pool_size = self._select_sybil_identity(observation)
        flags = {
            "sybil_boost": bool(same_controller),
            "sybil_identity_id": identity_id,
            "sybil_identity_index": int(identity_index),
            "sybil_identity_pool_size": int(pool_size),
        }
        if same_controller:
            return self._clamp(self.malicious_high), flags
        return self._clamp(self.malicious_low), flags

    def _respond_betrayal(self, observation: Any, source_is_malicious: bool) -> Tuple[float, Dict[str, Any]]:
        round_id = int(getattr(observation, "round_id", 0))
        honest_phase = self._betrayal_honest_phase(round_id)
        flags = {"betrayal_phase": "honest" if honest_phase else "malicious"}
        if honest_phase:
            return self._honest_response(), flags
        return self._malicious_response(source_is_malicious), flags

    def _betrayal_honest_phase(self, round_id: int) -> bool:
        if round_id < self.betrayal_start_round:
            return True
        if self.betrayal_mode == "on_off":
            period = max(1, int(self.on_off_period))
            duty_cycle = max(0.0, min(1.0, float(self.on_off_duty_cycle)))
            on_threshold = period * duty_cycle
            local_round = round_id - self.betrayal_start_round
            return (local_round % period) < on_threshold
        return False

    def _respond_pmfa(self, observation: Any, source_is_malicious: bool) -> Tuple[float, Dict[str, Any]]:
        predicted_kind, flags = self._pmfa_classify(observation)
        malicious_value = self._malicious_response(source_is_malicious)
        honest_value = self._honest_response()

        if predicted_kind == "REQUEST":
            if self.pmfa_strategy in ("partial_poisoning", "partial_poison"):
                if self.rng.random() < self.pmfa_poison_rate:
                    flags["pmfa_response"] = "malicious"
                    return malicious_value, flags
                flags["pmfa_response"] = "honest"
                return honest_value, flags
            flags["pmfa_response"] = "malicious"
            return malicious_value, flags

        flags["pmfa_response"] = "honest"
        return honest_value, flags

    def _pmfa_surface_id(self, observation: Any, default_id: str) -> str:
        flags = getattr(observation, "flags", {}) or {}
        surface = flags.get("pmfa_surface_id")
        if surface:
            return str(surface)
        return str(default_id)

    def _pmfa_effective_detect_prob(self, observation: Any) -> Tuple[float, float]:
        flags = getattr(observation, "flags", {}) or {}
        dmpo_enabled = bool(flags.get("dmpo_enabled", False))
        if not dmpo_enabled:
            return self._clamp01(self.pmfa_detect_prob), 0.0

        variants = max(1, int(flags.get("dmpo_variants", 1) or 1))
        delay_window_ms = 0.0
        try:
            delay_window_ms = float(flags.get("dmpo_delay_window_ms", 0.0) or 0.0)
        except Exception:
            delay_window_ms = 0.0

        # DMPO with more variants + larger delay window lowers fingerprinting success.
        variant_factor = min(0.8, 0.16 * max(0, variants - 1))
        delay_factor = min(0.2, delay_window_ms / 2000.0)
        penalty = self._clamp01(self.pmfa_dmpo_resistance * (variant_factor + delay_factor))
        effective = self._clamp01(self.pmfa_detect_prob * (1.0 - penalty))
        return effective, penalty

    def _pmfa_fallback_prediction(self, observation: Any) -> str:
        mode = self.pmfa_fallback_mode
        if mode in {"assume_challenge", "honest_on_challenge"}:
            return "CHALLENGE"

        if mode == "prior":
            prior_request = self.pmfa_request_prior
            flags = getattr(observation, "flags", {}) or {}
            if bool(flags.get("dmpo_enabled", False)):
                # DMPO makes request/challenge less distinguishable, reduce request prior.
                prior_request *= 0.5
            return "REQUEST" if self.rng.random() < self._clamp01(prior_request) else "CHALLENGE"

        # Safe default for unknown modes: avoid aggressive poisoning when uncertain.
        return "CHALLENGE"

    def _pmfa_classify(self, observation: Any) -> Tuple[str, Dict[str, Any]]:
        raw_kind = str(getattr(observation, "msg_kind", "REQUEST")).upper()
        actual_kind = "CHALLENGE" if raw_kind.startswith("CHALLENGE") else "REQUEST"
        round_id = int(getattr(observation, "round_id", 0))
        alarm_set_id = str(getattr(observation, "alarm_set_id", "") or "")
        surface_id = self._pmfa_surface_id(observation, alarm_set_id)

        if self.pmfa_cache:
            self.pmfa_cache.record(surface_id, round_id, int(getattr(self.node, "id", -1)))

        evidence_matches = 0
        evidence = False
        if self.pmfa_collusion_enabled and self.pmfa_cache:
            evidence_matches = self.pmfa_cache.match_count(
                surface_id,
                round_id,
                self.pmfa_match_window_rounds,
            )
            evidence = evidence_matches >= self.pmfa_min_matches

        effective_detect_prob, dmpo_penalty = self._pmfa_effective_detect_prob(observation)
        if self.pmfa_collusion_enabled:
            success = evidence and (self.rng.random() < effective_detect_prob)
        else:
            success = self.rng.random() < effective_detect_prob

        if success:
            predicted = actual_kind
        else:
            predicted = self._pmfa_fallback_prediction(observation)

        flags: Dict[str, Any] = {
            "pmfa_detected": bool(success),
            "pmfa_predicted_kind": predicted,
            "pmfa_actual_kind": actual_kind,
            "pmfa_surface_id": surface_id,
            "pmfa_fallback_mode": self.pmfa_fallback_mode,
            "pmfa_effective_detect_prob": float(effective_detect_prob),
            "pmfa_dmpo_penalty": float(dmpo_penalty),
        }
        if self.pmfa_collusion_enabled:
            flags["pmfa_match_count"] = int(evidence_matches)
        return predicted, flags

    @staticmethod
    def _hash_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _proof_valid_probability(self, tier: str, response_value: float, source_is_malicious: bool) -> float:
        if not getattr(self.node, "is_malicious", False):
            return 1.0

        tier_base = {
            "basic": 0.75,
            "advanced": 0.50,
            "final": 0.30,
        }.get(tier, 0.5)

        if self.attack_type == "pmfa" and source_is_malicious:
            tier_base += 0.1
        if self.attack_type == "betrayal":
            tier_base -= 0.1
        if response_value <= self.malicious_low + 1e-9:
            tier_base -= 0.2

        return max(0.0, min(1.0, tier_base))

    def _build_challenge_proof(self, observation: Any, response_value: float, source_is_malicious: bool) -> Dict[str, Any]:
        tier = str(getattr(observation, "challenge_tier", "basic") or "basic").lower()
        payload = getattr(observation, "challenge_payload", None) or {}
        nonce = str(payload.get("nonce", "none"))
        base = f"{self.node.id}|{getattr(observation, 'round_id', 0)}|{getattr(observation, 'alarm_set_id', '')}|{tier}|{nonce}"
        digest = self._hash_text(base)

        valid_prob = self._proof_valid_probability(tier, response_value, source_is_malicious)
        proof_valid = self.rng.random() < valid_prob

        flags: Dict[str, Any] = {
            "challenge_payload_kind": payload.get("question_type"),
            "challenge_proof_valid": bool(proof_valid),
            "challenge_payload_nonce": nonce,
        }

        if tier == "basic":
            proof_type = "basic_ack_token"
            proof_token = digest[:16]
            expected = str(payload.get("expected_ack", ""))
            if not proof_valid and expected:
                proof_token = expected[::-1]
            flags.update({
                "challenge_proof_type": proof_type,
                "challenge_ack_token": proof_token,
            })
        elif tier == "advanced":
            proof_type = "advanced_context_digest"
            context_seed = f"{digest}|{payload.get('context_digest', '')}|{int(self.node.id)}"
            context_digest = self._hash_text(context_seed)[:20]
            if not proof_valid:
                context_digest = context_digest[::-1]
            flags.update({
                "challenge_proof_type": proof_type,
                "challenge_context_digest": context_digest,
                "challenge_neighbor_vote": int(self.rng.randint(0, 5)),
            })
        else:
            proof_type = "final_attestation_bundle"
            auth_tag = self._hash_text(f"{digest}|{payload.get('auth_nonce', '')}")[:20]
            behavior_tag = self._hash_text(f"{digest}|{payload.get('behavior_commitment', '')}")[:20]
            if not proof_valid:
                auth_tag = auth_tag[::-1]
            flags.update({
                "challenge_proof_type": proof_type,
                "challenge_auth_tag": auth_tag,
                "challenge_behavior_tag": behavior_tag,
            })

        return flags
