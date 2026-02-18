import logging
import hashlib
import math
from typing import TYPE_CHECKING, Dict, Any, Optional, List

from .calculator import TrustCalculator
from .observation import Observation
from ...utils.perf import metric_logger

# Hindari circular import penuh, hanya import tipe jika perlu
if TYPE_CHECKING:
    from ...core.node import Node

class TrustManager:
    """
    Manages the trust evaluation process for a specific node.

    Attributes:
        node (Node): The node instance that owns this TrustManager.
        calculator (TrustCalculator): The calculator instance untuk 3-level challenge.
        logger (logging.Logger): Logger instance specific to this manager.
    """

    def __init__(self, node: 'Node', calculator: TrustCalculator, metrics_recorder=None):
        self.node = node # Node yang memiliki manager ini
        self.calculator = calculator
        self.logger = logging.getLogger(f"TrustManager-Node{self.node.id}")
        self.metrics_recorder = metrics_recorder
        self._dirichlet_cfg = self._build_dirichlet_config()
        self._dirichlet_state: Dict[int, Dict[str, Any]] = {}
        self._challenge_schedule_cfg = self._build_challenge_schedule_config()
        self._last_tier_challenge_iteration: Dict[int, Dict[str, int]] = {}
        self._collusion_cfg = self._build_collusion_config()
        self._coordination_history: Dict[int, List[int]] = {}
        # Backward-compatible plugin hook (optional; canonical flow uses 3-level challenge).
        self.trust_plugin = getattr(node, 'trust_method_instance', None)
        
        # Only CIDSeeks / 3-level challenge is supported
        self.trust_method = self._normalize_method_name(getattr(node, 'trust_method', '3-level-challenge'))
        self._log_selected_method()

    def _build_dirichlet_config(self) -> Dict[str, Any]:
        cfg = self.node.trust_config or {}
        raw_levels = cfg.get('dirichlet_levels', [0.0, 0.5, 1.0])
        levels: List[float] = []
        for value in raw_levels:
            try:
                levels.append(float(value))
            except (TypeError, ValueError):
                continue
        levels = sorted({max(0.0, min(1.0, v)) for v in levels})
        if len(levels) < 2:
            levels = [0.0, 0.5, 1.0]

        raw_weights = cfg.get('dirichlet_weights', levels)
        weights: List[float] = []
        for value in raw_weights:
            try:
                weights.append(float(value))
            except (TypeError, ValueError):
                continue
        if len(weights) != len(levels):
            weights = list(levels)

        try:
            prior_strength = float(cfg.get('dirichlet_prior_strength', 10.0))
        except (TypeError, ValueError):
            prior_strength = 10.0
        prior_strength = max(1e-6, prior_strength)

        ff_raw = cfg.get('dirichlet_forgetting_factor', cfg.get('forgetting_factor', cfg.get('lambda', 0.9)))
        try:
            forgetting_factor = float(ff_raw)
        except (TypeError, ValueError):
            forgetting_factor = 0.9
        forgetting_factor = max(0.0, min(1.0, forgetting_factor))

        try:
            neighbor_blend = float(cfg.get('dirichlet_neighbor_blend', 1.0))
        except (TypeError, ValueError):
            neighbor_blend = 1.0
        neighbor_blend = max(0.0, min(1.0, neighbor_blend))

        return {
            'levels': levels,
            'weights': weights,
            'prior_strength': prior_strength,
            'forgetting_factor': forgetting_factor,
            'neighbor_blend': neighbor_blend,
        }

    def _build_challenge_schedule_config(self) -> Dict[str, Any]:
        cfg = self.node.trust_config or {}
        global_rate = self._coerce_challenge_rate(
            cfg.get('challenge_rate', cfg.get('challenge_prob', 0.1))
        )

        raw_tier_rates = cfg.get('challenge_rate_tiers', {})
        if not isinstance(raw_tier_rates, dict):
            raw_tier_rates = {}
        tier_rates: Dict[str, float] = {}
        for tier in ("basic", "advanced", "final"):
            raw_value = raw_tier_rates.get(tier, global_rate)
            tier_rates[tier] = max(0.0, min(1.0, self._coerce_challenge_rate(raw_value)))

        raw_min_interval = cfg.get('challenge_min_interval_tiers', {})
        if not isinstance(raw_min_interval, dict):
            raw_min_interval = {}
        tier_min_interval: Dict[str, int] = {}
        for tier in ("basic", "advanced", "final"):
            try:
                tier_min_interval[tier] = max(0, int(raw_min_interval.get(tier, 0)))
            except (TypeError, ValueError):
                tier_min_interval[tier] = 0

        return {
            'global_rate': max(0.0, min(1.0, global_rate)),
            'tier_rates': tier_rates,
            'tier_min_interval': tier_min_interval,
        }

    def _build_collusion_config(self) -> Dict[str, Any]:
        cfg = self.node.trust_config or {}
        raw = cfg.get('collusion_penalty', {})
        if not isinstance(raw, dict):
            raw = {}

        trust_threshold = float(cfg.get('trust_threshold', 0.5))
        try:
            min_group_size = int(raw.get('min_group_size', 3))
        except (TypeError, ValueError):
            min_group_size = 3
        min_group_size = max(2, min_group_size)

        try:
            history_window = int(raw.get('history_window', 20))
        except (TypeError, ValueError):
            history_window = 20
        history_window = max(1, history_window)
        try:
            activation_count = int(raw.get('activation_count', 2))
        except (TypeError, ValueError):
            activation_count = 2
        activation_count = max(1, activation_count)

        def _safe_float(key: str, default: float) -> float:
            try:
                return float(raw.get(key, default))
            except (TypeError, ValueError):
                return float(default)

        activation_ratio = max(0.0, min(1.0, _safe_float('activation_ratio', 0.2)))
        trust_edge_threshold = max(0.0, min(1.0, _safe_float('trust_edge_threshold', trust_threshold)))
        density_threshold = max(0.0, min(1.0, _safe_float('density_threshold', 0.5)))
        max_penalty = max(0.0, min(1.0, _safe_float('max_penalty', 0.2)))
        flag_boost = max(0.0, min(1.0, _safe_float('flag_boost', 0.1)))

        return {
            'enabled': bool(raw.get('enabled', True)),
            'min_group_size': min_group_size,
            'history_window': history_window,
            'activation_count': activation_count,
            'activation_ratio': activation_ratio,
            'trust_edge_threshold': trust_edge_threshold,
            'density_threshold': density_threshold,
            'max_penalty': max_penalty,
            'flag_boost': flag_boost,
        }

    def _get_dirichlet_state(self, target_id: int) -> Dict[str, Any]:
        state = self._dirichlet_state.get(target_id)
        if state is None:
            levels = self._dirichlet_cfg['levels']
            prior = self._dirichlet_cfg['prior_strength'] / float(len(levels))
            state = {
                'gamma': [prior for _ in levels],
                'last_iteration': None,
            }
            self._dirichlet_state[target_id] = state
        return state

    @staticmethod
    def _value_to_level_index(value: float, levels: List[float]) -> int:
        best_idx = 0
        best_dist = float('inf')
        for idx, level in enumerate(levels):
            dist = abs(level - value)
            if dist < best_dist:
                best_dist = dist
                best_idx = idx
        return best_idx

    def _neighbor_reputation_mean(self, target_node: 'Node') -> float:
        try:
            neighbors = getattr(self.node, 'neighbors', [])
        except Exception:
            return 0.5
        values = []
        for neighbor in neighbors:
            try:
                if neighbor.id == target_node.id:
                    continue
                values.append(float(self.node.trust_scores.get(neighbor.id, 0.5)))
            except Exception:
                continue
        if not values:
            return 0.5
        return max(0.0, min(1.0, sum(values) / len(values)))

    def _update_dirichlet_reputation(self, target_id: int, iteration: int, response_value: float) -> float:
        state = self._get_dirichlet_state(target_id)
        gamma = list(state.get('gamma') or [])
        if not gamma:
            gamma = [self._dirichlet_cfg['prior_strength'] / len(self._dirichlet_cfg['levels'])] * len(self._dirichlet_cfg['levels'])

        last_iter = state.get('last_iteration')
        ff = self._dirichlet_cfg['forgetting_factor']
        if last_iter is not None:
            try:
                delta = max(0, int(iteration) - int(last_iter))
            except Exception:
                delta = 0
            if delta > 0 and ff < 1.0:
                decay = ff ** delta
                gamma = [max(1e-12, g * decay) for g in gamma]

        clean_response = float(response_value)
        if not math.isfinite(clean_response):
            clean_response = 0.5
        clean_response = max(0.0, min(1.0, clean_response))

        levels = self._dirichlet_cfg['levels']
        idx = self._value_to_level_index(clean_response, levels)
        gamma[idx] += 1.0

        state['gamma'] = gamma
        state['last_iteration'] = int(iteration)

        gamma_sum = sum(gamma)
        if gamma_sum <= 0:
            return 0.5
        weighted = sum(w * g for w, g in zip(self._dirichlet_cfg['weights'], gamma))
        return max(0.0, min(1.0, weighted / gamma_sum))

    @staticmethod
    def _normalize_method_name(method_name: str) -> str:
        aliases = {
            'default_3_level': '3-level-challenge',
            '3_level_challenge': '3-level-challenge',
            'CIDSeeks': '3-level-challenge',
        }
        return aliases.get(method_name, '3-level-challenge')

    def _log_selected_method(self) -> None:
        if self.trust_method != '3-level-challenge':
            self.logger.warning(
                "Trust method '%s' is not supported anymore. Falling back to 3-level challenge.",
                self.trust_method,
            )
            self.trust_method = '3-level-challenge'
        self.logger.info("Using 3-level challenge trust mechanism")

    @staticmethod
    def _coerce_challenge_rate(value: Any) -> float:
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            presets = {
                "low": 0.05,
                "med": 0.10,
                "medium": 0.10,
                "high": 0.20,
            }
            lowered = value.strip().lower()
            if lowered in presets:
                return presets[lowered]
            try:
                return float(value)
            except ValueError:
                return 0.1
        return 0.1

    def _resolve_tier_challenge_rate(self, challenge_tier: str) -> float:
        tier_rates = self._challenge_schedule_cfg.get('tier_rates', {})
        if challenge_tier in tier_rates:
            return float(tier_rates[challenge_tier])
        return float(self._challenge_schedule_cfg.get('global_rate', 0.1))

    def _resolve_tier_min_interval(self, challenge_tier: str) -> int:
        tier_min_interval = self._challenge_schedule_cfg.get('tier_min_interval', {})
        if challenge_tier in tier_min_interval:
            return int(tier_min_interval[challenge_tier])
        return 0

    def _build_challenge_payload(self, challenge_tier: str, target_id: int, iteration: int, alarm_set_id: str) -> Dict[str, Any]:
        nonce_seed = f"{self.node.id}|{target_id}|{iteration}|{alarm_set_id}|{challenge_tier}"
        digest = hashlib.sha256(nonce_seed.encode("utf-8")).hexdigest()

        if challenge_tier == "basic":
            return {
                "tier": "basic",
                "question_type": "basic_consistency_ping",
                "nonce": digest[:10],
                "expected_ack": digest[10:20],
                "timeout_hint_ms": 200,
            }
        if challenge_tier == "advanced":
            return {
                "tier": "advanced",
                "question_type": "advanced_context_corroboration",
                "nonce": digest[:12],
                "context_digest": digest[12:28],
                "reputation_window": int(self.node.trust_config.get("behavior_history_window", 20) or 20),
                "contribution_window": int(self.node.trust_config.get("behavior_history_window", 20) or 20),
            }
        return {
            "tier": "final",
            "question_type": "final_attestation_audit",
            "nonce": digest[:14],
            "auth_nonce": digest[14:30],
            "behavior_commitment": digest[30:46],
            "requires_auth_proof": True,
        }

    def _score_challenge_response(self, response_value: float, msg_kind: str, challenge_tier: Optional[str], flags: Dict[str, Any]) -> float:
        clean = float(response_value)
        if not math.isfinite(clean):
            clean = 0.5
        clean = max(0.0, min(1.0, clean))
        if msg_kind != "CHALLENGE" or not challenge_tier:
            return clean

        proof_valid = bool(flags.get("challenge_proof_valid", False))
        proof_type = str(flags.get("challenge_proof_type", "") or "")
        expected_prefix = {
            "basic": "basic_",
            "advanced": "advanced_",
            "final": "final_",
        }
        if proof_type and not proof_type.startswith(expected_prefix.get(challenge_tier, "")):
            proof_valid = False

        bonus = {"basic": 0.03, "advanced": 0.05, "final": 0.08}
        penalty = {"basic": 0.20, "advanced": 0.35, "final": 0.50}
        if proof_valid:
            clean += bonus.get(challenge_tier, 0.0)
        else:
            clean -= penalty.get(challenge_tier, 0.25)

        return max(0.0, min(1.0, clean))

    def _select_msg_kind(self, target_id: int, challenge_tier: str, iteration: int) -> str:
        rate = self._resolve_tier_challenge_rate(challenge_tier)
        min_interval = self._resolve_tier_min_interval(challenge_tier)
        tier_state = self._last_tier_challenge_iteration.setdefault(int(target_id), {})

        if min_interval > 0:
            last_iter = tier_state.get(challenge_tier)
            if last_iter is not None and int(iteration) - int(last_iter) < min_interval:
                return "REQUEST"

        if getattr(self.node, "rng", None) and self.node.rng.random() < rate:
            tier_state[challenge_tier] = int(iteration)
            return "CHALLENGE"
        return "REQUEST"

    def _dmpo_pmfa_guard_enabled(self) -> bool:
        raw = self.node.feature_config.get("dmpo_pmfa_guard", True)
        if isinstance(raw, str):
            return raw.strip().lower() not in {"0", "false", "off", "no", "disabled"}
        return bool(raw)

    def _request_pmfa_surface(self, base_alarm_set_id: str, target_id: int, iteration: int) -> tuple[str, Dict[str, Any]]:
        if not self._dmpo_pmfa_guard_enabled():
            return base_alarm_set_id, {
                "dmpo_enabled": False,
                "dmpo_variants": 1,
                "dmpo_variant_index": 1,
                "dmpo_delay_window_ms": 0.0,
                "alarm_family_id": base_alarm_set_id,
                "pmfa_surface_id": base_alarm_set_id,
            }

        variants = int(self.node.feature_config.get("variants_per_alarm", 3) or 3)
        variants = max(1, min(variants, 8))
        min_delay = float(self.node.feature_config.get("min_alarm_send_delay", 0.1) or 0.0)
        max_delay = float(self.node.feature_config.get("max_alarm_send_delay", min_delay) or min_delay)
        delay_window_ms = max(0.0, max_delay - min_delay) * 1000.0
        salt = str(self.node.feature_config.get("privacy_salt", "cidseeks"))

        idx_seed = f"{salt}|{self.node.id}|{target_id}|{iteration}|{base_alarm_set_id}"
        idx_digest = hashlib.sha256(idx_seed.encode("utf-8")).hexdigest()
        variant_index = (int(idx_digest[:8], 16) % variants) + 1

        surface_seed = (
            f"{salt}|{base_alarm_set_id}|{target_id}|{iteration}|"
            f"v{variant_index}|window{int(delay_window_ms)}"
        )
        surface_id = hashlib.sha256(surface_seed.encode("utf-8")).hexdigest()[:24]
        return surface_id, {
            "dmpo_enabled": True,
            "dmpo_variants": variants,
            "dmpo_variant_index": variant_index,
            "dmpo_delay_window_ms": delay_window_ms,
            "alarm_family_id": base_alarm_set_id,
            "pmfa_surface_id": surface_id,
        }

    def _get_thresholds(self) -> tuple[float, float, float]:
        trust_threshold = float(self.node.trust_config.get('trust_threshold', 0.5))
        fall = float(self.node.trust_config.get('trust_fall_threshold', trust_threshold))
        rise = float(self.node.trust_config.get('trust_rise_threshold', min(1.0, trust_threshold + 0.1)))
        return trust_threshold, fall, rise

    def _select_challenge_tier(self, prev_total: float) -> str:
        _, fall, rise = self._get_thresholds()
        if prev_total < fall:
            return "basic"
        if prev_total < rise:
            return "advanced"
        return "final"

    def _get_component_state(self, target_id: int) -> Dict[str, float]:
        initial = float(self.node.trust_config.get('initial_trust', 0.5))
        state = self.node.trust_components.get(target_id)
        if not state:
            state = {
                'basic': initial,
                'advanced': initial,
                'final': initial,
            }
            self.node.trust_components[target_id] = state
        return state

    def _record_behavior(self, target_id: int, response_value: float) -> None:
        history = self.node.behavior_history[target_id]
        history.append(float(response_value))
        window = int(self.node.trust_config.get('behavior_history_window', 20) or 20)
        if window > 0 and len(history) > window:
            del history[:-window]

    def evaluate(self, target_node: 'Node') -> float:
        """
        Orchestrates trust evaluation menggunakan method yang dipilih.
        
        Args:
            target_node: Node yang akan dievaluasi trust-nya
            
        Returns:
            float: Trust score dalam rentang [0, 1]
        """
        try:
            return self._evaluate_three_level_challenge(target_node)
                
        except Exception as e:
            self.logger.error(f"Error during trust evaluation for Node {target_node.id}: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            # Update skor ke default jika terjadi error parah selama evaluasi
            fallback = float(self.node.trust_config.get('initial_trust', 0.5))
            self.node.trust_scores[target_node.id] = fallback
            return fallback # Return default neutral trust on error

    def _evaluate_three_level_challenge(self, target_node: 'Node') -> float:
        """
        Implementasi original 3-level challenge method (metode yang diusulkan).
        
        Args:
            target_node: Node yang akan dievaluasi
            
        Returns:
            float: Trust score dari 3-level challenge
        """
        iteration = self.node.current_iteration
        target_id = target_node.id
        component_state = self._get_component_state(target_id)
        prev_basic = component_state['basic']
        prev_advanced = component_state['advanced']
        prev_final = component_state['final']
        initial_trust = float(self.node.trust_config.get('initial_trust', 0.5))
        prev_total = self.node.trust_scores.get(target_id, initial_trust)

        # --- Message kind (CHALLENGE vs REQUEST) for this evaluation ---
        challenge_tier = self._select_challenge_tier(prev_total)
        challenge_rate_used = self._resolve_tier_challenge_rate(challenge_tier)
        challenge_interval_used = self._resolve_tier_min_interval(challenge_tier)
        msg_kind = self._select_msg_kind(
            target_id=target_id,
            challenge_tier=challenge_tier,
            iteration=iteration,
        )
        challenge_payload: Optional[Dict[str, Any]] = None
        observation_flags: Dict[str, Any]
        if msg_kind == "REQUEST":
            base_alarm_set_id = self.node.current_request_alarm_set_id or f"req_{self.node.id}_{iteration}"
            alarm_set_id, observation_flags = self._request_pmfa_surface(
                base_alarm_set_id=base_alarm_set_id,
                target_id=target_id,
                iteration=iteration,
            )
            challenge_tier = None
        else:
            alarm_set_id = f"chal_{self.node.id}_{target_id}_{iteration}_{challenge_tier}"
            challenge_payload = self._build_challenge_payload(
                challenge_tier=challenge_tier,
                target_id=target_id,
                iteration=iteration,
                alarm_set_id=alarm_set_id,
            )
            observation_flags = {
                "dmpo_enabled": False,
                "dmpo_variants": 1,
                "dmpo_variant_index": 1,
                "dmpo_delay_window_ms": 0.0,
                "alarm_family_id": alarm_set_id,
                "pmfa_surface_id": alarm_set_id,
            }

        observation = Observation(
            round_id=iteration,
            src_id=self.node.id,
            dst_id=target_id,
            msg_kind=msg_kind,
            alarm_set_id=alarm_set_id,
            true_label=1.0 if msg_kind == "CHALLENGE" else None,
            challenge_tier=challenge_tier,
            challenge_payload=challenge_payload,
            flags=dict(observation_flags),
        )

        response_value, flags = target_node.behavior_policy.respond(
            observation,
            source_is_malicious=self.node.is_malicious,
        )
        if flags:
            observation.flags.update(flags)
        response_value = self._score_challenge_response(
            response_value=response_value,
            msg_kind=msg_kind,
            challenge_tier=challenge_tier,
            flags=observation.flags,
        )
        observation.response_value = response_value

        # Record response history for biometric-style scoring
        self._record_behavior(target_id, response_value)

        # Log challenge metadata for PMFA leakage analytics (both request/challenge)
        try:
                metric_logger.log_privacy_event({
                    'delay_ms': 0.0,
                    'payload_size': len(str({
                        'src': self.node.id,
                        'dst': target_id,
                    'round': iteration,
                    'kind': msg_kind,
                        'tier': challenge_tier,
                    }).encode('utf-8')),
                    'variant_id': observation.flags.get('pmfa_surface_id'),
                    'is_challenge': msg_kind == "CHALLENGE",
                    'dmpo_enabled': bool(observation.flags.get('dmpo_enabled', False)),
                    'sender_id': self.node.id,
                    'receiver_id': target_id,
                    'iteration': iteration,
                    'message_id': alarm_set_id,
                    'alarm_hash': observation.flags.get('alarm_family_id', alarm_set_id),
                })
        except Exception:
            self.logger.debug("Failed to log challenge privacy event", exc_info=True)

        # Store observation to DB if available
        if self.node.db:
            try:
                self.node.db.store_event(
                    timestamp=float(getattr(self.node.env, 'now', 0)),
                    iteration=iteration,
                    node_id=self.node.id,
                    event_type='observation',
                    details={
                        'src_id': self.node.id,
                        'dst_id': target_id,
                        'msg_kind': msg_kind,
                        'alarm_set_id': alarm_set_id,
                        'challenge_tier': challenge_tier,
                        'true_label': observation.true_label,
                        'response_value': response_value,
                        'challenge_payload': challenge_payload,
                        'dmpo_enabled': observation.flags.get('dmpo_enabled'),
                        'dmpo_variants': observation.flags.get('dmpo_variants'),
                        'dmpo_variant_index': observation.flags.get('dmpo_variant_index'),
                        'dmpo_delay_window_ms': observation.flags.get('dmpo_delay_window_ms'),
                        'alarm_family_id': observation.flags.get('alarm_family_id'),
                        'pmfa_surface_id': observation.flags.get('pmfa_surface_id'),
                        'sybil_identity_id': observation.flags.get('sybil_identity_id'),
                        'sybil_identity_pool_size': observation.flags.get('sybil_identity_pool_size'),
                        'flags': observation.flags,
                        'challenge_rate_used': challenge_rate_used,
                        'challenge_interval_used': challenge_interval_used,
                    },
                    related_node_id=target_id,
                )
            except Exception:
                self.logger.debug("Failed to store observation event", exc_info=True)

        # --- Gather Inputs for Calculator ---
        reputation = self._get_target_reputation(
            target_node=target_node,
            iteration=iteration,
            response_value=response_value,
        )
        contribution = self._get_target_contribution(target_node, iteration)
        direct_coordination_flag = bool(
            observation.flags.get('collusion_boost') or observation.flags.get('sybil_boost')
        )
        self._record_coordination_flag(
            target_id=target_id,
            iteration=iteration,
            direct_flag=direct_coordination_flag,
        )
        coordination_ratio = self._coordination_ratio(target_id, iteration)
        dense_subgraph_penalty = self._dense_subgraph_penalty(
            target_node=target_node,
            iteration=iteration,
            coordination_ratio=coordination_ratio,
            direct_flag=direct_coordination_flag,
        )
        penalty = self._compute_penalty(response_value, observation.flags) + dense_subgraph_penalty
        penalty = max(0.0, min(1.0, penalty))

        # --- Call Calculator Methods ---
        # Basic trust always updates (lightweight, frequent)
        basic_trust = self.calculator.calculate_basic_challenge_score(
            feedback=float(response_value),
            prev_trust=prev_basic,
            learning_rate=self.node.learning_rate,
        )

        # Advanced trust updates only on advanced/final challenge tiers
        advanced_trust = prev_advanced
        if msg_kind == "CHALLENGE" and challenge_tier in {"advanced", "final"}:
            advanced_trust = self.calculator.calculate_advanced_challenge_score(
                target_node_is_malicious=False,
                iteration=iteration,
                prev_trust=prev_advanced,
                reputation=reputation,
                contribution=contribution,
                penalty=penalty,
                weights=self.node.weights
            )

        # Final trust updates only on final challenges
        final_trust = prev_final
        auth_status = None
        biometric_score = None
        if msg_kind == "CHALLENGE" and challenge_tier == "final":
            auth_success = self.node.authenticate(target_node)
            auth_status = 1.0 if auth_success else 0.0
            biometric_score = self.node.calculate_biometric(target_node)
            final_trust = self.calculator.calculate_final_challenge_score(
                prev_trust=prev_final,
                auth_status=auth_status,
                biometric_score=biometric_score,
                weights=self.node.weights
            )

        # --- Combine Scores --- 
        # Ambil bobot total trust dari trust_config Node, fallback ke default jika tidak ada
        total_trust_config = self.node.trust_config.get('weights_total_trust', {})
        total_trust_weights = {
            'w1': total_trust_config.get('w1', 0.3), # Default dari YAML/struktur
            'w2': total_trust_config.get('w2', 0.3), # Default dari YAML/struktur
            'w3': total_trust_config.get('w3', 0.4)  # Default dari YAML/struktur
        }
        total_trust = self.calculator.calculate_total_trust(
            basic_trust=basic_trust,
            advanced_trust=advanced_trust,
            final_trust=final_trust,
            total_trust_weights=total_trust_weights
        )

        # Update per-tier state
        component_state['basic'] = basic_trust
        component_state['advanced'] = advanced_trust
        component_state['final'] = final_trust

        # Quarantine/unquarantine based on fall/rise thresholds
        _, fall, rise = self._get_thresholds()
        if total_trust < fall:
            self.node.quarantined_nodes.add(target_id)
        elif total_trust >= rise:
            self.node.quarantined_nodes.discard(target_id)

        # Log challenge events ke DB (untuk UI NodeAnalysis)
        if self.node.db:
            try:
                ts = float(getattr(self.node.env, 'now', 0))
                ev_base = {
                    'timestamp': ts,
                    'iteration': iteration,
                    'node_id': self.node.id,
                    'related_node_id': target_id,
                }
                # Basic challenge event
                self.node.db.store_event(
                    **ev_base,
                    event_type='challenge_basic',
                    details={
                        'score': basic_trust,
                        'prev_trust': prev_basic,
                        'challenge_tier': challenge_tier,
                        'msg_kind': msg_kind,
                        'alarm_set_id': alarm_set_id,
                        'challenge_payload': challenge_payload,
                        'dmpo_enabled': observation.flags.get('dmpo_enabled'),
                        'pmfa_surface_id': observation.flags.get('pmfa_surface_id'),
                        'alarm_family_id': observation.flags.get('alarm_family_id'),
                        'sybil_identity_id': observation.flags.get('sybil_identity_id'),
                        'sybil_identity_pool_size': observation.flags.get('sybil_identity_pool_size'),
                        'challenge_proof_type': observation.flags.get('challenge_proof_type'),
                        'challenge_proof_valid': observation.flags.get('challenge_proof_valid'),
                        'response_value': response_value,
                        'challenge_rate_used': challenge_rate_used,
                        'challenge_interval_used': challenge_interval_used,
                    },
                )
                # Advanced challenge event
                self.node.db.store_event(
                    **ev_base,
                    event_type='challenge_advanced',
                    details={
                        'score': advanced_trust,
                        'reputation': reputation,
                        'contribution': contribution,
                        'penalty': penalty,
                        'dense_subgraph_penalty': dense_subgraph_penalty,
                        'coordination_ratio': coordination_ratio,
                        'challenge_tier': challenge_tier,
                        'msg_kind': msg_kind,
                        'alarm_set_id': alarm_set_id,
                        'challenge_payload': challenge_payload,
                        'dmpo_enabled': observation.flags.get('dmpo_enabled'),
                        'pmfa_surface_id': observation.flags.get('pmfa_surface_id'),
                        'alarm_family_id': observation.flags.get('alarm_family_id'),
                        'sybil_identity_id': observation.flags.get('sybil_identity_id'),
                        'sybil_identity_pool_size': observation.flags.get('sybil_identity_pool_size'),
                        'challenge_proof_type': observation.flags.get('challenge_proof_type'),
                        'challenge_proof_valid': observation.flags.get('challenge_proof_valid'),
                        'challenge_rate_used': challenge_rate_used,
                        'challenge_interval_used': challenge_interval_used,
                    },
                )
                # Final challenge event
                self.node.db.store_event(
                    **ev_base,
                    event_type='challenge_final',
                    details={
                        'score': final_trust,
                        'auth': auth_status,
                        'biometric_score': biometric_score,
                        'challenge_tier': challenge_tier,
                        'msg_kind': msg_kind,
                        'alarm_set_id': alarm_set_id,
                        'challenge_payload': challenge_payload,
                        'dmpo_enabled': observation.flags.get('dmpo_enabled'),
                        'pmfa_surface_id': observation.flags.get('pmfa_surface_id'),
                        'alarm_family_id': observation.flags.get('alarm_family_id'),
                        'sybil_identity_id': observation.flags.get('sybil_identity_id'),
                        'sybil_identity_pool_size': observation.flags.get('sybil_identity_pool_size'),
                        'challenge_proof_type': observation.flags.get('challenge_proof_type'),
                        'challenge_proof_valid': observation.flags.get('challenge_proof_valid'),
                        'challenge_rate_used': challenge_rate_used,
                        'challenge_interval_used': challenge_interval_used,
                    },
                )
                # Aggregate challenge outcome for analytics
                self.node.db.store_event(
                    **ev_base,
                    event_type='challenge_outcome',
                    details={
                        'prev_trust': prev_total,
                        'total_trust': total_trust,
                        'auth': auth_status,
                        'basic': basic_trust,
                        'advanced': advanced_trust,
                        'final': final_trust,
                        'reputation': reputation,
                        'contribution': contribution,
                        'penalty': penalty,
                        'dense_subgraph_penalty': dense_subgraph_penalty,
                        'coordination_ratio': coordination_ratio,
                        'challenge_tier': challenge_tier,
                        'msg_kind': msg_kind,
                        'alarm_set_id': alarm_set_id,
                        'challenge_payload': challenge_payload,
                        'dmpo_enabled': observation.flags.get('dmpo_enabled'),
                        'pmfa_surface_id': observation.flags.get('pmfa_surface_id'),
                        'alarm_family_id': observation.flags.get('alarm_family_id'),
                        'sybil_identity_id': observation.flags.get('sybil_identity_id'),
                        'sybil_identity_pool_size': observation.flags.get('sybil_identity_pool_size'),
                        'challenge_proof_type': observation.flags.get('challenge_proof_type'),
                        'challenge_proof_valid': observation.flags.get('challenge_proof_valid'),
                        'response_value': response_value,
                        'challenge_rate_used': challenge_rate_used,
                        'challenge_interval_used': challenge_interval_used,
                    },
                )
            except Exception as evt_err:
                self.logger.debug(f"Failed to log challenge events: {evt_err}")

        # --- Detection latency hook -------------------------------------
        # If target is malicious and this is first time trust < threshold, log latency
        if target_node.is_malicious:
            detection_threshold, _, _ = self._get_thresholds()
            previous_score = prev_total
            if previous_score >= detection_threshold and total_trust < detection_threshold:
                # Need attack_start_tick attribute; fallback to 0 if absent
                attack_start = getattr(target_node, 'attack_start_tick', 0)
                current_tick = getattr(self.node.env, 'now', 0)
                from simulation.utils.perf import metric_logger  # absolute import, avoid package mismatch
                metric_logger.latencies.append(current_tick - attack_start)

        # --- Update Node's State and Log --- 
        # Manager memberitahu Node untuk update skor internalnya
        self.node.trust_scores[target_id] = total_trust 
        # Log dari manager
        self.logger.debug(f"3-Level Challenge: Evaluated trust for Node {target_id}: {total_trust:.4f} "
                       f"(B: {basic_trust:.4f}, A: {advanced_trust:.4f}, F: {final_trust:.4f}) at Iteration {iteration}")

        if self.metrics_recorder is not None:
            try:
                self.metrics_recorder.record_challenge_outcome(
                    source_node=self.node.id,
                    target_node=target_id,
                    iteration=iteration,
                    trust_before=prev_total,
                    trust_after=total_trust,
                    detection_threshold=self._get_thresholds()[0],
                    target_is_malicious=target_node.is_malicious,
                    details={
                        'basic': basic_trust,
                        'advanced': advanced_trust,
                        'final': final_trust,
                        'auth': auth_status,
                        'reputation': reputation,
                        'contribution': contribution,
                        'penalty': penalty,
                        'dense_subgraph_penalty': dense_subgraph_penalty,
                        'coordination_ratio': coordination_ratio,
                        'challenge_tier': challenge_tier,
                    },
                )
            except Exception as metrics_exc:
                self.logger.debug(f"Failed to record challenge outcome: {metrics_exc}")

        # Manager juga bisa bertanggung jawab menyimpan ke DB
        if self.node.db:
             try:
                self.node.db.store_trust_score(
                    node_id=self.node.id,
                    target_node_id=target_id,
                    score=total_trust,
                    iteration=iteration
                )
             except Exception as db_err:
                 self.logger.error(f"DB Error in TrustManager storing score for {target_id}: {db_err}")

        return total_trust
    
    def process_alarm(self, alarm: Dict[str, Any]) -> list:
        """
        Process alarm using active trust method.
        
        Args:
            alarm: Alarm data yang akan diproses
            
        Returns:
            list: Processed alarm(s)
        """
        try:
            if self.trust_plugin:
                # Use plugin method
                return self.trust_plugin.process_alarm(alarm, self.node)
            else:
                # Default: pass-through untuk 3-level challenge
                return [alarm]
                
        except Exception as e:
            self.logger.error(f"Error processing alarm: {e}")
            return [alarm]
    
    def handle_challenge(self, challenge: Any) -> Optional[Dict[str, Any]]:
        """
        Handle challenge using active trust method.
        
        Args:
            challenge: Challenge message
            
        Returns:
            Optional[Dict]: Challenge response, atau None
        """
        try:
            return {
                'type': 'challenge_response',
                'sender_id': self.node.id,
                'trust_method': '3_level_challenge',
                'timestamp': self.node.env.now if hasattr(self.node, 'env') else 0
            }
                
        except Exception as e:
            self.logger.error(f"Error handling challenge: {e}")
            return None
    
    def get_trust_method_info(self) -> Dict[str, Any]:
        """
        Get informasi tentang trust method yang sedang aktif.
        
        Returns:
            Dict: Informasi trust method
        """
        return {
            'name': '3-level-challenge',
            'description': 'Hierarchical 3-level trust mechanism (proposed method)',
            'features': [
                'Basic Challenge (λ learning rate)',
                'Advanced Challenge (reputation, contribution, penalty)',
                'Final Challenge (authentication, biometric)',
                'Total Trust Combination'
            ]
        }

    # --- Helper methods to get data needed for advanced challenge --- 
    # Implementasi sementara, idealnya data ini didapat dari DB atau cache
    def _get_target_reputation(
        self,
        target_node: 'Node',
        iteration: Optional[int] = None,
        response_value: Optional[float] = None,
    ) -> float:
        """Dirichlet reputation with optional neighbor blending."""
        if iteration is None or response_value is None:
            local_rep = 0.5
        else:
            local_rep = self._update_dirichlet_reputation(
                target_id=target_node.id,
                iteration=iteration,
                response_value=float(response_value),
            )

        blend = self._dirichlet_cfg.get('neighbor_blend', 1.0)
        if blend >= 1.0:
            return local_rep
        neighbor_rep = self._neighbor_reputation_mean(target_node)
        mixed = blend * local_rep + (1.0 - blend) * neighbor_rep
        return max(0.0, min(1.0, mixed))

    def _get_target_contribution(self, target_node: 'Node', iteration: int) -> float:
        """Contribution ratio based on accepted alarms from this target."""
        count = float(self.node.contribution_counts.get(target_node.id, 0))
        total = max(1.0, float(iteration + 1))
        return max(0.0, min(1.0, count / total))

    def _compute_penalty(self, response_value: float, flags: Dict[str, Any]) -> float:
        """Penalty derived from observed response and attack indicators."""
        penalty = 1.0 - float(response_value)
        if flags.get('collusion_boost') or flags.get('sybil_boost'):
            penalty += self._collusion_cfg.get('flag_boost', 0.1)
        if flags.get('pmfa_response') == 'malicious':
            penalty += 0.1
        return max(0.0, min(1.0, penalty))

    def _record_coordination_flag(self, target_id: int, iteration: int, direct_flag: bool) -> None:
        if not direct_flag:
            return
        history = self._coordination_history.setdefault(int(target_id), [])
        history.append(int(iteration))

        window = int(self._collusion_cfg.get('history_window', 20))
        cutoff = int(iteration) - window + 1
        if cutoff > 0:
            history[:] = [round_id for round_id in history if round_id >= cutoff]

    def _coordination_ratio(self, target_id: int, iteration: int) -> float:
        history = self._coordination_history.get(int(target_id), [])
        if not history:
            return 0.0
        window = int(self._collusion_cfg.get('history_window', 20))
        cutoff = int(iteration) - window + 1
        count = sum(1 for round_id in history if round_id >= cutoff)
        if count <= 0:
            return 0.0
        activation_count = int(self._collusion_cfg.get('activation_count', 2))
        return max(0.0, min(1.0, float(count) / float(max(1, activation_count))))

    def _resolve_node_by_id(self, node_id: int, target_node: 'Node') -> Optional['Node']:
        if node_id == self.node.id:
            return self.node
        if node_id == target_node.id:
            return target_node
        for neighbor in getattr(self.node, 'neighbors', []):
            if neighbor.id == node_id:
                return neighbor
        for neighbor in getattr(target_node, 'neighbors', []):
            if neighbor.id == node_id:
                return neighbor
        return None

    def _mutual_trust_above(self, node_a: 'Node', node_b: 'Node', threshold: float) -> bool:
        default_trust = float(self.node.trust_config.get('initial_trust', 0.5))
        try:
            a_to_b = float(getattr(node_a, 'trust_scores', {}).get(node_b.id, default_trust))
        except Exception:
            a_to_b = default_trust
        try:
            b_to_a = float(getattr(node_b, 'trust_scores', {}).get(node_a.id, default_trust))
        except Exception:
            b_to_a = default_trust
        return min(a_to_b, b_to_a) >= float(threshold)

    def _dense_subgraph_penalty(
        self,
        target_node: 'Node',
        iteration: int,
        coordination_ratio: float,
        direct_flag: bool,
    ) -> float:
        cfg = self._collusion_cfg
        if not cfg.get('enabled', True):
            return 0.0

        activation_ratio = float(cfg.get('activation_ratio', 0.2))
        if not direct_flag and coordination_ratio < activation_ratio:
            return 0.0

        candidate_ids = {int(target_node.id)}
        threshold = float(cfg.get('trust_edge_threshold', 0.7))
        for neighbor in getattr(target_node, 'neighbors', []):
            if neighbor.id == self.node.id:
                continue
            neighbor_ratio = self._coordination_ratio(neighbor.id, iteration)
            if neighbor_ratio >= activation_ratio:
                candidate_ids.add(int(neighbor.id))
            elif direct_flag and self._mutual_trust_above(target_node, neighbor, threshold):
                candidate_ids.add(int(neighbor.id))

        min_group_size = int(cfg.get('min_group_size', 3))
        if len(candidate_ids) < min_group_size:
            return 0.0

        candidate_nodes = []
        for node_id in sorted(candidate_ids):
            node_ref = self._resolve_node_by_id(node_id, target_node)
            if node_ref is not None:
                candidate_nodes.append(node_ref)

        if len(candidate_nodes) < min_group_size:
            return 0.0

        edge_count = 0
        possible_edges = 0
        for idx in range(len(candidate_nodes)):
            for jdx in range(idx + 1, len(candidate_nodes)):
                possible_edges += 1
                if self._mutual_trust_above(candidate_nodes[idx], candidate_nodes[jdx], threshold):
                    edge_count += 1

        if possible_edges <= 0:
            return 0.0

        density = edge_count / float(possible_edges)
        density_threshold = float(cfg.get('density_threshold', 0.5))
        if density <= density_threshold:
            return 0.0

        normalized_density = (density - density_threshold) / max(1e-9, 1.0 - density_threshold)
        activation = max(coordination_ratio, 1.0 if direct_flag else 0.0)
        max_penalty = float(cfg.get('max_penalty', 0.2))
        dense_penalty = max_penalty * normalized_density * activation
        return max(0.0, min(max_penalty, dense_penalty))
