from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass(frozen=True)
class DisseminationPolicy:
    policy_id: str
    K_t: int
    f_t: int
    ell_t: str
    d_t: str
    r_t: float


class DMPOXPolicyController:
    """Finite-policy selector constrained by privacy risk and bw/latency budgets."""

    def __init__(self, feature_config: Dict[str, Any]):
        privacy_cfg = feature_config.get("privacy", {}) or {}
        cfg = privacy_cfg.get("controller", {}) or {}
        strategy_name = str(
            feature_config.get("privacy_strategy")
            or privacy_cfg.get("strategy")
            or "dmpo_legacy"
        ).lower()
        self.enabled = bool(cfg.get("enabled", strategy_name == "dmpo_x"))
        self.lambda_bw = float(cfg.get("lambda_bw", 0.2))
        self.lambda_lat = float(cfg.get("lambda_lat", 0.2))
        self.lambda_privacy = float(cfg.get("lambda_privacy", 1.0))
        self.lambda_budget = float(cfg.get("lambda_budget", 2.0))
        self.budget_bw = max(0.1, float(cfg.get("budget_bw", 3.5)))
        self.budget_lat_ms = max(1.0, float(cfg.get("budget_lat_ms", 350.0)))
        raw_candidates: List[Dict[str, Any]] = cfg.get("candidate_policies") or []
        if not raw_candidates:
            raw_candidates = [
                {"policy_id": "p0", "K_t": 2, "f_t": 2, "ell_t": "small", "d_t": "exp_low", "r_t": 0.0},
                {"policy_id": "p1", "K_t": 3, "f_t": 3, "ell_t": "medium", "d_t": "exp_mid", "r_t": 0.15},
                {"policy_id": "p2", "K_t": 4, "f_t": 3, "ell_t": "medium", "d_t": "exp_high", "r_t": 0.30},
            ]
        self.candidates = [
            DisseminationPolicy(
                policy_id=str(c.get("policy_id", f"p{i}")),
                K_t=max(1, int(c.get("K_t", 2))),
                f_t=max(1, int(c.get("f_t", 2))),
                ell_t=str(c.get("ell_t", "medium")),
                d_t=str(c.get("d_t", "exp_mid")),
                r_t=max(0.0, float(c.get("r_t", 0.0))),
            )
            for i, c in enumerate(raw_candidates)
        ]

    @staticmethod
    def _clamp(value: Any, default: float = 0.5) -> float:
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            numeric = default
        return max(0.0, min(1.0, numeric))

    @staticmethod
    def _bw_cost(policy: DisseminationPolicy) -> float:
        return policy.K_t * 0.45 + policy.f_t * 0.30 + policy.r_t

    @staticmethod
    def _lat_cost_ms(policy: DisseminationPolicy) -> float:
        delay_cost = {"exp_low": 90.0, "exp_mid": 180.0, "exp_high": 320.0}.get(policy.d_t, 180.0)
        return delay_cost + 18.0 * policy.f_t

    @staticmethod
    def _privacy_strength(policy: DisseminationPolicy) -> float:
        size_score = {"small": 0.30, "medium": 0.55, "large": 0.80}.get(policy.ell_t, 0.55)
        delay_score = {"exp_low": 0.30, "exp_mid": 0.60, "exp_high": 0.85}.get(policy.d_t, 0.60)
        k_score = min(1.0, policy.K_t / 4.0)
        fanout_score = min(1.0, policy.f_t / 5.0)
        cover_score = min(1.0, policy.r_t)
        return 0.30 * k_score + 0.20 * fanout_score + 0.20 * size_score + 0.20 * delay_score + 0.10 * cover_score

    def select(
        self,
        *,
        severity: float = 0.5,
        trust_score: float = 0.5,
        node_load: float = 0.0,
        attacker_risk: float = 0.5,
    ) -> DisseminationPolicy:
        policy, _trace = self.select_with_trace(
            severity=severity,
            trust_score=trust_score,
            node_load=node_load,
            attacker_risk=attacker_risk,
        )
        return policy

    def select_with_trace(
        self,
        *,
        severity: float = 0.5,
        trust_score: float = 0.5,
        node_load: float = 0.0,
        attacker_risk: float = 0.5,
    ) -> tuple[DisseminationPolicy, Dict[str, Any]]:
        if not self.enabled:
            selected = self.candidates[0]
            return selected, self._build_trace(
                policy=selected,
                severity=severity,
                trust_score=trust_score,
                node_load=node_load,
                attacker_risk=attacker_risk,
                risk_target=0.0,
                objective=0.0,
                budget_penalty=0.0,
                selection_mode="disabled_default",
            )

        severity = self._clamp(severity)
        trust_score = self._clamp(trust_score)
        node_load = self._clamp(node_load, default=0.0)
        attacker_risk = self._clamp(attacker_risk)
        risk_target = (
            0.35 * severity
            + 0.25 * (1.0 - trust_score)
            + 0.20 * node_load
            + 0.20 * attacker_risk
        )

        best_policy = self.candidates[0]
        best_trace: Dict[str, Any] | None = None
        for policy in self.candidates:
            bw_cost = self._bw_cost(policy)
            lat_cost = self._lat_cost_ms(policy)
            privacy_strength = self._privacy_strength(policy)
            privacy_gap = max(0.0, risk_target - privacy_strength)
            budget_penalty = 0.0
            if bw_cost > self.budget_bw:
                budget_penalty += (bw_cost - self.budget_bw) / self.budget_bw
            if lat_cost > self.budget_lat_ms:
                budget_penalty += (lat_cost - self.budget_lat_ms) / self.budget_lat_ms
            objective = (
                self.lambda_privacy * privacy_gap
                + self.lambda_bw * (bw_cost / self.budget_bw)
                + self.lambda_lat * (lat_cost / self.budget_lat_ms)
                + self.lambda_budget * budget_penalty
            )
            trace = self._build_trace(
                policy=policy,
                severity=severity,
                trust_score=trust_score,
                node_load=node_load,
                attacker_risk=attacker_risk,
                risk_target=risk_target,
                objective=objective,
                budget_penalty=budget_penalty,
                selection_mode="objective_minimization",
                bw_cost=bw_cost,
                lat_cost_ms=lat_cost,
                privacy_strength=privacy_strength,
                privacy_gap=privacy_gap,
            )
            if best_trace is None or float(trace["objective"]) < float(best_trace["objective"]):
                best_policy = policy
                best_trace = trace
        return best_policy, dict(best_trace or {})

    def _build_trace(
        self,
        *,
        policy: DisseminationPolicy,
        severity: float,
        trust_score: float,
        node_load: float,
        attacker_risk: float,
        risk_target: float,
        objective: float,
        budget_penalty: float,
        selection_mode: str,
        bw_cost: float | None = None,
        lat_cost_ms: float | None = None,
        privacy_strength: float | None = None,
        privacy_gap: float | None = None,
    ) -> Dict[str, Any]:
        bw_cost = self._bw_cost(policy) if bw_cost is None else bw_cost
        lat_cost_ms = self._lat_cost_ms(policy) if lat_cost_ms is None else lat_cost_ms
        privacy_strength = self._privacy_strength(policy) if privacy_strength is None else privacy_strength
        privacy_gap = max(0.0, risk_target - privacy_strength) if privacy_gap is None else privacy_gap
        return {
            "selected_policy_id": policy.policy_id,
            "selected_K_t": int(policy.K_t),
            "selected_f_t": int(policy.f_t),
            "selected_ell_t": str(policy.ell_t),
            "selected_d_t": str(policy.d_t),
            "selected_r_t": float(policy.r_t),
            "severity": float(self._clamp(severity)),
            "trust_score": float(self._clamp(trust_score)),
            "node_load": float(self._clamp(node_load, default=0.0)),
            "attacker_risk": float(self._clamp(attacker_risk)),
            "risk_target": float(max(0.0, risk_target)),
            "bw_cost": float(max(0.0, bw_cost)),
            "lat_cost_ms": float(max(0.0, lat_cost_ms)),
            "privacy_strength": float(max(0.0, privacy_strength)),
            "privacy_gap": float(max(0.0, privacy_gap)),
            "budget_penalty": float(max(0.0, budget_penalty)),
            "objective": float(max(0.0, objective)),
            "selection_mode": str(selection_mode),
            "controller_enabled": bool(self.enabled),
            "budget_bw": float(self.budget_bw),
            "budget_lat_ms": float(self.budget_lat_ms),
            "lambda_bw": float(self.lambda_bw),
            "lambda_lat": float(self.lambda_lat),
            "lambda_privacy": float(self.lambda_privacy),
            "lambda_budget": float(self.lambda_budget),
            "candidate_count": int(len(self.candidates)),
        }
